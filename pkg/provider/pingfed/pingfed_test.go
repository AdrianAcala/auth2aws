package pingfed

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"
	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

func TestMakeAbsoluteURL(t *testing.T) {
	require.Equal(t, makeAbsoluteURL("/a", "https://example.com"), "https://example.com/a")
	require.Equal(t, makeAbsoluteURL("https://foo.com/a/b", "https://bar.com"), "https://foo.com/a/b")
}

var docTests = []struct {
	fn       func(*goquery.Document) bool
	file     string
	expected bool
}{
	{docIsLogin, "example/login.html", true},
	{docIsLogin, "example/login2.html", true},
	{docIsLogin, "example/otp.html", false},
	{docIsLogin, "example/swipe.html", false},
	{docIsLogin, "example/swipe-number.html", false},
	{docIsLogin, "example/form-redirect.html", false},
	{docIsLogin, "example/webauthn.html", false},
	{docIsOTP, "example/login.html", false},
	{docIsOTP, "example/otp.html", true},
	{docIsOTP, "example/swipe.html", false},
	{docIsOTP, "example/swipe-number.html", false},
	{docIsOTP, "example/form-redirect.html", false},
	{docIsOTP, "example/webauthn.html", false},
	{docIsSwipe, "example/login.html", false},
	{docIsSwipe, "example/otp.html", false},
	{docIsSwipe, "example/swipe.html", true},
	{docIsSwipe, "example/swipe-number.html", true},
	{docIsSwipe, "example/form-redirect.html", false},
	{docIsSwipe, "example/webauthn.html", false},
	{docIsFormRedirect, "example/login.html", false},
	{docIsFormRedirect, "example/otp.html", false},
	{docIsFormRedirect, "example/swipe.html", false},
	{docIsFormRedirect, "example/swipe-number.html", false},
	{docIsFormRedirect, "example/form-redirect.html", true},
	{docIsFormRedirect, "example/webauthn.html", false},
	{docIsWebAuthn, "example/login.html", false},
	{docIsWebAuthn, "example/otp.html", false},
	{docIsWebAuthn, "example/swipe.html", false},
	{docIsWebAuthn, "example/swipe-number.html", false},
	{docIsWebAuthn, "example/form-redirect.html", false},
	{docIsWebAuthn, "example/webauthn.html", true},
}

func TestDocTypes(t *testing.T) {
	for _, tt := range docTests {
		data, err := os.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		if tt.fn(doc) != tt.expected {
			t.Errorf("expect doc check of %v to be %v", tt.file, tt.expected)
		}
	}
}

func TestHandleLogin(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	data, err := os.ReadFile("example/login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, req, err := ac.handleLogin(ctx, doc, &url.URL{})
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "pf.username=fdsa")
	require.Contains(t, s, "pf.pass=secret")
}

func TestHandleOTP(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("StringRequired", "Enter passcode").Return("5309")

	data, err := os.ReadFile("example/otp.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	pingfedURL := &url.URL{
		Scheme: "https",
		Host:   "authenticator.pingone.com",
		Path:   "/pingid/ppm/auth/otp",
	}
	jar, err := cookiejar.New(&cookiejar.Options{})
	require.Nil(t, err)
	jar.SetCookies(pingfedURL, []*http.Cookie{{
		Name:    ".csrf",
		Secure:  true,
		Expires: time.Now().Add(time.Hour * 24 * 30),
		Value:   "some-token",
	}})

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{client: &provider.HTTPClient{Client: http.Client{Jar: jar}, Options: opts}}
	_, req, err := ac.handleOTP(context.Background(), doc, pingfedURL)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "otp=5309")
	require.Contains(t, s, "csrfToken=some-token")
}

func TestHandleSwipe(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pingid/ppm/auth/status":
			_, err := w.Write([]byte("{\"status\":\"OK\"}"))
			require.Nil(t, err)
		default:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	performTest := func(data []byte) bytes.Buffer {
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bytes.ReplaceAll(data, []byte("https://authenticator.pingone.com"), []byte(ts.URL))))
		require.Nil(t, err)

		testTransport := http.DefaultTransport.(*http.Transport).Clone()
		testTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		ac := Client{
			client: &provider.HTTPClient{Client: http.Client{Transport: testTransport}, Options: &provider.HTTPClientOptions{IsWithRetries: false}},
		}

		var out bytes.Buffer
		log.SetOutput(&out)
		_, req, err := ac.handleSwipe(context.Background(), doc, &url.URL{})
		log.SetOutput(os.Stderr)
		require.Nil(t, err)

		b, err := io.ReadAll(req.Body)
		require.Nil(t, err)

		s := string(b[:])
		require.Contains(t, s, "csrfToken=abdb4264-6aab-4e1a-a830-63c9188e2395")

		return out
	}

	t.Run("Swipe", func(t *testing.T) {
		data, err := os.ReadFile("example/swipe.html")
		require.Nil(t, err)

		performTest(data)
	})

	t.Run("Swipe with number", func(t *testing.T) {
		data, err := os.ReadFile("example/swipe-number.html")
		require.Nil(t, err)

		out := performTest(data)
		require.Contains(t, out.String(), "Select 10 in your PingID mobile app ...")
	})
}

func TestHandleFormRedirect(t *testing.T) {
	data, err := os.ReadFile("example/form-redirect.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleFormRedirect(context.Background(), doc, &url.URL{})
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "ppm_request=secret")
	require.Contains(t, s, "idp_account_id=some-uuid")
}

func TestHandleWebAuthn(t *testing.T) {
	data, err := os.ReadFile("example/webauthn.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleWebAuthn(context.Background(), doc, &url.URL{})
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "isWebAuthnSupportedByBrowser=false")
}

func newPingFedTestClient(t *testing.T, handler http.Handler, targetURL string) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	account := &cfg.IDPAccount{
		AmazonWebservicesURN: "urn:test:aws",
		TargetURL:            targetURL,
		HttpAttemptsCount:    "invalid",
	}
	client, err := New(account)
	require.NoError(t, err)
	return client, ts
}

func TestAuthenticatePasswordAndSAMLWithRedirect(t *testing.T) {
	const assertion = "pingfed-saml-assertion"
	encodedAssertion := base64.StdEncoding.EncodeToString([]byte(assertion))
	var requests []string
	var loginForm url.Values
	var targetURL string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/idp/startSSO.ping":
			require.Equal(t, "urn:test:aws", r.URL.Query().Get("PartnerSpId"))
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			_, _ = w.Write([]byte(`<form action="/login/submit" method="post"><input name="pf.username"><input name="pf.pass"></form>`))
		case "/login/submit":
			require.NoError(t, r.ParseForm())
			loginForm = r.Form
			_, _ = w.Write([]byte(`<form action="` + targetURL + `" method="post"><input name="SAMLResponse" value="` + encodedAssertion + `"></form>`))
		case "/saml":
			require.NoError(t, r.ParseForm())
			require.Equal(t, encodedAssertion, r.Form.Get("SAMLResponse"))
			_, _ = w.Write([]byte("unexpected extra request"))
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	})

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	targetURL = ts.URL + "/saml"
	account := &cfg.IDPAccount{AmazonWebservicesURN: "urn:test:aws", TargetURL: targetURL, HttpAttemptsCount: "invalid"}
	client, err := New(account)
	require.NoError(t, err)

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL, Username: "alice", Password: "secret"})
	require.NoError(t, err)
	require.Equal(t, encodedAssertion, got)
	require.Equal(t, []string{"GET /idp/startSSO.ping", "GET /login", "POST /login/submit"}, requests)
	require.Equal(t, "alice", loginForm.Get("pf.username"))
	require.Equal(t, "secret", loginForm.Get("pf.pass"))
}

func TestFollowRefreshWithoutLoginContext(t *testing.T) {
	client, ts := newPingFedTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<meta http-equiv="refresh" content="0;url=/start">`))
	}), "")
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)

	got, err := client.follow(context.Background(), req)
	require.Empty(t, got)
	require.EqualError(t, err, "no context value for login")
}

func TestHandleFormSelectDeviceMissingForm(t *testing.T) {
	pr := &mocks.Prompter{}
	pr.On("Choose", "Select which MFA Device to use", []string{}).Return(0)
	originalPrompter := prompter.ActivePrompter
	prompter.SetPrompter(pr)
	t.Cleanup(func() { prompter.SetPrompter(originalPrompter) })

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(`<form name="device-form"></form>`))
	require.NoError(t, err)

	client := Client{}
	_, req, err := client.handleFormSelectDevice(context.Background(), doc, &url.URL{Scheme: "https", Host: "idp.example"})
	require.Nil(t, req)
	require.ErrorContains(t, err, "error extracting select device form")
}

func TestAuthenticateUnknownPage(t *testing.T) {
	client, ts := newPingFedTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><p>unexpected page</p></body></html>`))
	}), "")

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, got)
	require.EqualError(t, err, "Unknown document type")
}

func TestAuthenticateMalformedSAMLResponse(t *testing.T) {
	client, ts := newPingFedTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form action="https://signin.aws.amazon.com/saml"><input name="SAMLResponse" value="%%%invalid%%"></form>`))
	}), "")

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, got)
	require.ErrorContains(t, err, "failed to decode saml-response")
}

func TestAuthenticateHTTPError(t *testing.T) {
	client, ts := newPingFedTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}), "")

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, got)
	require.ErrorContains(t, err, "error following")
	require.ErrorContains(t, err, "502 Bad Gateway")
}
