package pingntlm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"
	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
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
	{docIsLogin, "example/form-redirect.html", false},
	{docIsLogin, "example/webauthn.html", false},
	{docIsOTP, "example/login.html", false},
	{docIsOTP, "example/otp.html", true},
	{docIsOTP, "example/swipe.html", false},
	{docIsOTP, "example/form-redirect.html", false},
	{docIsOTP, "example/webauthn.html", false},
	{docIsSwipe, "example/login.html", false},
	{docIsSwipe, "example/otp.html", false},
	{docIsSwipe, "example/swipe.html", true},
	{docIsSwipe, "example/form-redirect.html", false},
	{docIsSwipe, "example/webauthn.html", false},
	{docIsFormRedirect, "example/login.html", false},
	{docIsFormRedirect, "example/otp.html", false},
	{docIsFormRedirect, "example/swipe.html", false},
	{docIsFormRedirect, "example/form-redirect.html", true},
	{docIsFormRedirect, "example/webauthn.html", false},
	{docIsWebAuthn, "example/login.html", false},
	{docIsWebAuthn, "example/otp.html", false},
	{docIsWebAuthn, "example/swipe.html", false},
	{docIsWebAuthn, "example/form-redirect.html", false},
	{docIsWebAuthn, "example/webauthn.html", true},
	{docIsFormSamlRequest, "example/login.html", false},
	{docIsFormSamlRequest, "example/otp.html", false},
	{docIsFormSamlRequest, "example/swipe.html", false},
	{docIsFormSamlRequest, "example/form-redirect.html", false},
	{docIsFormSamlRequest, "example/webauthn.html", false},
	{docIsFormSamlResponse, "example/login.html", false},
	{docIsFormSamlResponse, "example/otp.html", false},
	{docIsFormSamlResponse, "example/swipe.html", false},
	{docIsFormSamlResponse, "example/form-redirect.html", false},
	{docIsFormSamlResponse, "example/webauthn.html", false},
	{docIsFormResume, "example/login.html", false},
	{docIsFormResume, "example/otp.html", false},
	{docIsFormResume, "example/swipe.html", false},
	{docIsFormResume, "example/form-redirect.html", false},
	{docIsFormResume, "example/webauthn.html", false},
	{docIsFormRedirectToAWS, "example/login.html", false},
	{docIsFormRedirectToAWS, "example/otp.html", false},
	{docIsFormRedirectToAWS, "example/swipe.html", false},
	{docIsFormRedirectToAWS, "example/form-redirect.html", false},
	{docIsFormRedirectToAWS, "example/webauthn.html", false},
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

	_, req, err := ac.handleLogin(ctx, doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "pf.username=fdsa")
	require.Contains(t, s, "pf.pass=secret")
}

func TestHandleLoginNoContextValue(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey(""), &loginDetails)

	data, err := os.ReadFile("example/login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, _, err = ac.handleLogin(ctx, doc)
	assert.ErrorContains(t, err, "no context value for 'login'")
}

func TestHandleLoginNoForm(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	_, _, err = ac.handleLogin(ctx, doc)
	assert.ErrorContains(t, err, "error extracting login form")
}

func TestHandleOTP(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("StringRequired", "Enter passcode").Return("5309")

	data, err := os.ReadFile("example/otp.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleOTP(context.Background(), doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "otp=5309")
}

func TestHandleOTPNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleOTP(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting OTP form")
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
			client: &http.Client{Transport: testTransport},
		}

		var out bytes.Buffer
		log.SetOutput(&out)
		_, req, err := ac.handleSwipe(context.Background(), doc)
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
}

func TestHandleSwipeNoResponseView(t *testing.T) {
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
			client: &http.Client{Transport: testTransport},
		}

		var out bytes.Buffer
		log.SetOutput(&out)
		_, _, err = ac.handleSwipe(context.Background(), doc)
		log.SetOutput(os.Stderr)
		assert.ErrorContains(t, err, "error extracting swipe response form")

		return out
	}

	t.Run("Swipe", func(t *testing.T) {
		data, err := os.ReadFile("example/swipe-no-reponseView.html")
		require.Nil(t, err)

		performTest(data)
	})
}

func TestHandleSwipeNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleSwipe(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting swipe status form")
}

func TestHandleFormRedirect(t *testing.T) {
	data, err := os.ReadFile("example/form-redirect.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleFormRedirect(context.Background(), doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "ppm_request=secret")
	require.Contains(t, s, "idp_account_id=some-uuid")
}

func TestHandleFormRedirectNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleFormRedirect(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting redirect form")
}

func TestHandleWebAuthn(t *testing.T) {
	data, err := os.ReadFile("example/webauthn.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleWebAuthn(context.Background(), doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "isWebAuthnSupportedByBrowser=false")
}

func TestHandleWebAuthnNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleWebAuthn(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting webauthn form")
}

func TestNew(t *testing.T) {
	type args struct {
		idpAccount *cfg.IDPAccount
	}
	tests := []struct {
		name    string
		args    args
		want    *Client
		wantErr bool
	}{
		{
			name: "test client",
			args: args{
				idpAccount: &cfg.IDPAccount{
					SkipVerify: false,
				},
			},
			want:    &Client{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want.idpAccount = tt.args.idpAccount
			got, err := New(tt.args.idpAccount)
			tt.want.client = got.client
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticateInvalidHost(t *testing.T) {
	idpAccount := &cfg.IDPAccount{
		Provider:   "PingNTLM",
		MFA:        "Auto",
		SkipVerify: false,
	}
	client, err := New(idpAccount)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{Username: "testuser", Password: "testtestlol", URL: "https://id.example.com", MFAToken: "123456"}
	_, err = client.Authenticate(loginDetails)
	assert.ErrorContains(t, err, "no such host")
}

func TestClient_follow(t *testing.T) {
	type fields struct {
		ValidateBase provider.ValidateBase
		client       *http.Client
		idpAccount   *cfg.IDPAccount
	}
	type args struct {
		ctx context.Context
		req *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid request",
			args: args{
				ctx: context.TODO(),
				req: &http.Request{},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &Client{
				ValidateBase: tt.fields.ValidateBase,
				client:       tt.fields.client,
				idpAccount:   tt.fields.idpAccount,
			}
			got, err := ac.follow(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.follow() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.follow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticateSuccessfulFlow(t *testing.T) {
	const assertion = "pingntlm-saml-assertion"
	encodedAssertion := base64.StdEncoding.EncodeToString([]byte(assertion))
	var requests []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/idp/startSSO.ping", r.URL.Path)
		require.Equal(t, "urn:amazon:webservices", r.URL.Query().Get("PartnerSpId"))
		_, err := io.WriteString(w, `<form action="https://signin.aws.amazon.com/saml"><input name="SAMLResponse" value="`+encodedAssertion+`"></form>`)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client, err := New(&cfg.IDPAccount{AmazonWebservicesURN: "urn:amazon:webservices"})
	require.NoError(t, err)

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL, Username: "alice", Password: "secret"})
	require.NoError(t, err)
	require.Equal(t, assertion, string(mustDecodeSAML(t, got)))
	require.Equal(t, []string{"GET /idp/startSSO.ping?PartnerSpId=urn:amazon:webservices"}, requests)
	require.Equal(t, "ntlmssp.Negotiator", reflect.TypeOf(client.client.Transport).String())
}

func TestAuthenticateFollowsRedirect(t *testing.T) {
	const assertion = "redirected-assertion"
	encodedAssertion := base64.StdEncoding.EncodeToString([]byte(assertion))
	var paths []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/idp/startSSO.ping" {
			http.Redirect(w, r, "/idp/final", http.StatusFound)
			return
		}
		_, err := io.WriteString(w, `<form action="https://signin.aws.amazon.com/saml"><input name="SAMLResponse" value="`+encodedAssertion+`"></form>`)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client, err := New(&cfg.IDPAccount{AmazonWebservicesURN: "urn:amazon:webservices"})
	require.NoError(t, err)
	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL, Username: "alice", Password: "secret"})
	require.NoError(t, err)
	require.Equal(t, assertion, string(mustDecodeSAML(t, got)))
	require.Equal(t, []string{"/idp/startSSO.ping", "/idp/final"}, paths)
}

func TestFollowRedirectError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer ts.Close()

	client := &Client{client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirect denied")
	}}}
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	got, err := client.follow(context.Background(), req)
	require.Empty(t, got)
	require.ErrorContains(t, err, "error following")
	require.ErrorContains(t, err, "redirect denied")
}

func TestFollowTransportError(t *testing.T) {
	client := &Client{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("transport unavailable")
	})}}
	req, err := http.NewRequest(http.MethodGet, "https://example.test/login", nil)
	require.NoError(t, err)

	got, err := client.follow(context.Background(), req)
	require.Empty(t, got)
	require.EqualError(t, err, `error following: Get "https://example.test/login": transport unavailable`)
}

func TestFollowSAMLResponse(t *testing.T) {
	const assertion = "follow-assertion"
	encodedAssertion := base64.StdEncoding.EncodeToString([]byte(assertion))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, `<form action="https://signin.aws.amazon.com/saml"><input name="SAMLResponse" value="`+encodedAssertion+`"></form>`)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := &Client{client: &http.Client{}}
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	got, err := client.follow(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, encodedAssertion, got)
}

func TestDocClassifications(t *testing.T) {
	tests := []struct {
		name string
		body string
		fn   func(*goquery.Document) bool
	}{
		{"SAML request", `<form><input name="SAMLRequest" value="request"></form>`, docIsFormSamlRequest},
		{"SAML response", `<form><input name="SAMLResponse" value="response"></form>`, docIsFormSamlResponse},
		{"resume", `<form><input name="RelayState" value="resume"></form>`, docIsFormResume},
		{"AWS SAML target", `<form action="https://signin.aws.amazon.com/saml"><input name="SAMLResponse" value="response"></form>`, docIsFormRedirectToAWS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(tt.body))
			require.NoError(t, err)
			require.True(t, tt.fn(doc))
		})
	}
}

func mustDecodeSAML(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
