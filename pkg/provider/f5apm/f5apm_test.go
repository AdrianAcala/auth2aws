package f5apm

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/PuerkitoBio/goquery"

	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"

	"github.com/stretchr/testify/require"
)

func TestClient_getLoginForm(t *testing.T) {
	data, err := os.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{client: &provider.HTTPClient{Client: http.Client{Jar: jar}, Options: opts}}
	t.Log(ac)
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "groundcontrol", Password: "majortom"}
	t.Log(loginDetails)

	authForm, err := ac.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, url.Values{
		"username": []string{"groundcontrol"},
		"password": []string{"majortom"},
		"vhost":    []string{"standard"},
	}, authForm)
}
func TestClient_postLoginForm_user_pass(t *testing.T) {
	data, err := os.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{client: &provider.HTTPClient{Client: http.Client{Jar: jar}, Options: opts}}
	t.Log(ac)
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "groundcontrol", Password: "majortom"}
	t.Log(loginDetails)

	authForm := url.Values{}
	authForm.Add("username", "groundcontrol")
	authForm.Add("password", "majortom")
	resData, err := ac.postLoginForm(loginDetails, authForm)
	require.Nil(t, err)
	require.Equal(t, data, resData)
}

func TestClient_containsMFAForm(t *testing.T) {
	data, err := os.ReadFile("example/mfapage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	mfaFound, mfaMethods := containsMFAForm(doc)
	require.True(t, mfaFound)
	require.Equal(t, []string{"push", "token"}, mfaMethods)
}

func TestClient_containsMFAForm_False(t *testing.T) {
	data, err := os.ReadFile("example/loginpage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	mfaFound, mfaMethods := containsMFAForm(doc)
	require.False(t, mfaFound)
	require.Equal(t, []string(nil), mfaMethods)
}

func newF5APMTestClient(t *testing.T) *Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &Client{client: &provider.HTTPClient{
		Client:  http.Client{Jar: jar},
		Options: &provider.HTTPClientOptions{IsWithRetries: false},
	}}
}

func TestClient_Authenticate(t *testing.T) {
	assertion := base64.StdEncoding.EncodeToString([]byte("<Assertion>ok</Assertion>"))
	var posted url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<form><input name="username"><input name="password"><input name="vhost" value="standard"></form>`))
		case "/my.policy":
			_ = r.ParseForm()
			posted = r.Form
			_, _ = w.Write([]byte(`<html>logged in</html>`))
		case "/saml/idp/res":
			_, _ = w.Write([]byte(`<input name="SAMLResponse" value="` + assertion + `">`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ac := newF5APMTestClient(t)
	ac.policyID = "test-policy"
	got, err := ac.Authenticate(&creds.LoginDetails{URL: ts.URL, Username: "alice", Password: "secret"})
	require.NoError(t, err)
	require.Equal(t, assertion, got)
	require.Equal(t, "alice", posted.Get("username"))
	require.Equal(t, "secret", posted.Get("password"))
}

func TestClient_AuthenticateMFA(t *testing.T) {
	assertion := base64.StdEncoding.EncodeToString([]byte("assertion"))
	for _, tc := range []struct {
		name   string
		method string
		token  string
	}{
		{name: "token", method: "token", token: "123456"},
		{name: "push", method: "push", token: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posted []url.Values
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					_, _ = w.Write([]byte(`<form><input name="username"><input name="password"></form>`))
				case "/my.policy":
					_ = r.ParseForm()
					posted = append(posted, r.Form)
					if len(posted) == 1 {
						_, _ = w.Write([]byte(`<input id="mfa_retry"><select name="mfamethod"><option value="push">push</option><option value="token">token</option></select>`))
					} else {
						_, _ = w.Write([]byte(`<html>logged in</html>`))
					}
				case "/saml/idp/res":
					_, _ = w.Write([]byte(`<input name="SAMLResponse" value="` + assertion + `">`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			pr := mocks.NewPrompter(t)
			pr.On("ChooseWithDefault", "MFA Method", "push", []string{"push", "token"}).Return(tc.method, nil)
			if tc.method == "token" {
				pr.On("RequestSecurityCode", "000000").Return(tc.token)
			}
			previous := prompter.ActivePrompter
			prompter.SetPrompter(pr)
			defer prompter.SetPrompter(previous)

			ac := newF5APMTestClient(t)
			got, err := ac.Authenticate(&creds.LoginDetails{URL: ts.URL, Username: "alice", Password: "secret"})
			require.NoError(t, err)
			require.Equal(t, assertion, got)
			require.Len(t, posted, 2)
			require.Equal(t, tc.method, posted[1].Get("mfamethod"))
			require.Equal(t, tc.token, posted[1].Get("mfatoken"))
			require.Equal(t, "", posted[1].Get("mfa_retry"))
			if tc.method == "push" {
				require.NotEmpty(t, posted[1].Get("mfamethod"))
			}
		})
	}
}

func TestClient_AuthenticateHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer ts.Close()
	ac := newF5APMTestClient(t)
	ac.client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator
	_, err := ac.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Error(t, err)
	require.ErrorContains(t, err, "Error getting login form IDP")
}

func TestClient_getLoginFormMalformed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form><input value="without-name"><input name="username">`))
	}))
	defer ts.Close()

	authForm, err := newF5APMTestClient(t).getLoginForm(&creds.LoginDetails{URL: ts.URL, Username: "alice"})
	require.NoError(t, err)
	require.Equal(t, url.Values{"username": []string{"alice"}}, authForm)
}

func TestClient_getSAMLAssertionMissing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>no assertion</body></html>`))
	}))
	defer ts.Close()

	ac := newF5APMTestClient(t)
	got, err := ac.getSAMLAssertion(&creds.LoginDetails{URL: ts.URL})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestClient_AuthenticateMalformedAssertion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<form><input name="username"><input name="password"></form>`))
		case "/my.policy":
			_, _ = w.Write([]byte(`<html>logged in</html>`))
		case "/saml/idp/res":
			_, _ = w.Write([]byte(`<input name="SAMLResponse" value="%%%">`))
		}
	}))
	defer ts.Close()

	_, err := newF5APMTestClient(t).Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "Error decoding saml assertion"))
}
