package jumpcloud

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"
	"github.com/stretchr/testify/require"
)

type jumpCloudTestTransport struct {
	base      string
	transport http.RoundTripper
}

func (t jumpCloudTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copyReq := req.Clone(req.Context())
	copyReq.URL.Scheme = "http"
	copyReq.URL.Host = strings.TrimPrefix(t.base, "http://")
	return t.transport.RoundTrip(copyReq)
}

func newJumpCloudTestClient(serverURL, mfa string) *Client {
	hc, err := provider.NewHTTPClient(jumpCloudTestTransport{
		base:      serverURL,
		transport: http.DefaultTransport,
	}, provider.BuildHttpClientOpts(&cfg.IDPAccount{}))
	if err != nil {
		panic(err)
	}
	return &Client{client: hc, mfa: mfa}
}

func jumpCloudJSON(w http.ResponseWriter, value string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, value)
}

func TestAuthenticateSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userconsole/xsrf":
			jumpCloudJSON(w, `{"xsrf":"test-token"}`)
		case "/userconsole/auth":
			if r.Method == http.MethodPost {
				jumpCloudJSON(w, `{"redirectTo":"https://sso.jumpcloud.com/saml/redirect"}`)
			}
		case "/saml/redirect":
			_, _ = io.WriteString(w, `<html><form><input name="SAMLResponse" value="assertion"></form></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newJumpCloudTestClient(server.URL, "TOTP")
	assertion, err := client.Authenticate(&creds.LoginDetails{
		URL:      jcSSOBaseURL + "saml/login",
		Username: "user@example.com",
		Password: "password",
	})
	require.NoError(t, err)
	require.Equal(t, "assertion", assertion)
}

func TestAuthenticateTOTP(t *testing.T) {
	var authBodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userconsole/xsrf":
			jumpCloudJSON(w, `{"xsrf":"test-token"}`)
		case "/userconsole/auth":
			body, _ := io.ReadAll(r.Body)
			authBodies = append(authBodies, string(body))
			if len(authBodies) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				jumpCloudJSON(w, `{"message":"MFA required.","factors":[{"type":"totp","status":"available"}]}`)
			} else {
				jumpCloudJSON(w, `{"redirectTo":"https://sso.jumpcloud.com/saml/redirect"}`)
			}
		case "/saml/redirect":
			_, _ = io.WriteString(w, `<input name="SAMLResponse" value="totp-assertion">`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newJumpCloudTestClient(server.URL, "Auto")
	assertion, err := client.Authenticate(&creds.LoginDetails{
		URL:      jcSSOBaseURL + "saml/login",
		Username: "user@example.com",
		Password: "password",
		MFAToken: "123456",
	})
	require.NoError(t, err)
	require.Equal(t, "totp-assertion", assertion)
	require.Len(t, authBodies, 2)
	require.Contains(t, authBodies[1], `"OTP":"123456"`)
}

func TestAuthenticateDuoPush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userconsole/xsrf":
			jumpCloudJSON(w, `{"xsrf":"test-token"}`)
		case "/userconsole/auth":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusUnauthorized)
				jumpCloudJSON(w, `{"message":"MFA required.","factors":[{"type":"duo","status":"available"}]}`)
			}
		case "/userconsole/auth/duo":
			if r.Method == http.MethodGet {
				jumpCloudJSON(w, `{"api_host":"duo.example","sig_request":"signature:tail","token":"duo-token"}`)
			} else {
				jumpCloudJSON(w, `{"redirectTo":"https://sso.jumpcloud.com/saml/redirect"}`)
			}
		case "/frame/web/v1/auth":
			_, _ = io.WriteString(w, `<input name="sid" value="sid-value">`)
		case "/frame/prompt":
			jumpCloudJSON(w, `{"stat":"OK","response":{"txid":"tx-value"}}`)
		case "/frame/status":
			jumpCloudJSON(w, `{"response":{"result":"SUCCESS","result_url":"/frame/result","sid":"sid-value"}}`)
		case "/frame/result":
			jumpCloudJSON(w, `{"stat":"OK","response":{"cookie":"duo-cookie"}}`)
		case "/saml/redirect":
			_, _ = io.WriteString(w, `<input name="SAMLResponse" value="duo-assertion">`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newJumpCloudTestClient(server.URL, "DUO")
	assertion, err := client.Authenticate(&creds.LoginDetails{
		URL:          jcSSOBaseURL + "saml/login",
		Username:     "user@example.com",
		Password:     "password",
		DuoMFAOption: "Duo Push",
	})
	require.NoError(t, err)
	require.Equal(t, "duo-assertion", assertion)
}

func TestAuthenticateMalformedRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userconsole/xsrf":
			jumpCloudJSON(w, `{"xsrf":"test-token"}`)
		case "/userconsole/auth":
			jumpCloudJSON(w, `{not-json`)
		}
	}))
	defer server.Close()

	client := newJumpCloudTestClient(server.URL, "Auto")
	_, err := client.Authenticate(&creds.LoginDetails{URL: jcSSOBaseURL + "saml/login"})
	require.Error(t, err)
}

func TestAuthenticateAPIServerError(t *testing.T) {
	client := &Client{client: &provider.HTTPClient{Client: http.Client{Transport: errorTransport{}}}}
	_, err := client.Authenticate(&creds.LoginDetails{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "error retieving XSRF Token")
}

type errorTransport struct{}

func (errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("server unavailable")
}

func TestJumpCloudPushResponseJSON(t *testing.T) {
	var response JumpCloudPushResponse
	require.NoError(t, json.Unmarshal([]byte(`{"id":"request-id","status":"pending"}`), &response))
	require.Equal(t, "request-id", response.ID)
}
