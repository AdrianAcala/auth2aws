package akamai

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

// localTransport lets Authenticate continue to build the real HTTPS Akamai
// URLs while routing requests to a deterministic local test server.
type localTransport struct {
	base      string
	transport http.RoundTripper
}

func (t localTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copyReq := req.Clone(req.Context())
	copyReq.URL.Scheme = "http"
	copyReq.URL.Host = strings.TrimPrefix(t.base, "http://")
	return t.transport.RoundTrip(copyReq)
}

func newAkamaiTestClient(t *testing.T, handler http.Handler) (*Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	transport := localTransport{base: server.URL, transport: server.Client().Transport}
	httpClient, err := provider.NewHTTPClient(transport, &provider.HTTPClientOptions{IsWithRetries: false})
	require.NoError(t, err)
	httpClient.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator
	return &Client{client: httpClient}, server.Close
}

func TestAuthenticateSuccessWithoutMFA(t *testing.T) {
	var navigateCount int
	client, closeServer := newAkamaiTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<html><input id="xsrf" value="xsrf-token"></html>`)
		case "/api/v1/login":
			require.Equal(t, "xsrf-token", r.Header.Get("xsrf"))
			var request AuthRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			require.Equal(t, AuthRequest{Username: "alice", Password: "secret"}, request)
			_, _ = io.WriteString(w, `{"status":"200"}`)
		case "/api/v2/apps/navigate":
			require.Equal(t, "xsrf-token", r.Header.Get("xsrf"))
			navigateCount++
			if navigateCount == 1 {
				_, _ = io.WriteString(w, `{"mfa":{"status":"none"}}`)
			} else {
				_, _ = io.WriteString(w, `{"navigate":{"body":"<form><input name=\"SAMLResponse\" value=\"assertion\"></form>"}}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer closeServer()

	got, err := client.Authenticate(&creds.LoginDetails{
		URL:      "https://idp.example.test/?app=signing.aws.amazon.com",
		Username: "alice",
		Password: "secret",
	})
	require.NoError(t, err)
	require.Equal(t, "assertion", got)
	require.Equal(t, 2, navigateCount)
}

func TestAuthenticateRejectsInvalidLoginResponse(t *testing.T) {
	client, closeServer := newAkamaiTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = io.WriteString(w, `<input id="xsrf" value="token">`)
		case "/api/v1/login":
			_, _ = io.WriteString(w, `{"status":"401","msg":"bad credentials"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer closeServer()

	_, err := client.Authenticate(&creds.LoginDetails{URL: "https://idp.example.test/?app=target"})
	require.EqualError(t, err, "Login Failure")
}

func TestAuthenticateRejectsMissingXSRFToken(t *testing.T) {
	client, closeServer := newAkamaiTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><body>login</body></html>`)
	}))
	defer closeServer()

	_, err := client.Authenticate(&creds.LoginDetails{URL: "https://idp.example.test/?app=target"})
	require.EqualError(t, err, "unable to locate xsrf token in html")
}

func TestAuthenticateReturnsHTTPError(t *testing.T) {
	client, closeServer := newAkamaiTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "upstream unavailable")
			return
		}
		http.NotFound(w, r)
	}))
	defer closeServer()

	_, err := client.Authenticate(&creds.LoginDetails{URL: "https://idp.example.test/?app=target"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "error retrieving login request")
}

func TestAuthenticateRejectsMFARegistrationAndMissingAssertion(t *testing.T) {
	tests := []struct {
		name      string
		navigate  string
		wantError string
	}{
		{name: "mfa registration", navigate: `{"mfa":{"status":"register"}}`, wantError: "register mfa by logging to IDP"},
		{name: "missing assertion", navigate: `{"mfa":{"status":"none"}}`, wantError: "unable to locate SAMLResponse in html"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, closeServer := newAkamaiTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					_, _ = io.WriteString(w, `<input id="xsrf" value="token">`)
				case "/api/v1/login":
					_, _ = io.WriteString(w, `{"status":"200"}`)
				case "/api/v2/apps/navigate":
					_, _ = io.WriteString(w, test.navigate)
				default:
					http.NotFound(w, r)
				}
			}))
			defer closeServer()

			_, err := client.Authenticate(&creds.LoginDetails{URL: "https://idp.example.test/?app=target"})
			require.EqualError(t, err, test.wantError)
		})
	}
}

func TestVerifyMFARejectsInvalidConfigurationAndUnsupportedOption(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		settings  string
		mfa       string
		wantError string
	}{
		{name: "missing config", config: `{}`, settings: `{}`, mfa: "Auto", wantError: "Mfa not configured "},
		{name: "unsupported explicit option", config: `{"mfa":{"config":{"options":["hardware"]}}}`, settings: `{}`, mfa: "hardware", wantError: "unsupported mfa provider"},
		{name: "unsupported preferred option", config: `{"mfa":{"config":{"options":["totp"]}}}`, settings: `{"mfa":{"settings":{"preferred":{"option":"hardware"}}}}`, mfa: "Auto", wantError: "unsupported mfa provider"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, closeServer := newAkamaiTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/config/mfa":
					_, _ = io.WriteString(w, test.config)
				case "/api/v1/mfa/token/settings":
					_, _ = io.WriteString(w, test.settings)
				default:
					http.NotFound(w, r)
				}
			}))
			defer closeServer()

			client.mfa = test.mfa
			err := verifyMfa(client, "idp.example.test", &creds.LoginDetails{}, "token")
			require.EqualError(t, err, test.wantError)
		})
	}
}

func TestNewConfiguresClient(t *testing.T) {
	client, err := New(&cfg.IDPAccount{SkipVerify: true, MFA: "Auto"})
	require.NoError(t, err)
	require.NotNil(t, client)
	require.NotNil(t, client.client)
	require.NotNil(t, client.client.CheckResponseStatus)
}

func TestLocalTransportPropagatesRoundTripErrors(t *testing.T) {
	want := errors.New("transport failed")
	transport := localTransport{base: "http://example.test", transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, want
	})}
	_, err := transport.RoundTrip(mustRequest(t, "https://idp.example.test/"))
	require.ErrorIs(t, err, want)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	return req
}
