package shibboleth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	client, err := New(&cfg.IDPAccount{
		AmazonWebservicesURN: "urn:test:aws",
		SkipVerify:           true,
	})
	require.NoError(t, err)
	return client, ts
}

func TestAuthenticatePasswordAndSAML(t *testing.T) {
	var submitted url.Values
	client, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			require.Equal(t, "/idp/profile/SAML2/Unsolicited/SSO", r.URL.Path)
			require.Equal(t, "urn:test:aws", r.URL.Query().Get("providerId"))
			_, _ = w.Write([]byte(`<form action="/idp/auth" method="post">
				<input type="hidden" name="RelayState" value="relay">
				<input type="text" name="UserName">
				<input type="password" name="Password">
			</form>`))
		case http.MethodPost:
			require.Equal(t, "/idp/auth", r.URL.Path)
			require.NoError(t, r.ParseForm())
			submitted = r.Form
			_, _ = w.Write([]byte(`<input type="hidden" name="SAMLResponse" value="saml-assertion"/>`))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	assertion, err := client.Authenticate(&creds.LoginDetails{
		URL:      ts.URL,
		Username: "alice@example.com",
		Password: "secret",
	})
	require.NoError(t, err)
	require.Equal(t, "saml-assertion", assertion)
	require.Equal(t, "alice@example.com", submitted.Get("UserName"))
	require.Equal(t, "secret", submitted.Get("Password"))
	require.Equal(t, "relay", submitted.Get("RelayState"))
	require.Equal(t, "", submitted.Get("_eventId_proceed"))
}

func TestAuthenticateMalformedForms(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantErr  string
	}{
		{"missing action", `<input name="UserName">`, "unable to locate IDP authentication form submit URL"},
		{"missing assertion", `<form action="/idp/auth"></form>`, "unable to locate SAMLResponse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if tt.name == "missing action" {
						_, _ = w.Write([]byte(`<input name="UserName">`))
					} else {
						_, _ = w.Write([]byte(`<form action="/idp/auth"><input name="UserName"></form>`))
					}
					return
				}
				_, _ = w.Write([]byte(tt.response))
			}))
			assertion, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
			require.Empty(t, assertion)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAuthenticateHTTPError(t *testing.T) {
	client, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))

	assertion, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, assertion)
	require.ErrorContains(t, err, "error retrieving form")
	require.ErrorContains(t, err, "502 Bad Gateway")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthenticateMFADuoBypass(t *testing.T) {
	duo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/frame/web/v1/auth", r.URL.Path)
		require.Equal(t, "tx-id", r.URL.Query().Get("tx"))
		_, _ = w.Write([]byte(`<input name="js_cookie" value="duo-cookie">`))
	}))
	t.Cleanup(duo.Close)

	var mfaForm url.Values
	client, idp := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form action="/idp/auth"><input name="UserName"><input name="Password"></form>`))
			return
		}
		if r.URL.Path == "/idp/auth" {
			_, _ = w.Write([]byte(`<div data-host="duo.test" data-sig-request="tx-id:app-id" data-post-action="/idp/mfa"><input name="csrf_token" value="csrf"></div>`))
			return
		}
		require.Equal(t, "/idp/mfa", r.URL.Path)
		require.NoError(t, r.ParseForm())
		mfaForm = r.Form
		_, _ = w.Write([]byte(`<input name="SAMLResponse" value="mfa-assertion"/>`))
	}))
	client.idpAccount.MFA = "Auto"

	baseTransport := client.client.Transport
	client.client.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "duo.test" {
			clone := r.Clone(r.Context())
			clone.URL.Scheme = "https"
			u, err := url.Parse(duo.URL)
			require.NoError(t, err)
			clone.URL.Host = u.Host
			return baseTransport.RoundTrip(clone)
		}
		return baseTransport.RoundTrip(r)
	})

	assertion, err := client.Authenticate(&creds.LoginDetails{URL: idp.URL})
	require.NoError(t, err)
	require.Equal(t, "mfa-assertion", assertion)
	require.Equal(t, "proceed", mfaForm.Get("_eventId"))
	require.Equal(t, "duo-cookie:app-id", mfaForm.Get("sig_response"))
	require.Equal(t, "csrf", mfaForm.Get("csrf_token"))
}

func TestVerifyDuoMFAFailure(t *testing.T) {
	duo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/frame/web/v1/auth":
			_, _ = w.Write([]byte(`<input name="sid" value="sid-1">`))
		case "/frame/prompt":
			_, _ = w.Write([]byte(`{"stat":"FAIL","response":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(duo.Close)
	client, err := New(&cfg.IDPAccount{SkipVerify: true})
	require.NoError(t, err)
	baseTransport := client.client.Transport
	client.client.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		u, parseErr := url.Parse(duo.URL)
		require.NoError(t, parseErr)
		clone.URL.Scheme, clone.URL.Host = u.Scheme, u.Host
		return baseTransport.RoundTrip(clone)
	})

	_, err = verifyDuoMfa(client, &creds.LoginDetails{DuoMFAOption: "Duo Push"}, "duo.test", "http://idp.test/mfa", "tx:app")
	require.ErrorContains(t, err, `Duo status "FAIL"`)
}

func TestParseTokensMalformed(t *testing.T) {
	duoHost, postAction, tx, app, csrf := parseTokens(`<input name="csrf_token" value="csrf">`)
	require.Empty(t, duoHost)
	require.Empty(t, postAction)
	require.Empty(t, tx)
	require.Empty(t, app)
	require.Equal(t, "csrf", csrf)
}
