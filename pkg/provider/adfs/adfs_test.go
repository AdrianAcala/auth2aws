package adfs

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	account := &cfg.IDPAccount{AmazonWebservicesURN: "urn:test:aws"}
	client, err := New(account)
	require.NoError(t, err)
	return client, ts
}

func TestAuthenticatePasswordAndSAML(t *testing.T) {
	var postForm url.Values
	client, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			require.Equal(t, "/adfs/ls/IdpInitiatedSignOn.aspx", r.URL.Path)
			require.Equal(t, "urn:test:aws", r.URL.Query().Get("loginToRp"))
			_, _ = w.Write([]byte(`<form action="/adfs/auth" method="post">
				<input type="hidden" name="RelayState" value="relay">
				<input type="text" name="UserName">
				<input type="password" name="Password">
				<input type="text" name="Kmsi" value="  true  ">
			</form>`))
		case http.MethodPost:
			require.Equal(t, "/adfs/auth", r.URL.Path)
			require.NoError(t, r.ParseForm())
			postForm = r.Form
			_, _ = w.Write([]byte(`<form action="/adfs/auth" method="post">
				<input type="hidden" name="SAMLResponse" value="saml-assertion">
			</form>`))
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
	require.Equal(t, "alice@example.com", postForm.Get("UserName"))
	require.Equal(t, "secret", postForm.Get("Password"))
	require.Equal(t, "relay", postForm.Get("RelayState"))
	require.Equal(t, "true", postForm.Get("Kmsi"))
}

func TestAuthenticateWithProvidedMFAToken(t *testing.T) {
	postCount := 0
	client, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form action="/adfs/auth"><input name="UserName"><input name="Password"></form>`))
			return
		}

		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		postCount++
		if postCount == 1 {
			_, _ = w.Write([]byte(`<form action="/adfs/auth">
				<input type="hidden" name="AuthMethod" value="VIPAuthenticationProviderUPN">
				<input name="OathCode">
				<input type="hidden" name="RelayState" value="state">
			</form>`))
			return
		}
		require.Equal(t, 2, postCount)
		require.Equal(t, "123456", r.Form.Get("OathCode"))
		require.Equal(t, "state", r.Form.Get("RelayState"))
		_, _ = w.Write([]byte(`<input type="hidden" name="SAMLResponse" value="mfa-saml">`))
	}))

	assertion, err := client.Authenticate(&creds.LoginDetails{
		URL:      ts.URL,
		Username: "alice@example.com",
		Password: "secret",
		MFAToken: "123456",
	})
	require.NoError(t, err)
	require.Equal(t, "mfa-saml", assertion)
	require.Equal(t, 2, postCount)
}

func TestAuthenticateMalformedInitialPage(t *testing.T) {
	client, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><p>sign in</p></body></html>`))
	}))

	assertion, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, assertion)
	require.EqualError(t, err, "unable to locate IDP authentication form submit URL")
}

func TestAuthenticateServerError(t *testing.T) {
	client, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))

	assertion, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, assertion)
	require.ErrorContains(t, err, "failed to get adfs page")
	require.ErrorContains(t, err, "502 Bad Gateway")
}

func TestCheckResponseClassifications(t *testing.T) {
	tests := []struct {
		name string
		html string
		want AuthResponseType
	}{
		{"saml", `<input name="SAMLResponse" value="assertion">`, SAML_RESPONSE},
		{"oath", `<input name="OathCode">`, MFA_PROMPT},
		{"verification code", `<input name="VerificationCode">`, MFA_PROMPT},
		{"vip auth method", `<input name="AuthMethod" value="VIPAuthenticationProviderUPN">`, MFA_PROMPT},
		{"azure wait", `<input name="AuthMethod" value="AzureMfaAuthentication">`, AZURE_MFA_WAIT},
		{"azure server wait", `<input name="AuthMethod" value="AzureMfaServerAuthentication">`, AZURE_MFA_SERVER_WAIT},
		{"unknown", `<p>unexpected response</p>`, UNKNOWN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := newDocument(tt.html)
			require.NoError(t, err)
			got, _, err := checkResponse(doc)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func newDocument(html string) (*goquery.Document, error) {
	return goquery.NewDocumentFromReader(strings.NewReader(html))
}
