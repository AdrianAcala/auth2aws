package shibbolethecp

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"os"

	"github.com/beevik/etree"
)

func TestAuthnRequest(t *testing.T) {
	input := "foo"

	result, err := authnRequest(input, "")
	assert.NoError(t, err)

	doc := etree.NewDocument()
	_, err = doc.ReadFrom(result)
	assert.NoError(t, err)

	root := doc.Root()

	// find Issuer element
	element := root.FindElement("//saml2:Issuer")
	assert.NotNil(t, element)

	// check Issuer value
	value := element.Text()
	assert.Equal(t, input, strings.TrimSpace(value))
}

func TestExtractAssertion(t *testing.T) {
	data, err := os.Open("testdata/ecp_soap_response_success.xml")
	assert.Nil(t, err)

	assertion, err := extractAssertion(data)
	assert.Nil(t, err)
	assert.NotEmpty(t, assertion)
}

func newTestClient(t *testing.T, handler http.Handler, mfa string) (*Client, string, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	httpClient, err := provider.NewHTTPClient(server.Client().Transport, &provider.HTTPClientOptions{IsWithRetries: false})
	require.NoError(t, err)
	return &Client{
		client: httpClient,
		idpAccount: &cfg.IDPAccount{
			AmazonWebservicesURN: "urn:test:service",
			TargetURL:            "https://service.example.test/saml",
			MFA:                  mfa,
		},
	}, server.URL, server.Close
}

func successResponse(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/ecp_soap_response_success.xml")
	require.NoError(t, err)
	return data
}

func TestAuthenticateFullFlow(t *testing.T) {
	client, serverURL, closeServer := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "text/xml", r.Header.Get("Content-Type"))
		require.Equal(t, "utf-8", r.Header.Get("charset"))
		user, password, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "alice", user)
		require.Equal(t, "secret", password)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "urn:test:service")
		require.Contains(t, string(body), "https://service.example.test/saml")
		_, err = w.Write(successResponse(t))
		require.NoError(t, err)
	}), "")
	defer closeServer()

	got, err := client.Authenticate(&creds.LoginDetails{
		URL:      serverURL,
		Username: "alice",
		Password: "secret",
	})
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(got)
	require.NoError(t, err)
	require.Contains(t, string(decoded), "<saml2p:Response")
	require.Contains(t, string(decoded), "<saml2:Assertion")
}

func TestAuthenticateSendsMFAHeaders(t *testing.T) {
	tests := []struct {
		factor   string
		passcode string
	}{
		{factor: ""},
		{factor: "auto"},
		{factor: "push"},
		{factor: "phone"},
		{factor: "passcode", passcode: "123456"},
	}
	for _, tt := range tests {
		t.Run(tt.factor, func(t *testing.T) {
			client, serverURL, closeServer := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, tt.factor, r.Header.Get(SHIB_DUO_FACTOR))
				if tt.factor == "passcode" {
					require.Equal(t, tt.passcode, r.Header.Get(SHIB_DUO_PASSCODE))
				} else {
					require.Empty(t, r.Header.Get(SHIB_DUO_PASSCODE))
				}
				_, err := w.Write(successResponse(t))
				require.NoError(t, err)
			}), tt.factor)
			defer closeServer()
			_, err := client.Authenticate(&creds.LoginDetails{URL: serverURL, Username: "u", Password: "p", MFAToken: tt.passcode})
			require.NoError(t, err)
		})
	}
}

func TestAuthenticateReturnsHTTPError(t *testing.T) {
	client, serverURL, closeServer := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}), "")
	defer closeServer()

	_, err := client.Authenticate(&creds.LoginDetails{URL: serverURL})
	require.Error(t, err)
	require.Contains(t, err.Error(), "502 Bad Gateway")
	require.Contains(t, err.Error(), serverURL)
}

func TestExtractAssertionRejectsSOAPFault(t *testing.T) {
	soapFault := `<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Body><S:Fault><faultcode>S:Server</faultcode><faultstring>authentication failed</faultstring></S:Fault></S:Body></S:Envelope>`
	_, err := extractAssertion(strings.NewReader(soapFault))
	require.EqualError(t, err, "Unable to find StatusCode element by XML path")
}

func TestExtractAssertionRejectsMissingAssertion(t *testing.T) {
	response := fmt.Sprintf(`<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Body><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:Status><saml2p:StatusCode Value="%s"/></saml2p:Status></saml2p:Response></S:Body></S:Envelope>`, SAML_SUCCESS)
	_, err := extractAssertion(strings.NewReader(response))
	require.EqualError(t, err, "Unable to find Assertion element in IdP response by XML path")
}
