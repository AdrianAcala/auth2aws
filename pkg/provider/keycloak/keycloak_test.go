package keycloak

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"

	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"
	"github.com/stretchr/testify/require"
)

const (
	exampleLoginURL = "https://id.example.com/auth/realms/master/login-actions/authenticate?code=G5PSj-AJ7mC2wRS5yOA5NEGZ7BO97Y0_qUkS5zInmhQ&execution=e0c4f6fe-6f9a-435e-a7ff-d61eb2456d58&client_id=urn%3Aamazon%3Awebservices"
)

func testKeycloakClient() *Client {
	validator, _ := CustomizeAuthErrorValidator(&cfg.IDPAccount{})
	return &Client{client: &provider.HTTPClient{
		Client:  http.Client{},
		Options: &provider.HTTPClientOptions{IsWithRetries: false},
	}, authErrorValidator: validator}
}

func TestClient_Authenticate(t *testing.T) {
	assertion, err := os.ReadFile("example/assertion.html")
	require.NoError(t, err)

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `<form action="`+ts.URL+`/login" method="post"><input name="username"><input name="password"><input name="session_code" value="session"></form>`)
		case http.MethodPost:
			require.Equal(t, "/login", r.URL.Path)
			require.NoError(t, r.ParseForm())
			require.Equal(t, "alice", r.Form.Get("username"))
			require.Equal(t, "secret", r.Form.Get("password"))
			_, _ = w.Write(assertion)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	kc := testKeycloakClient()
	samlResponse, err := kc.Authenticate(&creds.LoginDetails{URL: ts.URL + "/start", Username: "alice", Password: "secret"})
	require.NoError(t, err)
	require.Equal(t, "abc123", samlResponse)
}

func TestClient_AuthenticateTOTP(t *testing.T) {
	loginPage := `<form action="%s/login" method="post"><input name="username"><input name="password"></form>`
	mfaPage, err := os.ReadFile("example/mfapage.html")
	require.NoError(t, err)
	mfaPage = bytes.Replace(mfaPage, []byte("https://id.example.com"), []byte("__KEYCLOAK_TEST_SERVER__"), 1)
	assertion, err := os.ReadFile("example/assertion.html")
	require.NoError(t, err)

	var ts *httptest.Server
	postCount := 0
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, fmt.Sprintf(loginPage, ts.URL))
		case http.MethodPost:
			postCount++
			if r.URL.Path == "/login" {
				_, _ = io.WriteString(w, strings.ReplaceAll(string(mfaPage), "__KEYCLOAK_TEST_SERVER__", ts.URL))
				return
			}
			require.Contains(t, r.URL.Path, "login-actions/authenticate")
			require.NoError(t, r.ParseForm())
			require.Equal(t, "123456", r.Form.Get("totp"))
			_, _ = w.Write(assertion)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	kc := testKeycloakClient()
	samlResponse, err := kc.Authenticate(&creds.LoginDetails{URL: ts.URL, Username: "alice", Password: "secret", MFAToken: "123456"})
	require.NoError(t, err)
	require.Equal(t, "abc123", samlResponse)
	require.Equal(t, 2, postCount)
}

func TestClient_AuthenticateErrors(t *testing.T) {
	tests := []struct {
		name      string
		loginURL  string
		wantError string
	}{
		{name: "login request", loginURL: "://bad-url", wantError: "error retrieving login form from idp"},
		{name: "missing login action", loginURL: "", wantError: "unable to locate IDP authentication form submit URL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.loginURL == "://bad-url" {
					http.Error(w, "unexpected", http.StatusInternalServerError)
					return
				}
				_, _ = io.WriteString(w, `<html><body>no form</body></html>`)
			}))
			defer ts.Close()

			loginURL := ts.URL
			if tt.loginURL == "://bad-url" {
				loginURL = tt.loginURL
			}
			_, err := testKeycloakClient().Authenticate(&creds.LoginDetails{URL: loginURL})
			require.Error(t, err)
			require.ErrorContains(t, err, tt.wantError)
		})
	}
}

func TestClient_AuthenticateMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "login post error", body: `<form action="://bad-url"><input name="username"></form>`, want: "error submitting login form"},
		{name: "missing saml response", body: `<html><body>authenticated</body></html>`, want: "unable to locate saml response field"},
		{name: "webauthn parameters", body: `<form id="webauth" action="https://example.invalid"><input name="authn_use_chk" value="credential"><script>const options = { rpId: "example.net" };</script></form>`, want: "could not extract Webauthn parameters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts *httptest.Server
			ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					action := ts.URL + "/login"
					if tt.name == "login post error" {
						action = "://bad-url"
					}
					_, _ = io.WriteString(w, `<form action="`+action+`"><input name="username"></form>`)
					return
				}
				_, _ = io.WriteString(w, tt.body)
			}))
			defer ts.Close()

			kc := testKeycloakClient()
			_, err := kc.doAuthenticate(&authContext{authenticatorIndexValid: false}, &creds.LoginDetails{URL: ts.URL, Username: "alice"})
			require.Error(t, err)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestClient_postWebauthnFormNoRecognizedDevice(t *testing.T) {
	kc := testKeycloakClient()
	_, err := kc.postWebauthnForm("http://example.invalid", nil, "challenge", "example.net", nil)
	require.EqualError(t, err, "tried all Webauthn devices, none was recognized")
}

func TestReencodeAsURLEncodingRejectsMalformedBase64(t *testing.T) {
	_, err := reencodeAsURLEncoding("not-base64")
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid base64 encoding")
}

func TestClient_getLoginForm(t *testing.T) {

	data, err := os.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}

	submitURL, authForm, authCookies, err := kc.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, exampleLoginURL, submitURL)
	require.Equal(t, url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}, authForm)
	require.Equal(t, []*http.Cookie([]*http.Cookie{}), authCookies)

}

func TestClient_getLoginFormTryAnotherWay(t *testing.T) {
	data, err := os.ReadFile("example/loginpage-another-way.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}

	submitURL, authForm, authCookies, err := kc.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, exampleLoginURL, submitURL)
	require.Equal(t, url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}, authForm)
	require.Equal(t, []*http.Cookie([]*http.Cookie{}), authCookies)
}

func TestClient_getLoginFormRedirect(t *testing.T) {

	redirectData, err := os.ReadFile("example/redirect.html")
	require.Nil(t, err)

	data, err := os.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count > 0 {
			_, _ = w.Write(data)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(bytes.Replace(redirectData, []byte(exampleLoginURL), []byte("http://"+r.Host), 1))
		}
		count++
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}

	submitURL, authForm, authCookies, err := kc.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, 2, count)
	require.Equal(t, exampleLoginURL, submitURL)
	require.Equal(t, url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}, authForm)
	require.Equal(t, []*http.Cookie([]*http.Cookie{}), authCookies)
}

func TestClient_postLoginForm(t *testing.T) {

	data, err := os.ReadFile("example/mfapage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	loginForm := url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	content, err := kc.postLoginForm(ts.URL, loginForm)
	require.Nil(t, err)
	require.NotNil(t, content)
}

func TestClient_postTotpForm(t *testing.T) {

	data, err := os.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	mfapage, err := os.ReadFile("example/mfapage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(mfapage))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	pr.Mock.On("RequestSecurityCode", "000000").Return("123456")

	authCtx := &authContext{"", 0, true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, false, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	pr.Mock.AssertCalled(t, "RequestSecurityCode", "000000")
}

func TestClient_postTotpFormWithProvidedMFAToken(t *testing.T) {

	data, err := os.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	mfapage, err := os.ReadFile("example/mfapage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(mfapage))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	authCtx := &authContext{"123456", 0, true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, false, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	pr.Mock.AssertNumberOfCalls(t, "RequestSecurityCode", 0)
}

func TestClient_postTotpFormWithMultipleAuthenticators(t *testing.T) {
	data, err := os.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	mfapage, err := os.ReadFile("example/mfapage2authenticators.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(mfapage))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	authCtx := &authContext{"123456", 0, true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, uint(1), authCtx.authenticatorIndex)
	require.Equal(t, true, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, uint(2), authCtx.authenticatorIndex)
	require.Equal(t, false, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	pr.Mock.AssertNumberOfCalls(t, "RequestSecurityCode", 0)
}

func TestClient_extractSamlResponse(t *testing.T) {
	data, err := os.ReadFile("example/assertion.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	samlResponse, err := extractSamlResponse(doc)
	require.Nil(t, err)
	require.Equal(t, samlResponse, "abc123")
}

func TestClient_containsTotpForm(t *testing.T) {
	data, err := os.ReadFile("example/mfapage.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	require.True(t, containsTotpForm(doc))
}

func TestClient_extractWebauthnParameters(t *testing.T) {
	data, err := os.ReadFile("example/webauthnPage.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	credentialIDs, challenge, rpID, err := extractWebauthnParameters(doc)
	require.Nil(t, err)

	expectedCredentialIDs := []string{"pcFg5E6QIk0ZFfJxmf8cfUcb3hirl5Knl8aJ-mjC6MRjVu1dOiBBs51wtjS_O1eP2uiJfGiSL3D8R2cBLnoZyw", "pcFg5E6QIk0ZFfJxmf8efUcb3hirl5Knl8aJ-mjC6MRjVu1dOaBBs51wtjS_O1eP2uiJfGiSL3D8R2cBLnoZyw"}
	require.Equal(t, expectedCredentialIDs, credentialIDs)
	require.Equal(t, "J3NKWZPkSmqXuoKLtzzshg", challenge)
	require.Equal(t, "localhost", rpID)
}

func TestClient_extractKc25WebauthnParameters(t *testing.T) {
	data, err := os.ReadFile("example/kc25-webauthnPage.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	credentialIDs, challenge, rpID, err := extractWebauthnParameters(doc)
	require.Nil(t, err)

	expectedCredentialIDs := []string{"fm6tY873_LAIZUMG5qhhGfJObXwcfWZZg8Aqu-6gi4BEok4pkyfbZgJ4uwfvRdgTTyuzNu4v_T3IubCXquypHQ"}
	require.Equal(t, expectedCredentialIDs, credentialIDs)
	require.Equal(t, "byaIeFP_TGOpiUdAnDQVVw", challenge)
	require.Equal(t, "example.com", rpID)
}

func TestClient_extractWebauthnParametersAcceptsDoubleQuotedObjectFields(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(`
		<input name="authn_use_chk" value="credential-id">
		<script>const options = { challenge: "challenge-value", rpId : "example.net" };</script>
	`))
	require.NoError(t, err)

	credentialIDs, challenge, rpID, err := extractWebauthnParameters(doc)
	require.NoError(t, err)
	require.Equal(t, []string{"credential-id"}, credentialIDs)
	require.Equal(t, "challenge-value", challenge)
	require.Equal(t, "example.net", rpID)
}

func TestClient_extractWebauthnParametersRequiresChallengeAndRpID(t *testing.T) {
	tests := []struct {
		name   string
		script string
		err    string
	}{
		{name: "missing challenge", script: `const options = { rpId: "example.net" };`, err: "no WebAuthn challenge found on page"},
		{name: "missing rpID", script: `const options = { challenge: "challenge-value" };`, err: "no WebAuthn relying party ID found on page"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(`<input name="authn_use_chk" value="credential-id"><script>` + tt.script + `</script>`))
			require.NoError(t, err)

			_, _, _, err = extractWebauthnParameters(doc)
			require.EqualError(t, err, tt.err)
		})
	}
}

func TestClient_CustomizeAuthErrorValidator_DefaultSetup(t *testing.T) {
	// Test with the default auth error message and the default HTTP element
	idpAccount := cfg.IDPAccount{
		KCAuthErrorMessage: "",
		KCAuthErrorElement: "",
	}
	authErrorValidator, err := CustomizeAuthErrorValidator(&idpAccount)
	require.Nil(t, err)
	require.Equal(t, authErrorValidator.httpMessageRE.String(), DefaultAuthErrorMessage)
	require.Equal(t, authErrorValidator.httpElement, DefaultAuthErrorElement)
}

func TestClient_CustomizeAuthErrorValidator_CustomSetup(t *testing.T) {
	// Test with multiple auth error messages and the default HTTP element
	ErrMessage1 := "Invalid username or password."
	ErrMessage2 := "Account is disabled, contact your administrator."
	httpElement := ""
	idpAccount := cfg.IDPAccount{
		KCAuthErrorMessage: ErrMessage1 + "|" + ErrMessage2,
		KCAuthErrorElement: httpElement,
	}
	authErrorValidator, err := CustomizeAuthErrorValidator(&idpAccount)
	require.Nil(t, err)
	require.Equal(t, authErrorValidator.httpMessageRE.String(), ErrMessage1+"|"+ErrMessage2)
	require.Equal(t, authErrorValidator.httpElement, DefaultAuthErrorElement)

	// Test with multiple auth error messages in a non-English language and a customized HTTP element
	ErrMessage1 = "無効なユーザー名またはパスワードです。"      // "Invalid username or password." in Japanese
	ErrMessage2 = "アカウントは無効です。管理者に連絡してください。" // "Account is disabled, contact your administrator." in Japanese
	httpElement = "span.kc-feedback-text"
	idpAccount = cfg.IDPAccount{
		KCAuthErrorMessage: ErrMessage1 + "|" + ErrMessage2,
		KCAuthErrorElement: httpElement,
	}
	authErrorValidator, err = CustomizeAuthErrorValidator(&idpAccount)
	require.Nil(t, err)
	require.Equal(t, authErrorValidator.httpMessageRE.String(), ErrMessage1+"|"+ErrMessage2)
	require.Equal(t, authErrorValidator.httpElement, httpElement)
}

func TestClient_passwordValid_DefaultValidator(t *testing.T) {
	// Test with the default auth error message and the default HTTP element
	idpAccount := cfg.IDPAccount{
		KCAuthErrorMessage: "",
		KCAuthErrorElement: "",
	}
	authErrorValidator, err := CustomizeAuthErrorValidator(&idpAccount)
	require.Nil(t, err)

	tCases := []struct {
		name string
		file string
	}{
		{name: "v1", file: "example/authError-invalidPassword.html"},
		{name: "v2", file: "example/authError-invalidPassword-v2.html"},
	}

	for _, tc := range tCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			require.Nil(t, err)

			doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
			require.Nil(t, err)

			require.Equal(t, passwordValid(doc, authErrorValidator), false)
		})
	}
}

func TestClient_passwordValid_CustomValidator(t *testing.T) {
	// Test with multiple auth error messages and the default HTTP element
	idpAccount := cfg.IDPAccount{
		KCAuthErrorMessage: "Invalid username or password.|Account is disabled, contact your administrator.",
		KCAuthErrorElement: "",
	}
	authErrorValidator, err := CustomizeAuthErrorValidator(&idpAccount)
	require.Nil(t, err)

	// Test with "Invalid username or password."
	data, err := os.ReadFile("example/authError-invalidPassword.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	require.Equal(t, passwordValid(doc, authErrorValidator), false)

	// Test with "Account is disabled, contact your administrator."
	data, err = os.ReadFile("example/authError-accountDisabled.html")
	require.Nil(t, err)

	doc, err = goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	require.Equal(t, passwordValid(doc, authErrorValidator), false)

	// Test with multiple auth error messages in a non-English language and a customized HTTP element
	idpAccount = cfg.IDPAccount{
		// "Invalid username or password.|Account is disabled, contact your administrator." in Japanese
		KCAuthErrorMessage: "無効なユーザー名またはパスワードです。|アカウントは無効です。管理者に連絡してください。",
		KCAuthErrorElement: "span.kc-feedback-text",
	}
	authErrorValidator, err = CustomizeAuthErrorValidator(&idpAccount)
	require.Nil(t, err)

	// Test with "Invalid username or password." in Japanese
	data, err = os.ReadFile("example/authError-invalidPassword_ja.html")
	require.Nil(t, err)

	doc, err = goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	require.Equal(t, passwordValid(doc, authErrorValidator), false)

	// Test with "Account is disabled, contact your administrator." in Japanese
	data, err = os.ReadFile("example/authError-accountDisabled_ja.html")
	require.Nil(t, err)

	doc, err = goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	require.Equal(t, passwordValid(doc, authErrorValidator), false)
}
