package googleapps

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"
	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

func TestExtractInputByName(t *testing.T) {
	html := `<html><body><input name="logincaptcha" value="test error message"\></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	captcha := mustFindInputByName(doc, "logincaptcha")
	require.Equal(t, "test error message", captcha)
}

func TestExtractInputsByFormQuery(t *testing.T) {
	html := `<html><body><form id="dev" action="http://example.com/test"><input name="pass" value="test error message"\></form></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	doc.Url = &url.URL{
		Scheme: "https",
		Host:   "google.com",
		Path:   "foobar",
	}

	form, actionURL, err := extractInputsByFormQuery(doc, "#dev")
	require.Nil(t, err)
	require.Equal(t, "http://example.com/test", actionURL)
	require.Equal(t, "test error message", form.Get("pass"))

	form2, actionURL2, err := extractInputsByFormQuery(doc, `[action$="/test"]`)
	require.Nil(t, err)
	require.Equal(t, "http://example.com/test", actionURL2)
	require.Equal(t, "test error message", form2.Get("pass"))
}
func TestExtractErrorMsg(t *testing.T) {
	html := `<html><body><span class="error-msg">test error message</span></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	captcha := mustFindErrorMsg(doc)
	require.Equal(t, "test error message", captcha)
}

func TestContentContainsMessage(t *testing.T) {
	html := `<html><body><h2>This extra step shows it’s really you trying to sign in</h2></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	txt := extractNodeText(doc, "h2", "This extra step shows it’s really you trying to sign in")
	require.Equal(t, "This extra step shows it’s really you trying to sign in", txt)
}

func TestContentContainsMessage2(t *testing.T) {
	html := `<html><body><h2>This extra step shows that it’s really you trying to sign in</h2></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	txt := extractNodeText(doc, "h2", "This extra step shows that it’s really you trying to sign in")
	require.Equal(t, "This extra step shows that it’s really you trying to sign in", txt)
}

func TestContentContainsMessage3(t *testing.T) {
	html := `<html><body><h1>2-Step Verification</h1></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	txt := extractNodeText(doc, "h1", "2-Step Verification")
	require.Equal(t, "2-Step Verification", txt)
}

func TestPasswordFormChallengeId1(t *testing.T) {
	data, err := os.ReadFile("example/form-password-challengeid-1.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test-id1@example.com", Password: "test123"}

	authForm := url.Values{}
	authForm.Set("bgresponse", "js_enabled")
	authForm.Set("Email", loginDetails.Username)

	passwordURL, passwordForm, err := kc.loadLoginPage(ts.URL, loginDetails.URL+"&hl=en&loc=US", authForm)
	require.Nil(t, err)
	require.NotEmpty(t, passwordURL)
	require.Equal(t, "1", passwordForm.Get("challengeId"))
	// check pre-filled email
	require.NotEmpty(t, passwordForm.Get("Email"))
	// check password form
	require.Empty(t, passwordForm.Get("Passwd"))
}

func TestPasswordFormChallengeId2(t *testing.T) {
	data, err := os.ReadFile("example/form-password-challengeid-2.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test-id2@example.com", Password: "test123"}

	authForm := url.Values{}
	authForm.Set("bgresponse", "js_enabled")
	authForm.Set("Email", loginDetails.Username)

	passwordURL, passwordForm, err := kc.loadLoginPage(ts.URL, loginDetails.URL+"&hl=en&loc=US", authForm)
	require.Nil(t, err)
	require.NotEmpty(t, passwordURL)
	require.Equal(t, "2", passwordForm.Get("challengeId"))
	// check pre-filled email
	require.NotEmpty(t, passwordForm.Get("Email"))
	// check password form
	require.Empty(t, passwordForm.Get("Passwd"))
}

func TestPasswordFormChallengeId3(t *testing.T) {
	data, err := os.ReadFile("example/form-password-challengeid-3.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test-id3@example.com", Password: "test123"}

	authForm := url.Values{}
	authForm.Set("bgresponse", "js_enabled")
	authForm.Set("identifier", loginDetails.Username)

	passwordURL, passwordForm, err := kc.loadLoginPage(ts.URL, loginDetails.URL+"&hl=en&loc=US", authForm)
	require.Nil(t, err)
	require.NotEmpty(t, passwordURL)
	// check pre-filled email
	require.NotEmpty(t, passwordForm.Get("identifier"))
	// check password form
	require.Empty(t, passwordForm.Get("Passwd"))
}

func TestChallengePage(t *testing.T) {

	data, err := os.ReadFile("example/challenge-totp.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}
	authForm := url.Values{}

	challengeDoc, err := kc.loadChallengePage(ts.URL, "https://accounts.google.com/signin/challenge/sl/password", authForm, loginDetails)
	require.Nil(t, err)
	require.NotNil(t, challengeDoc)
}

func TestSMSChallengePage(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("StringRequired", "Enter SMS token: G-").Return("000000")

	step1, err := os.ReadFile("example/challenge-sms-send.html")
	require.Nil(t, err)
	step2, err := os.ReadFile("example/challenge-sms.html")
	require.Nil(t, err)

	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { calls++ }()
		err := r.ParseForm()
		require.Nil(t, err)

		switch calls {
		case 0:
			_, _ = w.Write(step1)
		case 1:
			require.Equal(t, r.Form.Get("SendMethod"), "SMS")
			_, _ = w.Write(step2)
		case 2:
			require.Equal(t, r.Form.Get("Pin"), "000000")
			_, _ = w.Write(step2)
		default:
			require.Fail(t, "too many calls")
		}
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}
	authForm := url.Values{}

	challengeDoc, err := kc.loadChallengePage(ts.URL, "https://accounts.google.com/signin/challenge/sl/password", authForm, loginDetails)
	require.Nil(t, err)
	require.NotNil(t, challengeDoc)
	require.Equal(t, 3, calls)
}

func TestExtractDataAttributes(t *testing.T) {
	data, err := os.ReadFile("example/challenge-prompt.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	dataAttrs := extractDataAttributes(doc, "div[data-context]", []string{"data-context", "data-gapi-url", "data-tx-id", "data-tx-lifetime"})

	require.Equal(t, "https://apis.google.com/js/base.js", dataAttrs["data-gapi-url"])
}

func TestWrongPassword(t *testing.T) {
	passwordErrorId := "passwordError"
	html := `<html><body><span class="Qx8Abe" id="` + passwordErrorId + `">Wrong password. Try again or click Forgot password to reset it.</span></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)
	txt := doc.Selection.Find("#" + passwordErrorId).Text()
	require.NotEqual(t, "", txt)
}

func TestMustEnable2StepVerification(t *testing.T) {
	html := `<html><body><section class="aN1Vld "><div class="yOnVIb" jsname="MZArnb"><div jsname="x2WF9"><p class="vOZun">Your sign-in settings donâ€™t meet your organizationâ€™s 2-Step Verification policy.</p><p class="vOZun">Contact your admin for more info.</p></div><input type="hidden" name="identifierInput" value="" id="identifierId"></div></section></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)
	twoStepIsMissingErr := isMissing2StepSetup(doc)
	require.Error(t, twoStepIsMissingErr)
	require.Equal(t, twoStepIsMissingErr.Error(), "Because of your organization settings, you must set-up 2-Step Verification in your account")
}

func TestExtractDevicePushExtraNumber(t *testing.T) {
	data1, err := os.ReadFile("example/challenge-extra-number.html")
	require.Nil(t, err)
	doc1, err := goquery.NewDocumentFromReader(bytes.NewReader(data1))
	require.Nil(t, err)
	require.Equal(t, "89", extractDevicePushExtraNumber(doc1))

	for _, filename := range []string{"example/challenge-prompt.html", "example/challenge-totp.html"} {
		data2, err := os.ReadFile(filename)
		require.Nil(t, err)
		doc2, err := goquery.NewDocumentFromReader(bytes.NewReader(data2))
		require.Nil(t, err)
		require.Equal(t, "", extractDevicePushExtraNumber(doc2))
	}
}

func newTestGoogleClient(ts *httptest.Server) *Client {
	return &Client{client: &provider.HTTPClient{
		Client:  *ts.Client(),
		Options: &provider.HTTPClientOptions{IsWithRetries: false},
	}}
}

func TestAuthenticateSuccess(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			require.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write([]byte(`<form id="gaia_loginform" action="/identifier"><input name="continue" value="continue"></form>`))
		case 2:
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "test@example.com", r.FormValue("Email"))
			_, _ = w.Write([]byte(`<form id="gaia_loginform" action="/password"><input name="Email" value="test@example.com"><input name="challengeId" value="1"></form>`))
		case 3:
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "secret", r.FormValue("Passwd"))
			_, _ = w.Write([]byte(`<input name="SAMLResponse" value="saml-assertion">`))
		default:
			require.Fail(t, "unexpected request")
		}
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	assertion, err := kc.Authenticate(&creds.LoginDetails{URL: ts.URL + "/start?flow=1", Username: "test@example.com", Password: "secret"})
	require.NoError(t, err)
	require.Equal(t, "saml-assertion", assertion)
	require.Equal(t, 3, calls)
}

func TestAuthenticateWrongPassword(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			_, _ = w.Write([]byte(`<form id="gaia_loginform" action="/identifier"></form>`))
		case 2:
			_, _ = w.Write([]byte(`<form id="gaia_loginform" action="/password"></form>`))
		case 3:
			_, _ = w.Write([]byte(`<span class="error-msg">Wrong password</span>`))
		default:
			require.Fail(t, "unexpected request")
		}
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	_, err := kc.Authenticate(&creds.LoginDetails{URL: ts.URL + "/start?flow=1", Username: "test@example.com", Password: "bad"})
	require.EqualError(t, err, "error loading challenge page: Invalid username or password")
}

func TestAuthenticateMalformedFirstPage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>not a login form</body></html>`))
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	_, err := kc.Authenticate(&creds.LoginDetails{URL: ts.URL + "/start?flow=1", Username: "test@example.com", Password: "secret"})
	require.EqualError(t, err, "error loading first page: failed to build login form data: could not find any forms")
}

func TestAuthenticateHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	kc.client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator
	_, err := kc.Authenticate(&creds.LoginDetails{URL: ts.URL + "/start?flow=1", Username: "test@example.com", Password: "secret"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "error loading first page")
	require.Contains(t, err.Error(), "failed status: 502 Bad Gateway")
}

func TestAuthenticateRedirectError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	kc.client.DisableFollowRedirect()
	kc.client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator
	_, err := kc.Authenticate(&creds.LoginDetails{URL: ts.URL + "/start?flow=1", Username: "test@example.com", Password: "secret"})
	require.EqualError(t, err, "error loading first page: failed to build login form data: could not find any forms")
}

func TestLoadChallengePageTOTP(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = w.Write([]byte(`<h2>This extra step shows it’s really you trying to sign in</h2><form id="challenge" action="/challenge/totp"><input name="challengeId" value="7"></form>`))
			return
		}
		require.Equal(t, "654321", r.FormValue("Pin"))
		_, _ = w.Write([]byte(`<input name="SAMLResponse" value="totp-ok">`))
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	doc, err := kc.loadChallengePage(ts.URL+"/password", ts.URL+"/identifier", url.Values{}, &creds.LoginDetails{MFAToken: "654321"})
	require.NoError(t, err)
	require.Equal(t, "totp-ok", mustFindInputByName(doc, "SAMLResponse"))
	require.Equal(t, 2, calls)
}

func TestLoadChallengePagePushEOF(t *testing.T) {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_ = w.Close()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin; _ = r.Close() }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<h1>2-Step Verification</h1><form id="challenge" action="/challenge/dp"><input name="challengeId" value="7"></form>`))
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	_, err = kc.loadChallengePage(ts.URL+"/password", ts.URL+"/identifier", url.Values{}, &creds.LoginDetails{})
	require.EqualError(t, err, "error reading new line \\n: EOF")
}

func TestLoadChallengePageUnsupportedWebAuthn(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/password" {
			_, _ = w.Write([]byte(`<h1>2-Step Verification</h1><form id="challenge" action="/challenge/webauthn"><input name="challengeId" value="7"></form><form action="/challenge/skip"><input name="continue" value="yes"></form>`))
			return
		}
		_, _ = w.Write([]byte(`<html><body>no supported factor</body></html>`))
	}))
	defer ts.Close()

	kc := newTestGoogleClient(ts)
	_, err := kc.loadChallengePage(ts.URL+"/password", ts.URL+"/identifier", url.Values{}, &creds.LoginDetails{})
	require.EqualError(t, err, "unable to find supported second factor")
}
