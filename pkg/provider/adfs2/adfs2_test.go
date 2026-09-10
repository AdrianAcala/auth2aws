package adfs2

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestADFS2RSA(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authresp1 := fmt.Sprintf(`<form action="https://%s/authpost1" method="post">
			<input type="text" name="UserName">
			<input type="password" name="Password">
			<input type="submit" name="Submit" value="Submit">
			</form> `, r.Host)
		passcoderesp1 := fmt.Sprintf(`<form action="https://%s/passcodepost1" method="post">
			<input type="password" name="ChallengeQuestionAnswer">
			<input type="password" name="NextCode">
			<input type="submit" name="Submit" value="Submit">
			</form> `, r.Host)
		rsaresp1 := fmt.Sprintf(`<form action="https://%s/rsapost1" method="post">
			<input type="password" name="SAMLResponse" value="saml1">
			<input type="submit" name="Submit" value="Submit">
			</form> `, r.Host)
		if strings.HasPrefix(r.URL.String(), "/adfs/ls/IdpInitiatedSignOn.aspx") {
			_, err := w.Write([]byte(authresp1))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/authpost1") {
			_, err := w.Write([]byte(passcoderesp1))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/passcodepost1") {
			_, err := w.Write([]byte(rsaresp1))
			assert.Nil(t, err)
		} else {
			t.Fatalf("unexpected %v", r)
		}
	}))
	defer svr.Close()
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = svr.URL
	idpAccount.MFA = "RSA"
	idpAccount.Username = "user@example.com"
	idpAccount.SkipVerify = true

	loginDetails := &creds.LoginDetails{
		Username: idpAccount.Username,
		Password: "abc123",
		URL:      idpAccount.URL,
	}

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("Password", "Enter nextCode").Return("5309")
	pr.Mock.On("Password", "Enter passcode").Return("0953")

	ac, err := New(idpAccount)
	assert.Nil(t, err)
	resp, err := ac.Authenticate(loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, resp, "saml1")
}

func TestADFS2AuthenticateAutoUsesNTLMFlow(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adfs/ls/IdpInitiatedSignOn.aspx" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`<html><input name="SAMLResponse" value="ntlm-saml"></html>`))
	}))
	defer svr.Close()

	account := cfg.NewIDPAccount()
	account.URL = svr.URL
	account.MFA = "Auto"
	account.Username = "user@example.com"
	client, err := New(account)
	require.NoError(t, err)

	assertion, err := client.Authenticate(&creds.LoginDetails{
		Username: account.Username,
		Password: "password",
		URL:      account.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "ntlm-saml", assertion)
}

func TestADFS2AuthenticateMalformedFormsAndAssertions(t *testing.T) {
	tests := []struct {
		name      string
		mfa       string
		response  string
		wantInErr string
	}{
		{name: "RSA missing form", mfa: "RSA", response: `<html>not an authentication form</html>`, wantInErr: "error extracting login data"},
		{name: "Auto missing assertion", mfa: "Auto", response: `<html><form action="/login"></form></html>`, wantInErr: "SAML assertion"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.response))
			}))
			defer svr.Close()

			account := cfg.NewIDPAccount()
			account.URL = svr.URL
			account.MFA = tc.mfa
			account.Username = "user@example.com"
			client, err := New(account)
			require.NoError(t, err)

			_, err = client.Authenticate(&creds.LoginDetails{
				Username: account.Username,
				Password: "password",
				URL:      account.URL,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantInErr)
		})
	}
}

func TestADFS2AuthenticateHTTPError(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := svr.URL
	svr.Close()

	account := cfg.NewIDPAccount()
	account.URL = url
	account.MFA = "Auto"
	client, err := New(account)
	require.NoError(t, err)

	_, err = client.Authenticate(&creds.LoginDetails{URL: url})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error retieving login form")
}

func TestADFS2AuthenticateTLSError(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer svr.Close()

	account := cfg.NewIDPAccount()
	account.URL = svr.URL
	account.MFA = "Auto"
	client, err := New(account)
	require.NoError(t, err)

	_, err = client.Authenticate(&creds.LoginDetails{URL: svr.URL})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509")
}
