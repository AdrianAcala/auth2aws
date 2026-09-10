package onelogin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider/onelogin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Authenticate(t *testing.T) {
	type fields struct {
		client *provider.HTTPClient
	}
	type args struct {
		loginDetails *creds.LoginDetails
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oc := &onelogin.Client{Client: tt.fields.client}
			got, err := oc.Authenticate(tt.args.loginDetails)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOneLoginSuccess(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.String(), "/auth/oauth2/v2/token") {
			_, err := w.Write([]byte(`
				{
					"access_token": "accesstoken1"
				}
				`))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/api/2/saml_assertion") {
			_, err := w.Write([]byte(`
				{
					"message": "Success",
					"data": "saml1"
				}
				`))
			assert.Nil(t, err)
		} else {
			t.Fatalf("unexpected %v", r)
		}
	}))
	defer svr.Close()
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = svr.URL
	idpAccount.Username = "user@example.com"
	idpAccount.SkipVerify = true

	loginDetails := &creds.LoginDetails{
		Username: idpAccount.Username,
		Password: "abc123",
		URL:      idpAccount.URL,
	}

	oc, err := onelogin.New(idpAccount)
	assert.Nil(t, err)
	resp, err := oc.Authenticate(loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, "saml1", resp)
}

func TestOneLoginMFA(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.String(), "/auth/oauth2/v2/token") {
			_, err := w.Write([]byte(`
				{
					"access_token": "accesstoken1"
				}
				`))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/api/2/saml_assertion/verify_factor") {
			_, err := w.Write([]byte(`
				{
					"message": "Success",
					"data": "saml1"
				}
				`))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/api/2/saml_assertion") {
			_, err := w.Write([]byte(`
				{
					"message": "MFA is required for this user",
					"devices": [{"device_type": "Yubico YubiKey"}]
				}
				`))
			assert.Nil(t, err)
		} else {
			t.Fatalf("unexpected %v", r)
		}
	}))
	defer svr.Close()
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = svr.URL
	idpAccount.MFA = onelogin.IdentifierYubiKey
	idpAccount.Username = "user@example.com"
	idpAccount.SkipVerify = true

	loginDetails := &creds.LoginDetails{
		Username: idpAccount.Username,
		Password: "abc123",
		URL:      idpAccount.URL,
	}

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("StringRequired", "Enter verification code").Return("5309")

	oc, err := onelogin.New(idpAccount)
	assert.Nil(t, err)
	resp, err := oc.Authenticate(loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, "saml1", resp)
}

func TestOneLoginMFAUsesProvidedTOTP(t *testing.T) {
	verifyRequests := make(chan onelogin.VerifyRequest, 1)
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.String(), "/auth/oauth2/v2/token"):
			_, _ = w.Write([]byte(`{"access_token":"accesstoken1"}`))
		case strings.HasPrefix(r.URL.String(), "/api/2/saml_assertion/verify_factor"):
			var request onelogin.VerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			verifyRequests <- request
			_, _ = w.Write([]byte(`{"message":"Success","data":"saml1"}`))
		case strings.HasPrefix(r.URL.String(), "/api/2/saml_assertion"):
			_, _ = w.Write([]byte(`{
				"message":"MFA is required for this user",
				"state_token":"state1",
				"devices":[{"device_type":"Google Authenticator","device_id":"device1"}]
			}`))
		default:
			t.Fatalf("unexpected %v", r)
		}
	}))
	defer svr.Close()

	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = svr.URL
	idpAccount.MFA = onelogin.IdentifierTotpMfa
	idpAccount.Username = "user@example.com"
	idpAccount.SkipVerify = true

	oldPrompter := prompter.ActivePrompter
	t.Cleanup(func() { prompter.SetPrompter(oldPrompter) })
	pr := &mocks.Prompter{}
	pr.Test(t)
	prompter.SetPrompter(pr)

	oc, err := onelogin.New(idpAccount)
	require.NoError(t, err)
	resp, err := oc.Authenticate(&creds.LoginDetails{
		Username: idpAccount.Username,
		Password: "abc123",
		URL:      idpAccount.URL,
		MFAToken: "530912",
	})
	require.NoError(t, err)
	assert.Equal(t, "saml1", resp)

	request := <-verifyRequests
	assert.Equal(t, "device1", request.DeviceID)
	assert.Equal(t, "state1", request.StateToken)
	assert.Equal(t, "530912", request.OTPToken)
	pr.AssertExpectations(t)
}

func TestOneLoginSupportedMFAFactors(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		mfa        string
		mfaToken   string
		wantOTP    string
	}{
		{name: "OneLogin Protect", identifier: onelogin.IdentifierOneLoginProtectMfa, mfa: "OLP"},
		{name: "SMS", identifier: onelogin.IdentifierSmsMfa, mfa: "SMS", wantOTP: "123456"},
		{name: "TOTP", identifier: onelogin.IdentifierTotpMfa, mfa: "TOTP", mfaToken: "530912", wantOTP: "530912"},
		{name: "YubiKey", identifier: onelogin.IdentifierYubiKey, mfa: "YUBIKEY", wantOTP: "123456"},
		{name: "Duo", identifier: onelogin.IdentifierDuoSecurity, mfa: "DUO TOTP", wantOTP: "123456"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifyRequests := make(chan onelogin.VerifyRequest, 2)
			polls := 0
			svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/auth/oauth2/v2/token":
					_, _ = w.Write([]byte(`{"access_token":"token"}`))
				case "/api/2/saml_assertion":
					_, _ = w.Write([]byte(`{"message":"MFA is required for this user","state_token":"state","devices":[{"device_type":"` + tt.identifier + `","device_id":"device"}]}`))
				case "/api/2/saml_assertion/verify_factor":
					var request onelogin.VerifyRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					verifyRequests <- request
					polls++
					if tt.identifier == onelogin.IdentifierOneLoginProtectMfa && polls == 1 {
						_, _ = w.Write([]byte(`{"message":"Authentication pending"}`))
						return
					}
					_, _ = w.Write([]byte(`{"message":"Success","data":"assertion"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer svr.Close()

			oldPrompter := prompter.ActivePrompter
			t.Cleanup(func() { prompter.SetPrompter(oldPrompter) })
			pr := &mocks.Prompter{}
			pr.Test(t)
			if tt.wantOTP != "" && tt.mfaToken == "" {
				pr.On("StringRequired", "Enter verification code").Return(tt.wantOTP)
			}
			prompter.SetPrompter(pr)

			account := cfg.NewIDPAccount()
			account.URL, account.MFA, account.SkipVerify = svr.URL, tt.mfa, true
			oc, err := onelogin.New(account)
			require.NoError(t, err)
			assertion, err := oc.Authenticate(&creds.LoginDetails{URL: svr.URL, MFAToken: tt.mfaToken})
			require.NoError(t, err)
			assert.Equal(t, "assertion", assertion)

			var request onelogin.VerifyRequest
			for {
				select {
				case request = <-verifyRequests:
				default:
					goto gotLastRequest
				}
			}
		gotLastRequest:
			assert.Equal(t, "device", request.DeviceID)
			assert.Equal(t, "state", request.StateToken)
			if tt.identifier == onelogin.IdentifierOneLoginProtectMfa {
				assert.True(t, request.DoNotNotify)
			} else {
				assert.Equal(t, tt.wantOTP, request.OTPToken)
			}
			pr.AssertExpectations(t)
		})
	}
}

func TestOneLoginAuthenticateErrors(t *testing.T) {
	tests := []struct {
		name      string
		oauthBody string
		oauthCode int
		authBody  string
		authCode  int
		wantErr   string
	}{
		{name: "OAuth failure", oauthBody: `{"message":"bad client"}`, oauthCode: http.StatusUnauthorized, wantErr: "failed to generate oauth token: HTTP 401: bad client"},
		{name: "OAuth malformed response", oauthBody: "not-json", oauthCode: http.StatusOK, wantErr: "failed to generate oauth token: invalid oauth token response"},
		{name: "auth denial", oauthBody: `{"access_token":"token"}`, oauthCode: http.StatusOK, authBody: `{"message":"Access denied"}`, authCode: http.StatusUnauthorized, wantErr: "HTTP 401: Access denied"},
		{name: "auth malformed response", oauthBody: `{"access_token":"token"}`, oauthCode: http.StatusOK, authBody: "not-json", authCode: http.StatusOK, wantErr: "invalid SAML assertion response"},
		{name: "missing assertion", oauthBody: `{"access_token":"token"}`, oauthCode: http.StatusOK, authBody: `{"message":"Success"}`, authCode: http.StatusOK, wantErr: "invalid SAML assertion returned"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/auth/oauth2/v2/token" {
					w.WriteHeader(tt.oauthCode)
					_, _ = w.Write([]byte(tt.oauthBody))
					return
				}
				w.WriteHeader(tt.authCode)
				_, _ = w.Write([]byte(tt.authBody))
			}))
			defer svr.Close()
			account := cfg.NewIDPAccount()
			account.URL, account.SkipVerify = svr.URL, true
			oc, err := onelogin.New(account)
			require.NoError(t, err)
			_, err = oc.Authenticate(&creds.LoginDetails{URL: svr.URL})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestOneLoginMFAPollRejection(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/oauth2/v2/token":
			_, _ = w.Write([]byte(`{"access_token":"token"}`))
		case "/api/2/saml_assertion":
			_, _ = w.Write([]byte(`{"message":"MFA is required for this user","state_token":"state","devices":[{"device_type":"OneLogin Protect","device_id":"device"}]}`))
		case "/api/2/saml_assertion/verify_factor":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Authentication rejected"}`))
		}
	}))
	defer svr.Close()
	account := cfg.NewIDPAccount()
	account.URL, account.MFA, account.SkipVerify = svr.URL, "OLP", true
	oc, err := onelogin.New(account)
	require.NoError(t, err)
	_, err = oc.Authenticate(&creds.LoginDetails{URL: svr.URL})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 403: Authentication rejected")
}

func TestOneLoginMFAPollTimeout(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/oauth2/v2/token" {
			_, _ = w.Write([]byte(`{"access_token":"token"}`))
			return
		}
		if r.URL.Path == "/api/2/saml_assertion" {
			_, _ = w.Write([]byte(`{"message":"MFA is required for this user","state_token":"state","devices":[{"device_type":"OneLogin Protect","device_id":"device"}]}`))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}))
	defer svr.Close()
	account := cfg.NewIDPAccount()
	account.URL, account.MFA, account.SkipVerify = svr.URL, "OLP", true
	oc, err := onelogin.New(account)
	require.NoError(t, err)
	oc.Client.Timeout = 10 * time.Millisecond
	_, err = oc.Authenticate(&creds.LoginDetails{URL: svr.URL})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving verify response")
}
