package onelogin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
	"github.com/versent/saml2aws/v2/pkg/provider/onelogin"
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
