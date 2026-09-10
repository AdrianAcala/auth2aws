package saml2aws

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderList_Keys(t *testing.T) {
	want := []string{
		"ADFS", "ADFS2", "Akamai", "Auth0", "Authentik", "AzureAD", "Browser", "F5APM",
		"GoogleApps", "JumpCloud", "KeyCloak", "NetIQ", "Okta", "OneLogin", "Ping", "PingNTLM",
		"PingOne", "Shibboleth", "ShibbolethECP",
	}

	assert.Equal(t, want, MFAsByProvider.Names())
	assert.True(t, sort.StringsAreSorted(MFAsByProvider.Names()))
}

func TestProviderList_Mfas(t *testing.T) {
	want := map[string][]string{
		"ADFS":          {"Auto", "Azure", "Defender", "VIP"},
		"ADFS2":         {"Auto", "RSA"},
		"Akamai":        {"Auto", "DUO", "EMAIL", "SMS", "TOTP"},
		"Auth0":         {"Auto"},
		"Authentik":     {"Auto"},
		"AzureAD":       {"Auto", "OneWaySMS", "PhoneAppNotification", "PhoneAppOTP"},
		"Browser":       {"Auto"},
		"F5APM":         {"Auto"},
		"GoogleApps":    {"Auto"},
		"JumpCloud":     {"Auto", "DUO", "PUSH", "TOTP", "WEBAUTHN"},
		"KeyCloak":      {"Auto"},
		"NetIQ":         {"Auto", "Privileged"},
		"Okta":          {"Auto", "DUO", "EMAIL", "FIDO", "OKTA", "PUSH", "SMS", "SYMANTEC", "TOTP", "YUBICO TOKEN:HARDWARE"},
		"OneLogin":      {"Auto", "DUO TOTP", "OLP", "SMS", "TOTP", "YUBIKEY"},
		"Ping":          {"Auto"},
		"PingNTLM":      {"Auto"},
		"PingOne":       {"Auto"},
		"Shibboleth":    {"Auto", "None"},
		"ShibbolethECP": {"auto", "passcode", "phone", "push"},
	}

	for provider, expected := range want {
		provider, expected := provider, expected
		t.Run(provider, func(t *testing.T) {
			assert.Equal(t, expected, MFAsByProvider.Mfas(provider))
			assert.True(t, sort.StringsAreSorted(MFAsByProvider.Mfas(provider)))
		})
	}
}

func TestRegisteredProvidersConstructors(t *testing.T) {
	constructorTypes := map[string]string{
		"ADFS": "*adfs.Client", "ADFS2": "*adfs2.Client", "Akamai": "*akamai.Client", "Auth0": "*auth0.Client",
		"Authentik": "*authentik.Client", "AzureAD": "*aad.Client", "Browser": "*browser.Client", "F5APM": "*f5apm.Client",
		"GoogleApps": "*googleapps.Client", "JumpCloud": "*jumpcloud.Client", "KeyCloak": "*keycloak.Client", "NetIQ": "*netiq.Client",
		"Okta": "*okta.Client", "OneLogin": "*onelogin.Client", "Ping": "*pingfed.Client", "PingNTLM": "*pingntlm.Client",
		"PingOne": "*pingone.Client", "Shibboleth": "*shibboleth.Client", "ShibbolethECP": "*shibbolethecp.Client",
	}

	for _, provider := range MFAsByProvider.Names() {
		provider := provider
		t.Run(provider, func(t *testing.T) {
			account := &cfg.IDPAccount{Provider: provider, MFA: MFAsByProvider.Mfas(provider)[0]}
			client, err := newSAMLClientNoPanic(account)
			require.NoError(t, err)
			require.NotNil(t, client)
			assert.Equal(t, constructorTypes[provider], reflect.TypeOf(client).String())
		})
	}
}

func TestRegisteredProviderMFAsConstructors(t *testing.T) {
	for _, provider := range MFAsByProvider.Names() {
		provider := provider
		for _, mfa := range MFAsByProvider.Mfas(provider) {
			mfa := mfa
			t.Run(fmt.Sprintf("%s/%s", provider, mfa), func(t *testing.T) {
				client, err := newSAMLClientNoPanic(&cfg.IDPAccount{Provider: provider, MFA: mfa})
				require.NoError(t, err)
				require.NotNil(t, client)
			})
		}
	}
}

func TestInvalidProviderAndMFA(t *testing.T) {
	client, err := newSAMLClientNoPanic(&cfg.IDPAccount{Provider: "invalid-provider", MFA: "Auto"})
	assert.Nil(t, client)
	assert.EqualError(t, err, "Invalid provider: invalid-provider")

	for _, provider := range MFAsByProvider.Names() {
		provider := provider
		t.Run(provider, func(t *testing.T) {
			assert.True(t, invalidMFA(provider, "invalid-mfa"))
		})
	}

	for _, provider := range []string{"AzureAD", "ADFS", "ADFS2", "Ping", "PingNTLM", "PingOne", "JumpCloud", "Okta", "OneLogin", "Authentik", "KeyCloak", "GoogleApps", "Shibboleth", "ShibbolethECP", "F5APM", "Akamai", "NetIQ", "Auth0"} {
		provider := provider
		t.Run(provider+"/constructor", func(t *testing.T) {
			client, err := newSAMLClientNoPanic(&cfg.IDPAccount{Provider: provider, MFA: "invalid-mfa"})
			assert.Nil(t, client)
			assert.EqualError(t, err, "Invalid MFA type: invalid-mfa for "+provider+" provider")
		})
	}
}

func newSAMLClientNoPanic(account *cfg.IDPAccount) (client SAMLClient, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("NewSAMLClient panicked: %v", recovered)
			client = nil
		}
	}()
	return NewSAMLClient(account)
}

func TestProviderInvalid(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "foo1",
	}
	_, err := NewSAMLClient(account)
	assert.ErrorContains(t, err, "Invalid provider: foo1")
}

func TestProviderAzureADInvalidMFA(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "AzureAD",
	}
	_, err := NewSAMLClient(account)
	assert.ErrorContains(t, err, "Invalid MFA type: ")
}

func TestProviderAzureADMFA(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "AzureAD",
		MFA:      "PhoneAppOTP",
	}
	client, err := NewSAMLClient(account)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{Username: "testuser", Password: "testtestlol", URL: "https://id.example.com", MFAToken: "123456"}
	err = client.Validate(loginDetails)
	assert.Nil(t, err)
}

func TestProviderPingNTLMInvalidMFA(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "PingNTLM",
	}
	_, err := NewSAMLClient(account)
	assert.ErrorContains(t, err, "Invalid MFA type: ")
}

func TestProviderPingNTLMMFA(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "PingNTLM",
		MFA:      "Auto",
	}
	client, err := NewSAMLClient(account)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{Username: "testuser", Password: "testtestlol", URL: "https://id.example.com", MFAToken: "123456"}
	err = client.Validate(loginDetails)
	assert.Nil(t, err)
}
