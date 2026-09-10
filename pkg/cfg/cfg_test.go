package cfg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/require"
)

const throwAwayConfig = "example/saml2aws.test.ini"

func TestNewConfigManagerNew(t *testing.T) {

	cfgm, err := NewConfigManager("example/saml2aws.ini")
	require.Nil(t, err)
	require.NotNil(t, cfgm)
}

func TestIDPAccountString(t *testing.T) {
	cfgm, err := NewConfigManager("example/saml2aws.ini")
	require.Nil(t, err)

	require.NotNil(t, cfgm)

	idpAccount, err := cfgm.LoadIDPAccount("test123")
	require.Nil(t, err)
	s := idpAccount.String()
	require.Contains(t, s, "urn:amazon:webservices\n")
}

func TestNewConfigManagerDefaultEmpty(t *testing.T) {
	cfgm, err := NewConfigManager("")
	require.Nil(t, err)
	require.Contains(t, cfgm.configPath, ".saml2aws")
	idpAccount, err := cfgm.LoadIDPAccount("foo")
	require.Nil(t, err)
	require.Equal(t, idpAccount.URL, "")
}

func TestNewConfigManagerLoad(t *testing.T) {

	cfgm, err := NewConfigManager("example/saml2aws.ini")
	require.Nil(t, err)

	require.NotNil(t, cfgm)

	idpAccount, err := cfgm.LoadIDPAccount("test123")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{
		Name:                 "test123",
		URL:                  "https://id.whatever.com/#/hash",
		Username:             "abc@whatever.com",
		Provider:             "keycloak",
		MFA:                  "sms",
		AmazonWebservicesURN: DefaultAmazonWebservicesURN,
		SessionDuration:      3600,
		Profile:              "saml",
	}, idpAccount)

	idpAccount, err = cfgm.LoadIDPAccount("")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{
		AmazonWebservicesURN: DefaultAmazonWebservicesURN,
		SessionDuration:      3600,
		Profile:              "saml",
	}, idpAccount)
}

func TestNewConfigManagerSave(t *testing.T) {

	cfgm, err := NewConfigManager(throwAwayConfig)
	require.Nil(t, err)

	err = cfgm.SaveIDPAccount("testing2", &IDPAccount{
		URL:      "https://id.whatever.com",
		MFA:      "none",
		Provider: "keycloak",
		Username: "abc@whatever.com",
		Profile:  "saml",
	})
	require.Nil(t, err)
	idpAccount, err := cfgm.LoadIDPAccount("testing2")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{
		Name:                 "testing2",
		URL:                  "https://id.whatever.com",
		Username:             "abc@whatever.com",
		Provider:             "keycloak",
		MFA:                  "none",
		AmazonWebservicesURN: DefaultAmazonWebservicesURN,
		Profile:              "saml",
	}, idpAccount)

	os.Remove(throwAwayConfig)

}

func TestNewIDPAccountDefaults(t *testing.T) {
	require.Equal(t, &IDPAccount{
		AmazonWebservicesURN: DefaultAmazonWebservicesURN,
		SessionDuration:      DefaultSessionDuration,
		Profile:              DefaultProfile,
	}, NewIDPAccount())
}

func TestIDPAccountValidateRequiredFields(t *testing.T) {
	valid := func() *IDPAccount {
		return &IDPAccount{URL: "https://id.example.com", Provider: "Ping", MFA: "totp", Profile: "saml"}
	}

	tests := []struct {
		name    string
		mutate  func(*IDPAccount)
		errText string
	}{
		{name: "url", mutate: func(a *IDPAccount) { a.URL = "" }, errText: "URL empty"},
		{name: "malformed url", mutate: func(a *IDPAccount) { a.URL = "%" }, errText: "URL parse failed"},
		{name: "provider", mutate: func(a *IDPAccount) { a.Provider = "" }, errText: "Provider empty"},
		{name: "mfa", mutate: func(a *IDPAccount) { a.MFA = "" }, errText: "MFA empty"},
		{name: "profile", mutate: func(a *IDPAccount) { a.Profile = "" }, errText: "Profile empty"},
		{name: "prompter", mutate: func(a *IDPAccount) { a.Prompter = "not-a-prompter" }, errText: "prompter"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account := valid()
			test.mutate(account)
			err := account.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), test.errText)
		})
	}
}

func TestIDPAccountValidateProviderRequirements(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		mutate   func(*IDPAccount)
		errText  string
	}{
		{name: "onelogin app id", provider: "OneLogin", mutate: func(a *IDPAccount) { a.Subdomain = "example" }, errText: "app ID empty"},
		{name: "onelogin subdomain", provider: "OneLogin", mutate: func(a *IDPAccount) { a.AppID = "app" }, errText: "subdomain empty"},
		{name: "f5 resource id", provider: "F5APM", errText: "Resource ID empty"},
		{name: "azure app id", provider: "AzureAD", errText: "app ID empty"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account := &IDPAccount{URL: "https://id.example.com", Provider: test.provider, MFA: "totp", Profile: "saml"}
			if test.mutate != nil {
				test.mutate(account)
			}
			err := account.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), test.errText)
		})
	}

	for _, account := range []*IDPAccount{
		{URL: "https://id.example.com", Provider: "OneLogin", AppID: "app", Subdomain: "example", MFA: "totp", Profile: "saml"},
		{URL: "https://id.example.com", Provider: "F5APM", ResourceID: "resource", MFA: "totp", Profile: "saml"},
		{URL: "https://id.example.com", Provider: "AzureAD", AppID: "app", MFA: "totp", Profile: "saml"},
		{URL: "https://id.example.com", Provider: "Browser", Profile: "saml"},
	} {
		require.NoError(t, account.Validate())
	}
}

func TestNewConfigManagerExpandsHomePath(t *testing.T) {
	path, err := homedir.Expand("~/saml2aws-test-config")
	require.NoError(t, err)

	cfgm, err := NewConfigManager("~/saml2aws-test-config")
	require.NoError(t, err)
	require.Equal(t, path, cfgm.configPath)
}

func TestConfigManagerLoadMalformedConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "saml2aws.ini")
	require.NoError(t, os.WriteFile(configPath, []byte("[account\nurl = https://id.example.com\n"), 0600))

	cfgm, err := NewConfigManager(configPath)
	require.NoError(t, err)
	_, err = cfgm.LoadIDPAccount("account")
	require.Error(t, err)
}

func TestConfigManagerSaveToReadOnlyConfigPath(t *testing.T) {
	configPath := t.TempDir()
	cfgm, err := NewConfigManager(configPath)
	require.NoError(t, err)

	err = cfgm.SaveIDPAccount("account", &IDPAccount{URL: "https://id.example.com", Provider: "Ping", MFA: "totp", Profile: "saml"})
	require.Error(t, err)
}

func TestConfigManagerSaveLoadRoundTrip(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "saml2aws.ini")
	cfgm, err := NewConfigManager(configPath)
	require.NoError(t, err)

	want := &IDPAccount{
		Name: "full", AppID: "app", URL: "https://id.example.com/login", Username: "user@example.com",
		Provider: "OneLogin", BrowserType: "chrome", BrowserExecutablePath: "/usr/bin/chrome", BrowserAutoFill: true,
		MFA: "totp", MFAIPAddress: "127.0.0.1", SkipVerify: true, Timeout: 42,
		AmazonWebservicesURN: "urn:custom", SessionDuration: 7200, Profile: "work", ResourceID: "resource",
		Subdomain: "example", RoleARN: "arn:aws:iam::123:role/test", PolicyFile: "/tmp/policy.json",
		PolicyARNs: "arn:aws:iam::123:policy/test", Region: "us-east-1", HttpAttemptsCount: "3", HttpRetryDelay: "1s",
		CredentialsFile: "/tmp/credentials", SAMLCache: true, SAMLCacheFile: "/tmp/cache", TargetURL: "https://console.aws.amazon.com",
		DisableRememberDevice: true, DisableSessions: true, DownloadBrowser: true, BrowserDriverDir: "/tmp/drivers",
		Headless: true, Prompter: "default", KCAuthErrorMessage: "auth failed", KCAuthErrorElement: "#error", KCBroker: "broker",
	}
	require.NoError(t, cfgm.SaveIDPAccount("full", want))

	got, err := cfgm.LoadIDPAccount("full")
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestConfigManagerSaveUpdatesAccountAndPreservesOthers(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "saml2aws.ini")
	cfgm, err := NewConfigManager(configPath)
	require.NoError(t, err)
	first := &IDPAccount{URL: "https://first.example.com", Provider: "Ping", MFA: "totp", Profile: "first"}
	second := &IDPAccount{URL: "https://second.example.com", Provider: "Ping", MFA: "sms", Profile: "second"}
	require.NoError(t, cfgm.SaveIDPAccount("first", first))
	require.NoError(t, cfgm.SaveIDPAccount("second", second))

	updated := *first
	updated.URL = "https://updated.example.com"
	updated.MFA = "push"
	require.NoError(t, cfgm.SaveIDPAccount("first", &updated))

	gotFirst, err := cfgm.LoadIDPAccount("first")
	require.NoError(t, err)
	require.Equal(t, &IDPAccount{Name: "first", URL: updated.URL, Provider: updated.Provider, MFA: updated.MFA, Profile: updated.Profile, AmazonWebservicesURN: DefaultAmazonWebservicesURN}, gotFirst)
	gotSecond, err := cfgm.LoadIDPAccount("second")
	require.NoError(t, err)
	require.Equal(t, &IDPAccount{Name: "second", URL: second.URL, Provider: second.Provider, MFA: second.MFA, Profile: second.Profile, AmazonWebservicesURN: DefaultAmazonWebservicesURN}, gotSecond)
}
