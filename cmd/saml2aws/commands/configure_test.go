package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/helper/credentials"
	"github.com/AdrianAcala/saml2aws/v2/mocks"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/flags"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/AdrianAcala/saml2aws/v2/pkg/provider/onelogin"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type configureTestPrompter struct {
	chooseErr error
}

func (p *configureTestPrompter) RequestSecurityCode(string) string { return "" }
func (p *configureTestPrompter) ChooseWithDefault(string, string, []string) (string, error) {
	return "", p.chooseErr
}
func (p *configureTestPrompter) Choose(string, []string) int  { return 0 }
func (p *configureTestPrompter) String(string, string) string { return "" }
func (p *configureTestPrompter) StringRequired(string) string { return "" }
func (p *configureTestPrompter) Password(string) string       { return "" }
func (p *configureTestPrompter) Display(string)               {}

func configureTestHelper(t *testing.T) {
	t.Helper()
	old := credentials.CurrentHelper
	helperMock := &mocks.Helper{}
	helperMock.On("SupportsCredentialStorage").Return(false)
	credentials.CurrentHelper = helperMock
	t.Cleanup(func() { credentials.CurrentHelper = old })
}

func writeConfigureFile(t *testing.T, contents string) string {
	t.Helper()
	filename := path.Join(t.TempDir(), "saml2aws.ini")
	if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return filename
}

// Configure module
func TestConfigureStoresCredentialOnSupportedStorage(t *testing.T) {
	commonFlags := &flags.CommonFlags{URL: "https://id.example.com", Username: "some-username", Password: "password", SkipPrompt: true}
	creds := &credentials.Credentials{ServerURL: "https://id.example.com", Username: "some-username", Secret: "password"}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", creds).Return(nil).Once()
	helperMock.Mock.On("SupportsCredentialStorage").Return(true).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	err := Configure(commonFlags)
	// making linter happy
	if err != nil {
		credentials.CurrentHelper = oldCurrentHelper
	}

	helperMock.AssertCalled(t, "Add", creds)
	credentials.CurrentHelper = oldCurrentHelper
}

func TestConfigureCreatesAndUpdatesAccountPreservingExistingValues(t *testing.T) {
	configureTestHelper(t)
	configFile := writeConfigureFile(t, "[existing]\nurl = https://existing.example.com\nprovider = Ping\nmfa = Auto\nprofile = existing\nregion = us-west-2\n")

	err := Configure(&flags.CommonFlags{
		ConfigFile:  configFile,
		IdpAccount:  "new-account",
		URL:         "https://id.example.com",
		Username:    "new-user",
		IdpProvider: "Ping",
		MFA:         "Auto",
		Profile:     "new-profile",
		SkipPrompt:  true,
	})
	assert.NoError(t, err)

	cfgm, err := cfg.NewConfigManager(configFile)
	assert.NoError(t, err)
	created, err := cfgm.LoadIDPAccount("new-account")
	assert.NoError(t, err)
	assert.Equal(t, "https://id.example.com", created.URL)
	assert.Equal(t, "new-user", created.Username)
	assert.Equal(t, "new-profile", created.Profile)

	err = Configure(&flags.CommonFlags{
		ConfigFile: configFile,
		IdpAccount: "new-account",
		Username:   "updated-user",
		Region:     "eu-west-1",
		SkipPrompt: true,
	})
	assert.NoError(t, err)

	updated, err := cfgm.LoadIDPAccount("new-account")
	assert.NoError(t, err)
	assert.Equal(t, "updated-user", updated.Username)
	assert.Equal(t, "https://id.example.com", updated.URL)
	assert.Equal(t, "Ping", updated.Provider)
	assert.Equal(t, "Auto", updated.MFA)
	assert.Equal(t, "new-profile", updated.Profile)
	assert.Equal(t, "eu-west-1", updated.Region)

	existing, err := cfgm.LoadIDPAccount("existing")
	assert.NoError(t, err)
	assert.Equal(t, "https://existing.example.com", existing.URL)
	assert.Equal(t, "us-west-2", existing.Region)
}

func TestConfigureReturnsErrorWhenConfigurationCannotBeLoaded(t *testing.T) {
	configureTestHelper(t)
	err := Configure(&flags.CommonFlags{
		ConfigFile: t.TempDir(),
		IdpAccount: "account",
		SkipPrompt: true,
	})
	assert.ErrorContains(t, err, "failed to load idp account")
}

func TestConfigureReturnsPromptCancellationError(t *testing.T) {
	configureTestHelper(t)
	configFile := writeConfigureFile(t, "[account]\nurl = https://id.example.com\nprovider = Ping\nmfa = Auto\nprofile = saml\n")
	oldPrompter := prompter.ActivePrompter
	prompter.ActivePrompter = &configureTestPrompter{chooseErr: fmt.Errorf("cancelled")}
	t.Cleanup(func() { prompter.ActivePrompter = oldPrompter })

	err := Configure(&flags.CommonFlags{ConfigFile: configFile, IdpAccount: "account"})
	assert.ErrorContains(t, err, "failed to input configuration")
	assert.ErrorContains(t, err, "cancelled")
}

func TestSaveConfigurationReturnsValidationError(t *testing.T) {
	configureTestHelper(t)
	configFile := writeConfigureFile(t, "")
	cfgm, err := cfg.NewConfigManager(configFile)
	assert.NoError(t, err)

	err = saveConfiguration(cfgm, "account", &cfg.IDPAccount{Provider: "Ping"}, &flags.CommonFlags{}, "")
	assert.ErrorContains(t, err, "Account validation failed")
}

func TestSaveConfigurationReturnsWriteError(t *testing.T) {
	configureTestHelper(t)
	cfgm, err := cfg.NewConfigManager(t.TempDir())
	assert.NoError(t, err)
	account := &cfg.IDPAccount{URL: "https://id.example.com", Provider: "Ping", MFA: "Auto", Profile: "saml"}

	err = saveConfiguration(cfgm, "account", account, &flags.CommonFlags{}, "")
	assert.ErrorContains(t, err, "failed to save configuration")
}

// Store Credentials module
func TestStoreCredentialsOnDisabledKeychainFlagReturnsNil(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: true}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}

	result := storeCredentials(commonFlags, idpAccount, "password")

	assert.Nil(t, result)
}

func TestStoreCredentialsOnProvidedPasswordSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	creds := &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", creds).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	defer func() {
		credentials.CurrentHelper = oldCurrentHelper
	}()
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	helperMock.AssertCalled(t, "Add", creds)
	assert.Nil(t, result)
}

func TestStoreCredentialsOnProvidedPasswordHandlesErrorOnSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	creds := &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", creds).Return(errors.New("i am an error")).Once()
	oldCurrentHelper := credentials.CurrentHelper
	defer func() {
		credentials.CurrentHelper = oldCurrentHelper
	}()
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	helperMock.AssertCalled(t, "Add", creds)
	assert.ErrorContains(t, result, "i am an error")
	assert.ErrorContains(t, result, "error storing password in keychain")
}

func TestStoreCredentialsOnMissingPasswordSkipsSavingCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	creds := &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", creds).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	defer func() {
		credentials.CurrentHelper = oldCurrentHelper
	}()
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "")

	helperMock.AssertNotCalled(t, "Add")
	assert.Nil(t, result)
}

func TestStoreCredentialsOnMissingOneLoginClientIdExitsProgram(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "", ClientSecret: "oneloginSecret"}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", mock.Anything).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	defer func() {
		credentials.CurrentHelper = oldCurrentHelper
	}()
	credentials.CurrentHelper = helperMock

	if os.Getenv("BE_CRASHER") == "1" {
		err := storeCredentials(commonFlags, idpAccount, "password")
		// making linter happy
		if err != nil {
			return
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStoreCredentialsOnMissingOneLoginClientIdExitsProgram")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestStoreCredentialsOnMissingOneLoginClientSecretExitsProgram(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "oneloginSecret", ClientSecret: ""}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", mock.Anything).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	defer func() {
		credentials.CurrentHelper = oldCurrentHelper
	}()
	credentials.CurrentHelper = helperMock

	if os.Getenv("BE_CRASHER") == "1" {
		err := storeCredentials(commonFlags, idpAccount, "password")
		// making linter happy
		if err != nil {
			return
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStoreCredentialsOnMissingOneLoginClientSecretExitsProgram")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestStoreCredentialsOnProvidedOneLoginSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "oneloginId", ClientSecret: "oneloginSecret"}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}).Return(nil).Once()
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: path.Join("https://id.example.com", OneLoginOAuthPath), Username: "oneloginId", Secret: "oneloginSecret"}).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	defer func() {
		credentials.CurrentHelper = oldCurrentHelper
	}()
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	helperMock.AssertNumberOfCalls(t, "Add", 2)
	assert.Nil(t, result)
}

func TestStoreCredentialsOnProvidedOneLoginHandlesErrorOnSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "oneloginId", ClientSecret: "oneloginSecret"}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}).Return(nil).Once()
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: path.Join("https://id.example.com", OneLoginOAuthPath), Username: "oneloginId", Secret: "oneloginSecret"}).Return(errors.New("failed again")).Once()
	oldCurrentHelper := credentials.CurrentHelper
	defer func() {
		credentials.CurrentHelper = oldCurrentHelper
	}()
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	assert.ErrorContains(t, result, "failed again")
	assert.ErrorContains(t, result, "error storing client_id and client_secret in keychain")
}
