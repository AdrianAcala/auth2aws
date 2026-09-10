package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdrianAcala/saml2aws/v2"
	"github.com/AdrianAcala/saml2aws/v2/pkg/awsconfig"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/flags"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type workflowSAMLClient struct {
	assertion       string
	validateErr     error
	authenticateErr error
	validateCalls   int
	authCalls       int
}

func (c *workflowSAMLClient) Validate(*creds.LoginDetails) error {
	c.validateCalls++
	return c.validateErr
}

func (c *workflowSAMLClient) Authenticate(*creds.LoginDetails) (string, error) {
	c.authCalls++
	return c.assertion, c.authenticateErr
}

func loginWorkflowFlags(t *testing.T) (*flags.LoginExecFlags, string) {
	t.Helper()
	dir := t.TempDir()
	credentialsFile := filepath.Join(dir, "aws", "credentials")
	configFile := filepath.Join(dir, "saml2aws")
	config := "[default]\n" +
		"url = https://idp.example.com\n" +
		"username = user@example.com\n" +
		"provider = Shell\n" +
		"mfa = Auto\n" +
		"aws_profile = test-profile\n" +
		"aws_session_duration = 3600\n" +
		"credentials_file = " + credentialsFile + "\n"
	require.NoError(t, os.WriteFile(configFile, []byte(config), 0o600))
	return &flags.LoginExecFlags{CommonFlags: &flags.CommonFlags{
		ConfigFile:      configFile,
		IdpAccount:      "default",
		SkipPrompt:      true,
		Password:        "secret",
		DisableKeychain: true,
	}}, credentialsFile
}

func successfulLoginDependencies(client saml2aws.SAMLClient) loginDependencies {
	return loginDependencies{
		newSAMLClient:      func(*cfg.IDPAccount) (saml2aws.SAMLClient, error) { return client, nil },
		saveIDPCredentials: func(string, string, string) error { return nil },
		selectAWSRole: func(string, *cfg.IDPAccount) (*saml2aws.AWSRole, error) {
			return &saml2aws.AWSRole{RoleARN: "arn:aws:iam::123456789012:role/test", PrincipalARN: "arn:aws:iam::123456789012:saml-provider/test"}, nil
		},
		loginToSTS: func(account *cfg.IDPAccount, _ *saml2aws.AWSRole, assertion string) (*awsconfig.AWSCredentials, error) {
			return &awsconfig.AWSCredentials{
				AWSAccessKey: "access", AWSSecretKey: "secret", AWSSessionToken: "token",
				PrincipalARN: "arn:aws:sts::123456789012:assumed-role/test/user",
				Expires:      time.Now().Add(time.Hour), Region: account.Region,
			}, nil
		},
	}
}

func TestLoginWorkflowAuthenticatesAndPersistsCredentials(t *testing.T) {
	loginFlags, credentialsFile := loginWorkflowFlags(t)
	client := &workflowSAMLClient{assertion: "encoded-assertion"}
	deps := successfulLoginDependencies(client)

	require.NoError(t, login(loginFlags, deps))
	assert.Equal(t, 1, client.validateCalls)
	assert.Equal(t, 1, client.authCalls)

	provider := awsconfig.NewSharedCredentials("test-profile", credentialsFile)
	stored, err := provider.Load()
	require.NoError(t, err)
	assert.Equal(t, "access", stored.AWSAccessKey)
	assert.Equal(t, "secret", stored.AWSSecretKey)
	assert.Equal(t, "token", stored.AWSSessionToken)
}

func TestLoginWorkflowUsesUnexpiredCredentials(t *testing.T) {
	loginFlags, credentialsFile := loginWorkflowFlags(t)
	provider := awsconfig.NewSharedCredentials("test-profile", credentialsFile)
	require.NoError(t, provider.Save(&awsconfig.AWSCredentials{
		AWSAccessKey: "cached", AWSSecretKey: "secret", AWSSessionToken: "token",
		Expires: time.Now().Add(time.Hour),
	}))
	client := &workflowSAMLClient{assertion: "must-not-run"}
	deps := successfulLoginDependencies(client)

	require.NoError(t, login(loginFlags, deps))
	assert.Zero(t, client.validateCalls)
	assert.Zero(t, client.authCalls)
}

func TestLoginWorkflowForceRefreshesUnexpiredCredentials(t *testing.T) {
	loginFlags, credentialsFile := loginWorkflowFlags(t)
	loginFlags.Force = true
	provider := awsconfig.NewSharedCredentials("test-profile", credentialsFile)
	require.NoError(t, provider.Save(&awsconfig.AWSCredentials{
		AWSAccessKey: "old", AWSSecretKey: "old-secret", AWSSessionToken: "old-token",
		Expires: time.Now().Add(time.Hour),
	}))
	client := &workflowSAMLClient{assertion: "encoded-assertion"}

	require.NoError(t, login(loginFlags, successfulLoginDependencies(client)))
	assert.Equal(t, 1, client.authCalls)
	stored, err := provider.Load()
	require.NoError(t, err)
	assert.Equal(t, "access", stored.AWSAccessKey)
}

func TestLoginWorkflowErrorStages(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*workflowSAMLClient, *loginDependencies)
		want      string
	}{
		{name: "client construction", configure: func(_ *workflowSAMLClient, d *loginDependencies) {
			d.newSAMLClient = func(*cfg.IDPAccount) (saml2aws.SAMLClient, error) { return nil, errors.New("constructor failed") }
		}, want: "Error building IdP client"},
		{name: "validation", configure: func(c *workflowSAMLClient, _ *loginDependencies) { c.validateErr = errors.New("invalid login") }, want: "Error validating login details"},
		{name: "authentication", configure: func(c *workflowSAMLClient, _ *loginDependencies) { c.authenticateErr = errors.New("access denied") }, want: "Error authenticating to IdP"},
		{name: "empty assertion", configure: func(c *workflowSAMLClient, _ *loginDependencies) { c.assertion = "" }, want: "valid SAML assertion"},
		{name: "role selection", configure: func(_ *workflowSAMLClient, d *loginDependencies) {
			d.selectAWSRole = func(string, *cfg.IDPAccount) (*saml2aws.AWSRole, error) { return nil, errors.New("no role") }
		}, want: "Failed to assume role"},
		{name: "STS", configure: func(_ *workflowSAMLClient, d *loginDependencies) {
			d.loginToSTS = func(*cfg.IDPAccount, *saml2aws.AWSRole, string) (*awsconfig.AWSCredentials, error) {
				return nil, errors.New("STS denied")
			}
		}, want: "Error logging into AWS role"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginFlags, _ := loginWorkflowFlags(t)
			client := &workflowSAMLClient{assertion: "encoded-assertion"}
			deps := successfulLoginDependencies(client)
			tt.configure(client, &deps)
			err := login(loginFlags, deps)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestLoginWorkflowDoesNotPersistWhenSTSOrRoleSelectionFails(t *testing.T) {
	for _, stage := range []string{"role", "sts"} {
		t.Run(stage, func(t *testing.T) {
			loginFlags, credentialsFile := loginWorkflowFlags(t)
			client := &workflowSAMLClient{assertion: "encoded-assertion"}
			deps := successfulLoginDependencies(client)
			if stage == "role" {
				deps.selectAWSRole = func(string, *cfg.IDPAccount) (*saml2aws.AWSRole, error) { return nil, errors.New("failed") }
			} else {
				deps.loginToSTS = func(*cfg.IDPAccount, *saml2aws.AWSRole, string) (*awsconfig.AWSCredentials, error) {
					return nil, errors.New("failed")
				}
			}

			require.Error(t, login(loginFlags, deps))
			contents, err := os.ReadFile(credentialsFile)
			require.NoError(t, err)
			assert.NotContains(t, string(contents), "aws_access_key_id")
		})
	}
}

func TestSelectAWSRoleRejectsAssertionWithoutRoles(t *testing.T) {
	assertion := "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiLz4="
	_, err := selectAwsRole(assertion, &cfg.IDPAccount{})
	require.Error(t, err)
	assert.True(t, strings.Contains(strings.ToLower(err.Error()), "role"))
}

type fakeSAMLSTSClient struct {
	input  *sts.AssumeRoleWithSAMLInput
	output *sts.AssumeRoleWithSAMLOutput
	err    error
}

func (c *fakeSAMLSTSClient) AssumeRoleWithSAML(input *sts.AssumeRoleWithSAMLInput) (*sts.AssumeRoleWithSAMLOutput, error) {
	c.input = input
	return c.output, c.err
}

func TestLoginToSTSBuildsRequestAndMapsResponse(t *testing.T) {
	policyFile := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(policyFile, []byte(`{"Version":"2012-10-17"}`), 0o600))
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	client := &fakeSAMLSTSClient{output: &sts.AssumeRoleWithSAMLOutput{
		Credentials: &sts.Credentials{
			AccessKeyId: aws.String("access"), SecretAccessKey: aws.String("secret"),
			SessionToken: aws.String("token"), Expiration: aws.Time(expires),
		},
		AssumedRoleUser: &sts.AssumedRoleUser{Arn: aws.String("assumed-role")},
	}}
	account := &cfg.IDPAccount{
		Region: "us-gov-west-1", SessionDuration: 7200, PolicyFile: policyFile,
		PolicyARNs: " arn:aws:iam::aws:policy/ReadOnlyAccess, ,arn:aws:iam::123456789012:policy/custom ",
	}
	role := &saml2aws.AWSRole{RoleARN: "role-arn", PrincipalARN: "principal-arn"}

	got, err := loginToStsUsingRoleWithClient(account, role, "assertion", client)
	require.NoError(t, err)
	require.NotNil(t, client.input)
	assert.Equal(t, "role-arn", aws.StringValue(client.input.RoleArn))
	assert.Equal(t, "principal-arn", aws.StringValue(client.input.PrincipalArn))
	assert.Equal(t, "assertion", aws.StringValue(client.input.SAMLAssertion))
	assert.EqualValues(t, 7200, aws.Int64Value(client.input.DurationSeconds))
	assert.JSONEq(t, `{"Version":"2012-10-17"}`, aws.StringValue(client.input.Policy))
	require.Len(t, client.input.PolicyArns, 2)
	assert.Equal(t, "arn:aws:iam::aws:policy/ReadOnlyAccess", aws.StringValue(client.input.PolicyArns[0].Arn))
	assert.Equal(t, "arn:aws:iam::123456789012:policy/custom", aws.StringValue(client.input.PolicyArns[1].Arn))
	assert.Equal(t, "access", got.AWSAccessKey)
	assert.Equal(t, "secret", got.AWSSecretKey)
	assert.Equal(t, "token", got.AWSSessionToken)
	assert.Equal(t, "token", got.AWSSecurityToken)
	assert.Equal(t, "assumed-role", got.PrincipalARN)
	assert.Equal(t, "us-gov-west-1", got.Region)
	assert.True(t, got.Expires.Equal(expires))
}

func TestLoginToSTSErrors(t *testing.T) {
	t.Run("policy file", func(t *testing.T) {
		_, err := loginToStsUsingRoleWithClient(&cfg.IDPAccount{PolicyFile: filepath.Join(t.TempDir(), "missing")}, &saml2aws.AWSRole{}, "assertion", &fakeSAMLSTSClient{})
		require.ErrorContains(t, err, "Failed to load supplemental policy file")
	})
	t.Run("service", func(t *testing.T) {
		_, err := loginToStsUsingRoleWithClient(&cfg.IDPAccount{}, &saml2aws.AWSRole{}, "assertion", &fakeSAMLSTSClient{err: errors.New("denied")})
		require.ErrorContains(t, err, "Error retrieving STS credentials")
	})
	for name, output := range map[string]*sts.AssumeRoleWithSAMLOutput{
		"nil response":        nil,
		"missing credentials": {AssumedRoleUser: &sts.AssumedRoleUser{}},
		"missing expiration":  {Credentials: &sts.Credentials{}, AssumedRoleUser: &sts.AssumedRoleUser{}},
		"missing role":        {Credentials: &sts.Credentials{Expiration: aws.Time(time.Now())}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loginToStsUsingRoleWithClient(&cfg.IDPAccount{}, &saml2aws.AWSRole{}, "assertion", &fakeSAMLSTSClient{output: output})
			require.ErrorContains(t, err, "did not contain credentials")
		})
	}
}
