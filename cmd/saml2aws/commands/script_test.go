package commands

import (
	"testing"
	"time"

	"github.com/AdrianAcala/saml2aws/v2/pkg/awsconfig"
	"github.com/stretchr/testify/assert"
)

func TestBuildTmplBash(t *testing.T) {

	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Now(),
		},
	}

	st, err := buildTmpl("bash", data)
	assert.Nil(t, err)

	expected := []string{
		"export AWS_ACCESS_KEY_ID=access_key",
		"export AWS_SECRET_ACCESS_KEY=secret_key",
		"export AWS_SESSION_TOKEN=session_token",
		"export AWS_SECURITY_TOKEN=security_token",
		"export SAML2AWS_PROFILE=test_profile",
	}

	for _, test_string := range expected {
		assert.Contains(t, st, test_string)
	}

}

func TestBuildTmplSh(t *testing.T) {

	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Now(),
		},
	}

	st, err := buildTmpl("/bin/sh", data)
	assert.Nil(t, err)

	expected := []string{
		"export AWS_ACCESS_KEY_ID=access_key",
		"export AWS_SECRET_ACCESS_KEY=secret_key",
		"export AWS_SESSION_TOKEN=session_token",
		"export AWS_SECURITY_TOKEN=security_token",
		"export SAML2AWS_PROFILE=test_profile",
	}

	for _, test_string := range expected {
		assert.Contains(t, st, test_string)
	}

}

func TestBuildTmplFish(t *testing.T) {

	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Now(),
		},
	}

	st, err := buildTmpl("fish", data)
	assert.Nil(t, err)

	expected := []string{
		"set -gx AWS_ACCESS_KEY_ID access_key",
		"set -gx AWS_SECRET_ACCESS_KEY secret_key",
		"set -gx AWS_SESSION_TOKEN session_token",
		"set -gx AWS_SECURITY_TOKEN security_token",
		"set -gx SAML2AWS_PROFILE test_profile",
	}

	for _, test_string := range expected {
		assert.Contains(t, st, test_string)
	}

}

func TestBuildTmplEnv(t *testing.T) {

	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Now(),
		},
	}

	st, err := buildTmpl("env", data)
	assert.Nil(t, err)

	expected := []string{
		"AWS_ACCESS_KEY_ID=access_key",
		"AWS_SECRET_ACCESS_KEY=secret_key",
		"AWS_SESSION_TOKEN=session_token",
		"AWS_SECURITY_TOKEN=security_token",
		"SAML2AWS_PROFILE=test_profile",
	}

	for _, test_string := range expected {
		assert.Contains(t, st, test_string)
	}

}

func TestBuildTmplPowerShell(t *testing.T) {
	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("PST", -8*60*60)),
		},
	}

	st, err := buildTmpl("powershell", data)
	assert.NoError(t, err)
	assert.Equal(t, "$env:AWS_ACCESS_KEY_ID='access_key'\n"+
		"$env:AWS_SECRET_ACCESS_KEY='secret_key'\n"+
		"$env:AWS_SESSION_TOKEN='session_token'\n"+
		"$env:AWS_SECURITY_TOKEN='security_token'\n"+
		"$env:SAML2AWS_PROFILE='test_profile'\n"+
		"$env:AWS_CREDENTIAL_EXPIRATION='2026-01-02T03:04:05-08:00'\n", st)
}

func TestBuildTmplPreservesSpecialCharacters(t *testing.T) {
	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"profile with spaces;$HOME/'quotes'",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret with spaces;$HOME/'quotes'",
			AWSAccessKey:     "access;$(echo escaped)",
			AWSSessionToken:  "token=with=shell&special|chars",
			AWSSecurityToken: "security\twith\ttabs",
			Expires:          time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		},
	}

	for _, shell := range []string{"bash", "/bin/sh", "fish", "env", "powershell"} {
		st, err := buildTmpl(shell, data)
		assert.NoError(t, err, shell)
		assert.Contains(t, st, data.AWSAccessKey, shell)
		assert.Contains(t, st, data.AWSSecretKey, shell)
		assert.Contains(t, st, data.AWSSessionToken, shell)
		assert.Contains(t, st, data.AWSSecurityToken, shell)
		assert.Contains(t, st, data.ProfileName, shell)
	}
}

func TestBuildTmplExecutionError(t *testing.T) {
	st, err := buildTmpl("bash", struct{}{})
	assert.Error(t, err)
	assert.Equal(t, "export AWS_ACCESS_KEY_ID=", st)
}

func TestBuildTmplUnsupportedShell(t *testing.T) {
	st, err := buildTmpl("unsupported", struct{}{})
	assert.Error(t, err)
	assert.Empty(t, st)
}
