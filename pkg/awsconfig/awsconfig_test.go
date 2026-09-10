package awsconfig

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCredentials() *AWSCredentials {
	return &AWSCredentials{
		AWSAccessKey:     "test-access-key",
		AWSSecretKey:     "test-secret-key",
		AWSSessionToken:  "test-session-token",
		AWSSecurityToken: "test-security-token",
		PrincipalARN:     "arn:aws:iam::123456789012:saml-provider/test",
		Expires:          time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		Region:           "us-west-2",
	}
}

func TestCredsExistsCreatesMissingFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), ".aws", "credentials")
	provider := NewSharedCredentials("saml", filename)

	exists, err := provider.CredsExists()
	require.NoError(t, err)
	assert.True(t, exists)
	info, err := os.Stat(filename)
	require.NoError(t, err)
	assert.False(t, info.IsDir())
	contents, err := os.ReadFile(filename)
	require.NoError(t, err)
	assert.Equal(t, "[saml]", string(contents))
}

func TestSaveLoadRoundTripAndExpired(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "credentials")
	provider := NewSharedCredentials("saml", filename)
	creds := testCredentials()

	require.NoError(t, provider.Save(creds))
	loaded, err := provider.Load()
	require.NoError(t, err)
	assert.Equal(t, creds, loaded)
	assert.False(t, provider.Expired())

	creds.Expires = time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, provider.Save(creds))
	assert.True(t, provider.Expired())
}

func TestSavePreservesMultipleProfiles(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "credentials")
	first := NewSharedCredentials("first", filename)
	second := NewSharedCredentials("second", filename)
	firstCreds := testCredentials()
	secondCreds := testCredentials()
	secondCreds.AWSAccessKey = "second-access-key"

	require.NoError(t, first.Save(firstCreds))
	require.NoError(t, second.Save(secondCreds))

	loadedFirst, err := first.Load()
	require.NoError(t, err)
	loadedSecond, err := second.Load()
	require.NoError(t, err)
	assert.Equal(t, firstCreds, loadedFirst)
	assert.Equal(t, secondCreds, loadedSecond)
}

func TestCustomEnvironmentPath(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "custom-credentials")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filename)
	provider := NewSharedCredentials("custom", "")

	exists, err := provider.CredsExists()
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, filename, provider.Filename)
	require.NoError(t, provider.Save(testCredentials()))
	_, err = provider.Load()
	require.NoError(t, err)
}

func TestLoadMissingAndMalformedProfiles(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.WriteFile(filename, []byte("[other]\naws_access_key_id=present\n"), 0600))

	missing := NewSharedCredentials("missing", filename)
	_, err := missing.Load()
	assert.ErrorIs(t, err, ErrCredentialsNotFound)
	assert.True(t, missing.Expired())

	malformedFilename := filepath.Join(t.TempDir(), "credentials")
	require.NoError(t, os.WriteFile(malformedFilename, []byte("[saml\naws_access_key_id=broken\n"), 0600))
	malformed := NewSharedCredentials("saml", malformedFilename)
	_, err = malformed.Load()
	assert.Error(t, err)
	assert.True(t, malformed.Expired())
}

func TestLoadMissingFileAndCredsExistsError(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "does-not-exist")
	provider := NewSharedCredentials("saml", filename)

	_, err := provider.Load()
	assert.Error(t, err)

	// CredsExists creates a missing credentials file as part of ensuring its
	// parent directory exists, so use an invalid parent to exercise its error.
	parent := filepath.Join(t.TempDir(), "parent-file")
	require.NoError(t, os.WriteFile(parent, []byte("not a directory"), 0600))
	provider = NewSharedCredentials("saml", filepath.Join(parent, "credentials"))
	exists, err := provider.CredsExists()
	assert.False(t, exists)
	assert.Error(t, err)
}

func TestCredentialsFileAndDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	dir := t.TempDir()
	filename := filepath.Join(dir, "nested", "credentials")
	provider := NewSharedCredentials("saml", filename)

	require.NoError(t, provider.Save(testCredentials()))
	fileInfo, err := os.Stat(filename)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fileInfo.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(filename))
	require.NoError(t, err)
	assert.True(t, dirInfo.IsDir())
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm()&0700)
}

func TestSymlinkedCredentialsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated Windows privileges")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.WriteFile(target, []byte("[saml]\naws_access_key_id=linked\n"), 0600))
	require.NoError(t, os.Symlink(target, link))

	resolved, err := resolveSymlink(link)
	require.NoError(t, err)
	assert.Equal(t, target, resolved)
	provider := NewSharedCredentials("saml", link)
	loaded, err := provider.Load()
	require.NoError(t, err)
	assert.Equal(t, "linked", loaded.AWSAccessKey)
}

func TestResolveSymlinkMissingPath(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "missing")
	resolved, err := resolveSymlink(filename)
	require.NoError(t, err)
	assert.Equal(t, filename, resolved)
}

func TestSaveWriteError(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent-file")
	require.NoError(t, os.WriteFile(parent, []byte("not a directory"), 0600))
	provider := NewSharedCredentials("saml", filepath.Join(parent, "credentials"))

	err := provider.Save(testCredentials())
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ErrCredentialsNotFound))
}
