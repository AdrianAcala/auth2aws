package samlcache

import (
	b64 "encoding/base64"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"
)

func TestLocateCacheDefault(t *testing.T) {

	cache_location, err := locateCacheFile("")
	if err != nil {
		t.Error("Could not locate cache file:", err)
	}

	if cache_location == "" {
		t.Error("Retrieved location is empty")
	}

	if path.Base(cache_location) != "cache" {
		t.Error("Filename is not the default one (cache):", path.Base(cache_location))
	}

}

func TestLocateCacheAccount(t *testing.T) {

	cache_location, err := locateCacheFile("myaccount")
	if err != nil {
		t.Error("Could not locate cache file:", err)
	}

	if cache_location == "" {
		t.Error("Retrieved location is empty")
	}

	if path.Base(cache_location) != "cache_myaccount" {
		t.Error("Filename is not the default one (cache_myaccount):", path.Base(cache_location))
	}

}

func TestCanWrite(t *testing.T) {

	p := SAMLCacheProvider{
		Filename: "testdir/cache_file",
	}

	err := p.WriteRaw("test_write_cache")
	if err != nil {
		t.Error("Could not write cache:", err)
	}

	if _, err := os.Stat("testdir/cache_file"); os.IsNotExist(err) {
		t.Error("The cache file was not created:", err)
	}

	os.RemoveAll("testdir")

}

func TestCanRead(t *testing.T) {

	// create a dummy file
	_ = os.WriteFile("example_cache", []byte("testing output"), 0700)

	p := SAMLCacheProvider{
		Filename: "example_cache",
	}

	output, err := p.ReadRaw()
	if err != nil {
		t.Error("Could not read cache:", err)
	}

	if output != "testing output" {
		t.Error("Cache file does not contain the right thing", output)
	}

	os.Remove("example_cache")

}

type AssertionTemplateData struct {
	ExpiryRFC3339Time string
}

func templateAssertion(t time.Time) (string, error) {

	newfile, _ := os.CreateTemp("", "assert_tmpl_")

	data := AssertionTemplateData{
		ExpiryRFC3339Time: t.Format(time.RFC3339),
	}

	content, _ := os.ReadFile("./assertion_validity_template.gotmpl")
	tmpl, err := template.New("assertion_validity_template").Parse(string(content))
	if err != nil {
		defer os.Remove(newfile.Name())
		return "", err
	}

	encodeWriter := b64.NewEncoder(b64.StdEncoding, newfile)
	err = tmpl.Execute(encodeWriter, data)
	if err != nil {
		defer os.Remove(newfile.Name())
		return "", err
	}

	encodeWriter.Close()
	return newfile.Name(), nil
}

func TestIsValid(t *testing.T) {

	expiresIn10Minutes := time.Now().Add(10 * time.Minute)
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	t.Log(tmpFile)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if !p.IsValid() {
		t.Error("Cache file is not valid!")
	}

}

func TestIsValid2(t *testing.T) {

	// a date _really_ close to the expiration should still work
	expiresIn10Minutes := time.Now().Add(2 * time.Second)
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	t.Log(tmpFile)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if !p.IsValid() {
		t.Error("Cache file is not valid!")
	}

}

func TestIsNotValid1(t *testing.T) {

	expiresIn10Minutes := time.Now().Add(-10 * time.Minute)
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if p.IsValid() {
		t.Error("The cache has expired 10 minutes ago and should be invalid!")
	}

}

func TestIsNotValid2(t *testing.T) {

	// verifies that the cache is expired if the data is too close to now.
	expiresIn10Minutes := time.Now()
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if p.IsValid() {
		t.Error("Should be invalid; will expire imminently")
	}

}

func TestIsNotValid3(t *testing.T) {

	// if the cache file doesn't exist, it should be invalid
	p := SAMLCacheProvider{
		Filename: "This_file_does_not_exist",
	}

	if p.IsValid() {
		t.Error("There is no valid cache")
	}

}

func TestIsValidRejectsInvalidAndCorruptCaches(t *testing.T) {
	tests := map[string]string{
		"invalid base64": "not base64",
		"empty file":     "",
		"invalid XML":    b64.StdEncoding.EncodeToString([]byte("<not xml")),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "cache")
			if err := os.WriteFile(filename, []byte(content), SAMLCacheFilePermissions); err != nil {
				t.Fatal(err)
			}
			if (&SAMLCacheProvider{Filename: filename}).IsValid() {
				t.Fatal("invalid cache was accepted")
			}
		})
	}
}

func TestIsValidExpiryJitterBoundary(t *testing.T) {
	tests := []struct {
		name   string
		offset time.Duration
		valid  bool
	}{
		{name: "inside jitter window", offset: 500 * time.Millisecond, valid: false},
		{name: "outside jitter window", offset: 5 * time.Second, valid: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filename, err := templateAssertion(time.Now().Add(tc.offset))
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(filename)
			if got := (&SAMLCacheProvider{Filename: filename}).IsValid(); got != tc.valid {
				t.Fatalf("IsValid() = %v, want %v", got, tc.valid)
			}
		})
	}
}

func TestReadRawAndWriteRawCustomPath(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "nested", "cache")
	provider := &SAMLCacheProvider{Filename: filename}
	if err := provider.WriteRaw("encoded assertion"); err != nil {
		t.Fatalf("WriteRaw() error = %v", err)
	}
	got, err := provider.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw() error = %v", err)
	}
	if got != "encoded assertion" {
		t.Fatalf("ReadRaw() = %q, want %q", got, "encoded assertion")
	}
	if runtime.GOOS == "windows" {
		return
	}

	fileInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("cache permissions = %o, group/other access must be disabled", fileInfo.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(filename))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("cache directory permissions = %o, group/other access must be disabled", dirInfo.Mode().Perm())
	}
}

func TestReadAndWriteErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}

	if _, err := (&SAMLCacheProvider{Filename: filepath.Join(dir, "missing")}).ReadRaw(); err == nil {
		t.Fatal("ReadRaw() unexpectedly succeeded for a missing cache")
	}
	if _, err := (&SAMLCacheProvider{Filename: filepath.Join(dir, "directory")}).ReadRaw(); err == nil {
		t.Fatal("ReadRaw() unexpectedly succeeded for a directory")
	}
	if err := (&SAMLCacheProvider{Filename: filepath.Join(dir, "directory")}).WriteRaw("content"); err == nil {
		t.Fatal("WriteRaw() unexpectedly succeeded when target is a directory")
	}
}

func TestLocateCacheAccountPathTraversal(t *testing.T) {
	for _, account := range []string{"../escape", "../../escape", "nested/account", `nested\\account`, "account\x00name"} {
		if got, err := locateCacheFile(account); err == nil || got != "" {
			t.Fatalf("locateCacheFile(%q) = %q, %v; want ErrInvalidCachePath", account, got, err)
		}
	}
}

func TestLocateCacheResolvesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on some Windows configurations")
	}
	cacheDir := t.TempDir()
	if err := os.MkdirAll(cacheDir, SAMLCacheDirPermissions); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("cache"), SAMLCacheFilePermissions); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cacheDir, "cache_account")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSymlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Fatalf("locateCacheFile() = %q, want symlink target %q", got, target)
	}
}

func TestLocateCacheMissingSymlinkKeepsPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on some Windows configurations")
	}
	cacheDir := t.TempDir()
	if err := os.MkdirAll(cacheDir, SAMLCacheDirPermissions); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cacheDir, "cache_account")
	missing := filepath.Join(t.TempDir(), "missing")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSymlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != link {
		t.Fatalf("locateCacheFile() = %q, want original symlink path %q", got, link)
	}
}

func TestLocateCacheAccountPreservesSafeNames(t *testing.T) {
	got, err := locateCacheFile("my.account-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, filepath.Join(SAMLCacheDir, "cache_my.account-1")) {
		t.Fatalf("locateCacheFile() = %q, want safe account suffix", got)
	}
}
