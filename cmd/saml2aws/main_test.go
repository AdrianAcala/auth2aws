package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var cliBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "saml2aws-cli-contract-")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	binaryName := "saml2aws"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	cliBinary = filepath.Join(dir, binaryName)
	build := exec.Command("go", "build", "-o", cliBinary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		_, _ = os.Stderr.Write(output)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func runCLI(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(cliBinary, args...)
	cmd.Env = os.Environ()
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	status := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			status = exitErr.ExitCode()
		} else {
			t.Fatalf("run %q: %v", args, err)
		}
	}
	return status, stdout.String(), stderr.String()
}

func TestCLIHelpAndVersion(t *testing.T) {
	status, stdout, stderr := runCLI(t, nil, "--help")
	if status != 0 {
		t.Fatalf("help status = %d, stderr = %q", status, stderr)
	}
	if !strings.Contains(stdout, "usage: saml2aws") || !strings.Contains(stdout, "script") {
		t.Fatalf("help output does not describe the CLI: %q", stdout)
	}

	status, stdout, stderr = runCLI(t, nil, "--version")
	if status != 0 {
		t.Fatalf("version status = %d, stderr = %q", status, stderr)
	}
	if strings.TrimSpace(stdout) != Version {
		t.Fatalf("version output = %q, want %q", stdout, Version)
	}
}

func TestCLIRejectsInvalidCommandAndFlag(t *testing.T) {
	status, _, stderr := runCLI(t, nil, "not-a-command")
	if status != 1 || !strings.Contains(stderr, `expected command but got "not-a-command"`) {
		t.Fatalf("invalid command: status=%d stderr=%q", status, stderr)
	}

	status, _, stderr = runCLI(t, nil, "--not-a-flag")
	if status != 1 || !strings.Contains(stderr, "unknown long flag '--not-a-flag'") {
		t.Fatalf("invalid flag: status=%d stderr=%q", status, stderr)
	}
}

func TestCLIDeprecatedProviderFails(t *testing.T) {
	status, stdout, stderr := runCLI(t, nil, "--provider", "Okta", "script")
	if status != 1 {
		t.Fatalf("deprecated provider status = %d, stderr = %q", status, stderr)
	}
	if output := stdout + stderr; !strings.Contains(output, "--provider flag has been replaced") {
		t.Fatalf("deprecated provider message missing: %q", output)
	}
}

func TestCLIQuietAndVerboseLogging(t *testing.T) {
	quietDir := t.TempDir()
	quietFile := filepath.Join(quietDir, "quiet-credentials")
	quietConfig := filepath.Join(quietDir, "config")
	writeScriptConfig(t, quietConfig)
	writeScriptCredentials(t, quietFile)
	status, stdout, stderr := runCLI(t, map[string]string{"AWS_SHARED_CREDENTIALS_FILE": quietFile}, "--quiet", "--config", quietConfig, "script")
	if status != 0 || !strings.Contains(stdout, "AWS_ACCESS_KEY_ID=access") || stderr != "" {
		t.Fatalf("quiet script: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}

	verboseDir := t.TempDir()
	verboseFile := filepath.Join(verboseDir, "verbose-credentials")
	verboseConfig := filepath.Join(verboseDir, "config")
	writeScriptConfig(t, verboseConfig)
	writeScriptCredentials(t, verboseFile)
	status, stdout, stderr = runCLI(t, map[string]string{"AWS_SHARED_CREDENTIALS_FILE": verboseFile}, "--verbose", "--config", verboseConfig, "script")
	if output := stdout + stderr; status != 0 || !strings.Contains(output, "command=script") {
		t.Fatalf("verbose script: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}

func writeScriptConfig(t *testing.T, filename string) {
	t.Helper()
	if err := os.WriteFile(filename, []byte("[default]\nurl = https://id.example.test\nprovider = Browser\nprofile = saml\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeScriptCredentials(t *testing.T, filename string) {
	t.Helper()
	if err := os.WriteFile(filename, []byte("[saml]\naws_access_key_id = access\naws_secret_access_key = secret\naws_session_token = session\naws_security_token = security\nx_security_token_expires = 2099-01-01T00:00:00Z\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCLIScriptOutputAndExitStatus(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config")
	credentialsFile := filepath.Join(dir, "credentials")
	writeScriptConfig(t, configFile)
	writeScriptCredentials(t, credentialsFile)

	status, stdout, stderr := runCLI(t, map[string]string{"AWS_SHARED_CREDENTIALS_FILE": credentialsFile}, "--config", configFile, "script", "--profile", "saml", "--shell", "env")
	if status != 0 {
		t.Fatalf("script status = %d, stderr = %q", status, stderr)
	}
	for _, line := range []string{
		"AWS_ACCESS_KEY_ID=access",
		"AWS_SECRET_ACCESS_KEY=secret",
		"AWS_SESSION_TOKEN=session",
		"AWS_SECURITY_TOKEN=security",
		"SAML2AWS_PROFILE=saml",
	} {
		if !strings.Contains(stdout, line) {
			t.Fatalf("script output missing %q: %q", line, stdout)
		}
	}
}

func TestCLICredentialProcessPrintsOnlyJSON(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config")
	credentialsFile := filepath.Join(dir, "credentials")
	writeScriptConfig(t, configFile)
	writeScriptCredentials(t, credentialsFile)

	status, stdout, stderr := runCLI(t, map[string]string{"AWS_SHARED_CREDENTIALS_FILE": credentialsFile}, "--config", configFile, "login", "--profile", "saml", "--credential-process")
	if status != 0 {
		t.Fatalf("credential process status = %d, stderr = %q", status, stderr)
	}
	var document struct {
		Version         int
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string
		SessionToken    string
		Expiration      string
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("credential process stdout is not a single JSON document: %q: %v", stdout, err)
	}
	if document.Version != 1 || document.AccessKeyID != "access" || document.SecretAccessKey != "secret" || document.SessionToken != "session" || document.Expiration != "2099-01-01T00:00:00Z" {
		t.Fatalf("unexpected credential process document: %#v", document)
	}
	if strings.Contains(stdout, "Logged in") || strings.Contains(stdout, "Using IdP") {
		t.Fatalf("credential process stdout contains diagnostic text: %q", stdout)
	}
}
