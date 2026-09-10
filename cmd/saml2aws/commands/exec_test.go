package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdrianAcala/saml2aws/v2/pkg/flags"
)

func TestExecRequiresCommand(t *testing.T) {
	if err := Exec(nil, nil); err == nil || err.Error() != "Command to execute required" {
		t.Fatalf("Exec() error = %v, want missing-command error", err)
	}
}

func TestExecCredentialFailures(t *testing.T) {
	tests := []struct {
		name        string
		credentials string
		want        string
	}{
		{name: "missing", credentials: "[other]\naws_access_key_id=access\n", want: "error loading credentials: aws credentials not found"},
		{name: "malformed", credentials: "[saml\n", want: "error loading credentials"},
		{name: "expired", credentials: "[saml]\naws_access_key_id=access\naws_secret_access_key=secret\nx_security_token_expires=2000-01-01T00:00:00Z\n", want: "error aws credentials have expired"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "saml2aws.ini")
			credentialsPath := filepath.Join(dir, "credentials")
			if err := os.WriteFile(configPath, []byte("[saml]\nurl=https://idp.example\nprovider=Browser\nprofile=saml\ncredentials_file="+credentialsPath+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if tt.credentials != "" {
				if err := os.WriteFile(credentialsPath, []byte(tt.credentials), 0600); err != nil {
					t.Fatal(err)
				}
			}

			err := Exec(&flags.LoginExecFlags{CommonFlags: &flags.CommonFlags{
				ConfigFile: configPath,
				IdpAccount: "saml",
			}}, []string{"echo", "ok"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Exec() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestExecBuildsChildCommandAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "saml2aws.ini")
	credentialsPath := filepath.Join(dir, "credentials")
	if err := os.WriteFile(configPath, []byte("[saml]\nurl=https://idp.example\nprovider=Browser\nprofile=saml\ncredentials_file="+credentialsPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialsPath, []byte("[saml]\naws_access_key_id=access\naws_secret_access_key=secret\naws_session_token=session\nx_security_token_expires="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	oldCheck, oldExec := checkTokenFunc, execShellCmdFunc
	t.Cleanup(func() { checkTokenFunc, execShellCmdFunc = oldCheck, oldExec })
	checkTokenFunc = func(string) (bool, error) { return true, nil }
	var gotCmd []string
	var gotEnv []string
	execShellCmdFunc = func(cmd []string, env []string) error {
		gotCmd = append([]string(nil), cmd...)
		gotEnv = append([]string(nil), env...)
		return nil
	}

	err := Exec(&flags.LoginExecFlags{CommonFlags: &flags.CommonFlags{
		ConfigFile: configPath,
		IdpAccount: "saml",
	}}, []string{"sh", "-c", "printf '%s' \"$AWS_ACCESS_KEY_ID\""})
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if want := []string{"sh", "-c", "printf '%s' \"$AWS_ACCESS_KEY_ID\""}; !equalStrings(gotCmd, want) {
		t.Fatalf("child command = %#v, want %#v", gotCmd, want)
	}
	for _, want := range []string{"AWS_ACCESS_KEY_ID=access", "AWS_SECRET_ACCESS_KEY=secret", "AWS_SESSION_TOKEN=session", "AWS_PROFILE=saml", "AWS_DEFAULT_PROFILE=saml"} {
		if !containsString(gotEnv, want) {
			t.Errorf("child environment does not contain %q: %#v", want, gotEnv)
		}
	}
}

func TestCheckTokenErrorOutcomes(t *testing.T) {
	for _, code := range []string{"ExpiredToken", "NoCredentialProviders"} {
		ok, err := checkTokenError(&testAWSError{code: code})
		if ok || err != nil {
			t.Errorf("checkTokenError(%q) = (%v, %v), want (false, nil)", code, ok, err)
		}
	}
	ok, err := checkTokenError(errors.New("other"))
	if ok || err == nil {
		t.Fatalf("checkTokenError(other) = (%v, %v), want (false, error)", ok, err)
	}
}

type testAWSError struct{ code string }

func (e *testAWSError) Error() string   { return e.code }
func (e *testAWSError) Code() string    { return e.code }
func (e *testAWSError) Message() string { return e.code }
func (e *testAWSError) OrigErr() error  { return nil }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
