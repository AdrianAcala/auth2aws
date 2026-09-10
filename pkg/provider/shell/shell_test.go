package shell

import (
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
)

func TestClientValidate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell provider validation relies on Unix executable bits")
	}
	client, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	executable := t.TempDir() + "/provider"
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("create executable: %v", err)
	}
	nonExecutable := t.TempDir() + "/provider"
	if err := os.WriteFile(nonExecutable, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("create non-executable file: %v", err)
	}

	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "empty URL", want: "Empty URL"},
		{name: "missing executable", url: t.TempDir() + "/missing", want: "URL for shell provider does not point to a valid executable"},
		{name: "non-executable file", url: nonExecutable, want: "URL for shell provider does not point to a valid executable"},
		{name: "executable file", url: executable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.Validate(&creds.LoginDetails{URL: tt.url})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestClientAuthenticate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell provider executes commands through sh")
	}

	client, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Setenv("SHELL_PROVIDER_TEST_VALUE", "environment-value")
	tests := []struct {
		name       string
		command    string
		wantOutput string
		wantExit   int
	}{
		{
			name:       "successful assertion",
			command:    "printf %s assertion-value",
			wantOutput: "assertion-value",
			wantExit:   -1,
		},
		{
			name:       "arguments and environment",
			command:    "printf '%s:%s' \"$SHELL_PROVIDER_TEST_VALUE\" 'argument with spaces'",
			wantOutput: "environment-value:argument with spaces",
			wantExit:   -1,
		},
		{
			name:       "empty output",
			command:    "true",
			wantOutput: "",
			wantExit:   -1,
		},
		{
			name:       "malformed assertion is returned unchanged",
			command:    "printf %s not-base64",
			wantOutput: "not-base64",
			wantExit:   -1,
		},
		{
			name:       "nonzero exit preserves stdout",
			command:    "printf %s partial; exit 7",
			wantOutput: "partial",
			wantExit:   7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.Authenticate(&creds.LoginDetails{URL: tt.command})
			if got != tt.wantOutput {
				t.Errorf("Authenticate() output = %q, want %q", got, tt.wantOutput)
			}
			if tt.wantExit < 0 {
				if err != nil {
					t.Errorf("Authenticate() error = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Authenticate() error = nil, want exit status %d", tt.wantExit)
			}
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("Authenticate() error type = %T, want *exec.ExitError", err)
			}
			if exitErr.ExitCode() != tt.wantExit {
				t.Errorf("Authenticate() exit status = %d, want %d", exitErr.ExitCode(), tt.wantExit)
			}
		})
	}
}
