//go:build !windows
// +build !windows

package shell

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecShellCmd(t *testing.T) {

	err := ExecShellCmd([]string{"echo", "$TESTTEST"}, []string{"TESTTEST=123"})

	assert.Nil(t, err)

}

func TestPrepCmd(t *testing.T) {

	cmd := prepCmd([]string{"echo", "some$TESTTEST", "one   two"}, []string{"TESTTEST=123"})

	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	assert.Nil(t, err)

	assert.Equal(t, "some$TESTTEST one   two\n", out.String(), "no eval, spaces preserved")
}

func TestPrepCmdShell(t *testing.T) {
	cmd := prepCmd([]string{"sh", "-c", "echo some$TESTTEST one   two"}, []string{"TESTTEST=123"})

	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	assert.Nil(t, err)

	assert.Equal(t, "some123 one two\n", out.String(), "var evaled, spaces squashed")

}

func TestPrepCmdPreservesArgumentsAndAddsEnvironment(t *testing.T) {
	cmd := prepCmd([]string{"sh", "-c", "printf '%s|%s' \"$1\" \"$TESTTEST\"", "shell", "one two"}, []string{"TESTTEST=123"})
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "one two|123"; got != want {
		t.Fatalf("command output = %q, want %q", got, want)
	}
}

func TestExecShellCmdReturnsChildExitError(t *testing.T) {
	err := ExecShellCmd([]string{"sh", "-c", "exit 7"}, nil)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("ExecShellCmd() error = %v, want *exec.ExitError", err)
	}
	if got, want := exitErr.ExitCode(), 7; got != want {
		t.Fatalf("child exit code = %d, want %d", got, want)
	}
}
