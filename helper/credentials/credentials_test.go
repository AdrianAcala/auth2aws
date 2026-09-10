package credentials

import (
	"errors"
	"testing"
)

type recordingHelper struct {
	get              func(string) (string, string, error)
	add              func(*Credentials) error
	supports         bool
	getRequests      []string
	addedCredentials []*Credentials
}

func (h *recordingHelper) Add(c *Credentials) error {
	h.addedCredentials = append(h.addedCredentials, c)
	if h.add != nil {
		return h.add(c)
	}
	return nil
}

func (h *recordingHelper) Delete(string) error { return nil }

func (h *recordingHelper) Get(serverURL string) (string, string, error) {
	h.getRequests = append(h.getRequests, serverURL)
	if h.get != nil {
		return h.get(serverURL)
	}
	return "", "", ErrCredentialsNotFound
}

func (h *recordingHelper) SupportsCredentialStorage() bool { return h.supports }

func TestIsErrCredentialsNotFound(t *testing.T) {
	if !IsErrCredentialsNotFound(ErrCredentialsNotFound) {
		t.Fatal("sentinel not-found error was not classified")
	}
	if IsErrCredentialsNotFound(nil) {
		t.Fatal("nil error was classified as not-found")
	}
	if IsErrCredentialsNotFound(errors.New("credentials not found in native keychain")) {
		t.Fatal("an unrelated error was classified as not-found")
	}
}

func TestDefaultHelper(t *testing.T) {
	var helper defaultHelper
	if err := helper.Add(&Credentials{}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := helper.Delete("https://idp.example.com"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, _, err := helper.Get("https://idp.example.com"); !IsErrCredentialsNotFound(err) {
		t.Fatalf("Get() error = %v, want not-found", err)
	}
	if helper.SupportsCredentialStorage() {
		t.Fatal("default helper unexpectedly reports credential storage support")
	}
}

func TestSaveCredentials(t *testing.T) {
	helperErr := errors.New("store unavailable")
	h := &recordingHelper{add: func(*Credentials) error { return helperErr }}
	previous := CurrentHelper
	CurrentHelper = h
	t.Cleanup(func() { CurrentHelper = previous })

	err := SaveCredentials("https://idp.example.com", "alice", "secret")
	if !errors.Is(err, helperErr) {
		t.Fatalf("SaveCredentials() error = %v, want %v", err, helperErr)
	}
	if len(h.addedCredentials) != 1 {
		t.Fatalf("Add() calls = %d, want 1", len(h.addedCredentials))
	}
	if got := *h.addedCredentials[0]; got != (Credentials{ServerURL: "https://idp.example.com", Username: "alice", Secret: "secret"}) {
		t.Fatalf("saved credentials = %+v", got)
	}
}

func TestSupportsStorage(t *testing.T) {
	h := &recordingHelper{supports: true}
	previous := CurrentHelper
	CurrentHelper = h
	t.Cleanup(func() { CurrentHelper = previous })
	if !SupportsStorage() {
		t.Fatal("SupportsStorage() = false, want true")
	}

	h.supports = false
	if SupportsStorage() {
		t.Fatal("SupportsStorage() = true, want false")
	}
}
