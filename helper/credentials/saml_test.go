package credentials

import (
	"errors"
	"reflect"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
)

func TestLookupCredentials(t *testing.T) {
	baseURL := "idp.example.com"
	h := &recordingHelper{get: func(serverURL string) (string, string, error) {
		switch serverURL {
		case baseURL:
			return "alice", "password", nil
		case baseURL + "/sessionCookie":
			return "", "sid-cookie", nil
		case baseURL + "/auth/oauth2/v2/token":
			return "client-id", "client-secret", nil
		default:
			return "", "", ErrCredentialsNotFound
		}
	}}
	previous := CurrentHelper
	CurrentHelper = h
	t.Cleanup(func() { CurrentHelper = previous })

	t.Run("generic", func(t *testing.T) {
		details := &creds.LoginDetails{URL: baseURL}
		if err := LookupCredentials(details, "Google"); err != nil {
			t.Fatalf("LookupCredentials() error = %v", err)
		}
		if details.Username != "alice" || details.Password != "password" {
			t.Fatalf("details = %+v", details)
		}
		if details.OktaSessionCookie != "" || details.ClientID != "" || details.ClientSecret != "" {
			t.Fatalf("unexpected provider-specific details = %+v", details)
		}
		if !reflect.DeepEqual(h.getRequests, []string{baseURL}) {
			t.Fatalf("Get() requests = %v", h.getRequests)
		}
	})

	h.getRequests = nil
	t.Run("Okta", func(t *testing.T) {
		details := &creds.LoginDetails{URL: baseURL}
		if err := LookupCredentials(details, "Okta"); err != nil {
			t.Fatalf("LookupCredentials() error = %v", err)
		}
		if details.Username != "alice" || details.Password != "password" || details.OktaSessionCookie != "sid-cookie" {
			t.Fatalf("details = %+v", details)
		}
		if !reflect.DeepEqual(h.getRequests, []string{baseURL, baseURL + "/sessionCookie"}) {
			t.Fatalf("Get() requests = %v", h.getRequests)
		}
	})

	h.getRequests = nil
	t.Run("OneLogin", func(t *testing.T) {
		details := &creds.LoginDetails{URL: baseURL}
		if err := LookupCredentials(details, "OneLogin"); err != nil {
			t.Fatalf("LookupCredentials() error = %v", err)
		}
		if details.Username != "alice" || details.Password != "password" || details.ClientID != "client-id" || details.ClientSecret != "client-secret" {
			t.Fatalf("details = %+v", details)
		}
		if !reflect.DeepEqual(h.getRequests, []string{baseURL, baseURL + "/auth/oauth2/v2/token"}) {
			t.Fatalf("Get() requests = %v", h.getRequests)
		}
	})
}

func TestLookupCredentialsReturnsPrimaryHelperError(t *testing.T) {
	helperErr := errors.New("keychain is locked")
	h := &recordingHelper{get: func(string) (string, string, error) { return "", "", helperErr }}
	previous := CurrentHelper
	CurrentHelper = h
	t.Cleanup(func() { CurrentHelper = previous })

	details := &creds.LoginDetails{URL: "idp.example.com", Username: "existing", Password: "existing"}
	if err := LookupCredentials(details, "Okta"); !errors.Is(err, helperErr) {
		t.Fatalf("LookupCredentials() error = %v, want %v", err, helperErr)
	}
	if !reflect.DeepEqual(h.getRequests, []string{"idp.example.com"}) {
		t.Fatalf("Get() requests = %v", h.getRequests)
	}
	if details.Username != "existing" || details.Password != "existing" {
		t.Fatalf("primary details changed after helper error: %+v", details)
	}
}

func TestLookupCredentialsIgnoresMissingOktaSessionCookie(t *testing.T) {
	h := &recordingHelper{get: func(serverURL string) (string, string, error) {
		if serverURL == "idp.example.com" {
			return "alice", "password", nil
		}
		return "", "", ErrCredentialsNotFound
	}}
	previous := CurrentHelper
	CurrentHelper = h
	t.Cleanup(func() { CurrentHelper = previous })

	details := &creds.LoginDetails{URL: "idp.example.com"}
	if err := LookupCredentials(details, "Okta"); err != nil {
		t.Fatalf("LookupCredentials() error = %v, want nil", err)
	}
	if details.Username != "alice" || details.Password != "password" || details.OktaSessionCookie != "" {
		t.Fatalf("details = %+v", details)
	}
}

func TestLookupCredentialsReturnsOneLoginHelperError(t *testing.T) {
	helperErr := errors.New("token credentials unavailable")
	h := &recordingHelper{get: func(serverURL string) (string, string, error) {
		if serverURL == "idp.example.com" {
			return "alice", "password", nil
		}
		return "", "", helperErr
	}}
	previous := CurrentHelper
	CurrentHelper = h
	t.Cleanup(func() { CurrentHelper = previous })

	details := &creds.LoginDetails{URL: "idp.example.com"}
	if err := LookupCredentials(details, "OneLogin"); !errors.Is(err, helperErr) {
		t.Fatalf("LookupCredentials() error = %v, want %v", err, helperErr)
	}
	if details.Username != "alice" || details.Password != "password" {
		t.Fatalf("primary details = %+v", details)
	}
}
