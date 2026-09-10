package commands

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AdrianAcala/saml2aws/v2/pkg/awsconfig"
	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/flags"
)

type consoleRoundTripper func(*http.Request) (*http.Response, error)

func (f consoleRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func consoleHTTPClient(roundTrip consoleRoundTripper) *http.Client {
	return &http.Client{Transport: roundTrip}
}

func consoleResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func testConsoleCreds() *awsconfig.AWSCredentials {
	return &awsconfig.AWSCredentials{
		AWSAccessKey:    "access key",
		AWSSecretKey:    "secret/key",
		AWSSessionToken: "session token",
	}
}

func TestFederatedLoginLinkAndEncodedRequest(t *testing.T) {
	creds := testConsoleCreds()
	var gotQuery url.Values
	var output strings.Builder
	client := consoleHTTPClient(func(req *http.Request) (*http.Response, error) {
		gotQuery = req.URL.Query()
		return consoleResponse(http.StatusOK, `{"SigninToken":"token with spaces/+"}`), nil
	})

	err := federatedLoginWith(creds, &flags.ConsoleFlags{Link: true}, client, func(string) error {
		t.Fatal("opener should not be called for --link")
		return nil
	}, &output)
	if err != nil {
		t.Fatalf("federatedLoginWith returned error: %v", err)
	}
	if got, want := gotQuery.Get("Action"), "getSigninToken"; got != want {
		t.Errorf("Action = %q, want %q", got, want)
	}
	if got, want := gotQuery.Get("Session"), `{"sessionId":"access key","sessionKey":"secret/key","sessionToken":"session token"}`; got != want {
		t.Errorf("Session = %q, want %q", got, want)
	}
	if got, want := output.String(), "https://signin.aws.amazon.com/federation?Action=login&Issuer=saml2aws&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F&SigninToken=token+with+spaces%2F%2B\n"; got != want {
		t.Errorf("link = %q, want %q", got, want)
	}
}

func TestFederatedLoginOpensURL(t *testing.T) {
	var opened string
	err := federatedLoginWith(testConsoleCreds(), &flags.ConsoleFlags{}, consoleHTTPClient(func(*http.Request) (*http.Response, error) {
		return consoleResponse(http.StatusOK, `{"SigninToken":"abc"}`), nil
	}), func(url string) error {
		opened = url
		return nil
	}, io.Discard)
	if err != nil {
		t.Fatalf("federatedLoginWith returned error: %v", err)
	}
	if !strings.Contains(opened, "SigninToken=abc") {
		t.Errorf("opened URL = %q, want SigninToken=abc", opened)
	}
}

func TestFederatedLoginErrors(t *testing.T) {
	tests := []struct {
		name   string
		client *http.Client
		want   string
	}{
		{"non-200", consoleHTTPClient(func(*http.Request) (*http.Response, error) {
			return consoleResponse(http.StatusBadRequest, "bad"), nil
		}), "Call to getSigninToken failed with Bad Request"},
		{"bad JSON", consoleHTTPClient(func(*http.Request) (*http.Response, error) {
			return consoleResponse(http.StatusOK, "{"), nil
		}), "unexpected end of JSON input"},
		{"missing token", consoleHTTPClient(func(*http.Request) (*http.Response, error) {
			return consoleResponse(http.StatusOK, `{}`), nil
		}), "response did not contain SigninToken"},
		{"transport failure", consoleHTTPClient(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		}), "network down"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := federatedLoginWith(testConsoleCreds(), &flags.ConsoleFlags{Link: true}, tt.client, func(string) error { return nil }, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

type consoleLoader struct {
	creds *awsconfig.AWSCredentials
	err   error
	loads int
}

func (l *consoleLoader) Load() (*awsconfig.AWSCredentials, error) {
	l.loads++
	return l.creds, l.err
}

func consoleFlags(force bool) *flags.ConsoleFlags {
	return &flags.ConsoleFlags{LoginExecFlags: &flags.LoginExecFlags{Force: force, CommonFlags: &flags.CommonFlags{}}}
}

func TestLoadOrLoginValidCredentials(t *testing.T) {
	creds := testConsoleCreds()
	loader := &consoleLoader{creds: &awsconfig.AWSCredentials{Expires: time.Now().Add(time.Hour), AWSAccessKey: creds.AWSAccessKey}}
	checks := 0
	got, err := loadOrLoginWith(&cfg.IDPAccount{Profile: "profile"}, loader, consoleFlags(false), func(*flags.LoginExecFlags) error { t.Fatal("login should not run"); return nil }, func(profile string) (bool, error) {
		checks++
		if profile != "profile" {
			t.Errorf("profile = %q", profile)
		}
		return true, nil
	}, time.Now)
	if err != nil || got != loader.creds || checks != 1 {
		t.Fatalf("got creds=%v err=%v checks=%d", got, err, checks)
	}
}

func TestLoadOrLoginExpiredMissingAndForced(t *testing.T) {
	tests := []struct {
		name  string
		flags *flags.ConsoleFlags
		load  *consoleLoader
	}{
		{"expired", consoleFlags(false), &consoleLoader{creds: &awsconfig.AWSCredentials{Expires: time.Now().Add(-time.Hour)}}},
		{"missing", consoleFlags(false), &consoleLoader{err: awsconfig.ErrCredentialsNotFound}},
		{"force", consoleFlags(true), &consoleLoader{creds: testConsoleCreds()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refreshed := testConsoleCreds()
			loggedIn := false
			got, err := loadOrLoginWith(&cfg.IDPAccount{Profile: "profile"}, tt.load, tt.flags, func(*flags.LoginExecFlags) error {
				loggedIn = true
				tt.load.creds, tt.load.err = refreshed, nil
				return nil
			}, func(string) (bool, error) { t.Fatal("token check should not run"); return false, nil }, time.Now)
			if err != nil || got != refreshed || !loggedIn {
				t.Fatalf("got creds=%v err=%v loggedIn=%v", got, err, loggedIn)
			}
		})
	}
}
