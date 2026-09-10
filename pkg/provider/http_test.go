package provider

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/stretchr/testify/require"
)

func TestClientDoGetOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	rt := NewDefaultTransport(false)
	opts := &HTTPClientOptions{IsWithRetries: false}
	hc, err := NewHTTPClient(rt, opts)
	require.Nil(t, err)

	// hc := &HTTPClient{Client: http.Client{}}

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.Nil(t, err)

	res, err := hc.Do(req)
	require.Nil(t, err)

	require.Equal(t, 200, res.StatusCode)
}

func TestClientDisableRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(302)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	rt := NewDefaultTransport(false)

	opts := &HTTPClientOptions{IsWithRetries: false}
	hc, err := NewHTTPClient(rt, opts)
	require.Nil(t, err)

	hc.DisableFollowRedirect()

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.Nil(t, err)

	res, err := hc.Do(req)
	require.Nil(t, err)
	require.Equal(t, 302, res.StatusCode)
}

func TestClientRedirectToggles(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("final"))
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirect.Close()

	hc, err := NewHTTPClient(NewDefaultTransport(false), &HTTPClientOptions{})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, redirect.URL, nil)
	require.NoError(t, err)

	hc.DisableFollowRedirect()
	res, err := hc.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, res.StatusCode)
	require.NoError(t, res.Body.Close())

	hc.EnableFollowRedirect()
	redirectReq, err := http.NewRequest(http.MethodGet, redirect.URL, nil)
	require.NoError(t, err)
	res, err = hc.Do(redirectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	require.Equal(t, "final", string(body))
}

func TestClientDoResponseCheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	opts := &HTTPClientOptions{IsWithRetries: false}
	hc := &HTTPClient{Client: http.Client{}, Options: opts}

	hc.CheckResponseStatus = SuccessOrRedirectResponseValidator

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.Nil(t, err)

	res, err := hc.Do(req)
	require.Error(t, err)
	require.Equal(t, 400, res.StatusCode)
	require.NoError(t, res.Body.Close())
}

func TestResponseValidators(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/login", nil)
	for _, tc := range []struct {
		name       string
		statusCode int
		valid      bool
	}{
		{name: "informational", statusCode: 199},
		{name: "success", statusCode: 200, valid: true},
		{name: "success upper bound", statusCode: 399, valid: true},
		{name: "client error", statusCode: 400},
		{name: "unauthorized", statusCode: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &http.Response{StatusCode: tc.statusCode, Status: http.StatusText(tc.statusCode)}
			err := SuccessOrRedirectResponseValidator(req, res)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, "request for url: https://example.test/login failed status: "+res.Status)
			}
		})
	}

	for _, tc := range []struct {
		name       string
		statusCode int
		valid      bool
	}{
		{name: "success", statusCode: 200, valid: true},
		{name: "redirect", statusCode: 302, valid: true},
		{name: "unauthorized", statusCode: 401, valid: true},
		{name: "forbidden", statusCode: 403},
	} {
		t.Run("unauthorized/"+tc.name, func(t *testing.T) {
			res := &http.Response{StatusCode: tc.statusCode, Status: http.StatusText(tc.statusCode)}
			err := SuccessOrRedirectOrUnauthorizedResponseValidator(req, res)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestBuildHTTPClientOpts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		account  cfg.IDPAccount
		retries  bool
		attempts uint
		delay    time.Duration
	}{
		{name: "configured", account: cfg.IDPAccount{HttpAttemptsCount: "3", HttpRetryDelay: "2"}, retries: true, attempts: 3, delay: 2 * time.Second},
		{name: "invalid attempts", account: cfg.IDPAccount{HttpAttemptsCount: "nope", HttpRetryDelay: "4"}, retries: false, attempts: DefaultAttemptsCount, delay: 4 * time.Second},
		{name: "invalid delay", account: cfg.IDPAccount{HttpAttemptsCount: "2", HttpRetryDelay: "nope"}, retries: true, attempts: 2, delay: DefaultRetryDelay},
		{name: "empty", account: cfg.IDPAccount{}, retries: false, attempts: DefaultAttemptsCount, delay: DefaultRetryDelay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := BuildHttpClientOpts(&tc.account)
			require.Equal(t, tc.retries, opts.IsWithRetries)
			require.Equal(t, tc.attempts, opts.AttemptsCount)
			require.Equal(t, tc.delay, opts.RetryDelay)
		})
	}
}

func TestClientSetsUserAgentAndClosesRequestBody(t *testing.T) {
	var requestBodyClosed atomic.Bool
	var userAgentSet atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil && string(body) == "payload" {
			userAgentSet.Store(strings.Contains(r.Header.Get("User-Agent"), "saml2aws/1.0"))
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	hc, err := NewHTTPClient(NewDefaultTransport(false), &HTTPClientOptions{})
	require.NoError(t, err)
	hc.Client.Timeout = time.Second
	req, err := http.NewRequest(http.MethodPost, server.URL, &trackingReadCloser{Reader: strings.NewReader("payload"), closed: &requestBodyClosed})
	require.NoError(t, err)
	res, err := hc.Do(req)
	require.NoError(t, err)
	require.True(t, userAgentSet.Load())
	require.True(t, requestBodyClosed.Load())
	require.NoError(t, res.Body.Close())
}

func TestClientReturnsTransportError(t *testing.T) {
	transportErr := errors.New("transport failed")
	hc, err := NewHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	}), &HTTPClientOptions{})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	require.NoError(t, err)
	res, err := hc.Do(req)
	require.ErrorIs(t, err, transportErr)
	require.Nil(t, res)
}

func TestClientRetriesTransportErrors(t *testing.T) {
	var attempts atomic.Int32
	transportErr := errors.New("temporary transport failure")
	hc, err := NewHTTPClient(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if attempts.Add(1) < 3 {
			return nil, transportErr
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
	}), &HTTPClientOptions{IsWithRetries: true, AttemptsCount: 3, RetryDelay: 0})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	require.NoError(t, err)
	res, err := hc.Do(req)
	require.NoError(t, err)
	require.Equal(t, int32(3), attempts.Load())
	require.NoError(t, res.Body.Close())
}

func TestClientResponseBodyReadError(t *testing.T) {
	readErr := errors.New("response body failed")
	hc, err := NewHTTPClient(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: &errorReadCloser{err: readErr}, Request: req}, nil
	}), &HTTPClientOptions{})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	require.NoError(t, err)
	res, err := hc.Do(req)
	require.NoError(t, err)
	_, err = io.ReadAll(res.Body)
	require.ErrorIs(t, err, readErr)
	require.NoError(t, res.Body.Close())
}

func TestClientTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	hc, err := NewHTTPClient(NewDefaultTransport(false), &HTTPClientOptions{})
	require.NoError(t, err)
	hc.Client.Timeout = 20 * time.Millisecond
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	_, err = hc.Do(req)
	require.Error(t, err)
	var timeoutErr net.Error
	require.ErrorAs(t, err, &timeoutErr)
	require.True(t, timeoutErr.Timeout())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelReq, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	_, err = hc.Do(cancelReq)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestNewDefaultTransportTLSVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))
	defer server.Close()

	withoutSkip, err := NewHTTPClient(NewDefaultTransport(false), &HTTPClientOptions{})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	_, err = withoutSkip.Do(req)
	require.Error(t, err)

	withSkip, err := NewHTTPClient(NewDefaultTransport(true), &HTTPClientOptions{})
	require.NoError(t, err)
	req, err = http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	res, err := withSkip.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NoError(t, res.Body.Close())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type trackingReadCloser struct {
	*strings.Reader
	closed *atomic.Bool
}

func (r *trackingReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

type errorReadCloser struct {
	err error
}

func (r *errorReadCloser) Read([]byte) (int, error) { return 0, r.err }

func (r *errorReadCloser) Close() error { return nil }
