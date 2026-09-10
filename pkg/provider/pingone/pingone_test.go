package pingone

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
	"github.com/AdrianAcala/saml2aws/v2/pkg/prompter"
	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

var docTests = []struct {
	fn       func(*goquery.Document) bool
	file     string
	expected bool
}{
	{docIsFormSelectDevice, "example/selectdevice.html", true},
}

func TestMakeAbsoluteURL(t *testing.T) {
	url1, _ := makeAbsoluteURL("/pingid/ppm/devices", "https://authentication.pingone.com")
	url2, _ := makeAbsoluteURL("/pingid/ppm/devices", "https://authentication.pingone.com/")
	url3, _ := makeAbsoluteURL("https://authentication.pingone.com/pingid/ppm/devices", "https://authentication.pingone.com/")

	require.Equal(t, url1, "https://authentication.pingone.com/pingid/ppm/devices")
	require.Equal(t, url2, "https://authentication.pingone.com/pingid/ppm/devices")
	require.Equal(t, url3, "https://authentication.pingone.com/pingid/ppm/devices")
}

func TestDocTypes(t *testing.T) {
	for _, tt := range docTests {
		data, err := os.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		if tt.fn(doc) != tt.expected {
			t.Errorf("expect doc check of %v to be %v", tt.file, tt.expected)
		}
	}
}

func TestHandleFormDeviceProfiling(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(`
		<form action="/wrong"><input name="decoy" value="ignore"></form>
		<form id="device-profile-form" action="../profile/collect" method="post">
			<input type="hidden" name="devicePayload" value="payload-value">
			<input type="hidden" name="csrf" value="csrf-value">
		</form>
	`))
	require.NoError(t, err)
	require.True(t, docIsFormDeviceProfiling(doc))

	requestURL, err := url.Parse("https://authentication.example.com:8443/pingid/start")
	require.NoError(t, err)
	response := &http.Response{Request: &http.Request{URL: requestURL}}

	client := &Client{}
	_, request, err := client.handleFormDeviceProfiling(context.Background(), doc, response)
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, request.Method)
	require.Equal(t, "https://authentication.example.com:8443/profile/collect", request.URL.String())
	require.NoError(t, request.ParseForm())
	require.Equal(t, "payload-value", request.Form.Get("devicePayload"))
	require.Equal(t, "csrf-value", request.Form.Get("csrf"))
	require.Empty(t, request.Form.Get("decoy"))
}

func TestDocIsFormDeviceProfilingRequiresAction(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(`<form id="device-profile-form"></form>`))
	require.NoError(t, err)
	require.False(t, docIsFormDeviceProfiling(doc))
}

var deviceNameTests = []struct {
	file     string
	expected map[string]string
}{
	{"example/selectdevice.html", map[string]string{"iPhone": "3270134077889335000", "Android": "3964291169487703000"}},
	{"example/selectdevicebutton.html", map[string]string{"iPhone": "3270134077889335000", "Android": "3964291169487703000"}},
}

func TestFindDeviceMap(t *testing.T) {
	for _, tt := range deviceNameTests {
		data, err := os.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		deviceMap := findDeviceMap(doc)

		eq := reflect.DeepEqual(deviceMap, tt.expected)

		if eq != true {
			t.Errorf("expected deviceMap %v to be %v", deviceMap, tt.expected)
		}
	}
}

type pingOneTestPrompter struct {
	token  string
	device string
}

func (p pingOneTestPrompter) RequestSecurityCode(string) string { return p.token }
func (p pingOneTestPrompter) ChooseWithDefault(string, string, []string) (string, error) {
	return p.device, nil
}
func (p pingOneTestPrompter) Choose(_ string, options []string) int {
	for i, option := range options {
		if option == p.device {
			return i
		}
	}
	return -1
}
func (p pingOneTestPrompter) StringRequired(string) string { return p.token }
func (p pingOneTestPrompter) String(string, string) string { return p.token }
func (p pingOneTestPrompter) Password(string) string       { return p.token }
func (p pingOneTestPrompter) Display(string)               {}

func newPingOneTestClient(t *testing.T, handler http.Handler, targetURL string) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	account := &cfg.IDPAccount{TargetURL: targetURL, HttpAttemptsCount: "invalid"}
	client, err := New(account)
	require.NoError(t, err)
	return client, ts
}

func TestAuthenticateFullFlowWithDeviceAndOTP(t *testing.T) {
	const assertion = "pingone-saml-assertion"
	encodedAssertion := base64.StdEncoding.EncodeToString([]byte(assertion))
	var requests []string
	var loginForm url.Values
	var webAuthnForm url.Values
	var deviceForm url.Values
	var otpForm url.Values
	var targetURL string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		base := "http://" + r.Host
		switch len(requests) {
		case 1:
			require.Equal(t, http.MethodGet, r.Method)
			targetURL = "http://" + r.Host + "/saml"
			_, _ = w.Write([]byte(`<form action="` + base + `/login" method="post"><input name="pf.username"><input name="pf.pass"></form>`))
		case 2:
			require.NoError(t, r.ParseForm())
			loginForm = r.Form
			_, _ = w.Write([]byte(`<form action="` + base + `/webauthn" method="post"><input name="isWebAuthnSupportedByBrowser" value="true"></form>`))
		case 3:
			require.NoError(t, r.ParseForm())
			webAuthnForm = r.Form
			_, _ = w.Write([]byte(`<form name="device-form" action="` + base + `/device" method="post"><ul class="device-list"><li data-id="phone-id"><a><div class="device-name">Phone</div></a></li><li data-id="tablet-id"><a><div class="device-name">Tablet</div></a></li></ul></form>`))
		case 4:
			require.NoError(t, r.ParseForm())
			deviceForm = r.Form
			_, _ = w.Write([]byte(`<form id="otp-form" action="` + base + `/otp" method="post"><input name="otp"></form>`))
		case 5:
			require.NoError(t, r.ParseForm())
			otpForm = r.Form
			_, _ = w.Write([]byte(`<form action="` + targetURL + `" method="post"><input name="SAMLResponse" value="` + encodedAssertion + `"></form>`))
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	})

	// The target action is discovered from the first request's URL, so construct the
	// client after the server exists and update its account target for the final page.
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	account := &cfg.IDPAccount{TargetURL: ts.URL + "/saml", HttpAttemptsCount: "invalid"}
	client, err := New(account)
	require.NoError(t, err)
	originalPrompter := prompter.ActivePrompter
	prompter.SetPrompter(pingOneTestPrompter{token: "123456", device: "Tablet"})
	t.Cleanup(func() { prompter.SetPrompter(originalPrompter) })

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL + "/start", Username: "alice", Password: "secret"})
	require.NoError(t, err)
	require.Equal(t, encodedAssertion, got)
	require.Equal(t, []string{"GET /start", "POST /login", "POST /webauthn", "POST /device", "POST /otp"}, requests)
	require.Equal(t, "alice", loginForm.Get("pf.username"))
	require.Equal(t, "secret", loginForm.Get("pf.pass"))
	require.Equal(t, "false", webAuthnForm.Get("isWebAuthnSupportedByBrowser"))
	require.Equal(t, "tablet-id", deviceForm.Get("deviceId"))
	require.Equal(t, "123456", otpForm.Get("otp"))
}

func TestAuthenticateUnknownPage(t *testing.T) {
	client, ts := newPingOneTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><p>unexpected page</p></body></html>`))
	}), "")

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, got)
	require.EqualError(t, err, "Unknown document type")
}

func TestAuthenticateMalformedSAMLResponse(t *testing.T) {
	client, ts := newPingOneTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form action="https://signin.aws.amazon.com/saml"><input name="SAMLResponse" value="%%%invalid%%"></form>`))
	}), "")

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, got)
	require.ErrorContains(t, err, "failed to decode saml-response")
}

func TestAuthenticateHTTPError(t *testing.T) {
	client, ts := newPingOneTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}), "")

	got, err := client.Authenticate(&creds.LoginDetails{URL: ts.URL})
	require.Empty(t, got)
	require.ErrorContains(t, err, "error following")
	require.ErrorContains(t, err, "502 Bad Gateway")
}
