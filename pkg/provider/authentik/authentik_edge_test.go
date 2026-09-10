package authentik

import (
	"net/http"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AdrianAcala/saml2aws/v2/pkg/cfg"
	"github.com/AdrianAcala/saml2aws/v2/pkg/creds"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(&cfg.IDPAccount{})
	require.NoError(t, err)
	gock.InterceptClient(&client.client.Client)
	t.Cleanup(gock.Off)
	return client
}

func testLoginDetails() *creds.LoginDetails {
	return &creds.LoginDetails{
		Username: "user",
		Password: "password",
		MFAToken: "123456",
		URL:      "http://127.0.0.1/if/flow/default/",
	}
}

func testExecutorLoginDetails() *creds.LoginDetails {
	loginDetails := testLoginDetails()
	loginDetails.URL = "http://127.0.0.1/api/v3/flows/executor/default/"
	return loginDetails
}

func TestAuthenticateWrapsInitialRequestError(t *testing.T) {
	client, err := New(&cfg.IDPAccount{})
	require.NoError(t, err)

	_, err = client.Authenticate(&creds.LoginDetails{URL: "://invalid"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving saml response from idp")
	assert.Contains(t, err.Error(), "error retrieving initial url")
}

func TestAuthenticateRejectsMalformedPayload(t *testing.T) {
	client := newTestClient(t)
	gock.New("http://127.0.0.1").
		Get("/if/flow/default/").
		Reply(http.StatusOK).
		BodyString("")
	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default/").
		Reply(http.StatusOK).
		BodyString("{")

	_, err := client.Authenticate(testLoginDetails())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving saml response from idp")
	assert.Contains(t, err.Error(), "unexpected end of JSON input")
}

func TestQueryNextRejectsUnknownPayloadType(t *testing.T) {
	client := newTestClient(t)
	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default/").
		Reply(http.StatusOK).
		JSON(map[string]string{"type": "unexpected"})

	ctx := &authentikContext{loginDetails: testExecutorLoginDetails()}
	shouldContinue, next, err := client.queryNext(ctx)
	require.Error(t, err)
	assert.False(t, shouldContinue)
	assert.Empty(t, next)
	assert.EqualError(t, err, "Unknown type: unexpected")
}

func TestQueryNextRejectsMalformedRedirectLocation(t *testing.T) {
	client := newTestClient(t)
	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default/").
		Reply(http.StatusFound).
		SetHeader("Location", "://invalid")

	ctx := &authentikContext{loginDetails: testExecutorLoginDetails()}
	shouldContinue, next, err := client.queryNext(ctx)
	require.Error(t, err)
	assert.False(t, shouldContinue)
	assert.Empty(t, next)
}

func TestDoPostQueryReturnsResponseErrors(t *testing.T) {
	client := newTestClient(t)
	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default/").
		Reply(http.StatusOK).
		JSON(map[string]interface{}{
			"component": "ak-stage-password",
			"response_errors": map[string][]map[string]string{
				"password": {{"code": "invalid", "string": "Password is incorrect."}},
			},
		})

	ctx := &authentikContext{loginDetails: testExecutorLoginDetails()}
	next, err := client.doPostQuery(ctx, &authentikPayload{Component: "ak-stage-password"})
	require.Error(t, err)
	assert.Empty(t, next)
	assert.EqualError(t, err, "password invalid: Password is incorrect.")
}

func TestDoPostQueryReturnsUnexpectedSuccessfulResponse(t *testing.T) {
	client := newTestClient(t)
	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default/").
		Reply(http.StatusOK).
		JSON(map[string]string{"component": "ak-stage-password"})

	ctx := &authentikContext{loginDetails: testExecutorLoginDetails()}
	next, err := client.doPostQuery(ctx, &authentikPayload{Component: "ak-stage-password"})
	require.Error(t, err)
	assert.Empty(t, next)
	assert.EqualError(t, err, "Unexpected")
}

func TestDoPostQueryFollowsNonOKLocation(t *testing.T) {
	client := newTestClient(t)
	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default/").
		Reply(http.StatusFound).
		SetHeader("Location", "/next")

	ctx := &authentikContext{loginDetails: testExecutorLoginDetails()}
	next, err := client.doPostQuery(ctx, &authentikPayload{Component: "ak-stage-password"})
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1/next", next)
}
