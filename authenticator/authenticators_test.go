package authenticator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorSet_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	var dis = caddyfile.NewTestDispenser(`
		authenticate bearer
		authenticate none
		authenticate header X-Api-Key
		authenticate header X-Access-Token
		authenticate query api-key
		authenticate preserve_request
	`)

	var authenticatorSet Set

	for dis.Next() {
		err := authenticatorSet.UnmarshalCaddyfile(dis)
		require.NoError(t, err)
	}

	assert.Equal(t, []json.RawMessage{
		json.RawMessage(`{"authenticator":"bearer"}`),
		json.RawMessage(`{"authenticator":"none"}`),
		json.RawMessage(`{"header":"X-Api-Key","authenticator":"header"}`),
		json.RawMessage(`{"header":"X-Access-Token","authenticator":"header"}`),
		json.RawMessage(`{"query":"api-key","authenticator":"query"}`),
	}, authenticatorSet.AuthenticatorsRaw)

	assert.True(t, authenticatorSet.PreserveRequest)
}

func TestAuthenticatorSet_Provision(t *testing.T) {
	t.Parallel()

	var authenticatorSet = &Set{
		AuthenticatorsRaw: []json.RawMessage{
			json.RawMessage(`{"authenticator": "bearer"}`),
		},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := authenticatorSet.Provision(ctx)
	require.NoError(t, err)

	if assert.Len(t, authenticatorSet.Authenticators, 1) {
		_, ok := authenticatorSet.Authenticators[0].(*BearerAuthenticator)
		assert.True(t, ok)
	}
}

type TestRequestAuthenticator struct {
}

func (TestRequestAuthenticator) Method() AuthMethod { return AuthMethodBearer }

func (TestRequestAuthenticator) AuthenticateRequest(_ OIDCConfiguration, _ *http.Request) (*session.Session, error) {
	return &session.Session{UID: "test"}, nil
}

func (TestRequestAuthenticator) StripRequest(_ *http.Request) {}

func TestAuthenticatorSet_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	var cfg pkgtest.TestOIDCConfiguration

	var authenticatorSet = &Set{
		Authenticators: []RequestAuthenticator{
			TestRequestAuthenticator{},
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	m, s, err := authenticatorSet.AuthenticateRequest(&cfg, r)
	require.NoError(t, err)
	assert.Equal(t, AuthMethodBearer, m)
	assert.Equal(t, "test", s.UID)
}

func TestAuthenticatorSet_AuthenticateRequest_NoAuthentication(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		set Set
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, _, err := set.AuthenticateRequest(&cfg, r)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusUnauthorized, ce.StatusCode)
		assert.ErrorIs(t, ce.Unwrap(), ErrNoAuthentication)
	}
}

type SendExpiredError struct {
}

func (SendExpiredError) Method() AuthMethod           { return AuthMethodNone }
func (SendExpiredError) StripRequest(_ *http.Request) {}

func (SendExpiredError) AuthenticateRequest(_ OIDCConfiguration, _ *http.Request) (*session.Session, error) {
	return nil, &oidc.TokenExpiredError{}
}

func TestAuthenticatorSet_AuthenticateRequest_HandlesExpired(t *testing.T) {
	t.Parallel()

	var set = &Set{
		Authenticators: []RequestAuthenticator{
			&SendExpiredError{},
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, _, err := set.AuthenticateRequest(&pkgtest.TestOIDCConfiguration{}, r)
	assert.ErrorIs(t, err, ErrNoAuthentication)
}

type testAuthenticateCallCountImpl struct {
	StripRequestCalled int
	AuthenticateCalled int
}

func (*testAuthenticateCallCountImpl) Method() AuthMethod { return AuthMethodNone }
func (t *testAuthenticateCallCountImpl) StripRequest(_ *http.Request) {
	t.StripRequestCalled++
}
func (t *testAuthenticateCallCountImpl) AuthenticateRequest(_ OIDCConfiguration, _ *http.Request) (*session.Session, error) {
	t.AuthenticateCalled++

	return session.Anonymous(), nil
}

func TestSet_StripRequest(t *testing.T) {
	t.Parallel()

	var (
		au  = &testAuthenticateCallCountImpl{}
		set = Set{
			PreserveRequest: false,
			Authenticators: []RequestAuthenticator{
				au,
			},
		}
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	set.StripRequest(r)
	assert.Equal(t, 1, au.StripRequestCalled)
}

func TestSet_StripRequest_Preserve(t *testing.T) {
	t.Parallel()

	var (
		au  = &testAuthenticateCallCountImpl{}
		set = Set{
			PreserveRequest: true,
			Authenticators: []RequestAuthenticator{
				au,
			},
		}
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	set.StripRequest(r)
	assert.Equal(t, 0, au.StripRequestCalled)
}

type testGetAuthenticateImpl1 struct {
	Check string
}

func (testGetAuthenticateImpl1) Method() AuthMethod           { return AuthMethodNone }
func (testGetAuthenticateImpl1) StripRequest(_ *http.Request) {}
func (testGetAuthenticateImpl1) AuthenticateRequest(_ OIDCConfiguration, _ *http.Request) (*session.Session, error) {
	//nolint:nilnil
	return nil, nil
}

type testGetAuthenticateImpl2 struct {
	Check string
}

func (testGetAuthenticateImpl2) Method() AuthMethod           { return AuthMethodNone }
func (testGetAuthenticateImpl2) StripRequest(_ *http.Request) {}
func (testGetAuthenticateImpl2) AuthenticateRequest(_ OIDCConfiguration, _ *http.Request) (*session.Session, error) {
	//nolint:nilnil
	return nil, nil
}

type testGetAuthenticateImpl3 struct {
	Check string
}

func (testGetAuthenticateImpl3) Method() AuthMethod           { return AuthMethodNone }
func (testGetAuthenticateImpl3) StripRequest(_ *http.Request) {}
func (testGetAuthenticateImpl3) AuthenticateRequest(_ OIDCConfiguration, _ *http.Request) (*session.Session, error) {
	//nolint:nilnil
	return nil, nil
}

func TestGetAuthenticator(t *testing.T) {
	t.Parallel()

	var set = Set{
		Authenticators: []RequestAuthenticator{
			testGetAuthenticateImpl1{Check: "1"},
			testGetAuthenticateImpl2{Check: "2"},
		},
	}

	v, ok := GetAuthenticator[testGetAuthenticateImpl1](&set)
	require.True(t, ok)
	assert.Equal(t, testGetAuthenticateImpl1{Check: "1"}, v)

	v2, ok := GetAuthenticator[testGetAuthenticateImpl2](&set)
	require.True(t, ok)
	assert.Equal(t, testGetAuthenticateImpl2{Check: "2"}, v2)

	_, ok = GetAuthenticator[testGetAuthenticateImpl3](&set)
	assert.False(t, ok)
}
