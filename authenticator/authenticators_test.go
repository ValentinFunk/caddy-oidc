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
	`)

	var authenticatorSet Set

	for dis.Next() {
		err := authenticatorSet.UnmarshalCaddyfile(dis)
		require.NoError(t, err)
	}

	assert.Equal(t, []json.RawMessage{
		json.RawMessage(`{"authenticator":"bearer"}`),
		json.RawMessage(`{"authenticator":"none"}`),
	}, authenticatorSet.AuthenticatorsRaw)
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

	var cfg pkgtest.TestOIDCConfiguration
	var authenticatorSet Set

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, _, err := authenticatorSet.AuthenticateRequest(&cfg, r)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusUnauthorized, ce.StatusCode)
		assert.ErrorIs(t, ce.Unwrap(), ErrNoAuthentication)
	}
}

type SendExpiredError struct {
}

func (SendExpiredError) Method() AuthMethod { return AuthMethodNone }

func (SendExpiredError) AuthenticateRequest(cfg OIDCConfiguration, r *http.Request) (*session.Session, error) {
	return nil, &oidc.TokenExpiredError{}
}

func TestAuthenticatorSet_AuthenticateRequest_HandlesExpired(t *testing.T) {
	var set = &Set{
		Authenticators: []RequestAuthenticator{
			&SendExpiredError{},
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, _, err := set.AuthenticateRequest(&pkgtest.TestOIDCConfiguration{}, r)
	assert.ErrorIs(t, err, ErrNoAuthentication)
}
