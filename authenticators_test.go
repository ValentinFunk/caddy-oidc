package caddy_oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorSet_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	var dis = caddyfile.NewTestDispenser(`
		authenticate bearer
		authenticate cookie
		authenticate none
	`)

	var authenticatorSet AuthenticatorSet

	for dis.Next() {
		err := authenticatorSet.UnmarshalCaddyfile(dis)
		require.NoError(t, err)
	}

	assert.Equal(t, []json.RawMessage{
		json.RawMessage(`{"authenticator":"bearer"}`),
		json.RawMessage(`{"authenticator":"cookie"}`),
		json.RawMessage(`{"authenticator":"none"}`),
	}, authenticatorSet.AuthenticatorsRaw)
}

func TestAuthenticatorSet_Provision(t *testing.T) {
	t.Parallel()

	var authenticatorSet = &AuthenticatorSet{
		AuthenticatorsRaw: []json.RawMessage{
			json.RawMessage(`{"authenticator": "cookie"}`),
		},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := authenticatorSet.Provision(ctx)
	require.NoError(t, err)

	if assert.Len(t, authenticatorSet.Authenticators, 1) {
		_, ok := authenticatorSet.Authenticators[0].(*SessionCookieAuthenticator)
		assert.True(t, ok)
	}
}

func TestAuthenticatorSet_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()

	var authenticatorSet = &AuthenticatorSet{
		Authenticators: []RequestAuthenticator{
			&BearerAuthenticator{},
		},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTExpiresAt(pr.clock().Add(time.Hour)))

	m, s, err := authenticatorSet.AuthenticateRequest(pr, r)
	require.NoError(t, err)
	assert.Equal(t, AuthMethodBearer, m)
	assert.Equal(t, "test", s.UID)
}

func TestAuthenticatorSet_AuthenticateRequest_NoAuthentication(t *testing.T) {
	t.Parallel()

	var authenticatorSet = &AuthenticatorSet{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, _, err := authenticatorSet.AuthenticateRequest(GenerateTestProvider(), r)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusUnauthorized, ce.StatusCode)
		assert.ErrorIs(t, ce.Unwrap(), ErrNoAuthentication)
	}
}

func TestNoneAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()
	au := &NoneAuthenticator{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s, err := au.AuthenticateRequest(pr, r)
	require.NoError(t, err)
	assert.True(t, s.Anonymous)
}

func TestBearerAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	au := BearerAuthenticator{}
	pr := GenerateTestProvider()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTExpiresAt(pr.clock().Add(time.Hour)))

	s, err := au.AuthenticateRequest(pr, r)
	require.NoError(t, err)
	assert.Equal(t, "test", s.UID)
}

func TestBearerAuthentication_AuthenticateRequest_WithoutBearerToken(t *testing.T) {
	t.Parallel()

	au := BearerAuthenticator{}
	pr := GenerateTestProvider()

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := au.AuthenticateRequest(pr, r)
	assert.ErrorIs(t, err, ErrNoAuthentication)
}

func TestBearerAuthentication_AuthenticateRequest_InvalidBearerToken(t *testing.T) {
	t.Parallel()

	au := BearerAuthenticator{}
	pr := GenerateTestProvider()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer xxxxx")

	_, err := au.AuthenticateRequest(pr, r)
	require.Error(t, err)
	assert.ErrorContains(t, err, "compact JWS format must have three parts")
}

func TestBearerAuthentication_AuthenticateRequest_BearerTokenExpired(t *testing.T) {
	t.Parallel()

	au := BearerAuthenticator{}
	pr := GenerateTestProvider()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTExpiresAt(pr.clock().Add(-time.Hour)))

	_, err := au.AuthenticateRequest(pr, r)
	assert.ErrorIs(t, err, ErrNoAuthentication)
}

func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookie(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()
	au := &SessionCookieAuthenticator{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	session := &Session{UID: "test"}
	cookie, err := session.HTTPCookie(pr.cookie, pr.cookies)
	require.NoError(t, err)

	r.AddCookie(cookie)

	session, err = au.AuthenticateRequest(pr, r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", session.UID)
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookieSignedByOther(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()
	au := &SessionCookieAuthenticator{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &Session{UID: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := s.HTTPCookie(pr.cookie, cookieSigner)
	require.NoError(t, err)

	r.AddCookie(cookie)

	_, err = au.AuthenticateRequest(pr, r)
	require.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
	}
}
