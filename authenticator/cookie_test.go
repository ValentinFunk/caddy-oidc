package authenticator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionCookieAuthenticator_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		expect    SessionCookieAuthenticator
		shouldErr bool
	}{
		{
			name:  "inline name",
			input: `my_cookie`,
			expect: SessionCookieAuthenticator{
				Name: "my_cookie",
			},
		},
		{
			name: "block configuration",
			input: `{
				name block_cookie
				same_site strict
				insecure
				domain example.com
				path /auth
			}`,
			expect: SessionCookieAuthenticator{
				Name:     "block_cookie",
				SameSite: SameSiteStrict,
				Insecure: true,
				Domain:   "example.com",
				Path:     "/auth",
			},
		},
		{
			name: "invalid same_site",
			input: `{
				same_site mysterious
			}`,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := caddyfile.NewTestDispenser(tt.input)

			var cookies SessionCookieAuthenticator

			err := cookies.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expect, cookies)
		})
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookie(t *testing.T) {
	t.Parallel()

	var cfg pkgtest.TestOIDCConfiguration
	au := &SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.NewCookie(cookieValue))

	s, err = au.AuthenticateRequest(&cfg, r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.UID)
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookieSignedByOther(t *testing.T) {
	t.Parallel()

	var cfg pkgtest.TestOIDCConfiguration
	au := &SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := cookieSigner.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.NewCookie(cookie))

	_, err = au.AuthenticateRequest(&cfg, r)
	require.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_SessionExpired(t *testing.T) {
	t.Parallel()

	var cfg pkgtest.TestOIDCConfiguration
	au := &SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test", ExpiresAt: cfg.Now().Add(-time.Hour).Unix()}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.NewCookie(cookieValue))

	_, err = au.AuthenticateRequest(&cfg, r)
	require.Error(t, err)

	var ee *oidc.TokenExpiredError
	assert.ErrorAs(t, err, &ee)
}
