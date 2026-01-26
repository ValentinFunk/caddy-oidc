package authenticator

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

//
//func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookie(t *testing.T) {
//	t.Parallel()
//
//	var cfg pkgtest.TestOIDCConfiguration
//	au := &SessionCookieAuthenticator{}
//
//	r := httptest.NewRequest(http.MethodGet, "/", nil)
//
//	session := &Session{UID: "test"}
//	cookie, err := session.HTTPCookie(pr.cookie, pr.cookies)
//	require.NoError(t, err)
//
//	r.AddCookie(cookie)
//
//	session, err = au.AuthenticateRequest(pr, r)
//	if assert.NoError(t, err) {
//		assert.Equal(t, "test", session.UID)
//	}
//}
//
//func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookieSignedByOther(t *testing.T) {
//	t.Parallel()
//
//	var cfg pkgtest.TestOIDCConfiguration
//	au := &SessionCookieAuthenticator{}
//
//	r := httptest.NewRequest(http.MethodGet, "/", nil)
//
//	s := &Session{UID: "test"}
//	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))
//
//	cookie, err := s.HTTPCookie(pr.cookie, cookieSigner)
//	require.NoError(t, err)
//
//	r.AddCookie(cookie)
//
//	_, err = au.AuthenticateRequest(pr, r)
//	require.Error(t, err)
//
//	var he caddyhttp.HandlerError
//	if assert.ErrorAs(t, err, &he) {
//		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
//	}
//}
//
