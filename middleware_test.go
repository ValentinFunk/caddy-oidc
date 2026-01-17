package caddy_oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
)

type TestHandler struct {
	calls int
}

func (h *TestHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	h.calls++
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth(t *testing.T) {
	auth := &OIDCMiddleware{
		au: Defer(func() (*Authenticator, error) { return GenerateTestAuthenticator(), nil }),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Sec-Fetch-Dest", "document")
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.NoError(t, err)
	assert.Equal(t, 0, h.calls)
	assert.Equal(t, http.StatusFound, w.Code)

	redir, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)

	assert.Equal(t, "http", redir.Scheme)
	assert.Equal(t, "openid", redir.Host)
	assert.Equal(t, "/example/authorize", redir.Path)
	assert.Equal(t, "S256", redir.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, redir.Query().Get("code_challenge"))
	assert.Equal(t, "code", redir.Query().Get("response_type"))
	assert.Equal(t, "xyz", redir.Query().Get("client_id"))
	assert.NotEmpty(t, redir.Query().Get("state"))
	assert.Equal(t, "http://example.com/oauth2/callback", redir.Query().Get("redirect_uri"))

	c, err := http.ParseSetCookie(w.Header().Get("Set-Cookie"))
	if assert.NoError(t, err) {
		assert.Equal(t, fmt.Sprintf("%s|%s", "session", redir.Query().Get("state")), c.Name)
	}
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_NoRedirectSupport(t *testing.T) {
	auth := &OIDCMiddleware{
		au: Defer(func() (*Authenticator, error) { return GenerateTestAuthenticator(), nil }),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.Equal(t, 0, h.calls)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusUnauthorized, ce.StatusCode)
	}

	wwwAuthenticate := w.Header().Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuthenticate)
	assert.Equal(t, `Bearer resource_metadata="http://example.com/.well-known/oauth-protected-resource", scope="openid profile email offline_access"`, wwwAuthenticate)
}

func TestOIDCMiddleware_ServeHTTP_WithBearerAuthentication_NoPolicy(t *testing.T) {
	auth := &OIDCMiddleware{
		au: Defer(func() (*Authenticator, error) { return GenerateTestAuthenticator(), nil }),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWT())
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.ErrorIs(t, err, ErrAccessDenied)
}

func TestOIDCMiddleware_ServeHTTP_WellKnownOAuthProtectedResource(t *testing.T) {
	auth := &OIDCMiddleware{
		au: Defer(func() (*Authenticator, error) {
			pr := GenerateTestAuthenticator()
			pr.protectedResource.Audience = true
			return pr, nil
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.NoError(t, err)
	assert.Equal(t, 0, h.calls)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, `{
  "resource": "http://example.com",
  "authorization_servers": [
    "https://openid/example"
  ],
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "offline_access"
  ],
  "bearer_methods_supported": [
    "header"
  ],
  "audience": "xyz"
}
`, w.Body.String())
}

func TestOIDCMiddleware_ServeHTTP_WellKnownOAuthProtectedResource_Disabled(t *testing.T) {
	auth := &OIDCMiddleware{
		au: Defer(func() (*Authenticator, error) {
			pr := GenerateTestAuthenticator()
			pr.protectedResource.Disable = true
			return pr, nil
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.Equal(t, 0, h.calls)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusNotFound, ce.StatusCode)
	}
}

func TestOIDCMiddleware_ServeHTTP_SetsReplacerVars(t *testing.T) {
	auth := &OIDCMiddleware{
		Policies: PolicySet{
			{
				Action: Allow,
				Matchers: caddyhttp.MatcherSet{
					&MatchUser{Usernames: []string{"*"}},
				},
			},
		},
		au: Defer(func() (*Authenticator, error) {
			pr := GenerateTestAuthenticator()
			pr.claims = append(pr.claims, "aud")
			return pr, nil
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWT())

	repl := caddyhttp.NewTestReplacer(r)

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.NoError(t, err)
	assert.Equal(t, 1, h.calls)

	assert.Equal(t, "false", repl.ReplaceAll("{http.auth.user.anonymous}", ""))
	assert.Equal(t, "test", repl.ReplaceAll("{http.auth.user.id}", ""))
	assert.Equal(t, "xyz", repl.ReplaceAll("{http.auth.user.claim.aud}", ""))
}
