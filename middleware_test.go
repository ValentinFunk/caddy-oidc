package caddy_oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/relvacode/caddy-oidc/authenticator"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestHandler struct {
	calls int
}

func (h *TestHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	h.calls++

	w.WriteHeader(http.StatusOK)

	return nil
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_AuthorizationFlowSupported(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Sec-Fetch-Dest", "document")

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, 0, h.calls)
	assert.Equal(t, http.StatusFound, w.Code)

	redir, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)

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
		assert.Equal(t, fmt.Sprintf("%s|%s", "test-cookie", redir.Query().Get("state")), c.Name)
	}
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_Iframe_ServesPopupLoginPage(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	r.Header.Set("Sec-Fetch-Dest", "iframe")

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, 0, h.calls)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "Login Required")
	assert.Contains(t, w.Body.String(), "popup=1")
	assert.Contains(t, w.Body.String(), "oidc-login-complete")
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_BearerOnly(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
	}

	auth.Provider.Authenticators.Authenticators = []authenticator.RequestAuthenticator{
		&authenticator.BearerAuthenticator{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Sec-Fetch-Dest", "document")

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.Equal(t, 0, h.calls)
	require.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.ErrorIs(t, he.Unwrap(), ErrAccessDenied)
		assert.Equal(t, http.StatusUnauthorized, he.StatusCode)
	}
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_NoRedirectSupport(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
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

func TestOIDCMiddleware_ServeHTTP_BearerOK(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
		Policies: Ruleset{
			{
				Action: ActionAllow,
				Matchers: caddyhttp.MatcherSet{
					&MatchUser{Usernames: []string{"*"}},
				},
			},
		},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(auth.Provider.Clock().Add(time.Hour)))

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, h.calls)
}

func TestOIDCMiddleware_ServeHTTP_WithBearerAuthentication_EmptyRuleset(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(auth.Provider.Clock().Add(time.Hour)))

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.ErrorIs(t, err, ErrAccessDenied)
}

func TestOIDCMiddleware_ServeHTTP_WellKnownOAuthProtectedResource(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
	}

	auth.Provider.ProtectedResource.Audience = true

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, 0, h.calls)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.JSONEq(t, `{
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
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
	}

	auth.Provider.ProtectedResource.Disable = true

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.Equal(t, 0, h.calls)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusNotFound, ce.StatusCode)
	}
}

func TestOIDCMiddleware_ServeHTTP_SetsReplacerVars(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		Provider: GenerateTestProvider(),
		Policies: Ruleset{
			{
				ID:     "TestRule",
				Action: ActionAllow,
				Matchers: caddyhttp.MatcherSet{
					&MatchUser{Usernames: []string{"*"}},
				},
			},
		},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(auth.Provider.Clock().Add(time.Hour)))

	repl := caddyhttp.NewTestReplacer(r)

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, 1, h.calls)

	assert.Equal(t, "false", repl.ReplaceAll("{http.auth.user.anonymous}", ""))
	assert.Equal(t, "test", repl.ReplaceAll("{http.auth.user.id}", ""))
	assert.Equal(t, "xyz", repl.ReplaceAll("{http.auth.user.claim.aud}", ""))
	assert.Equal(t, "read,write", repl.ReplaceAll("{http.auth.user.claim.roles}", ""))
	assert.Equal(t, "TestRule", repl.ReplaceAll("{http.auth.rule}", ""))
	assert.Equal(t, "allow", repl.ReplaceAll("{http.auth.result}", ""))
	assert.Equal(t, "bearer", repl.ReplaceAll("{http.auth.method}", ""))
}
