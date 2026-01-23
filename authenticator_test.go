package caddy_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type testOAuthClientImpl struct{}

func (testOAuthClientImpl) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	var oConfig = oauth2.Config{
		ClientID:    "xyz",
		RedirectURL: "https://localhost/oauth2/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://openid/example/authorize",
			TokenURL: "http://openid/example/token",
		},
	}

	return oConfig.AuthCodeURL(state, opts...)
}

func (testOAuthClientImpl) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return nil, errors.New("token exchange not supported in test")
}

func (testOAuthClientImpl) Scopes() []string {
	return []string{"openid", "profile", "email", "offline_access"}
}

func (testOAuthClientImpl) ClientID() string {
	return "xyz"
}

func GenerateTestAuthenticator() *Authenticator {
	return &Authenticator{
		cookie: &Cookies{
			Name:     "session",
			SameSite: sameSite{http.SameSiteLaxMode},
			Path:     "/",
		},
		clock: func() time.Time {
			return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		redirectUri: &url.URL{
			Path: "/oauth2/callback",
		},
		protectedResource: new(ProtectedResourceMetadataConfiguration),
		log:               zap.NewNop(),
		uid:               DefaultUsernameClaim,
		issuer:            "https://openid/example",
		claims:            []string{"email", "role"},
		cookies:           securecookie.New([]byte("VTQOz22ZZiyYNciwtDyckU1aJWQSCXnm"), []byte("VTQOz22ZZiyYNciwtDyckU1aJWQSCXnm")),
		verifier: oidc.NewVerifier("http://openid/example", TestKeySet{}, &oidc.Config{
			ClientID:             "xyz",
			SupportedSigningAlgs: []string{"HS256"},
			SkipExpiryCheck:      true,
		}),
		oauth2: testOAuthClientImpl{},
	}
}

type claimsStr string

func (c claimsStr) Claims(v any) error {
	return json.Unmarshal([]byte(c), v)
}

func TestAuthenticator_SessionFromClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		claims    claimsStr
		expect    Session
		shouldErr bool
	}{
		{
			name:   "basic",
			claims: claimsStr(`{"sub": "test"}`),
			expect: Session{
				UID:    "test",
				Claims: json.RawMessage(`{}`),
			},
		},
		{
			name:   "with expiry",
			claims: claimsStr(`{"sub": "test", "exp": 1577836800}`),
			expect: Session{
				UID:       "test",
				ExpiresAt: 1577836800,
				Claims:    json.RawMessage(`{}`),
			},
		},
		{
			name:   "with claims partial",
			claims: claimsStr(`{"sub": "test", "email": "x@example.org"}`),
			expect: Session{
				UID:    "test",
				Claims: json.RawMessage(`{"email":"x@example.org"}`),
			},
		},
		{
			name:   "with claims full",
			claims: claimsStr(`{"sub": "test", "email": "x@example.org", "role": ["admin", "viewer"]}`),
			expect: Session{
				UID:    "test",
				Claims: json.RawMessage(`{"email":"x@example.org","role":["admin", "viewer"]}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			au := GenerateTestAuthenticator()

			session, err := au.SessionFromClaims(tt.claims)
			if tt.shouldErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expect, *session)
		})
	}
}

func TestAuthenticator_StartLoginRedirectUrl(t *testing.T) {
	t.Parallel()

	au := GenerateTestAuthenticator()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Forwarded-Proto", "https")

	w := httptest.NewRecorder()

	err := au.StartLogin(w, r)
	require.NoError(t, err)

	redirectUrl, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)

	postRedirectUrl, err := url.Parse(redirectUrl.Query().Get("redirect_uri"))
	require.NoError(t, err)

	assert.Equal(t, "https", postRedirectUrl.Scheme)
	assert.Equal(t, "localhost", postRedirectUrl.Host)
	assert.Equal(t, "/oauth2/callback", postRedirectUrl.Path)
}

func TestAuthenticator_Authenticate_WithBearerAuthentication(t *testing.T) {
	t.Parallel()

	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWT())

	m, s, err := pr.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, AuthMethodBearer, m)
		assert.Equal(t, "test", s.UID)
		assert.JSONEq(t, `{"email":"x@example.org"}`, string(s.Claims))
	}
}

func TestAuthenticator_Authenticate_WithSessionCookie(t *testing.T) {
	t.Parallel()

	au := GenerateTestAuthenticator()

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	session := &Session{UID: "test"}
	cookie, err := session.HTTPCookie(au.cookie, au.cookies)
	require.NoError(t, err)

	r.AddCookie(cookie)

	m, session, err := au.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, AuthMethodCookie, m)
		assert.Equal(t, "test", session.UID)
	}
}

func TestAuthenticator_Authenticate_WithSessionCookie_SignedByOther(t *testing.T) {
	t.Parallel()

	au := GenerateTestAuthenticator()

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &Session{UID: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := s.HTTPCookie(au.cookie, cookieSigner)
	require.NoError(t, err)

	r.AddCookie(cookie)

	_, _, err = au.Authenticate(r)
	require.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
	}
}

func TestAuthenticator_SessionFromCookie(t *testing.T) {
	t.Parallel()

	au := GenerateTestAuthenticator()

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &Session{UID: "test", ExpiresAt: au.clock().Add(-1 * time.Hour).Unix()}

	cookie, err := s.HTTPCookie(au.cookie, au.cookies)
	require.NoError(t, err)

	r.AddCookie(cookie)

	_, _, err = au.SessionFromCookie(r)

	var e *oidc.TokenExpiredError
	assert.ErrorAs(t, err, &e)
}

func TestAuthenticator_ProtectedResourceMetadata(t *testing.T) {
	t.Parallel()

	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest(http.MethodGet, "http://example.com/endpoint?x=y", nil)

	metadata, ok := pr.ProtectedResourceMetadata(r)
	assert.True(t, ok)
	assert.Equal(t, &OAuthProtectedResource{
		Resource:               "http://example.com",
		ScopesSupported:        []string{"openid", "profile", "email", "offline_access"},
		BearerMethodsSupported: []string{"header"},
		AuthorizationServers: []string{
			"https://openid/example",
		},
	}, metadata)
}

func TestAuthenticator_ProtectedResourceMetadata_WithAudience(t *testing.T) {
	t.Parallel()

	pr := GenerateTestAuthenticator()
	pr.protectedResource.Audience = true

	r := httptest.NewRequest(http.MethodGet, "http://example.com/endpoint?x=y", nil)

	metadata, ok := pr.ProtectedResourceMetadata(r)
	assert.True(t, ok)
	assert.Equal(t, &OAuthProtectedResource{
		Resource:               "http://example.com",
		ScopesSupported:        []string{"openid", "profile", "email", "offline_access"},
		BearerMethodsSupported: []string{"header"},
		Audience:               "xyz",
		AuthorizationServers: []string{
			"https://openid/example",
		},
	}, metadata)
}
