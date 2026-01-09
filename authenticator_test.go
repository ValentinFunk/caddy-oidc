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
			SameSite: SameSite{http.SameSiteLaxMode},
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
				Uid:    "test",
				Claims: json.RawMessage(`{}`),
			},
		},
		{
			name:   "with expiry",
			claims: claimsStr(`{"sub": "test", "exp": 1577836800}`),
			expect: Session{
				Uid:       "test",
				ExpiresAt: 1577836800,
				Claims:    json.RawMessage(`{}`),
			},
		},
		{
			name:   "with claims partial",
			claims: claimsStr(`{"sub": "test", "email": "x@example.org"}`),
			expect: Session{
				Uid:    "test",
				Claims: json.RawMessage(`{"email":"x@example.org"}`),
			},
		},
		{
			name:   "with claims full",
			claims: claimsStr(`{"sub": "test", "email": "x@example.org", "role": ["admin", "viewer"]}`),
			expect: Session{
				Uid:    "test",
				Claims: json.RawMessage(`{"email":"x@example.org","role":["admin", "viewer"]}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			au := GenerateTestAuthenticator()
			s, err := au.SessionFromClaims(tt.claims)
			if tt.shouldErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, tt.expect, *s)
		})
	}
}

func TestAuthenticator_StartLoginRedirectUrl(t *testing.T) {
	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "localhost"
	r.Header.Set("X-Forwarded-Proto", "https")

	w := httptest.NewRecorder()

	err := pr.StartLogin(w, r)
	assert.NoError(t, err)

	redirectUrl, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)

	postRedirectUrl, err := url.Parse(redirectUrl.Query().Get("redirect_uri"))
	assert.NoError(t, err)

	assert.Equal(t, "https", postRedirectUrl.Scheme)
	assert.Equal(t, "localhost", postRedirectUrl.Host)
	assert.Equal(t, "/oauth2/callback", postRedirectUrl.Path)
}

func TestAuthenticator_Authenticate_WithBearerAuthentication(t *testing.T) {
	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWT())

	s, err := pr.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.Uid)
		assert.Equal(t, json.RawMessage(`{"email":"x@example.org"}`), s.Claims)
	}
}

func TestAuthenticator_Authenticate_WithSessionCookie(t *testing.T) {
	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test"}
	cookie, err := s.HttpCookie(pr.cookie, pr.cookies)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	s, err = pr.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.Uid)
	}
}

func TestAuthenticator_Authenticate_WithSessionCookie_SignedByOther(t *testing.T) {
	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := s.HttpCookie(pr.cookie, cookieSigner)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	_, err = pr.Authenticate(r)
	assert.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
	}
}

func TestAuthenticator_SessionFromCookie(t *testing.T) {
	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test", ExpiresAt: pr.clock().Add(-1 * time.Hour).Unix()}

	cookie, err := s.HttpCookie(pr.cookie, pr.cookies)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	_, err = pr.SessionFromCookie(r)
	assert.Error(t, err)

	var e *oidc.TokenExpiredError
	assert.ErrorAs(t, err, &e)
}

func TestAuthenticator_ProtectedResourceMetadata(t *testing.T) {
	pr := GenerateTestAuthenticator()

	r := httptest.NewRequest("GET", "http://example.com/endpoint?x=y", nil)

	md, ok := pr.ProtectedResourceMetadata(r)
	assert.True(t, ok)
	assert.EqualValues(t, &OAuthProtectedResource{
		Resource:               "http://example.com",
		ScopesSupported:        []string{"openid", "profile", "email", "offline_access"},
		BearerMethodsSupported: []string{"header"},
		AuthorizationServers: []string{
			"https://openid/example",
		},
	}, md)
}

func TestAuthenticator_ProtectedResourceMetadata_WithAudience(t *testing.T) {
	pr := GenerateTestAuthenticator()
	pr.protectedResource.Audience = true

	r := httptest.NewRequest("GET", "http://example.com/endpoint?x=y", nil)

	md, ok := pr.ProtectedResourceMetadata(r)
	assert.True(t, ok)
	assert.EqualValues(t, &OAuthProtectedResource{
		Resource:        "http://example.com",
		ScopesSupported: []string{"openid", "profile", "email", "offline_access"},
		Audience:        "xyz",
		AuthorizationServers: []string{
			"https://openid/example",
		},
	}, md)
}
