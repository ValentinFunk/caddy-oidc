package caddy_oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/relvacode/caddy-oidc/authenticator"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
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

func (testOAuthClientImpl) Exchange(_ context.Context, _ string, _ ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return nil, errors.New("token exchange not supported in test")
}

func (testOAuthClientImpl) Scopes() []string {
	return []string{"openid", "profile", "email", "offline_access"}
}

func (testOAuthClientImpl) ClientID() string {
	return "xyz"
}

func GenerateTestProvider() *Provider {
	cookie := &authenticator.SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := cookie.Provision(ctx)
	if err != nil {
		panic(err)
	}

	provider := &Provider{
		Clock: func() time.Time {
			return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		Authenticators: authenticator.Set{
			Authenticators: []authenticator.RequestAuthenticator{
				&authenticator.BearerAuthenticator{},
				cookie,
				&authenticator.NoneAuthenticator{},
			},
		},
		ProtectedResource: new(ProtectedResourceMetadataConfiguration),
		Log:               zap.NewNop(),
		UsernameClaim:     DefaultUsernameClaim,
		Issuer:            "https://openid/example",
	}

	provider.Discovery = Defer[*providerDiscoveryConfiguration](func() (*providerDiscoveryConfiguration, error) {
		return &providerDiscoveryConfiguration{
			Verifier: pkgtest.NewTestVerifier(provider.Clock),
			OAuth2:   testOAuthClientImpl{},
		}, nil
	})

	return provider
}

func TestProvider_ProtectedResourceMetadata(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()

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

func TestProvider_ProtectedResourceMetadata_WithAudience(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()
	pr.ProtectedResource.Audience = true

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
