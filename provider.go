package caddy_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/relvacode/caddy-oidc/authenticator"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// oauth2Client is an interface for the oauth2 client.
type oauth2Client interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Scopes() []string
	ClientID() string
}

// oauth2ConfigWithHTTPClient wraps an oauth2.Config to inject an HTTP client instance for token exchange.
type oauth2ConfigWithHTTPClient struct {
	*oauth2.Config

	httpClient *http.Client
}

func (c *oauth2ConfigWithHTTPClient) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)

	return c.Config.Exchange(ctx, code, opts...)
}

func (c *oauth2ConfigWithHTTPClient) Scopes() []string {
	return c.Config.Scopes
}

func (c *oauth2ConfigWithHTTPClient) ClientID() string {
	return c.Config.ClientID
}

type userInfoClient interface {
	UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error)
}

type providerDiscoveryConfiguration struct {
	Verifier *oidc.IDTokenVerifier
	UserInfo userInfoClient
	OAuth2   oauth2Client
}

var (
	_ authenticator.OIDCConfiguration                   = (*Provider)(nil)
	_ authenticator.OAuthAuthorizationFlowConfiguration = (*Provider)(nil)
)

// Provider holds the built configuration for an OIDC provider and authentication logic.
type Provider struct {
	Log               *zap.Logger
	RedirectURL       *url.URL
	Clock             func() time.Time
	Issuer            string
	UsernameClaim     string
	ProtectedResource *ProtectedResourceMetadataConfiguration
	Authenticators    authenticator.Set
	Discovery         *DeferredResult[*providerDiscoveryConfiguration]
}

func (pr *Provider) Now() time.Time           { return pr.Clock() }
func (pr *Provider) GetUsernameClaim() string { return pr.UsernameClaim }

func (pr *Provider) GetVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.Verifier, nil
}

// GetAbsRedirectUri returns the absolute redirect URI, resolving it relative to the request URL if necessary.
func (pr *Provider) GetAbsRedirectUri(r *http.Request) string {
	if pr.RedirectURL.IsAbs() {
		return pr.RedirectURL.String()
	}

	// Caddy should be sanitising X-Forwarded-Proto headers
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	var u = *r.URL

	u.Scheme = scheme
	u.Host = r.Host

	return u.ResolveReference(pr.RedirectURL).String()
}

func (pr *Provider) AuthCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) (string, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return "", err
	}

	return discovery.OAuth2.AuthCodeURL(state, opts...), nil
}

func (pr *Provider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.OAuth2.Exchange(ctx, code, opts...)
}

func (pr *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.UserInfo.UserInfo(ctx, tokenSource)
}

// ProtectedResourceMetadata returns the OAuth protected resource metadata for this authenticator.
// If protected resource metadata is not enabled, then false is returned.
func (pr *Provider) ProtectedResourceMetadata(r *http.Request) (*OAuthProtectedResource, bool) {
	if pr.ProtectedResource.Disable {
		return nil, false
	}

	discovery, err := pr.Discovery.Get(r.Context())
	if err != nil {
		return nil, false
	}

	var (
		ru       = RequestURL(r)
		metadata = &OAuthProtectedResource{
			Resource:        fmt.Sprintf("%s://%s", ru.Scheme, ru.Host),
			ScopesSupported: discovery.OAuth2.Scopes(),
			AuthorizationServers: []string{
				pr.Issuer,
			},
			// OIDC middleware only supports bearer authentication via the Authorization header
			BearerMethodsSupported: []string{
				"header",
			},
		}
	)

	if pr.ProtectedResource.Audience {
		metadata.Audience = discovery.OAuth2.ClientID()
	}

	return metadata, true
}

// WellKnownOAuthProtectedResourcePath is the path for the OAuth protected resource metadata endpoint.
const WellKnownOAuthProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ServeHTTPOAuthProtectedResource returns the OAuth protected resource metadata for the endpoint
// .well-known/oauth-protected-resource.
// If the endpoint is disabled, then a 404 not found response is returned.
func (pr *Provider) ServeHTTPOAuthProtectedResource(rw http.ResponseWriter, r *http.Request) error {
	metadata, ok := pr.ProtectedResourceMetadata(r)
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, errors.New("protected resource metadata is disabled"))
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")

	return enc.Encode(metadata)
}
