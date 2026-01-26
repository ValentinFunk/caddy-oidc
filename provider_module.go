package caddy_oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(new(OIDCProviderModule))
}

const (
	// DefaultRedirectUriPath is the default redirect URI used for OAuth callback if none is specified.
	DefaultRedirectUriPath = "/oauth2/callback"
	// DefaultUsernameClaim is the default username claim to use if none is specified.
	DefaultUsernameClaim = "sub"
)

var (
	// DefaultAuthMethods are the default authentication methods supported when none are provided.
	DefaultAuthMethods = []AuthMethod{AuthMethodBearer, AuthMethodCookie, AuthMethodNone}
)

var _ caddy.Module = (*OIDCProviderModule)(nil)
var _ caddy.Provisioner = (*OIDCProviderModule)(nil)
var _ caddy.Validator = (*OIDCProviderModule)(nil)
var _ caddyfile.Unmarshaler = (*OIDCProviderModule)(nil)

// OIDCProviderModule holds the configuration for an OIDC provider.
type OIDCProviderModule struct {
	Issuer                    string                                  `json:"issuer"`
	ClientID                  string                                  `json:"client_id"`
	SecretKey                 string                                  `json:"secret_key"`
	Authenticators            *AuthenticatorSet                       `json:"authenticators,omitempty"`
	RedirectURI               string                                  `json:"redirect_uri,omitempty"`
	TLSInsecureSkipVerify     bool                                    `json:"tls_insecure_skip_verify,omitempty"`
	Cookie                    *Cookies                                `json:"cookie,omitempty"`
	ProtectedResourceMetadata *ProtectedResourceMetadataConfiguration `json:"protected_resource_metadata,omitempty"`
	Scope                     []string                                `json:"scope,omitempty"`
	Username                  string                                  `json:"username,omitempty"`
	Claims                    []string                                `json:"claims,omitempty"`
}

func (*OIDCProviderModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  moduleID + ".provider",
		New: func() caddy.Module { return new(OIDCProviderModule) },
	}
}

// UnmarshalCaddyfile sets up the OIDCProviderModule instance from Caddyfile tokens.
/*
	{
		issuer <issuer>
		client_id <client_id>
		redirect_uri [<redirect_uri>]
		secret_key <secret_key>
		authenticate <authenticator>
		tls_insecure_skip_verify
		discovery_url <discovery_url>
		scope [<scope>...]
		username <username>
		claim [<claim>...]
		protected_resource <protected_resource>
		cookie <cookie>
	}
*/
func (m *OIDCProviderModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "issuer":
			if !d.NextArg() {
				return d.ArgErr()
			}

			m.Issuer = d.Val()
		case "client_id":
			if !d.NextArg() {
				return d.ArgErr()
			}

			m.ClientID = d.Val()
		case "redirect_uri":
			if !d.NextArg() {
				return d.ArgErr()
			}

			m.RedirectURI = d.Val()
		case "secret_key":
			if !d.NextArg() {
				return d.ArgErr()
			}

			m.SecretKey = d.Val()

		case "authenticate":
			if m.Authenticators == nil {
				m.Authenticators = new(AuthenticatorSet)
			}

			err := m.Authenticators.UnmarshalCaddyfile(d)
			if err != nil {
				return err
			}

		case "cookie":
			m.Cookie = new(Cookies)
			*m.Cookie = DefaultCookieOptions() // Apply defaults

			d.Prev()

			err := m.Cookie.UnmarshalCaddyfile(d)
			if err != nil {
				return err
			}
		case "protected_resource_metadata":
			m.ProtectedResourceMetadata = new(ProtectedResourceMetadataConfiguration)

			d.Prev()

			err := m.ProtectedResourceMetadata.UnmarshalCaddyfile(d)
			if err != nil {
				return err
			}
		case "tls_insecure_skip_verify":
			m.TLSInsecureSkipVerify = true
		case "scope":
			m.Scope = append(m.Scope, d.RemainingArgs()...)
		case "username":
			if !d.NextArg() {
				return d.ArgErr()
			}

			m.Username = d.Val()
		case "claim":
			m.Claims = append(m.Claims, d.RemainingArgs()...)
		default:
			return d.Errf("unrecognized oidc subdirective '%s'", d.Val())
		}
	}

	return nil
}

func (m *OIDCProviderModule) Provision(ctx caddy.Context) error {
	var repl = caddy.NewReplacer()

	m.SecretKey = repl.ReplaceAll(m.SecretKey, "")

	if m.Cookie == nil {
		m.Cookie = new(Cookies)
		*m.Cookie = DefaultCookieOptions()
	}

	if m.ProtectedResourceMetadata == nil {
		m.ProtectedResourceMetadata = new(ProtectedResourceMetadataConfiguration)
	}

	if m.Authenticators == nil {
		m.Authenticators = NewDefaultAuthenticatorSet()
	}

	err := m.Authenticators.Provision(ctx)
	if err != nil {
		return err
	}

	if m.Scope == nil {
		m.Scope = []string{oidc.ScopeOpenID}
	}

	if m.Username == "" {
		m.Username = DefaultUsernameClaim
	}

	if m.RedirectURI == "" {
		m.RedirectURI = DefaultRedirectUriPath
	}

	return nil
}

func (m *OIDCProviderModule) Validate() error {
	if m.Issuer == "" {
		return errors.New("issuer cannot be empty")
	}

	if m.ClientID == "" {
		return errors.New("client_id cannot be empty")
	}

	if m.SecretKey == "" {
		return errors.New("secret_key cannot be empty")
	}

	if len(m.SecretKey) != 32 && len(m.SecretKey) != 64 {
		return errors.New("secret_key must be 32 or 64 bytes")
	}

	if m.Username == "" {
		return errors.New("username cannot be empty")
	}

	err := m.Authenticators.Validate()
	if err != nil {
		return err
	}

	err = m.Cookie.Validate()
	if err != nil {
		return err
	}

	return nil
}

// setupHTTPClient creates a new HTTP client from provider configuration for communicating with the OIDC provider.
func (m *OIDCProviderModule) setupHTTPClient(log *zap.Logger) *http.Client {
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = slog.New(zapslog.NewHandler(log.Core(), zapslog.WithName(log.Name()), zapslog.WithCaller(false)))
	retryClient.RetryMax = 5

	// Copy the default settings from HTTP DefaultTransport
	//nolint:forcetypeassert
	retryClientTransport := http.DefaultTransport.(*http.Transport).Clone()
	if m.TLSInsecureSkipVerify {
		if retryClientTransport.TLSClientConfig == nil {
			retryClientTransport.TLSClientConfig = new(tls.Config)
		}

		retryClientTransport.TLSClientConfig.InsecureSkipVerify = true
	}

	retryClient.HTTPClient = &http.Client{
		Transport: retryClientTransport,
	}

	return retryClient.StandardClient()
}

// Create creates a Provider instance from this provider module configuration.
func (m *OIDCProviderModule) Create(ctx caddy.Context) (*Provider, error) {
	redirectUri, err := url.Parse(m.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect_uri: %w", err)
	}

	var (
		log        = ctx.Logger(m)
		httpClient = m.setupHTTPClient(log)
		authorizer = &Provider{
			log:               log,
			redirectUri:       redirectUri,
			authenticators:    *m.Authenticators,
			uid:               m.Username,
			claims:            m.Claims,
			clock:             time.Now,
			cookies:           securecookie.New([]byte(m.SecretKey), []byte(m.SecretKey)),
			cookie:            m.Cookie,
			protectedResource: m.ProtectedResourceMetadata,
			issuer:            m.Issuer,
		}
	)

	providerCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	provider, err := oidc.NewProvider(providerCtx, m.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	authorizer.log.Debug("OIDC provider discovery successful", zap.Any("discovery", provider.Endpoint()))

	authorizer.verifier = provider.Verifier(&oidc.Config{
		ClientID: m.ClientID,
		Now:      authorizer.clock,
	})

	authorizer.userInfo = provider
	authorizer.oauth2 = &oauth2ConfigWithHTTPClient{
		httpClient: httpClient,
		Config: &oauth2.Config{
			ClientID: m.ClientID,
			Endpoint: provider.Endpoint(),
			Scopes:   m.Scope,
		},
	}

	return authorizer, nil
}
