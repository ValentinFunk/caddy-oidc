package caddy_oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/relvacode/caddy-oidc/authenticator"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(new(OIDCProviderModule))
}

const (
	// DefaultUsernameClaim is the default username claim to use for the BearerAuthenticator if none is specified.
	DefaultUsernameClaim = "sub"
)

var _ caddy.Module = (*OIDCProviderModule)(nil)
var _ caddy.Provisioner = (*OIDCProviderModule)(nil)
var _ caddy.Validator = (*OIDCProviderModule)(nil)
var _ caddyfile.Unmarshaler = (*OIDCProviderModule)(nil)

// OIDCProviderModule holds the configuration for an OIDC provider.
type OIDCProviderModule struct {
	Issuer                    string                                  `json:"issuer"`
	ClientID                  string                                  `json:"client_id"`
	Scope                     []string                                `json:"scope,omitempty"`
	Username                  string                                  `json:"username,omitempty"`
	Authenticators            *authenticator.Set                      `json:"authenticators,omitempty"`
	TLSInsecureSkipVerify     bool                                    `json:"tls_insecure_skip_verify,omitempty"`
	ProtectedResourceMetadata *ProtectedResourceMetadataConfiguration `json:"protected_resource_metadata,omitempty"`
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
		authenticate <authenticator>
		tls_insecure_skip_verify
		scope [<scope>...]
		protected_resource <protected_resource>
	}
*/
func (m *OIDCProviderModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "issuer":
			if !d.Args(&m.Issuer) {
				return d.ArgErr()
			}
		case "client_id":
			if !d.Args(&m.ClientID) {
				return d.ArgErr()
			}

		case "username":
			if !d.Args(&m.Username) {
				return d.ArgErr()
			}
		case "authenticate":
			if m.Authenticators == nil {
				m.Authenticators = new(authenticator.Set)
			}

			err := m.Authenticators.UnmarshalCaddyfile(d)
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
		default:
			return d.Errf("unrecognized oidc subdirective '%s'", d.Val())
		}
	}

	return nil
}

func (m *OIDCProviderModule) Provision(ctx caddy.Context) error {
	if m.ProtectedResourceMetadata == nil {
		m.ProtectedResourceMetadata = new(ProtectedResourceMetadataConfiguration)
	}

	if m.Authenticators == nil {
		m.Authenticators = authenticator.NewDefaultSet()
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

	return nil
}

func (m *OIDCProviderModule) Validate() error {
	if m.Issuer == "" {
		return errors.New("issuer cannot be empty")
	}

	if m.ClientID == "" {
		return errors.New("client_id cannot be empty")
	}

	err := m.Authenticators.Validate()
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
	var (
		log        = ctx.Logger(m)
		httpClient = m.setupHTTPClient(log)
		authorizer = &Provider{
			Log:               log,
			Authenticators:    *m.Authenticators,
			Clock:             time.Now,
			ProtectedResource: m.ProtectedResourceMetadata,
			Issuer:            m.Issuer,
			UsernameClaim:     m.Username,
			Discovery: Defer[*providerDiscoveryConfiguration](func() (*providerDiscoveryConfiguration, error) {
				providerCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

				provider, err := oidc.NewProvider(providerCtx, m.Issuer)
				if err != nil {
					return nil, fmt.Errorf("oidc discovery failed: %w", err)
				}

				log.Debug("OIDC provider discovery successful", zap.Any("discovery", provider.Endpoint()))

				return &providerDiscoveryConfiguration{
					Verifier: provider.Verifier(&oidc.Config{
						ClientID: m.ClientID,
					}),
					UserInfo: provider,
					OAuth2: &oauth2ConfigWithHTTPClient{
						httpClient: httpClient,
						Config: &oauth2.Config{
							ClientID: m.ClientID,
							Endpoint: provider.Endpoint(),
							Scopes:   m.Scope,
						},
					},
				}, nil
			}),
		}
	)

	return authorizer, nil
}
