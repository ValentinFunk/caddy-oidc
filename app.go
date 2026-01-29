// Package caddy_oidc is a Caddy plugin for providing authentication and authorization using an OIDC IdP
package caddy_oidc

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	_ "github.com/relvacode/caddy-oidc/authenticator" // Registers the built-in authenticator modules
)

const moduleID = "oidc"

func init() {
	caddy.RegisterModule(new(App))
	httpcaddyfile.RegisterGlobalOption("oidc", parseGlobalConfig)
}

func parseGlobalConfig(d *caddyfile.Dispenser, prev any) (any, error) {
	var app App

	switch prev := prev.(type) {
	case httpcaddyfile.App:
		err := json.Unmarshal(prev.Value, &app)
		if err != nil {
			return nil, err
		}
	case nil:
		app.Providers = make(map[string]*OIDCProviderModule)
	default:
		return nil, fmt.Errorf("conflicting global parser option for the oidc directive: %T", prev)
	}

	for d.Next() {
		if !d.NextArg() {
			return nil, d.ArgErr()
		}

		var name = d.Val()

		var config OIDCProviderModule

		err := config.UnmarshalCaddyfile(d)
		if err != nil {
			return nil, err
		}

		app.Providers[name] = &config
	}

	return httpcaddyfile.App{
		Name:  moduleID,
		Value: caddyconfig.JSON(&app, nil),
	}, nil
}

//nolint:ireturn
func parseCaddyfileHandler[T any, Ptr interface {
	*T
	caddyfile.Unmarshaler
	caddyhttp.MiddlewareHandler
}](h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(T)

	err := Ptr(handler).UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}

	return Ptr(handler), nil
}

var _ caddy.App = (*App)(nil)
var _ caddy.Module = (*App)(nil)
var _ caddy.Validator = (*App)(nil)
var _ caddy.Provisioner = (*App)(nil)

// App holds configuration for all the named OIDC providers within a Caddy configuration.
type App struct {
	Providers map[string]*OIDCProviderModule `json:"providers,omitempty"`
	provided  map[string]*Provider
}

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  moduleID,
		New: func() caddy.Module { return new(App) },
	}
}

func (*App) Start() error { return nil }
func (*App) Stop() error  { return nil }

func (a *App) Provision(ctx caddy.Context) error {
	a.provided = make(map[string]*Provider, len(a.Providers))

	for providerName := range a.Providers {
		var provider = a.Providers[providerName]

		err := provider.Provision(ctx)
		if err != nil {
			return fmt.Errorf("failed to provision oidc provider '%s': %w", providerName, err)
		}

		cfg, err := provider.Create(ctx)
		if err != nil {
			return fmt.Errorf("failed to create oidc provider configuration '%s': %w", providerName, err)
		}

		// Built authenticator configuration is deferred as we don't want to block provision during OIDC discovery.
		// Doing so might mean discovery isn't even possible until Caddy fully initializes if the IDP is proxied by Caddy as well.
		a.provided[providerName] = cfg
	}

	return nil
}

func (a *App) Validate() error {
	for k, p := range a.Providers {
		err := p.Validate()
		if err != nil {
			return fmt.Errorf("oidc provider '%s' validation failed: %w", k, err)
		}
	}

	return nil
}
