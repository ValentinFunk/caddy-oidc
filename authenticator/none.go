package authenticator

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/relvacode/caddy-oidc/session"
)

func init() {
	caddy.RegisterModule(new(NoneAuthenticator))
}

var (
	_ caddy.Module          = (*NoneAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*NoneAuthenticator)(nil)
	_ RequestAuthenticator  = (*NoneAuthenticator)(nil)
)

// NoneAuthenticator always returns an anonymous session from the request.
type NoneAuthenticator struct{}

func (*NoneAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.none",
		New: func() caddy.Module {
			return new(NoneAuthenticator)
		},
	}
}

func (*NoneAuthenticator) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error { return nil }

func (*NoneAuthenticator) Method() AuthMethod { return AuthMethodNone }

func (*NoneAuthenticator) AuthenticateRequest(_ OIDCConfiguration, _ *http.Request) (*session.Session, error) {
	return session.Anonymous(), nil
}
