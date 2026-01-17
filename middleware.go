package caddy_oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(new(OIDCMiddleware))
	httpcaddyfile.RegisterHandlerDirective("oidc", parseCaddyfileHandler[OIDCMiddleware])
	httpcaddyfile.RegisterDirectiveOrder("oidc", httpcaddyfile.Before, "basicauth")
}

var ErrAccessDenied = errors.New("access denied")

var _ caddy.Module = (*OIDCMiddleware)(nil)
var _ caddy.Provisioner = (*OIDCMiddleware)(nil)
var _ caddy.Validator = (*OIDCMiddleware)(nil)
var _ caddyfile.Unmarshaler = (*OIDCMiddleware)(nil)
var _ caddyhttp.MiddlewareHandler = (*OIDCMiddleware)(nil)

type OIDCMiddleware struct {
	Provider string    `json:"provider"`
	Policies PolicySet `json:"policies"`

	au *DeferredResult[*Authenticator]
}

func (mw *OIDCMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidc",
		New: func() caddy.Module { return new(OIDCMiddleware) },
	}
}

// UnmarshalCaddyfile sets up the OIDCMiddleware from Caddyfile tokens.
/*
oidc example {
	allow|deny {
		...
	}
}
*/
func (mw *OIDCMiddleware) UnmarshalCaddyfile(dis *caddyfile.Dispenser) error {
	for dis.Next() {
		if !dis.NextArg() {
			return dis.ArgErr()
		}
		mw.Provider = dis.Val()

		err := mw.Policies.UnmarshalCaddyfile(dis)
		if err != nil {
			return err
		}
	}

	return nil
}

func (mw *OIDCMiddleware) Provision(ctx caddy.Context) error {
	val, err := ctx.AppIfConfigured(ModuleID)
	if err != nil {
		return err
	}

	app := val.(*App)

	au, ok := app.provided[mw.Provider]
	if !ok {
		return fmt.Errorf("oidc provider '%s' not configured", mw.Provider)
	}

	mw.au = au

	err = mw.Policies.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (mw *OIDCMiddleware) Validate() error {
	return mw.Policies.Validate()
}

func (mw *OIDCMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	au, err := mw.au.Get(r.Context())
	if err != nil {
		return err
	}

	// Check if the request is an OAuth callback
	if r.Method == http.MethodGet && r.URL.Path == au.redirectUri.Path {
		return au.HandleCallback(rw, r, next)
	}

	// Check for supported well-knowns
	if r.Method == http.MethodGet && r.URL.Path == WellKnownOAuthProtectedResourcePath {
		return au.ServeHTTPOAuthProtectedResource(rw, r)
	}

	s, err := au.Authenticate(r)
	if err != nil {
		return err
	}

	// Set replacer vars
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.user.anonymous", s.Anonymous)
		if !s.Anonymous {
			repl.Set("http.auth.user.id", s.Uid)
		}
	}

	// Inject session into request context
	r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, s))

	e, err := mw.Policies.Evaluate(r)
	if err != nil {
		return err
	}

	switch e {
	case Permit:
		return next.ServeHTTP(rw, r)
	case RejectExplicit:
	case RejectImplicit:
		// If the evaluation result is an implicit reject, then check if the session is anonymous.
		// If anonymous:
		//		Start the authorization flow if the request is likely coming from a browser.
		//		Otherwise, return a 401 Unauthorized error.
		if s.Anonymous {
			if ShouldStartLogin(r) {
				return au.StartLogin(rw, r)
			}

			if rs, ok := au.ProtectedResourceMetadata(r); ok {
				rw.Header().Set("WWW-Authenticate", rs.WWWAuthenticate())
			}

			return caddyhttp.Error(http.StatusUnauthorized, ErrAccessDenied)
		}
	default:
		// impossible
		panic("invalid policy evaluation result")
	}

	return caddyhttp.Error(http.StatusForbidden, ErrAccessDenied)
}
