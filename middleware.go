package caddy_oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/tidwall/gjson"
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
	Provider string  `json:"provider"`
	Policies Ruleset `json:"policies"`

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

// interceptRequest intercepts the request and performs authentication and authorization checks.
// If returns "true" if the request was handled and a response was written.
func (mw *OIDCMiddleware) interceptRequest(rw http.ResponseWriter, r *http.Request) (bool, error) {
	au, err := mw.au.Get(r.Context())
	if err != nil {
		return false, err
	}

	// Check if the request is an OAuth callback
	if r.Method == http.MethodGet && r.URL.Path == au.redirectUri.Path {
		return true, au.HandleCallback(rw, r)
	}

	// Check for supported well-knowns
	if r.Method == http.MethodGet && r.URL.Path == WellKnownOAuthProtectedResourcePath {
		return true, au.ServeHTTPOAuthProtectedResource(rw, r)
	}

	s, err := au.Authenticate(r)
	if err != nil {
		return false, err
	}

	// Set replacer vars
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.user.anonymous", s.Anonymous)
		if !s.Anonymous {
			repl.Set("http.auth.user.id", s.Uid)
		}

		claimValues := gjson.ParseBytes(s.Claims)
		claimValues.ForEach(func(key, value gjson.Result) bool {
			var valueStringBuilder strings.Builder
			switch {
			case value.IsArray():
				for i, v := range value.Array() {
					if i > 0 {
						valueStringBuilder.WriteByte(',')
					}
					valueStringBuilder.WriteString(v.String())
				}
			default:
				valueStringBuilder.WriteString(value.String())
			}

			repl.Set(fmt.Sprintf("http.auth.user.claim.%s", key.String()), valueStringBuilder.String())
			return true
		})
	}

	// Inject session into request context
	r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, s))

	result, err := mw.Policies.Evaluate(r)
	if err != nil {
		return false, err
	}

	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.rule", result.RuleID)
		repl.Set("http.auth.result", result.Result.String())
	}

	switch result.Result {
	case EvaluationResultAllow:
		return false, nil
	case EvaluationResultExplicitDeny:
	case EvaluationResultImplicitDeny:
		// If the evaluation result is an implicit reject, then check if the session is anonymous.
		// If anonymous:
		//		Start the authorization flow if the request is likely coming from a browser.
		//		Otherwise, return a 401 Unauthorized error.
		if s.Anonymous {
			if ShouldStartLogin(r) {
				return true, au.StartLogin(rw, r)
			}

			if rs, ok := au.ProtectedResourceMetadata(r); ok {
				rw.Header().Set("WWW-Authenticate", rs.WWWAuthenticate())
			}

			return false, caddyhttp.Error(http.StatusUnauthorized, ErrAccessDenied)
		}
	}

	return false, caddyhttp.Error(http.StatusForbidden, ErrAccessDenied)
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
// It wraps interceptRequest to handle errors to ensure any error returned is a caddyhttp.HandlerError.
// Without this, Caddy's error_directive does not properly set error replacer vars,
// which can result in HTTP 200 responses when it tries to parse `{err.status_code}`.
func (mw *OIDCMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	handled, err := mw.interceptRequest(rw, r)
	if err != nil {
		var he caddyhttp.HandlerError
		if !errors.As(err, &he) {
			he = caddyhttp.Error(http.StatusInternalServerError, err)
		}

		return he
	}

	if handled {
		return nil
	}

	return next.ServeHTTP(rw, r)
}
