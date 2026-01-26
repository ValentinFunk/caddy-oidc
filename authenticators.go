package caddy_oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tidwall/sjson"
)

//go:generate go tool go-enum -f=$GOFILE --marshal

func init() {
	caddy.RegisterModule(new(NoneAuthenticator))
	caddy.RegisterModule(new(BearerAuthenticator))
	caddy.RegisterModule(new(SessionCookieAuthenticator))
}

// AuthMethod represents one of the supported authentication methods.
// ENUM(none, bearer, cookie)
type AuthMethod string

// ErrNoAuthentication is returned when no valid authentication could be found in the request.
var ErrNoAuthentication = errors.New("no valid authentication credentials provided")

type RequestAuthenticator interface {
	// Method returns the authentication method type provided by this RequestAuthenticator
	Method() AuthMethod

	// AuthenticateRequest extracts authentication session information from the incoming request.
	// If the request does not contain valid authentication then it must return ErrNoAuthentication.
	AuthenticateRequest(au *Provider, r *http.Request) (*Session, error)
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

func (*NoneAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (*NoneAuthenticator) Method() AuthMethod { return AuthMethodNone }

func (*NoneAuthenticator) AuthenticateRequest(_ *Provider, _ *http.Request) (*Session, error) {
	return AnonymousSession(), nil
}

var (
	_ caddy.Module          = (*BearerAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*BearerAuthenticator)(nil)
	_ RequestAuthenticator  = (*BearerAuthenticator)(nil)
)

// BearerAuthenticator authenticates the request from a JWT found in the "Authorization" header.
type BearerAuthenticator struct{}

func (*BearerAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.bearer",
		New: func() caddy.Module {
			return new(BearerAuthenticator)
		},
	}
}

func (*BearerAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (*BearerAuthenticator) Method() AuthMethod { return AuthMethodBearer }

func (*BearerAuthenticator) AuthenticateRequest(pr *Provider, r *http.Request) (*Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	parts := strings.SplitN(authHeader, " ", 2) //nolint:mnd
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	id, err := pr.verifier.Verify(r.Context(), parts[1])
	if err != nil {
		// An expired token is treated as unauthenticated
		var te *oidc.TokenExpiredError
		if errors.As(err, &te) {
			return nil, ErrNoAuthentication
		}

		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	s, err := pr.SessionFromClaims(id)
	if err != nil {
		return nil, err
	}

	return s, nil
}

var (
	_ caddy.Module          = (*SessionCookieAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*SessionCookieAuthenticator)(nil)
	_ RequestAuthenticator  = (*SessionCookieAuthenticator)(nil)
)

// SessionCookieAuthenticator authenticates the request from a signed cookie.
type SessionCookieAuthenticator struct{}

func (*SessionCookieAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.cookie",
		New: func() caddy.Module {
			return new(SessionCookieAuthenticator)
		},
	}
}

func (*SessionCookieAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (*SessionCookieAuthenticator) Method() AuthMethod { return AuthMethodCookie }

func (*SessionCookieAuthenticator) AuthenticateRequest(pr *Provider, r *http.Request) (*Session, error) {
	cookiePlain, err := r.Cookie(pr.cookie.Name)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, errors.Join(ErrNoAuthentication, err))
	}

	var session Session

	err = pr.cookies.Decode(pr.cookie.Name, cookiePlain.Value, &session)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	err = session.ValidateClock(pr.clock())
	if err != nil {
		return nil, err
	}

	return &session, nil
}

var (
	_ caddyfile.Unmarshaler = (*AuthenticatorSet)(nil)
	_ caddy.Provisioner     = (*AuthenticatorSet)(nil)
	_ caddy.Validator       = (*AuthenticatorSet)(nil)
)

type AuthenticatorSet struct {
	AuthenticatorsRaw []json.RawMessage      `caddy:"namespace=http.oidc.authenticators inline_key=authenticator" json:"authenticators"`
	Authenticators    []RequestAuthenticator `json:"-"`
}

// NewDefaultAuthenticatorSet returns the default set of authenticators.
func NewDefaultAuthenticatorSet() *AuthenticatorSet {
	return &AuthenticatorSet{
		AuthenticatorsRaw: []json.RawMessage{
			json.RawMessage(`{"authenticator": "bearer"}`),
			json.RawMessage(`{"authenticator": "cookie"}`),
			json.RawMessage(`{"authenticator": "none"}`),
		},
	}
}

func (am *AuthenticatorSet) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	type RequestAuthenticatorAndCaddyfileUnmarshaler interface {
		caddyfile.Unmarshaler
		RequestAuthenticator
	}

	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		authenticatorName := d.Val()

		mod, err := caddy.GetModule("http.oidc.authenticators." + authenticatorName)
		if err != nil {
			return d.Errf("getting authenticator module '%s': %v", authenticatorName, err)
		}

		unm, ok := mod.New().(RequestAuthenticatorAndCaddyfileUnmarshaler)
		if !ok {
			return d.Errf("authenticator module '%s' is not a Caddyfile unmarshaler", authenticatorName)
		}

		err = unm.UnmarshalCaddyfile(d)
		if err != nil {
			return err
		}

		jsonBytes, err := json.Marshal(unm)
		if err == nil {
			jsonBytes, err = sjson.SetBytes(jsonBytes, "authenticator", authenticatorName)
		}

		if err != nil {
			return d.Errf("marshaling authenticator module '%s': %v", authenticatorName, err)
		}

		am.AuthenticatorsRaw = append(am.AuthenticatorsRaw, jsonBytes)
	}

	return nil
}

func (am *AuthenticatorSet) Provision(ctx caddy.Context) error {
	modules, err := ctx.LoadModule(am, "AuthenticatorsRaw")
	if err != nil {
		return err
	}

	for _, mod := range modules.([]any) {
		impl, ok := mod.(RequestAuthenticator)
		if !ok {
			return errors.New("loaded module is not a valid RequestAuthenticator implementation")
		}

		am.Authenticators = append(am.Authenticators, impl)
	}

	return nil
}

func (am *AuthenticatorSet) Validate() error {
	if len(am.Authenticators) == 0 {
		return errors.New("no request authenticators configured")
	}

	return nil
}

// AuthenticateRequest attempts to authenticate the request using the configured authenticators.
// It returns the first successful authentication method and session,
// or AuthMethodNone and AnonymousSession with ErrNoAuthentication wrapped in a caddyhttp.Error if no authenticator succeeds.
func (am *AuthenticatorSet) AuthenticateRequest(pr *Provider, r *http.Request) (AuthMethod, *Session, error) {
	for _, authenticator := range am.Authenticators {
		session, err := authenticator.AuthenticateRequest(pr, r)
		if err == nil {
			return authenticator.Method(), session, nil
		}
		if !errors.Is(err, ErrNoAuthentication) {
			return AuthMethodNone, nil, err
		}
	}

	return AuthMethodNone, AnonymousSession(), caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
}
