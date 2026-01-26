package authenticator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/tidwall/gjson"
)

func init() {
	caddy.RegisterModule(new(BearerAuthenticator))
}

var (
	_ caddy.Module          = (*BearerAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*BearerAuthenticator)(nil)
	_ RequestAuthenticator  = (*BearerAuthenticator)(nil)
)

// MissingRequiredClaimError is returned when a required claim is not provided.
type MissingRequiredClaimError struct {
	Claim string
}

func (e MissingRequiredClaimError) Error() string {
	return fmt.Sprintf("request authentication is missing the required claim '%s'", e.Claim)
}

// BearerAuthenticator authenticates the request from a JWT found in the "Authorization" header.
type BearerAuthenticator struct {
}

func (*BearerAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.bearer",
		New: func() caddy.Module {
			return new(BearerAuthenticator)
		},
	}
}

func (au *BearerAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

func (*BearerAuthenticator) Method() AuthMethod { return AuthMethodBearer }

func (au *BearerAuthenticator) SessionFromIDToken(cfg OIDCConfiguration, id *oidc.IDToken) (*session.Session, error) {
	// A bit of a hack to extract the original claims from the decoder
	var rawClaims *json.RawMessage

	err := id.Claims(&rawClaims)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	uid := gjson.GetBytes(*rawClaims, cfg.GetUsernameClaim())
	if !uid.Exists() || uid.Type != gjson.String {
		return nil, caddyhttp.Error(http.StatusUnauthorized, MissingRequiredClaimError{Claim: cfg.GetUsernameClaim()})
	}

	return &session.Session{
		UID:    uid.String(),
		Claims: *rawClaims,

		// Expiry deliberately omitted as the OIDC verifier configuration will verify the token exp claim
	}, nil
}

func (au *BearerAuthenticator) AuthenticateRequest(cfg OIDCConfiguration, r *http.Request) (*session.Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	parts := strings.SplitN(authHeader, " ", 2) //nolint:mnd
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	verifier, err := cfg.GetVerifier(r.Context())
	if err != nil {
		return nil, err
	}

	id, err := verifier.Verify(r.Context(), parts[1])
	if err != nil {
		// An expired token is treated as unauthenticated
		var te *oidc.TokenExpiredError
		if errors.As(err, &te) {
			return nil, ErrNoAuthentication
		}

		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return au.SessionFromIDToken(cfg, id)
}
