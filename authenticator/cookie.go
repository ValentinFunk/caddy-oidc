package authenticator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/relvacode/caddy-oidc/request"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/oauth2"
)

//go:generate go tool go-enum -f=$GOFILE --marshal

func init() {
	caddy.RegisterModule(new(SessionCookieAuthenticator))
}

const (
	defaultCookieName     = "caddy"
	defaultCookieSameSite = SameSiteLax
	defaultCookiePath     = "/"
	//nolint:gosec
	defaultCookieSecret = "{env.COOKIE_SECRET}"
	defaultRedirectURL  = "/oauth2/callback"
)

// ErrNoIDToken is returned when an OAuth2 code exchange response does not contain an ID token.
var ErrNoIDToken = errors.New("authentication server did not return an ID token")

// OAuthAuthorizationFlowConfiguration represents the configuration required
// to implement an OAuth2 Authorization Code Flow.
type OAuthAuthorizationFlowConfiguration interface {
	OIDCConfiguration

	AuthCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) (string, error)
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error)
}

// SameSite represents the same site attribute of a cookie.
// ENUM(lax, strict, none)
type SameSite string

func (ss SameSite) HTTPSameSite() http.SameSite {
	switch ss {
	case SameSiteLax:
		return http.SameSiteLaxMode
	case SameSiteStrict:
		return http.SameSiteStrictMode
	case SameSiteNone:
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

var (
	_ caddy.Module          = (*SessionCookieAuthenticator)(nil)
	_ caddy.Provisioner     = (*SessionCookieAuthenticator)(nil)
	_ caddy.Validator       = (*SessionCookieAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*SessionCookieAuthenticator)(nil)
	_ RequestAuthenticator  = (*SessionCookieAuthenticator)(nil)
)

// SessionCookieAuthenticator authenticates the request from a signed cookie.
type SessionCookieAuthenticator struct {
	Name        string   `json:"name,omitempty"`
	SameSite    SameSite `json:"same_site,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Path        string   `json:"path,omitempty"`
	Secret      string   `json:"secret,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	RedirectURL string   `json:"redirect_url,omitempty"`

	secure      *securecookie.SecureCookie
	redirectURL *url.URL
}

func (*SessionCookieAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.cookie",
		New: func() caddy.Module {
			return new(SessionCookieAuthenticator)
		},
	}
}

func (au *SessionCookieAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// If there's an argument, it must be the name (and no block follows)
	if d.NextArg() {
		au.Name = d.Val()
		if d.NextArg() || d.NextBlock(0) {
			return d.ArgErr()
		}

		return nil
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "name":
			if !d.Args(&au.Name) {
				return d.ArgErr()
			}
		case "same_site":
			if !d.NextArg() {
				return d.ArgErr()
			}

			ss, err := ParseSameSite(d.Val())
			if err != nil {
				return err
			}

			au.SameSite = ss
		case "insecure":
			au.Insecure = true
		case "domain":
			if !d.Args(&au.Domain) {
				return d.ArgErr()
			}
		case "path":
			if !d.Args(&au.Path) {
				return d.ArgErr()
			}
		case "claim":
			au.Claims = append(au.Claims, d.RemainingArgs()...)
		case "secret":
			if !d.Args(&au.Secret) {
				return d.ArgErr()
			}
		case "redirect_url":
			if !d.Args(&au.RedirectURL) {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized cookie subdirective: %s", d.Val())
		}
	}

	return nil
}

func (au *SessionCookieAuthenticator) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()

	var err error

	if au.Name == "" {
		au.Name = defaultCookieName
	}

	au.Name, err = repl.ReplaceOrErr(au.Name, true, true)
	if err != nil {
		return err
	}

	if au.Path == "" {
		au.Path = defaultCookiePath
	}

	au.Path, err = repl.ReplaceOrErr(au.Path, false, true)
	if err != nil {
		return err
	}

	au.Domain, err = repl.ReplaceOrErr(au.Domain, false, true)
	if err != nil {
		return err
	}

	if au.SameSite == "" {
		au.SameSite = defaultCookieSameSite
	}

	if au.Secret == "" {
		au.Secret = defaultCookieSecret
	}

	au.Secret, err = repl.ReplaceOrErr(au.Secret, true, true)
	if err != nil {
		return err
	}

	if len(au.Secret) != 32 && len(au.Secret) != 64 {
		return errors.New("secret must be 32 or 64 bytes")
	}

	au.secure = securecookie.New([]byte(au.Secret), []byte(au.Secret))
	au.secure.SetSerializer(&securecookie.JSONEncoder{})

	if au.RedirectURL == "" {
		au.RedirectURL = defaultRedirectURL
	}

	au.RedirectURL, err = repl.ReplaceOrErr(au.RedirectURL, true, true)
	if err != nil {
		return err
	}

	au.redirectURL, err = url.Parse(au.RedirectURL)
	if err != nil {
		return fmt.Errorf("invalid redirect_url: %w", err)
	}

	return nil
}

func (au *SessionCookieAuthenticator) Validate() error {
	if au.Name == "" {
		return errors.New("cookie name is required")
	}

	if !au.SameSite.IsValid() {
		return fmt.Errorf("invalid cookie same_site value: %s", au.SameSite)
	}

	return nil
}

func (*SessionCookieAuthenticator) Method() AuthMethod { return AuthMethodCookie }

func (au *SessionCookieAuthenticator) AuthenticateRequest(cfg OIDCConfiguration, r *http.Request) (*session.Session, error) {
	cookiePlain, err := r.Cookie(au.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
		}

		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	var s session.Session

	err = au.secure.Decode(au.Name, cookiePlain.Value, &s)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	err = s.ValidateClock(cfg.Now())
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (au *SessionCookieAuthenticator) NewCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     au.Name,
		Value:    value,
		SameSite: au.SameSite.HTTPSameSite(),
		Path:     au.Path,
		Domain:   au.Domain,
		HttpOnly: true,
		Secure:   !au.Insecure,
	}
}

// CSRFToken is the CSRF cookie payload when perform an OAuth2 Authorization Flow.
type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

// GetAbsRedirectURI returns the absolute redirect URI, resolving it relative to the request URL if necessary.
func (au *SessionCookieAuthenticator) GetAbsRedirectURI(r *http.Request) *url.URL {
	if au.redirectURL.IsAbs() {
		return au.redirectURL
	}

	return request.URL(r).ResolveReference(au.redirectURL)
}

// StartLogin starts the authorization flow by setting the state cookie and redirecting to the authorization endpoint.
// The state cookie is in the format of `<cookie_name>|<state>`, with the value containing the PKCE code verifier.
// The OAuth2 redirect URI is set to the configured redirect URI made absolute relative to the request URL.
func (au *SessionCookieAuthenticator) StartLogin(cfg OAuthAuthorizationFlowConfiguration, rw http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookieName    = fmt.Sprintf("%s|%s", au.Name, state)
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	csrfCookieValue, err := au.secure.Encode(csrfCookieName, csrfCookiePayload)
	if err != nil {
		return err
	}

	csrfCookie := au.NewCookie(csrfCookieValue)
	csrfCookie.Name = csrfCookieName
	csrfCookie.MaxAge = 900 // 15-minute short expiry time for the CSRF cookie

	http.SetCookie(rw, csrfCookie)

	authCodeURL, err := cfg.AuthCodeURL(r.Context(), state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectURI(r).String()),
	)
	if err != nil {
		return err
	}

	http.Redirect(rw, r, authCodeURL, http.StatusFound)

	return nil
}

// handleCallbackParseCSRFCookie parses the CSRF cookie from the request and returns the CSRF token payload.
// If any CSRF cookie is found, then a Set-Cookie is sent to remove the cookie from the client.
func (au *SessionCookieAuthenticator) handleCallbackParseCSRFCookie(rw http.ResponseWriter, r *http.Request) (*CSRFToken, error) {
	var csrfCookieName = fmt.Sprintf("%s|%s", au.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	// Delete CSRF cookie
	deleteCsrfCookie := au.NewCookie("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(rw, deleteCsrfCookie)

	var csrfToken CSRFToken

	err = au.secure.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	return &csrfToken, nil
}

// handleCodeExchange performs the OAuth2 token exchange using the PKCE code Verifier.
// It then verifies the ID token and returns the userinfo claims as well as the ID token expiry time.
func (au *SessionCookieAuthenticator) handleCodeExchange(
	cfg OAuthAuthorizationFlowConfiguration,
	r *http.Request,
	pkceVerifier string,
) (*oidc.UserInfo, time.Time, error) {
	response, err := cfg.Exchange(r.Context(), r.FormValue("code"),
		oauth2.VerifierOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectURI(r).String()),
	)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to exchange token: %w", err)
	}

	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return nil, time.Time{}, ErrNoIDToken
	}

	verifier, err := cfg.GetVerifier(r.Context())
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to get verifier: %w", err)
	}

	_, err = verifier.Verify(r.Context(), idTokenPlain)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to verify id_token: %w", err)
	}

	userInfo, err := cfg.UserInfo(r.Context(), oauth2.StaticTokenSource(response))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to fetch userinfo: %w", err)
	}

	return userInfo, response.Expiry, nil
}

// IsCallbackURL returns true if the request is a callback from the authorization endpoint.
// Determined if the absolute form of the redirect URI relative to the current request
// matches the scheme, host, and path of the current request.
func (au *SessionCookieAuthenticator) IsCallbackURL(r *http.Request) bool {
	var (
		req      = request.URL(r)
		redirect = au.GetAbsRedirectURI(r)
	)

	return req.Scheme == redirect.Scheme && req.Host == redirect.Host && req.Path == redirect.Path
}

// HandleCallback handles the callback from the authorization endpoint.
func (au *SessionCookieAuthenticator) HandleCallback(cfg OAuthAuthorizationFlowConfiguration, rw http.ResponseWriter, r *http.Request) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	csrfToken, err := au.handleCallbackParseCSRFCookie(rw, r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Exchange code for ID token
	userInfo, idTokenExpires, err := au.handleCodeExchange(cfg, r, csrfToken.PKCEVerifier)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	var jsonClaims *json.RawMessage

	err = userInfo.Claims(&jsonClaims)
	if err != nil {
		return fmt.Errorf("failed to extract claims from user info: %w", err)
	}

	uidJSON := gjson.GetBytes(*jsonClaims, cfg.GetUsernameClaim())
	if !uidJSON.Exists() || uidJSON.Type != gjson.String {
		return fmt.Errorf("invalid response from user info endpoint: %w", session.MissingRequiredClaimError{Claim: cfg.GetUsernameClaim()})
	}

	s := &session.Session{
		UID:       uidJSON.String(),
		Claims:    json.RawMessage(`{}`),
		ExpiresAt: idTokenExpires.Unix(),
	}

	// Copy claims
	claimValues := gjson.GetManyBytes(*jsonClaims, au.Claims...)
	for i, claimValue := range claimValues {
		if claimValue.Exists() {
			s.Claims, err = sjson.SetBytes(s.Claims, au.Claims[i], claimValue.Raw)
			if err != nil {
				return fmt.Errorf("failed to set claim %s: %w", au.Claims[i], err)
			}
		}
	}

	cookieValue, err := au.secure.Encode(au.Name, s)
	if err != nil {
		return fmt.Errorf("failed to encode session cookie: %w", err)
	}

	http.SetCookie(rw, au.NewCookie(cookieValue))

	// Redirect to the configured redirect URI
	var redirectURI = csrfToken.RedirectURI
	if redirectURI == "" {
		redirectURI = "/" // Fall back to root
	}

	http.Redirect(rw, r, redirectURI, http.StatusFound)

	return nil
}

func (au *SessionCookieAuthenticator) StripRequest(r *http.Request) {
	// Read all cookies and only keep any that aren't our session cookie
	cookies := slices.DeleteFunc(r.Cookies(), func(cookie *http.Cookie) bool {
		return cookie.Name == au.Name
	})

	// Delete any original Cookie header
	r.Header.Del("Cookie")

	// Add any remaining cookies back to the request
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
}
