package caddy_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var ErrNoAuthorization = errors.New("no authorization provided")

type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

// OAuth2Client is an interface for the oauth2 client.
type OAuth2Client interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Scopes() []string
}

// oauth2ConfigWithHTTPClient wraps an oauth2.Config to inject an HTTP client instance for token exchange
type oauth2ConfigWithHTTPClient struct {
	httpClient *http.Client
	*oauth2.Config
}

func (c *oauth2ConfigWithHTTPClient) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	return c.Config.Exchange(ctx, code, opts...)
}

func (c *oauth2ConfigWithHTTPClient) Scopes() []string {
	return c.Config.Scopes
}

type UserInfoClient interface {
	UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error)
}

// A ClaimsDecoder is a type that can decode arbitrary claims into a value using JSON.
// The value might be a json.RawMessage.
type ClaimsDecoder interface {
	Claims(v any) error
}

// Authenticator holds the built configuration for an OIDC provider and authentication logic
type Authenticator struct {
	log               *zap.Logger
	redirectUri       *url.URL
	clock             func() time.Time
	issuer            string
	protectedResource *ProtectedResourceMetadataConfiguration
	verifier          *oidc.IDTokenVerifier
	uid               string
	claims            []string
	userInfo          UserInfoClient
	oauth2            OAuth2Client
	cookie            *Cookies
	cookies           *securecookie.SecureCookie
}

// SessionFromClaims extracts a session from claims contained within the given ClaimsDecoder.
func (au *Authenticator) SessionFromClaims(claims ClaimsDecoder) (*Session, error) {
	// A bit of a hack to extract the original claims from the decoder
	var rawClaims *json.RawMessage
	err := claims.Claims(&rawClaims)
	if err != nil {
		return nil, err
	}

	uid := gjson.GetBytes(*rawClaims, au.uid)
	if !uid.Exists() || uid.Type != gjson.String {
		return nil, fmt.Errorf("missing claim '%s' required for session username", au.uid)
	}

	session := &Session{
		Uid:    uid.String(),
		Claims: json.RawMessage(`{}`),
	}

	// Extract expiration time from claims
	exp := gjson.GetBytes(*rawClaims, "exp")
	if exp.Exists() && exp.Type == gjson.Number {
		if expUnix := exp.Int(); expUnix > 0 {
			session.ExpiresAt = expUnix
		}
	}

	// Extract claims we want to store in the session cookie
	extract := gjson.GetManyBytes(*rawClaims, au.claims...)
	for i, claim := range extract {
		if claim.Exists() {
			session.Claims, err = sjson.SetRawBytes(session.Claims, au.claims[i], []byte(claim.Raw))
			if err != nil {
				return nil, err
			}
		}
	}

	return session, nil
}

// SessionFromAuthorizationHeader extracts the session an access or ID token parsed from the request Authorization header.
// Returns ErrNoAuthorization if a valid token could not be found or a valid, signed token exists but is expired.
func (au *Authenticator) SessionFromAuthorizationHeader(r *http.Request) (*Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	id, err := au.verifier.Verify(r.Context(), parts[1])
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return au.SessionFromClaims(id)
}

// SessionFromCookie extracts the session from the secure request cookie.
// Returns ErrNoAuthorization if the cookie is not found or a signed token does exist but is not expired.
func (au *Authenticator) SessionFromCookie(r *http.Request) (*Session, error) {
	cookiePlain, err := r.Cookie(au.cookie.Name)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, errors.Join(ErrNoAuthorization, err))
	}

	var session Session
	err = au.cookies.Decode(au.cookie.Name, cookiePlain.Value, &session)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Validate the session cookie.
	// TODO refresh token exchange
	err = session.ValidateClock(au.clock())
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// AuthFromRequestSources are request token sources that are expected to return a valid non-anonymous non-expired session if the error is not-nil.
// Returning ErrNoAuthorization or *oidc.TokenExpiredError indicates that no valid token was found.
// Any other error is returned directly.
var AuthFromRequestSources = []func(*Authenticator, *http.Request) (*Session, error){
	(*Authenticator).SessionFromAuthorizationHeader,
	(*Authenticator).SessionFromCookie,
}

// Authenticate the incoming request by either reading a token from the Authorization header or the session token,
// preferring an explicit token from the Authorization header.
func (au *Authenticator) Authenticate(r *http.Request) (*Session, error) {
	for _, source := range AuthFromRequestSources {
		s, err := source(au, r)
		if err == nil {
			return s, nil
		}

		var e *oidc.TokenExpiredError
		if !errors.Is(err, ErrNoAuthorization) && !errors.As(err, &e) {
			return nil, err
		}
	}

	return AnonymousSession, nil
}

// GetAbsRedirectUri returns the absolute redirect URI, resolving it relative to the request URL if necessary.
func (au *Authenticator) GetAbsRedirectUri(r *http.Request) string {
	if au.redirectUri.IsAbs() {
		return au.redirectUri.String()
	}

	// Caddy should be sanitising X-Forwarded-Proto headers
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	var u = *r.URL
	u.Scheme = scheme
	u.Host = r.Host

	return u.ResolveReference(au.redirectUri).String()
}

// StartLogin starts the authorization flow by setting the state cookie and redirecting to the authorization endpoint.
// The state cookie is in the format of `<cookie_name>|<state>`, with the value containing the PKCE code verifier.
// The OAuth2 redirect URI is set to the configured redirect URI made absolute relative to the request URL.
func (au *Authenticator) StartLogin(w http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookieName    = fmt.Sprintf("%s|%s", au.cookie.Name, state)
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	csrfCookieValue, err := au.cookies.Encode(csrfCookieName, csrfCookiePayload)
	if err != nil {
		return err
	}

	csrfCookie := au.cookie.New(csrfCookieValue)
	csrfCookie.Name = csrfCookieName
	csrfCookie.MaxAge = 900 // 15-minute short expiry time for the CSRF cookie

	http.SetCookie(w, csrfCookie)

	authCodeUrl := au.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectUri(r)),
	)

	http.Redirect(w, r, authCodeUrl, http.StatusFound)

	return nil
}

// HandleCallback handles the callback from the authorization endpoint.
func (au *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	// Read CSRF state cookie
	var csrfCookieName = fmt.Sprintf("%s|%s", au.cookie.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Delete CSRF cookie
	deleteCsrfCookie := au.cookie.New("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(w, deleteCsrfCookie)

	// Decode PKCE code verifier from CSRF cookie
	var csrfToken CSRFToken
	err = au.cookies.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Exchange code for tokens
	response, err := au.oauth2.Exchange(r.Context(), r.FormValue("code"),
		oauth2.VerifierOption(csrfToken.PKCEVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectUri(r)),
	)

	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to exchange token: %w", err))
	}

	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no id_token in response"))
	}

	_, err = au.verifier.Verify(r.Context(), idTokenPlain)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to verify id_token: %w", err))
	}

	userInfo, err := au.userInfo.UserInfo(r.Context(), oauth2.StaticTokenSource(response))
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to fetch userinfo: %w", err))
	}

	// Generate the session cookie and set it
	session, err := au.SessionFromClaims(userInfo)
	if err != nil {
		return fmt.Errorf("failed to extract session from user info: %w", err)
	}

	// Ensure the expiry information is taken from the ID token
	session.ExpiresAt = response.Expiry.Unix()

	sessionCookie, err := session.HttpCookie(au.cookie, au.cookies)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to create session cookie: %w", err))
	}

	http.SetCookie(w, sessionCookie)

	// Redirect to the configured redirect URI
	var redirectUri = csrfToken.RedirectURI
	if redirectUri == "" {
		redirectUri = "/" // Fall back to root
	}

	http.Redirect(w, r, redirectUri, http.StatusFound)

	return nil
}

// Realm returns the realm for this authenticator based on the cookie domain and protected resource configuration.
// An explicit realm can be configured in the protected resource configuration.
// If the cookie domain is empty, then the real is based on the request host.
// https://datatracker.ietf.org/doc/html/rfc2617#section-1.2
func (au *Authenticator) Realm(r *http.Request) string {
	if au.protectedResource.Realm != "" {
		return au.protectedResource.Realm
	}

	var requestUrl = RequestUrl(r)
	var domain = au.cookie.Domain
	if domain == "" {
		domain = requestUrl.Host
	}

	var scheme = "https"
	if requestUrl.Scheme == "http" && au.cookie.Insecure {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s", scheme, domain)
}

// ProtectedResourceMetadata returns the OAuth protected resource metadata for this authenticator.
// If protected resource metadata is not enabled, then false is returned.
func (au *Authenticator) ProtectedResourceMetadata(r *http.Request) (*OAuthProtectedResource, bool) {
	if au.protectedResource.Disable {
		return nil, false
	}

	return &OAuthProtectedResource{
		Resource:        au.Realm(r),
		ScopesSupported: au.oauth2.Scopes(),
		AuthorizationServers: []string{
			au.issuer,
		},
	}, true
}

const WellKnownOAuthProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ServeHTTPOAuthProtectedResource returns the OAuth protected resource metadata for the endpoint
// .well-known/oauth-protected-resource.
// If the endpoint is disabled, then a 404 not found response is returned.
func (au *Authenticator) ServeHTTPOAuthProtectedResource(rw http.ResponseWriter, r *http.Request) error {
	rs, ok := au.ProtectedResourceMetadata(r)
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, errors.New("protected resource metadata is disabled"))
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")

	return enc.Encode(rs)
}
