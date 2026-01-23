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

//go:generate go tool go-enum -f=$GOFILE --marshal

var (
	// ErrNoAuthentication is returned when no valid authentication could be found in the request.
	ErrNoAuthentication = errors.New("no valid authentication credentials provided")
	// ErrNoIdToken is returned when an OAuth2 code exchange response does not contain an ID token.
	ErrNoIdToken = errors.New("authentication server did not return an ID token")
)

// MissingRequiredClaimError is returned when a required claim is not provided.
type MissingRequiredClaimError struct {
	Claim string
}

func (e MissingRequiredClaimError) Error() string {
	return fmt.Sprintf("request authentication is missing the required claim '%s'", e.Claim)
}

// AuthMethod represents one of the supported authentication methods.
// ENUM(none, bearer, cookie)
type AuthMethod string

// CSRFToken is the CSRF cookie payload when perform an OAuth2 Authorization Flow.
type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

// oauth2Client is an interface for the oauth2 client.
type oauth2Client interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Scopes() []string
	ClientID() string
}

// oauth2ConfigWithHTTPClient wraps an oauth2.Config to inject an HTTP client instance for token exchange.
type oauth2ConfigWithHTTPClient struct {
	*oauth2.Config

	httpClient *http.Client
}

func (c *oauth2ConfigWithHTTPClient) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)

	return c.Config.Exchange(ctx, code, opts...)
}

func (c *oauth2ConfigWithHTTPClient) Scopes() []string {
	return c.Config.Scopes
}

func (c *oauth2ConfigWithHTTPClient) ClientID() string {
	return c.Config.ClientID
}

type userInfoClient interface {
	UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error)
}

// A ClaimsDecoder is a type that can decode arbitrary claims into a value using JSON.
// The value might be a json.RawMessage.
type ClaimsDecoder interface {
	Claims(v any) error
}

// Authenticator holds the built configuration for an OIDC provider and authentication logic.
type Authenticator struct {
	log               *zap.Logger
	redirectUri       *url.URL
	clock             func() time.Time
	issuer            string
	protectedResource *ProtectedResourceMetadataConfiguration
	verifier          *oidc.IDTokenVerifier
	uid               string
	claims            []string
	userInfo          userInfoClient
	oauth2            oauth2Client
	cookie            *Cookies
	cookies           *securecookie.SecureCookie
}

// SessionFromClaims extracts a session from claims contained within the given ClaimsDecoder.
func (au *Authenticator) SessionFromClaims(claims ClaimsDecoder) (*Session, error) {
	// A bit of a hack to extract the original claims from the decoder
	var rawClaims *json.RawMessage

	err := claims.Claims(&rawClaims)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	uid := gjson.GetBytes(*rawClaims, au.uid)
	if !uid.Exists() || uid.Type != gjson.String {
		return nil, caddyhttp.Error(http.StatusUnauthorized, MissingRequiredClaimError{Claim: au.uid})
	}

	session := &Session{
		UID:    uid.String(),
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
// Returns ErrNoAuthentication if a valid token could not be found or a valid, signed token exists but is expired.
func (au *Authenticator) SessionFromAuthorizationHeader(r *http.Request) (AuthMethod, *Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return AuthMethodNone, nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	parts := strings.SplitN(authHeader, " ", 2) //nolint:mnd
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return AuthMethodNone, nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	id, err := au.verifier.Verify(r.Context(), parts[1])
	if err != nil {
		return AuthMethodNone, nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	s, err := au.SessionFromClaims(id)
	if err != nil {
		return AuthMethodNone, nil, err
	}

	return AuthMethodBearer, s, nil
}

// SessionFromCookie extracts the session from the secure request cookie.
// Returns ErrNoAuthentication if the cookie is not found or a signed token does exist but is not expired.
func (au *Authenticator) SessionFromCookie(r *http.Request) (AuthMethod, *Session, error) {
	cookiePlain, err := r.Cookie(au.cookie.Name)
	if err != nil {
		return AuthMethodNone, nil, caddyhttp.Error(http.StatusUnauthorized, errors.Join(ErrNoAuthentication, err))
	}

	var session Session

	err = au.cookies.Decode(au.cookie.Name, cookiePlain.Value, &session)
	if err != nil {
		return AuthMethodNone, nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Validate the session cookie.
	err = session.ValidateClock(au.clock())
	if err != nil {
		return AuthMethodNone, nil, err
	}

	return AuthMethodCookie, &session, nil
}

// authFromRequestSources are request token sources that are expected to return a valid non-anonymous non-expired session if the error is not-nil.
// Returning ErrNoAuthentication or *oidc.TokenExpiredError indicates that no valid token was found.
// Any other error is returned directly.
//
//nolint:gochecknoglobals
var authFromRequestSources = []func(*Authenticator, *http.Request) (AuthMethod, *Session, error){
	(*Authenticator).SessionFromAuthorizationHeader,
	(*Authenticator).SessionFromCookie,
}

// Authenticate the incoming request by either reading a token from the Authorization header or the session token,
// preferring an explicit token from the Authorization header.
func (au *Authenticator) Authenticate(r *http.Request) (AuthMethod, *Session, error) {
	for _, source := range authFromRequestSources {
		m, s, err := source(au, r)
		if err == nil {
			return m, s, nil
		}

		var e *oidc.TokenExpiredError
		if !errors.Is(err, ErrNoAuthentication) && !errors.As(err, &e) {
			return AuthMethodNone, nil, err
		}
	}

	var anon = AnonymousSession()

	return AuthMethodNone, &anon, nil
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
func (au *Authenticator) StartLogin(rw http.ResponseWriter, r *http.Request) error {
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

	http.SetCookie(rw, csrfCookie)

	authCodeUrl := au.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectUri(r)),
	)

	http.Redirect(rw, r, authCodeUrl, http.StatusFound)

	return nil
}

// handleCallbackParseCSRFCookie parses the CSRF cookie from the request and returns the CSRF token payload.
// If any CSRF cookie is found, then a Set-Cookie is sent to remove the cookie from the client.
func (au *Authenticator) handleCallbackParseCSRFCookie(rw http.ResponseWriter, r *http.Request) (*CSRFToken, error) {
	var csrfCookieName = fmt.Sprintf("%s|%s", au.cookie.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	// Delete CSRF cookie
	deleteCsrfCookie := au.cookie.New("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(rw, deleteCsrfCookie)

	var csrfToken CSRFToken

	err = au.cookies.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	return &csrfToken, nil
}

// handleCallbackOAuthCodeExchange performs the OAuth2 token exchange using the PKCE code verifier.
// It then verifies the ID token and returns the userinfo claims as well as the ID token expiry time.
func (au *Authenticator) handleCallbackOAuthCodeExchange(r *http.Request, pkceVerifier string) (*oidc.UserInfo, time.Time, error) {
	response, err := au.oauth2.Exchange(r.Context(), r.FormValue("code"),
		oauth2.VerifierOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectUri(r)),
	)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to exchange token: %w", err)
	}

	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return nil, time.Time{}, ErrNoIdToken
	}

	_, err = au.verifier.Verify(r.Context(), idTokenPlain)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to verify id_token: %w", err)
	}

	userInfo, err := au.userInfo.UserInfo(r.Context(), oauth2.StaticTokenSource(response))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to fetch userinfo: %w", err)
	}

	return userInfo, response.Expiry, nil
}

// HandleCallback handles the callback from the authorization endpoint.
func (au *Authenticator) HandleCallback(rw http.ResponseWriter, r *http.Request) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	csrfToken, err := au.handleCallbackParseCSRFCookie(rw, r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Exchange code for ID token
	userInfo, idTokenExpires, err := au.handleCallbackOAuthCodeExchange(r, csrfToken.PKCEVerifier)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Generate the session cookie and set it
	session, err := au.SessionFromClaims(userInfo)
	if err != nil {
		return fmt.Errorf("failed to extract session from user info: %w", err)
	}

	// Ensure the expiry information is taken from the ID token
	session.ExpiresAt = idTokenExpires.Unix()

	sessionCookie, err := session.HTTPCookie(au.cookie, au.cookies)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to create session cookie: %w", err))
	}

	http.SetCookie(rw, sessionCookie)

	// Redirect to the configured redirect URI
	var redirectUri = csrfToken.RedirectURI
	if redirectUri == "" {
		redirectUri = "/" // Fall back to root
	}

	http.Redirect(rw, r, redirectUri, http.StatusFound)

	return nil
}

// ProtectedResourceMetadata returns the OAuth protected resource metadata for this authenticator.
// If protected resource metadata is not enabled, then false is returned.
func (au *Authenticator) ProtectedResourceMetadata(r *http.Request) (*OAuthProtectedResource, bool) {
	if au.protectedResource.Disable {
		return nil, false
	}

	var (
		ru       = RequestURL(r)
		metadata = &OAuthProtectedResource{
			Resource:        fmt.Sprintf("%s://%s", ru.Scheme, ru.Host),
			ScopesSupported: au.oauth2.Scopes(),
			AuthorizationServers: []string{
				au.issuer,
			},
			// OIDC middleware only supports bearer authentication via the Authorization header
			BearerMethodsSupported: []string{
				"header",
			},
		}
	)

	if au.protectedResource.Audience {
		metadata.Audience = au.oauth2.ClientID()
	}

	return metadata, true
}

// WellKnownOAuthProtectedResourcePath is the path for the OAuth protected resource metadata endpoint.
const WellKnownOAuthProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ServeHTTPOAuthProtectedResource returns the OAuth protected resource metadata for the endpoint
// .well-known/oauth-protected-resource.
// If the endpoint is disabled, then a 404 not found response is returned.
func (au *Authenticator) ServeHTTPOAuthProtectedResource(rw http.ResponseWriter, r *http.Request) error {
	metadata, ok := au.ProtectedResourceMetadata(r)
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, errors.New("protected resource metadata is disabled"))
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")

	return enc.Encode(metadata)
}
