package caddy_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

var (
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

// Provider holds the built configuration for an OIDC provider and authentication logic.
type Provider struct {
	log               *zap.Logger
	redirectUri       *url.URL
	clock             func() time.Time
	issuer            string
	authenticators    AuthenticatorSet
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
func (pr *Provider) SessionFromClaims(claims ClaimsDecoder) (*Session, error) {
	// A bit of a hack to extract the original claims from the decoder
	var rawClaims *json.RawMessage

	err := claims.Claims(&rawClaims)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	uid := gjson.GetBytes(*rawClaims, pr.uid)
	if !uid.Exists() || uid.Type != gjson.String {
		return nil, caddyhttp.Error(http.StatusUnauthorized, MissingRequiredClaimError{Claim: pr.uid})
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
	extract := gjson.GetManyBytes(*rawClaims, pr.claims...)
	for i, claim := range extract {
		if claim.Exists() {
			session.Claims, err = sjson.SetRawBytes(session.Claims, pr.claims[i], []byte(claim.Raw))
			if err != nil {
				return nil, err
			}
		}
	}

	return session, nil
}

// GetAbsRedirectUri returns the absolute redirect URI, resolving it relative to the request URL if necessary.
func (pr *Provider) GetAbsRedirectUri(r *http.Request) string {
	if pr.redirectUri.IsAbs() {
		return pr.redirectUri.String()
	}

	// Caddy should be sanitising X-Forwarded-Proto headers
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	var u = *r.URL

	u.Scheme = scheme
	u.Host = r.Host

	return u.ResolveReference(pr.redirectUri).String()
}

// StartLogin starts the authorization flow by setting the state cookie and redirecting to the authorization endpoint.
// The state cookie is in the format of `<cookie_name>|<state>`, with the value containing the PKCE code verifier.
// The OAuth2 redirect URI is set to the configured redirect URI made absolute relative to the request URL.
func (pr *Provider) StartLogin(rw http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookieName    = fmt.Sprintf("%s|%s", pr.cookie.Name, state)
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	csrfCookieValue, err := pr.cookies.Encode(csrfCookieName, csrfCookiePayload)
	if err != nil {
		return err
	}

	csrfCookie := pr.cookie.New(csrfCookieValue)
	csrfCookie.Name = csrfCookieName
	csrfCookie.MaxAge = 900 // 15-minute short expiry time for the CSRF cookie

	http.SetCookie(rw, csrfCookie)

	authCodeUrl := pr.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", pr.GetAbsRedirectUri(r)),
	)

	http.Redirect(rw, r, authCodeUrl, http.StatusFound)

	return nil
}

// handleCallbackParseCSRFCookie parses the CSRF cookie from the request and returns the CSRF token payload.
// If any CSRF cookie is found, then a Set-Cookie is sent to remove the cookie from the client.
func (pr *Provider) handleCallbackParseCSRFCookie(rw http.ResponseWriter, r *http.Request) (*CSRFToken, error) {
	var csrfCookieName = fmt.Sprintf("%s|%s", pr.cookie.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	// Delete CSRF cookie
	deleteCsrfCookie := pr.cookie.New("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(rw, deleteCsrfCookie)

	var csrfToken CSRFToken

	err = pr.cookies.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	return &csrfToken, nil
}

// handleCallbackOAuthCodeExchange performs the OAuth2 token exchange using the PKCE code verifier.
// It then verifies the ID token and returns the userinfo claims as well as the ID token expiry time.
func (pr *Provider) handleCallbackOAuthCodeExchange(r *http.Request, pkceVerifier string) (*oidc.UserInfo, time.Time, error) {
	response, err := pr.oauth2.Exchange(r.Context(), r.FormValue("code"),
		oauth2.VerifierOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", pr.GetAbsRedirectUri(r)),
	)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to exchange token: %w", err)
	}

	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return nil, time.Time{}, ErrNoIdToken
	}

	_, err = pr.verifier.Verify(r.Context(), idTokenPlain)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to verify id_token: %w", err)
	}

	userInfo, err := pr.userInfo.UserInfo(r.Context(), oauth2.StaticTokenSource(response))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to fetch userinfo: %w", err)
	}

	return userInfo, response.Expiry, nil
}

// HandleCallback handles the callback from the authorization endpoint.
func (pr *Provider) HandleCallback(rw http.ResponseWriter, r *http.Request) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	csrfToken, err := pr.handleCallbackParseCSRFCookie(rw, r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Exchange code for ID token
	userInfo, idTokenExpires, err := pr.handleCallbackOAuthCodeExchange(r, csrfToken.PKCEVerifier)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Generate the session cookie and set it
	session, err := pr.SessionFromClaims(userInfo)
	if err != nil {
		return fmt.Errorf("failed to extract session from user info: %w", err)
	}

	// Ensure the expiry information is taken from the ID token
	session.ExpiresAt = idTokenExpires.Unix()

	sessionCookie, err := session.HTTPCookie(pr.cookie, pr.cookies)
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
func (pr *Provider) ProtectedResourceMetadata(r *http.Request) (*OAuthProtectedResource, bool) {
	if pr.protectedResource.Disable {
		return nil, false
	}

	var (
		ru       = RequestURL(r)
		metadata = &OAuthProtectedResource{
			Resource:        fmt.Sprintf("%s://%s", ru.Scheme, ru.Host),
			ScopesSupported: pr.oauth2.Scopes(),
			AuthorizationServers: []string{
				pr.issuer,
			},
			// OIDC middleware only supports bearer authentication via the Authorization header
			BearerMethodsSupported: []string{
				"header",
			},
		}
	)

	if pr.protectedResource.Audience {
		metadata.Audience = pr.oauth2.ClientID()
	}

	return metadata, true
}

// WellKnownOAuthProtectedResourcePath is the path for the OAuth protected resource metadata endpoint.
const WellKnownOAuthProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ServeHTTPOAuthProtectedResource returns the OAuth protected resource metadata for the endpoint
// .well-known/oauth-protected-resource.
// If the endpoint is disabled, then a 404 not found response is returned.
func (pr *Provider) ServeHTTPOAuthProtectedResource(rw http.ResponseWriter, r *http.Request) error {
	metadata, ok := pr.ProtectedResourceMetadata(r)
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, errors.New("protected resource metadata is disabled"))
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")

	return enc.Encode(metadata)
}
