package caddy_oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/tidwall/gjson"
)

var AnonymousSession = &Session{Anonymous: true}

// A ClaimsDecoder is a type that can decode arbitrary claims into a value using JSON.
// The value might be a json.RawMessage.
type ClaimsDecoder interface {
	Claims(v any) error
}

const UidSubClaimKey UidClaim = "sub"

// UidClaim represents a JWT claim that contains the user id
type UidClaim string

// FromClaims extracts the user id from the claims
func (u UidClaim) FromClaims(claims ClaimsDecoder) (string, error) {
	var rawClaims *json.RawMessage
	err := claims.Claims(&rawClaims)
	if err != nil {
		return "", err
	}

	val := gjson.GetBytes(*rawClaims, string(u))
	if !val.Exists() || val.Type != gjson.String {
		return "", fmt.Errorf("missing claim '%s' for username", u)
	}

	return val.String(), nil
}

type Session struct {
	Uid       string `json:"u"`
	Anonymous bool   `json:"-"`
	ExpiresAt int64  `json:"e,omitempty"`
}

// HttpCookie returns the http cookie representation of the cookies
func (s *Session) HttpCookie(cookies *Cookies, encoder *securecookie.SecureCookie) (*http.Cookie, error) {
	value, err := encoder.Encode(cookies.Name, s)
	if err != nil {
		return nil, err
	}

	httpCookie := cookies.New(value)

	if s.ExpiresAt > 0 {
		httpCookie.Expires = time.Unix(s.ExpiresAt, 0)
	}

	return httpCookie, nil
}

// Expires returns the expiration time of the session.
// Returns a zero time if the session has no expiration time
func (s *Session) Expires() time.Time {
	if s.ExpiresAt == 0 {
		return time.Time{}
	}

	return time.Unix(s.ExpiresAt, 0)
}

const Leeway = time.Second * 5

// ValidateClock checks if the session is still valid.
// If the session has expired, then it returns an oidc.TokenExpiredError
func (s *Session) ValidateClock(now time.Time) error {
	if expires := s.Expires(); !expires.IsZero() && expires.Before(now.Add(-Leeway)) {
		return &oidc.TokenExpiredError{Expiry: expires}
	}

	return nil
}
