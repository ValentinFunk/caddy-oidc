package session

import (
	"encoding/json"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Anonymous returns a session to use when a request is unauthenticated.
func Anonymous() *Session {
	return &Session{
		Anonymous: true,
		Claims:    json.RawMessage(`{}`),
	}
}

// Session represents an authentication session.
// A session can be one that is authenticated (anonymous) or authenticated with a user identity.
// A session may optionally expire.
type Session struct {
	Anonymous bool            `json:"-"`
	UID       string          `json:"u"`
	ExpiresAt int64           `json:"e,omitempty"`
	Claims    json.RawMessage `json:"c,omitempty"`
}

// Expires returns the expiration time of the session.
// Returns a zero time if the session has no expiration time.
func (s *Session) Expires() time.Time {
	if s.ExpiresAt == 0 {
		return time.Time{}
	}

	return time.Unix(s.ExpiresAt, 0)
}

// Leeway is the amount of leeway permitted in a session's expiration time
// allowing for clock skew between the authenticator and the client.
const Leeway = time.Second * 5

// ValidateClock checks if the session is still valid.
// If the session has expired, then it returns an oidc.TokenExpiredError.
func (s *Session) ValidateClock(now time.Time) error {
	if expires := s.Expires(); !expires.IsZero() && expires.Before(now.Add(-Leeway)) {
		return &oidc.TokenExpiredError{Expiry: expires}
	}

	return nil
}
