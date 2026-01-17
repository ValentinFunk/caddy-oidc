package caddy_oidc

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(new(MatchUser))
}

// MatchWildcard matches a possible wildcard pattern against a value.
// Uses the same wildcard matching logic as caddyhttp.MatchHeader.
func MatchWildcard(pattern string, value string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*"):
		return strings.Contains(value, pattern[1:len(pattern)-1])
	case strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(value, pattern[1:])
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	default:
		return pattern == value
	}
}

var (
	_ caddy.Module                      = (*MatchUser)(nil)
	_ caddyfile.Unmarshaler             = (*MatchUser)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchUser)(nil)
	_ caddyhttp.RequestMatcher          = (*MatchUser)(nil)
)

// MatchUser matches the request against a list of wildcard-matched usernames present
// within the session stored in the incoming context.
// If the session is anonymous, no usernames are considered and the match always fails.
type MatchUser struct {
	Usernames []string `json:"usernames,omitempty"`
}

func (*MatchUser) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.user",
		New: func() caddy.Module { return new(MatchUser) },
	}
}

func (m *MatchUser) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var username string
		if !d.Args(&username) {
			return d.ArgErr()
		}

		m.Usernames = append(m.Usernames, username)
	}
	return nil
}

func (m *MatchUser) MatchWithError(r *http.Request) (bool, error) {
	session, ok := r.Context().Value(SessionCtxKey).(*Session)
	if !ok {
		// No session stored in request context
		return false, nil
	}

	// No users can match anonymous sessions
	if session.Anonymous {
		return false, nil
	}

	if len(m.Usernames) == 0 {
		return true, nil
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	for _, allowedVal := range m.Usernames {
		if MatchWildcard(repl.ReplaceAll(allowedVal, ""), session.Uid) {
			return true, nil
		}
	}

	return false, nil
}

func (m *MatchUser) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)
	return ok
}

//func f() {
//	caddy.ReplacerCtxKey
//	caddyhttp.MatchHeader{}.Match()
//}
