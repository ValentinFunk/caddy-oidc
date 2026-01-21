package caddy_oidc

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/tidwall/gjson"
)

func init() {
	caddy.RegisterModule(new(MatchUser))
	caddy.RegisterModule(new(MatchAnonymous))
	caddy.RegisterModule(new(MatchClaim))
	caddy.RegisterModule(new(MatchAuthMethod))
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

var (
	_ caddy.Module                      = (*MatchAnonymous)(nil)
	_ caddyfile.Unmarshaler             = (*MatchAnonymous)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchAnonymous)(nil)
)

// MatchAnonymous matches requests that are anonymous or do not have a valid session in the request context.
type MatchAnonymous struct{}

func (*MatchAnonymous) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.anonymous",
		New: func() caddy.Module { return new(MatchAnonymous) },
	}
}

func (*MatchAnonymous) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		if d.NextBlock(0) {
			return d.Err("unexpected block")
		}
	}
	return nil
}

func (*MatchAnonymous) MatchWithError(r *http.Request) (bool, error) {
	s, ok := r.Context().Value(SessionCtxKey).(*Session)
	if !ok || s.Anonymous {
		return true, nil
	}

	return false, nil
}

func (m *MatchAnonymous) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)
	return ok
}

var (
	_ caddy.Module                      = (*MatchClaim)(nil)
	_ caddyfile.Unmarshaler             = (*MatchClaim)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchClaim)(nil)
)

type ClaimMatch struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// MatchClaim matches claims in a request session.
// The claim value in the session must be a string or an array of strings.
// If the claim value is an array, the match succeeds if any of the values match.
type MatchClaim []ClaimMatch

func (*MatchClaim) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.claim",
		New: func() caddy.Module { return new(MatchClaim) },
	}
}

func (m *MatchClaim) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}

		var claim = ClaimMatch{
			Name:   d.Val(),
			Values: d.RemainingArgs(),
		}

		if len(claim.Values) == 0 {
			return d.Err("claim must have at least one value")
		}

		*m = append(*m, claim)
	}

	return nil
}

func (m *MatchClaim) MatchWithError(r *http.Request) (bool, error) {
	session, ok := r.Context().Value(SessionCtxKey).(*Session)
	if !ok {
		// No session stored in request context
		return false, nil
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	for _, claimMatch := range *m {
		claimNameVal := repl.ReplaceAll(claimMatch.Name, "")

		claimsValueMatch := gjson.GetBytes(session.Claims, claimNameVal)
		if !claimsValueMatch.Exists() {
			return false, nil
		}

		var foundMatch bool
	findMatch:
		for _, claimValue := range claimMatch.Values {
			claimValueVal := repl.ReplaceAll(claimValue, "")

			switch {
			case claimsValueMatch.Type == gjson.String:
				if MatchWildcard(claimValueVal, claimsValueMatch.String()) {
					foundMatch = true
					break findMatch
				}
			case claimsValueMatch.IsArray():
				for _, claimValueMatchElem := range claimsValueMatch.Array() {
					if claimValueMatchElem.Type != gjson.String {
						continue
					}

					if MatchWildcard(claimValueVal, claimValueMatchElem.String()) {
						foundMatch = true
						break findMatch
					}
				}
			default:
				return false, nil
			}
		}

		if !foundMatch {
			return false, nil
		}
	}

	return true, nil
}

func (m *MatchClaim) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)
	return ok
}

var (
	_ caddy.Module                      = (*MatchAuthMethod)(nil)
	_ caddyfile.Unmarshaler             = (*MatchAuthMethod)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchAuthMethod)(nil)
)

// MatchAuthMethod matches the authentication method used for the incoming request.
type MatchAuthMethod struct {
	Match []AuthMethod `json:"match,omitempty"`
}

func (*MatchAuthMethod) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.auth_method",
		New: func() caddy.Module { return new(MatchAuthMethod) },
	}
}

func (m *MatchAuthMethod) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var methodVal string
		if !d.Args(&methodVal) {
			return d.ArgErr()
		}

		method, err := ParseAuthMethod(methodVal)
		if err != nil {
			return err
		}

		m.Match = append(m.Match, method)

		if d.NextBlock(0) {
			return d.Err("unexpected block")
		}
	}
	return nil
}

func (m *MatchAuthMethod) MatchWithError(r *http.Request) (bool, error) {
	authMethod, ok := r.Context().Value(AuthMethodCtxKey).(AuthMethod)
	if !ok {
		// If the auth method isn't set in the request context, default to none
		authMethod = AuthMethodNone
	}

	for _, method := range m.Match {
		if method == authMethod {
			return true, nil
		}
	}

	return false, nil
}
