package caddy_oidc

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/tidwall/gjson"
)

type Action uint8

const (
	Allow Action = iota + 1
	Deny
)

func (a *Action) String() string {
	switch *a {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return fmt.Sprintf("unknown action %d", *a)
	}
}

func (a *Action) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a *Action) UnmarshalText(text []byte) error {
	switch string(text) {
	case "allow":
		*a = Allow
	case "deny":
		*a = Deny
	default:
		return fmt.Errorf("unrecognized action '%s'", text)
	}

	return nil
}

type Wildcard string

func (w Wildcard) Match(s string) bool {
	if w == "*" {
		return true
	}

	var (
		iw int
		iv int
	)

ptn:
	for iw < len(s) && iv < len(w) {
		switch w[iw] {
		case '*':
			// Current pattern character is a wildcard, find the next anchor block
			iw++
			var j = iw
			for ; j < len(w) && w[j] != '*'; j++ {
			}

			// There is no text anchor after this wildcard; this wildcard matches all remaining text
			if iw == j {
				return true
			}

			// Advance the index to the next wildcard character
			var anchor = string(w[iw:j])
			for ; iv <= len(s)-len(anchor); iv++ {
				if s[iv:iv+len(anchor)] == anchor {
					// Found the anchor
					iw = j
					iv += len(anchor)
					continue ptn
				}
			}

			return false
		default:
			// Match character by character
			if s[iv] != w[iw] {
				return false
			}
			iw++
			iv++
		}
	}

	// No more remaining text to match.
	// State must be at the end of both values.
	return iv == len(s) && iw == len(w)
}

type IpRange struct {
	netip.Prefix
}

func (ir *IpRange) UnmarshalText(text []byte) error {
	i := bytes.LastIndex(text, []byte("/"))
	if i < 0 {
		// No prefix specified, expect an IP address, with the range equal to the length of the IP bits
		ip, err := netip.ParseAddr(string(text))
		if err != nil {
			return err
		}

		ir.Prefix = netip.PrefixFrom(ip, ip.BitLen())

		return nil
	}

	pr, err := netip.ParsePrefix(string(text))
	if err != nil {
		return err
	}

	ir.Prefix = pr.Masked() // Mask original IP to range

	return nil
}

func (ir *IpRange) MarshalText() ([]byte, error) {
	return []byte(ir.String()), nil
}

type RequestValue struct {
	Name  string    `json:"name"`
	Value *Wildcard `json:"value,omitempty"`
}

func (rv *RequestValue) String() string {
	var s strings.Builder
	s.WriteString(rv.Name)
	if rv.Value != nil {
		s.WriteString("=")
		s.WriteString((string)(*rv.Value))
	}

	return s.String()
}

// UnmarshalCaddyfile sets up a RequestValue from Caddyfile tokens.
/* syntax
name[=<value]
*/
func (rv *RequestValue) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	rv.Name = d.Val()

	name, value, ok := strings.Cut(d.Val(), "=")
	if ok {
		rv.Name = name
		rv.Value = (*Wildcard)(&value)
	}

	return nil
}

func (rv *RequestValue) MatchValues(values url.Values) bool {
	if rv.Value == nil {
		return values.Has(rv.Name)
	}

	return rv.Value.Match(values.Get(rv.Name))
}

func (rv *RequestValue) MatchHeader(header http.Header) bool {
	if rv.Value == nil {
		_, ok := header[http.CanonicalHeaderKey(rv.Name)]
		return ok
	}

	return rv.Value.Match(header.Get(rv.Name))
}

type RequestMatcher struct {
	Anonymous bool                  `json:"anonymous,omitempty"`
	User      []Wildcard            `json:"user,omitempty"`
	Client    []IpRange             `json:"client,omitempty"`
	Query     []*RequestValue       `json:"query,omitempty"`
	Header    []*RequestValue       `json:"header,omitempty"`
	Claims    map[string][]Wildcard `json:"claims,omitempty"`
}

func (p *RequestMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "anonymous":
			p.Anonymous = true
		case "user":
			for _, arg := range d.RemainingArgs() {
				p.User = append(p.User, Wildcard(arg))
			}
		case "client":
			for _, arg := range d.RemainingArgs() {
				var ir IpRange
				err := ir.UnmarshalText([]byte(arg))
				if err != nil {
					return fmt.Errorf("invalid IP or IP range: %w", err)
				}

				p.Client = append(p.Client, ir)
			}
		case "query":
			for d.NextArg() {
				d.Prev()

				var rv RequestValue
				err := rv.UnmarshalCaddyfile(d)
				if err != nil {
					return err
				}

				p.Query = append(p.Query, &rv)
			}
		case "header":
			for d.NextArg() {
				d.Prev()

				var rv RequestValue
				err := rv.UnmarshalCaddyfile(d)
				if err != nil {
					return err
				}

				p.Header = append(p.Header, &rv)
			}
		case "claim":
			for d.NextArg() {
				name, value, ok := strings.Cut(d.Val(), "=")
				if !ok {
					return d.SyntaxErr("a name=value pair is required for claim")
				}

				if p.Claims == nil {
					p.Claims = make(map[string][]Wildcard)
				}

				p.Claims[name] = append(p.Claims[name], Wildcard(value))
			}
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}

	return nil
}

// Any returns true if any element in the match slice matches the find value.
func Any[T any, S ~[]T, V any](match S, find V, predicate func(m T, v V) bool) bool {
	for _, m := range match {
		if predicate(m, find) {
			return true
		}
	}
	return false
}

// All returns true if all elements in the match slice match the find value or if the slice is empty.
func All[T any, S ~[]T, V any](match S, find V, predicate func(m T, v V) bool) bool {
	for _, m := range match {
		if !predicate(m, find) {
			return false
		}
	}
	return true
}

// Evaluate evaluates the policy and returns true if the request is allowed.
// An empty policy always returns true.
func (p *RequestMatcher) Evaluate(r *http.Request, s *Session) (bool, error) {
	if p.Anonymous != s.Anonymous {
		return false, nil
	}

	if len(p.User) > 0 && !Any(p.User, s.Uid, Wildcard.Match) {
		return false, nil
	}

	if len(p.Client) > 0 {
		client, err := ClientIP(r)
		if err != nil {
			return false, err
		}

		if !Any(p.Client, client, IpRange.Contains) {
			return false, nil
		}
	}

	if len(p.Query) > 0 && !Any(p.Query, r.URL.Query(), (*RequestValue).MatchValues) {
		return false, nil
	}
	if len(p.Header) > 0 && !Any(p.Header, r.Header, (*RequestValue).MatchHeader) {
		return false, nil
	}

	if len(p.Claims) > 0 {
		// Any desired claims cannot match empty session claims
		if len(s.Claims) == 0 {
			return false, nil
		}

		for name, values := range p.Claims {
			sessionValue := gjson.GetBytes(s.Claims, name)
			if !sessionValue.Exists() {
				// Impossible match, session is missing claim
				return false, nil
			}

			var claimDoesMatch = false
			switch {
			case sessionValue.Type == gjson.String:
				claimDoesMatch = All(values, sessionValue.String(), Wildcard.Match)
			case sessionValue.IsArray():
				claimDoesMatch = All(values, sessionValue.Array(), func(m Wildcard, v []gjson.Result) bool {
					return Any(v, m, func(m gjson.Result, v Wildcard) bool {
						return m.Exists() && m.Type == gjson.String && v.Match(m.String())
					})
				})
			default:
				// Any other claim type is not supported
			}

			if !claimDoesMatch {
				return false, nil
			}
		}
	}

	return true, nil
}

type Policy struct {
	Action Action `json:"action"`
	RequestMatcher
}

type Evaluation uint8

const (
	Permit         Evaluation = 0b01
	RejectExplicit Evaluation = 0b10
	RejectImplicit Evaluation = 0b00
)

type PolicySet []*Policy

func (ps *PolicySet) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		var pol Policy
		switch d.Val() {
		case "allow":
			pol.Action = Allow
		case "deny":
			pol.Action = Deny
		default:
			return d.Errf("unrecognized action '%s'", d.Val())
		}

		err := pol.UnmarshalCaddyfile(d)
		if err != nil {
			return err
		}

		*ps = append(*ps, &pol)
	}

	return nil
}

// ContainsAllow returns true if the set contains at least one Allow policy.
func (ps *PolicySet) ContainsAllow() bool {
	for _, p := range *ps {
		if p.Action == Allow {
			return true
		}
	}
	return false
}

// Evaluate evaluates the policies in the set and returns true if the request is allowed.
// If at least one Allow policy is found, then the evaluation result is Permit.
// If at least one Deny policy is found, then the evaluation result is RejectExplicit.
// Otherwise, the evaluation result is RejectImplicit.
func (ps *PolicySet) Evaluate(r *http.Request, s *Session) (Evaluation, error) {
	var isAllowed = false

	for _, p := range *ps {
		ok, err := p.Evaluate(r, s)
		if err != nil {
			return 0, err
		}

		if ok {
			switch p.Action {
			case Allow:
				isAllowed = true
			case Deny:
				return RejectExplicit, nil
			}
		}
	}

	if isAllowed {
		return Permit, nil
	}

	return RejectImplicit, nil
}
