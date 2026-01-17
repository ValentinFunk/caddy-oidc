package caddy_oidc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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

type Evaluation uint8

const (
	Permit         Evaluation = 0b01
	RejectExplicit Evaluation = 0b10
	RejectImplicit Evaluation = 0b00
)

func (e Evaluation) String() string {
	switch e {
	case Permit:
		return "permit"
	case RejectExplicit:
		return "reject explicit"
	case RejectImplicit:
		return "reject implicit"
	default:
		panic("invalid evaluation result")
	}
}

var _ caddy.Provisioner = (*Policy)(nil)
var _ caddyhttp.RequestMatcherWithError = (*Policy)(nil)

type Policy struct {
	Action         Action               `json:"action"`
	MatcherSetsRaw caddy.ModuleMap      `json:"match,omitempty" caddy:"namespace=http.matchers"`
	Matchers       caddyhttp.MatcherSet `json:"-"`
}

func (p *Policy) Provision(ctx caddy.Context) error {
	matchersIface, err := ctx.LoadModule(p, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher modules: %v", err)
	}

	for _, matcher := range matchersIface.(map[string]any) {
		switch matcher.(type) {
		case caddyhttp.RequestMatcherWithError:
			p.Matchers = append(p.Matchers, matcher)

		//nolint: staticcheck // RequestMatcher deprecated for implementation but kept here for backwards compatibility for parsing
		case caddyhttp.RequestMatcher:
			p.Matchers = append(p.Matchers, matcher)
		default:
			return fmt.Errorf("decoded module is not a RequestMatcher or RequestMatcherWithError: %#v", matcher)
		}
	}

	return nil
}

// MatchWithError returns true if the request matches the policy.
// Unlike caddyhttp.MatcherSets, an empty matcher set never matches a request.
func (p *Policy) MatchWithError(r *http.Request) (bool, error) {
	if len(p.Matchers) == 0 {
		return false, nil
	}

	return p.Matchers.MatchWithError(r)
}

var _ caddyfile.Unmarshaler = (*PolicySet)(nil)
var _ caddy.Provisioner = (*PolicySet)(nil)
var _ caddy.Validator = (*PolicySet)(nil)

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

		var err error
		pol.MatcherSetsRaw, err = caddyhttp.ParseCaddyfileNestedMatcherSet(d)
		if err != nil {
			return err
		}

		*ps = append(*ps, &pol)
	}

	return nil
}

func (ps *PolicySet) Provision(ctx caddy.Context) error {
	for _, p := range *ps {
		err := p.Provision(ctx)
		if err != nil {
			return err
		}
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

// Validate the policy set.
// Returns an error if there isn't at least one Allow policy.
func (ps *PolicySet) Validate() error {
	if !ps.ContainsAllow() {
		return errors.New("no authorization policy is configured to allow access, all requests will be denied without at least one allow policy")
	}

	return nil
}

// Evaluate all policies in the set and return the evaluation result.
// If any Deny policy is matched, return RejectExplicit.
// If at least one Allow policy is matched, return Permit.
// Otherwise, return RejectImplicit.
func (ps *PolicySet) Evaluate(r *http.Request) (Evaluation, error) {
	var isAllowed = false

	for _, p := range *ps {
		match, err := p.MatchWithError(r)
		if err != nil {
			return 0, err
		}

		if match {
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
