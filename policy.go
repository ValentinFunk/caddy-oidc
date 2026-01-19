package caddy_oidc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

//go:generate go tool go-enum -f=$GOFILE --marshal

// Action represents the possible actions for policy evaluation.
// ENUM(allow, deny)
type Action uint8

// EvaluationResult represents the possible results of policy evaluation.
// ENUM(implicit deny, explicit deny, allow)
type EvaluationResult uint8

type PolicyEvaluation struct {
	Result   EvaluationResult `json:"result"`
	PolicyID string           `json:"policy_id"`
}

var _ caddy.Provisioner = (*Policy)(nil)
var _ caddyhttp.RequestMatcherWithError = (*Policy)(nil)

type Policy struct {
	ID             string               `json:"id,omitempty"`
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
			pol.Action = ActionAllow
		case "deny":
			pol.Action = ActionDeny
		default:
			return d.Errf("unrecognized action '%s'", d.Val())
		}

		_ = d.Args(&pol.ID)

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

// ContainsAllow returns true if the set contains at least one ActionAllow policy.
func (ps *PolicySet) ContainsAllow() bool {
	for _, p := range *ps {
		if p.Action == ActionAllow {
			return true
		}
	}
	return false
}

// Validate the policy set.
// Returns an error if there isn't at least one ActionAllow policy.
func (ps *PolicySet) Validate() error {
	if !ps.ContainsAllow() {
		return errors.New("no authorization policy is configured to allow access, all requests will be denied without at least one allow policy")
	}

	return nil
}

// Evaluate all policies in the set and return the evaluation result.
// If any ActionDeny policy is matched, return ResultImplicitDeny.
// If at least one ActionAllow policy is matched, return ResultAllow.
// Otherwise, return ResultExplicitDeny.
func (ps *PolicySet) Evaluate(r *http.Request) (e PolicyEvaluation, err error) {
	e.Result = EvaluationResultImplicitDeny

	for _, p := range *ps {
		// Skip allow policy if already accepted.
		if p.Action == ActionAllow && e.Result == EvaluationResultAllow {
			continue
		}

		var ok bool
		ok, err = p.MatchWithError(r)
		if err != nil {
			return
		}

		if !ok {
			continue
		}

		e.PolicyID = p.ID

		switch p.Action {
		case ActionAllow:
			e.Result = EvaluationResultAllow
		case ActionDeny:
			// Return immediately if any 'deny' policy is matched.
			e.Result = EvaluationResultExplicitDeny
			return
		}
	}

	return
}
