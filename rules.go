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

// Action represents the possible actions to take when a rule is matched.
// ENUM(allow, deny)
type Action uint8

// EvaluationResult represents the possible results of ruleset evaluation.
// ENUM(implicit deny, explicit deny, allow)
type EvaluationResult uint8

type RuleEvaluation struct {
	Result EvaluationResult `json:"result"`
	RuleID string           `json:"rule_id"`
}

var _ caddy.Provisioner = (*Rule)(nil)
var _ caddyhttp.RequestMatcherWithError = (*Rule)(nil)

type Rule struct {
	ID             string               `json:"id,omitempty"`
	Action         Action               `json:"action"`
	MatcherSetsRaw caddy.ModuleMap      `json:"match,omitempty" caddy:"namespace=http.matchers"`
	Matchers       caddyhttp.MatcherSet `json:"-"`
}

func (r *Rule) Provision(ctx caddy.Context) error {
	matchersIface, err := ctx.LoadModule(r, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher modules: %v", err)
	}

	for _, matcher := range matchersIface.(map[string]any) {
		switch matcher.(type) {
		case caddyhttp.RequestMatcherWithError:
			r.Matchers = append(r.Matchers, matcher)

		//nolint: staticcheck // RequestMatcher deprecated for implementation but kept here for backwards compatibility for parsing
		case caddyhttp.RequestMatcher:
			r.Matchers = append(r.Matchers, matcher)
		default:
			return fmt.Errorf("decoded module is not a RequestMatcher or RequestMatcherWithError: %#v", matcher)
		}
	}

	return nil
}

// MatchWithError returns true if the request matches the rule.
// Unlike caddyhttp.MatcherSets, an empty matcher set never matches a request.
func (r *Rule) MatchWithError(req *http.Request) (bool, error) {
	if len(r.Matchers) == 0 {
		return false, nil
	}

	return r.Matchers.MatchWithError(req)
}

var _ caddyfile.Unmarshaler = (*Ruleset)(nil)
var _ caddy.Provisioner = (*Ruleset)(nil)
var _ caddy.Validator = (*Ruleset)(nil)

type Ruleset []*Rule

func (rules *Ruleset) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		var pol Rule
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

		*rules = append(*rules, &pol)
	}

	return nil
}

func (rules *Ruleset) Provision(ctx caddy.Context) error {
	for _, p := range *rules {
		err := p.Provision(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

// ContainsAllow returns true if the set contains at least one ActionAllow rule.
func (rules *Ruleset) ContainsAllow() bool {
	for _, p := range *rules {
		if p.Action == ActionAllow {
			return true
		}
	}
	return false
}

func (rules *Ruleset) Validate() error {
	if !rules.ContainsAllow() {
		return errors.New("no authorization rule is configured to allow access, all requests will be denied without at least one allow rule")
	}

	return nil
}

// Evaluate all rules in the set and return the evaluation result.
// At least one allow rule must match to return EvaluationResultAllow.
// If any "deny" rule is matched, return EvaluationResultExplicitDeny.
func (rules *Ruleset) Evaluate(r *http.Request) (e RuleEvaluation, err error) {
	e.Result = EvaluationResultImplicitDeny

	for _, p := range *rules {
		// Skip allow rule if already accepted.
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

		e.RuleID = p.ID

		switch p.Action {
		case ActionAllow:
			e.Result = EvaluationResultAllow
		case ActionDeny:
			// Return immediately on deny
			e.Result = EvaluationResultExplicitDeny
			return
		}
	}

	return
}
