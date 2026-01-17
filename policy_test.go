package caddy_oidc

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestMatcherSet_MatchZero(t *testing.T) {
	type Matchers struct {
		MatcherSetsRaw caddyhttp.RawMatcherSets `json:"matchers,omitempty" caddy:"namespace=http.matchers"`
		Matchers       caddyhttp.MatcherSets    `json:"-"`
	}

	d := caddyfile.NewTestDispenser(`{ }`)
	var m Matchers

	mm, err := caddyhttp.ParseCaddyfileNestedMatcherSet(d)
	assert.NoError(t, err)

	m.MatcherSetsRaw = append(m.MatcherSetsRaw, mm)

	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

	matchersIface, err := ctx.LoadModule(&m, "MatcherSetsRaw")
	assert.NoError(t, err)

	err = m.Matchers.FromInterface(matchersIface)
	assert.NoError(t, err)

	r := httptest.NewRequest("GET", "/foo", nil)
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

	ok, err := m.Matchers.AnyMatchWithError(r)
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestPolicySet_Evaluate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		session *Session
		expect  Evaluation
	}{
		{
			name: "empty allow authenticated",
			input: `{
				allow { }
			}`,
			session: &Session{
				Uid: "test",
			},
			expect: RejectImplicit,
		},
		{
			name: "deny explicit path match",
			input: `{
				deny {
					path /foo
				}
			}`,
			session: &Session{
				Uid: "test",
			},
			expect: RejectExplicit,
		},
		{
			name: "deny explicit user",
			input: `{
				deny {
					user bob@example.com
					user steve@example.com
				}
			}`,
			session: &Session{
				Uid: "steve@example.com",
			},
			expect: RejectExplicit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var ps PolicySet

			err := ps.UnmarshalCaddyfile(d)
			assert.NoError(t, err)

			pCtx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

			err = ps.Provision(pCtx)
			assert.NoError(t, err)

			t.Log("policy set:", spew.Sdump(ps))

			r := httptest.NewRequest("GET", "/foo?foo=bar", nil)
			r.Header.Set("X-Api-Key", "xyz")
			r.Header.Set("Referer", "https://example.com/page?q=123")
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
				caddyhttp.ClientIPVarKey: "127.0.0.1",
			}))
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
			r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, tt.session))

			e, err := ps.Evaluate(r)
			assert.NoError(t, err)
			assert.Equalf(t, tt.expect, e, "expected: %s, got: %s", tt.expect, e)
		})
	}
}
