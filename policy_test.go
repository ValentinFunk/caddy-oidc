package caddy_oidc

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

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
		{
			name: "deny anonymous at path",
			input: `{
				deny {
					anonymous
					path /foo
				}
			}`,
			session: &Session{
				Anonymous: true,
			},
			expect: RejectExplicit,
		},
		{
			name: "deny anonymous at another path",
			input: `{
				deny {
					anonymous
					path /bar
				}
			}`,
			session: &Session{
				Anonymous: true,
			},
			expect: RejectImplicit,
		},
		{
			name: "deny matching claim",
			input: `{
				deny {
					claim sub steve@example.com
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"sub": "steve@example.com"}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "deny matching claim multiple OR",
			input: `{
				deny {
					claim sub bob@example.com steve@example.com
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"sub": "steve@example.com"}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "deny matching claim multiple AND",
			input: `{
				deny {
					claim role read
					claim role write
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"role": ["read": "write"]}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "deny matching claim wildcard",
			input: `{
				deny {
					claim sub *@example.com
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"sub": "steve@example.com"}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "deny matching claim replacer var",
			input: `{
				deny {
					claim host {http.host}
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"host": "example.com"}`),
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

			repl := caddy.NewReplacer()
			repl.Set("http.host", "example.com")

			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
			r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, tt.session))

			e, err := ps.Evaluate(r)
			assert.NoError(t, err)
			assert.Equalf(t, tt.expect, e, "expected: %s, got: %s", tt.expect, e)
		})
	}
}
