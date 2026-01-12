package caddy_oidc

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
)

func TestWildcard_Match(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		expect  bool
	}{
		{pattern: "*", input: "test", expect: true},
		{pattern: "test", input: "test", expect: true},
		{pattern: "test*", input: "test", expect: false},
		{pattern: "test*", input: "test1", expect: true},
		{pattern: "test*", input: "test123", expect: true},
		{pattern: "test*est", input: "testtest", expect: true},
		{pattern: "test*test", input: "testtest", expect: true},
		{pattern: "*est", input: "test", expect: true},
		{pattern: "**", input: "test", expect: true},
		{pattern: "*@example.com", input: "", expect: false},
		{pattern: "*@example.com", input: "foo@example.com", expect: true},
		{pattern: "*@example.com", input: "foo@example.bar", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.expect, Wildcard(tt.pattern).Match(tt.input))
		})
	}
}

func TestRequestMatcher_UnmarshalCaddyfile(t *testing.T) {
	var bar = "bar"
	tests := []struct {
		name      string
		input     string
		expect    RequestMatcher
		shouldErr bool
	}{
		{
			name: "anonymous",
			input: `{
				anonymous
			}`,
			expect: RequestMatcher{
				Anonymous: true,
			},
		},
		{
			name: "users",
			input: `{
				user a b c
			}`,
			expect: RequestMatcher{
				User: []Wildcard{"a", "b", "c"},
			},
		},
		{
			name: "clients",
			input: `{
				client 192.168.0.1/24 10.0.0.0/8 1.1.1.1
			}`,
			expect: RequestMatcher{
				Client: []IpRange{
					{Prefix: netip.MustParsePrefix("192.168.0.0/24")},
					{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
					{Prefix: netip.MustParsePrefix("1.1.1.1/32")},
				},
			},
		},
		{
			name: "query",
			input: `{
				query foo=bar bar
			}`,
			expect: RequestMatcher{
				Query: []*RequestValue{
					{Name: "foo", Value: (*Wildcard)(&bar)},
					{Name: "bar", Value: nil},
				},
			},
		},
		{
			name: "header",
			input: `{
				header foo=bar bar
			}`,
			expect: RequestMatcher{
				Header: []*RequestValue{
					{Name: "foo", Value: (*Wildcard)(&bar)},
					{Name: "bar", Value: nil},
				},
			},
		},
		{
			name: "claims",
			input: `{
				claim role=read:* role=write email=*@example.com
			}`,
			expect: RequestMatcher{
				Claims: map[string][]Wildcard{
					"role":  {"read:*", "write"},
					"email": {"*@example.com"},
				},
			},
		},
		{
			name: "method",
			input: `{
				method get post
			}`,
			expect: RequestMatcher{
				Method: []string{"get", "post"},
			},
		},
		{
			name: "path",
			input: `{
				path /foo*
			}`,
			expect: RequestMatcher{
				Path: []Wildcard{"/foo*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var o RequestMatcher
			err := o.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, tt.expect, o)
		})
	}
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
			expect: Permit,
		},
		{
			name: "empty allow anonymous",
			input: `{
				allow { }
			}`,
			session: AnonymousSession,
			expect:  RejectImplicit,
		},
		{
			name: "empty allow explicit deny",
			input: `{
				allow { }
				deny {
					anonymous
				}
			}`,
			session: AnonymousSession,
			expect:  RejectExplicit,
		},
		{
			name: "allow user",
			input: `{
				allow {
					user foo bar test
				}
			}`,
			session: &Session{
				Uid: "test",
			},
			expect: Permit,
		},
		{
			name: "allow user in domain",
			input: `{
				allow {
					user *@example.com
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "deny client",
			input: `{
				deny {
					client 127.0.0.1/32
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: RejectExplicit,
		},
		{
			name: "allow multiple and",
			input: `{
				allow {
					user test@example.com
					client 127.0.0.1/32
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "allow query where exists",
			input: `{
				allow {
					query foo
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "allow query with value",
			input: `{
				allow {
					query foo=bar
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "deny query not equal",
			input: `{
				allow {
					query foo=baz
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: RejectImplicit,
		},
		{
			name: "allow header where exists",
			input: `{
				allow {
					header x-api-key
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "allow header with value",
			input: `{
				allow {
					header x-api-key=xyz
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "allow header with value (canonical)",
			input: `{
				allow {
					header X-Api-Key=xyz
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "allow header with value (wildcard)",
			input: `{
				allow {
					header Referer=https://example.com/*
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "deny query not equal",
			input: `{
				allow {
					query x-api-key=xyz
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: RejectImplicit,
		},
		{
			name: "match claim simple",
			input: `{
				allow {
					claim role=read
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"role": "read"}`),
			},
			expect: Permit,
		},
		{
			name: "match claim simple not equal",
			input: `{
				allow {
					claim role=write
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"role": "read"}`),
			},
			expect: RejectImplicit,
		},
		{
			name: "match claim in array",
			input: `{
				allow {
					claim role=write
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"role": ["read", "write"]}`),
			},
			expect: Permit,
		},
		{
			name: "match claim wildcard",
			input: `{
				allow {
					claim role=read:*
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"role": ["read:api", "read:admin"]}`),
			},
			expect: Permit,
		},
		{
			name: "match claim different type",
			input: `{
				allow {
					claim x=1
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectImplicit,
		},
		{
			name: "match method",
			input: `{
				deny {
					method GET
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "match method any",
			input: `{
				deny {
					method POST GET
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "match method lower",
			input: `{
				deny {
					method get
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "match method incorrect method",
			input: `{
				allow {
					method post
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectImplicit,
		},
		{
			name: "match path exact",
			input: `{
				deny {
					path /foo
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "match path wildcard",
			input: `{
				deny {
					path /*
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectExplicit,
		},
		{
			name: "match path wildcard unmatched",
			input: `{
				deny {
					path /bar
				}
			}`,
			session: &Session{
				Claims: json.RawMessage(`{"x": 1}`),
			},
			expect: RejectImplicit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var ps PolicySet

			err := ps.UnmarshalCaddyfile(d)
			assert.NoError(t, err)

			r := httptest.NewRequest("GET", "/foo?foo=bar", nil)
			r.Header.Set("X-Api-Key", "xyz")
			r.Header.Set("Referer", "https://example.com/page?q=123")
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
				caddyhttp.ClientIPVarKey: "127.0.0.1",
			}))

			e, err := ps.Evaluate(r, tt.session)
			assert.NoError(t, err)
			assert.Equal(t, tt.expect, e)
		})
	}
}
