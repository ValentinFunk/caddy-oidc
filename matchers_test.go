package caddy_oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
)

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		expect  bool
	}{
		{
			name:    "exact match",
			pattern: "steve@example.com",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "exact match",
			pattern: "steve@example.com",
			input:   "bob@example.com",
			expect:  false,
		},
		{
			name:    "prefix wildcard match",
			pattern: "steve@*",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "prefix wildcard no match",
			pattern: "steve@*",
			input:   "bob@example.com",
			expect:  false,
		},
		{
			name:    "suffix wildcard match",
			pattern: "*@example.com",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "suffix wildcard no match",
			pattern: "*@example.com",
			input:   "steve@other.com",
			expect:  false,
		},
		{
			name:    "contains wildcard match",
			pattern: "*@example*",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "contains wildcard no match",
			pattern: "*@example*",
			input:   "steve@other.com",
			expect:  false,
		},
		{
			name:    "match all wildcard",
			pattern: "*",
			input:   "anything@example.com",
			expect:  true,
		},
		{
			name:    "match all wildcard empty input",
			pattern: "*",
			input:   "",
			expect:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok := MatchWildcard(tt.pattern, tt.input)
			assert.Equal(t, tt.expect, ok)
		})
	}
}

func TestMatchUser_MatchWithError(t *testing.T) {
	tests := []struct {
		name    string
		session Session
		matcher MatchUser
		match   bool
	}{
		{
			name:    "match empty",
			session: Session{},
			matcher: MatchUser{},
			match:   true,
		},
		{
			name:    "match anonymous",
			session: Session{Anonymous: true},
			matcher: MatchUser{},
			match:   false,
		},
		{
			name:    "match any user",
			session: Session{Uid: "steve@example.com"},
			matcher: MatchUser{
				Usernames: []string{"*"},
			},
			match: true,
		},
		{
			name:    "match exact multiple",
			session: Session{Uid: "steve@example.com"},
			matcher: MatchUser{
				Usernames: []string{"bob@example.com", "steve@example.com"},
			},
			match: true,
		},
		{
			name:    "match exact with replacer variable",
			session: Session{Uid: "steve@example.com"},
			matcher: MatchUser{
				Usernames: []string{"steve@{test.domain}"},
			},
			match: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			repl := caddy.NewReplacer()
			repl.Set("test.domain", "example.com")
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
			r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, &tt.session))

			ok, err := tt.matcher.MatchWithError(r)
			assert.NoError(t, err)
			assert.Equal(t, tt.match, ok)
		})
	}
}
