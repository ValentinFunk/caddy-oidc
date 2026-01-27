package caddy_oidc

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCProvider_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expect    string
	}{
		{
			name: "full configuration",
			input: `{
				issuer http://openid/example
				client_id xyz
				tls_insecure_skip_verify
				scope openid email profile
				username email
				authenticate bearer
				authenticate cookie {
					name session_id
					same_site strict
					insecure
					secret 7DFSrbya1rvBBmcaxD
					claim email role
					redirect_url http://localhost/oauth/callback
				}
				authenticate none
				protected_resource_metadata {
					audience
				}
			}`,
			shouldErr: false,
			expect: `{
  "issuer": "http://openid/example",
  "client_id": "xyz",
  "scope": [
    "openid",
    "email",
    "profile"
  ],
  "username": "email",
  "authenticators": {
    "authenticators": [
      {
        "authenticator": "bearer"
      },
      {
        "name": "session_id",
        "same_site": "strict",
        "insecure": true,
        "secret": "7DFSrbya1rvBBmcaxD",
        "claims": [
          "email",
          "role"
        ],
		"redirect_url": "http://localhost/oauth/callback",
        "authenticator": "cookie"
      },
      {
        "authenticator": "none"
      }
    ]
  },
  "tls_insecure_skip_verify": true,
  "protected_resource_metadata": {
    "disable": false,
    "audience": true
  }
}`,
		},
		{
			name: "missing issuer_url argument",
			input: `{
				issuer_url
			}`,
			shouldErr: true,
		},
		{
			name: "invalid cookie same_site",
			input: `{
				cookie {
					same_site invalid
				}
			}`,
			shouldErr: true,
		},
		{
			name: "unknown directive",
			input: `{
				unknown_directive foo
			}`,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			module := new(OIDCProviderModule)
			d := caddyfile.NewTestDispenser(tt.input)

			err := module.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)

			jsonBytes, err := json.Marshal(module)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expect, string(jsonBytes))
		})
	}
}
