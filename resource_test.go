package caddy_oidc

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
)

func TestProtectedResourceMetadataConfiguration_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expect    *ProtectedResourceMetadataConfiguration
		shouldErr bool
	}{
		{
			name:   "empty",
			input:  `protected_resource_metadata { }`,
			expect: &ProtectedResourceMetadataConfiguration{},
		},
		{
			name:  "disable",
			input: `protected_resource_metadata off`,
			expect: &ProtectedResourceMetadataConfiguration{
				Disable: true,
			},
		},
		{
			name: "realm",
			input: `protected_resource_metadata {
				realm https://example.com
			}`,
			expect: &ProtectedResourceMetadataConfiguration{
				Realm: "https://example.com",
			},
		},
		{
			name: "audience",
			input: `protected_resource_metadata {
				audience
			}`,
			expect: &ProtectedResourceMetadataConfiguration{
				Audience: true,
			},
		},
		{
			name:      "unexpected arg",
			input:     `protected_resource_metadata value`,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := new(ProtectedResourceMetadataConfiguration)
			d := caddyfile.NewTestDispenser(tt.input)

			err := p.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, tt.expect, p)
		})
	}
}

func TestOAuthProtectedResource_WWWAuthenticate(t *testing.T) {
	md := &OAuthProtectedResource{
		Resource:        "http://example.com",
		ScopesSupported: []string{"openid", "profile", "email"},
	}

	assert.Equal(t, "Bearer realm=\"http://example.com\", resource_metadata=\"http://example.com/.well-known/oauth-protected-resource\", scope=\"openid profile email\"", md.WWWAuthenticate())
}
