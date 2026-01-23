package caddy_oidc

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectedResourceMetadataConfiguration_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			metaConfig := new(ProtectedResourceMetadataConfiguration)
			d := caddyfile.NewTestDispenser(tt.input)

			err := metaConfig.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expect, metaConfig)
		})
	}
}

func TestOAuthProtectedResource_WWWAuthenticate(t *testing.T) {
	t.Parallel()

	md := &OAuthProtectedResource{
		Resource:        "http://example.com",
		ScopesSupported: []string{"openid", "profile", "email"},
	}

	assert.Equal(t, "Bearer resource_metadata=\"http://example.com/.well-known/oauth-protected-resource\", scope=\"openid profile email\"", md.WWWAuthenticate())
}
