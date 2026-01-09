package caddy_oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOAuthProtectedResource_WWWAuthenticate(t *testing.T) {
	md := &OAuthProtectedResource{
		Resource:        "http://example.com",
		ScopesSupported: []string{"openid", "profile", "email"},
	}

	assert.Equal(t, "Bearer realm=\"http://example.com\", resource_metadata=\"http://example.com/.well-known/oauth-protected-resource\", scope=\"openid profile email\"", md.WWWAuthenticate())
}
