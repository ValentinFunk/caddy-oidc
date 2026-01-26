package authenticator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoneAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	var cfg pkgtest.TestOIDCConfiguration
	au := &NoneAuthenticator{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s, err := au.AuthenticateRequest(&cfg, r)
	require.NoError(t, err)
	assert.True(t, s.Anonymous)
}
