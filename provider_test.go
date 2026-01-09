package caddy_oidc

import (
	"context"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
)

var testKey = []byte("secret-key-for-testing-purposes-only")

type TestKeySet struct{}

func (TestKeySet) VerifySignature(ctx context.Context, token string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return nil, err
	}

	return jws.Verify(testKey)
}

type ExtendedClaims struct {
	jwt.Claims
	Email string `json:"email"`
}

func GenerateTestJWT() string {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: testKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	cl := ExtendedClaims{
		Claims: jwt.Claims{
			Subject:  "test",
			Issuer:   "http://openid/example",
			Audience: jwt.Audience{"xyz"},
		},
		Email: "x@example.org",
	}

	raw, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func TestOIDCProvider_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expect    *OIDCProviderModule
	}{
		{
			name: "full configuration",
			input: `{
				issuer http://openid/example
				client_id xyz
				redirect_uri http://localhost/oauth/callback
				secret_key 7DFSrbya1rvBBmcaxD
				tls_insecure_skip_verify
				scope openid email profile
				username email
				claim email role
				cookie {
					name session_id
					same_site strict
					insecure
				}
				protected_resource_metadata {
					audience
				}
			}`,
			shouldErr: false,
			expect: &OIDCProviderModule{
				Issuer:                "http://openid/example",
				ClientID:              "xyz",
				RedirectURI:           "http://localhost/oauth/callback",
				SecretKey:             "7DFSrbya1rvBBmcaxD",
				TLSInsecureSkipVerify: true,
				Scope:                 []string{"openid", "email", "profile"},
				Username:              "email",
				Claims:                []string{"email", "role"},
				Cookie: &Cookies{
					Name:     "session_id",
					SameSite: SameSite{http.SameSiteStrictMode},
					Insecure: true,
					Path:     "/",
				},
				ProtectedResourceMetadata: &ProtectedResourceMetadataConfiguration{
					Disable:  false,
					Audience: true,
				},
			},
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
			p := new(OIDCProviderModule)
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
