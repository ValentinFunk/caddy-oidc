// Package pkgtest provides utilities for testing.
package pkgtest

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

//nolint:gochecknoglobals
var testKey = []byte("secret-key-for-testing-purposes-only")

type testKeySet struct{}

func (testKeySet) VerifySignature(_ context.Context, token string) ([]byte, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return nil, err
	}

	return jws.Verify(testKey)
}

type extendedClaims struct {
	jwt.Claims

	Email string   `json:"email"`
	Roles []string `json:"roles,omitempty"`
}

// GenerateTestJWTExpiresAt generates a JWT with the given expiration time.
// The generated JWT is signed with the testKey.
func GenerateTestJWTExpiresAt(exp time.Time) string {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: testKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	claims := extendedClaims{
		Claims: jwt.Claims{
			Subject:  "test",
			Issuer:   "http://openid/example",
			Audience: jwt.Audience{"xyz"},
			Expiry:   jwt.NewNumericDate(exp),
		},
		Email: "x@example.org",
		Roles: []string{"read", "write"},
	}

	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}

	return raw
}

// NewTestVerifier returns a new IDTokenVerifier that uses the testKey for signing.
func NewTestVerifier(clock func() time.Time) *oidc.IDTokenVerifier {
	return oidc.NewVerifier("http://openid/example", testKeySet{}, &oidc.Config{
		ClientID:             "xyz",
		SupportedSigningAlgs: []string{"HS256"},
		Now:                  clock,
	})
}

// TestOIDCConfiguration is a test implementation of OIDCConfiguration.
type TestOIDCConfiguration struct {
	clock         func() time.Time
	Verifier      *oidc.IDTokenVerifier
	UsernameClaim string
}

func (c *TestOIDCConfiguration) Now() time.Time {
	if c.clock == nil {
		return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	return c.clock()
}

func (c *TestOIDCConfiguration) GetVerifier(_ context.Context) (*oidc.IDTokenVerifier, error) {
	if c.Verifier == nil {
		c.Verifier = NewTestVerifier(c.Now)
	}

	return c.Verifier, nil
}

func (c *TestOIDCConfiguration) GetUsernameClaim() string {
	if c.UsernameClaim == "" {
		return "sub"
	}

	return c.UsernameClaim
}
