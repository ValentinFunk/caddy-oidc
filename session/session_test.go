package session

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

func TestSession_ValidateClock(t *testing.T) {
	t.Parallel()

	tRef := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var session = &Session{
			ExpiresAt: tRef.Add(time.Hour).Unix(),
		}

		err := session.ValidateClock(tRef)
		assert.NoError(t, err)
	})

	t.Run("valid with leeway", func(t *testing.T) {
		t.Parallel()

		var session = &Session{
			ExpiresAt: tRef.Add(-time.Second).Unix(),
		}

		err := session.ValidateClock(tRef)
		assert.NoError(t, err)
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()

		var session = &Session{
			ExpiresAt: tRef.Add(-time.Hour).Unix(),
		}

		err := session.ValidateClock(tRef)

		var exp *oidc.TokenExpiredError
		if assert.ErrorAs(t, err, &exp) {
			assert.True(t, exp.Expiry.Equal(tRef.Add(-time.Hour)))
		}
	})
}

type JSONClaims json.RawMessage

func (j JSONClaims) Claims(v any) error {
	return json.Unmarshal(j, v)
}

func TestNewFromClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		uidClaim  string
		claims    string
		expect    Session
		expectErr error
	}{
		{
			name:     "valid",
			uidClaim: "sub",
			claims:   `{"sub": "steve"}`,
			expect: Session{
				UID:    "steve",
				Claims: json.RawMessage(`{"sub": "steve"}`),
			},
		},
		{
			name:      "missing username claim",
			uidClaim:  "email",
			claims:    `{"sub": "steve"}`,
			expectErr: MissingRequiredClaimError{Claim: "email"},
		},
		{
			name:      "claim with incorrect type",
			uidClaim:  "sub",
			claims:    `{"sub": 1}`,
			expectErr: MissingRequiredClaimError{Claim: "sub"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s, err := NewFromClaims(tt.uidClaim, JSONClaims(tt.claims))
			assert.ErrorIs(t, err, tt.expectErr)
			if s != nil {
				assert.Equal(t, tt.expect, *s)
			}
		})
	}
}
