package caddy_oidc

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/stretchr/testify/assert"
)

func Test_Caddyfile_ParseFull(t *testing.T) {
	const caddyfile = `{
	auto_https off
	oidc example1 {
		issuer https://example.org/example1
		client_id abc
		secret_key d5zXc7gk2qO7lnSWsmSTCSBQ3tqeYbNu
	}

	oidc example2 {
		issuer https://example.org/example2
		client_id abc
		secret_key d5zXc7gk2qO7lnSWsmSTCSBQ3tqeYbNu
		redirect_uri https://example2.org/_oauth/callback
		cookie {
			name _example2_session
			same_site strict
		}
	}
}

example1.org {
	oidc example1 {
		allow {
			user *
		}
	}
}

example2.org {
	oidc example2 {
		allow {
			user *@example2.org
		}
		deny {
			anonymous
		}
	}
}
`

	adapter := caddyconfig.GetAdapter("caddyfile")

	_, warnings, err := adapter.Adapt([]byte(caddyfile), nil)
	assert.NoError(t, err)
	assert.Empty(t, warnings)
}
