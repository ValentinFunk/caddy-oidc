package caddy_oidc

import (
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

var _ caddyfile.Unmarshaler = (*ProtectedResourceMetadataConfiguration)(nil)

type ProtectedResourceMetadataConfiguration struct {
	Disable bool   `json:"disable"`
	Realm   string `json:"realm,omitempty"`
}

// UnmarshalCaddyfile sets up the ProtectedResourceMetadataConfiguration from Caddyfile tokens.
/* syntax
protected_resource_metadata disable | {
	realm [<realm>]
}
*/
func (c *ProtectedResourceMetadataConfiguration) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.SyntaxErr("protected_resource_metadata directive requires arguments")
	}

	if d.NextArg() {
		if d.Val() == "off" {
			c.Disable = true
			return nil
		}
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "realm":
			if !d.NextArg() {
				return d.ArgErr()
			}

			c.Realm = d.Val()
		default:
			return fmt.Errorf("unrecognized protected_resource_metadata subdirective '%s'", d.Val())
		}
	}

	return nil
}

// OAuthProtectedResource is the JSON payload sent from /.well-known/oauth-protected-resource
// or advertised in WWW-Authenticate on 401 responses.
type OAuthProtectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// WWWAuthenticate returns the value of the WWW-Authenticate header for this resource.
// https://datatracker.ietf.org/doc/html/rfc9728#name-use-of-www-authenticate-for
// https://datatracker.ietf.org/doc/html/rfc6750#section-3
func (md *OAuthProtectedResource) WWWAuthenticate() string {
	var params = []string{
		fmt.Sprintf("realm=%q", md.Resource),
		fmt.Sprintf("resource_metadata=%q", fmt.Sprintf("%s/.well-known/oauth-protected-resource", md.Resource)),
	}

	if len(md.ScopesSupported) > 0 {
		params = append(params, fmt.Sprintf("scope=%q", strings.Join(md.ScopesSupported, " ")))
	}

	return fmt.Sprintf("Bearer %s", strings.Join(params, ", "))
}
