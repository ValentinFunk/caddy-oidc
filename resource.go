package caddy_oidc

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

var _ caddyfile.Unmarshaler = (*ProtectedResourceMetadataConfiguration)(nil)

// ProtectedResourceMetadataConfiguration configures the protected resource metadata endpoint.
type ProtectedResourceMetadataConfiguration struct {
	Disable  bool `json:"disable"`
	Audience bool `json:"audience,omitempty"`
}

// UnmarshalCaddyfile sets up the ProtectedResourceMetadataConfiguration from Caddyfile tokens.
/*
	protected_resource_metadata disable | {
		audience
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
		case "audience":
			c.Audience = true
		default:
			return d.Errf("unrecognized protected_resource_metadata subdirective '%s'", d.Val())
		}
	}

	return nil
}

// OAuthProtectedResource is the JSON payload sent from /.well-known/oauth-protected-resource
// or advertised in WWW-Authenticate on 401 responses.
type OAuthProtectedResource struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// Audience is a custom extension to the OAuth Protected Resource Metadata spec.
	Audience string `json:"audience,omitempty"`
}

// WWWAuthenticate returns the value of the WWW-Authenticate header for this resource.
// https://datatracker.ietf.org/doc/html/rfc9728#name-use-of-www-authenticate-for
// https://datatracker.ietf.org/doc/html/rfc6750#section-3
func (md *OAuthProtectedResource) WWWAuthenticate() string {
	var params = []string{
		"resource_metadata=" + strconv.Quote(md.Resource+"/.well-known/oauth-protected-resource"),
	}

	if len(md.ScopesSupported) > 0 {
		params = append(params, "scope="+strconv.Quote(strings.Join(md.ScopesSupported, " ")))
	}

	return "Bearer " + strings.Join(params, ", ")
}
