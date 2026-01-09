package caddy_oidc

import (
	"fmt"
	"strings"
)

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
