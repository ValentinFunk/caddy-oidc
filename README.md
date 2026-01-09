# Caddy OIDC

A Caddy plugin for OIDC authentication and authorization.

Inspired by [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) but instead of requiring each application to be
configured individually, perform authentication and authorization at the Caddy level.

# Advantages over oauth2-proxy

- Avoids the need to configure each application individually, with N+1 oauth2 proxies per application
- Centralized access logging that includes user ID
- Easier integration with security tools like fail2ban, etc
- Anonymous access and client ip-based authorization rules
- Support for RFC9728 (OAuth 2.0 Protected Resource Metadata)

# Configuration

`caddy-oidc` has a global and per-route `oidc` directive.

The global directive is used to configure the OIDC provider. An example minimum configuration is shown below.

```caddyfile
{
    oidc example {
        issuer https://accounts.google.com
        client_id < client_id >
        secret_key {env.OIDC_SECRET_KEY}
    }
}
```

Each route then uses the `oidc` directive to configure the route using the named provider

```caddyfile
example.com {
    oidc example {
        allow {
            user *
        }
    }
    reverse_proxy localhost:8080
}
```

### Global Directive

- `issuer` - The OIDC issuer URL
- `client_id` - The OIDC client ID
- `secret_key` - A secret key used to sign cookies with, must be either 32 or 64 bytes long
- `redirect_url` - (optional) The URL to redirect to after authentication. Defaults to `/oauth2/callback`. If the URL is
  relative, the fully qualified URL is constructed using the request host and protocol.
- `tls_insecure_skip_verify` - (optional) Skip TLS certificate verification with the OIDC provider.
- `scope` - (optional) The scope to request from the OIDC provider. Defaults to `openid`.
- `username` - (optional) The claim to use as the username. Defaults to `sub`.
- `claim` - (optional) A list of claims to include in the session. Used for request authorization. Any access policy
  rules that use a claim must be configured here.
- `cookie` - (optional) Configures the cookie used to store the authentication state.
- `protected_resource_metadata` - (optional) Configure or disable RFC9728 support.

### Cookie

Cookie configuration is used to control how the authentication session cookie is set.
The session cookie is a signed cookie containing minimal state about the user's authentication.

- `name` - The name of the cookie.
- `domain` - (optional) The domain of the cookie.
- `path` - (optional) The path of the cookie.
- `insecure` - (optional) Disable secure cookies.
- `same_site` - (optional) The samesite mode of the cookie.

The default configuration is shown below.

```caddyfile
cookie {
    name caddy
    same_site lax
    path /
}
```

### [RFC9728](https://datatracker.ietf.org/doc/rfc9728/) Support (`protected_resource_metadata`)

Caddy OIDC supports RFC9728 (OAuth 2.0 Protected Resource Metadata) to discover the OIDC provider metadata via the
well-known URL `/.well-known/oauth-protected-resource`.

If the request is unauthenticated, passes at least one `allow` rule, and the request is not made by a browser,
then a `401 Unauthorized` response is returned with a WWW-Authenticate header conforming
to [WWW-Authenticate Response](https://datatracker.ietf.org/doc/html/rfc9728#section-5.1).

Settings can be controlled via the `oidc` directive `protected_resource_metadata`. The default behavior is to enable.

```caddyfile
# Disable RFC9728 support.
# This makes /.well-known/oauth-protected-resource return a 404 Not Found.
protected_resource_metadata off
```

#### Audience

As a custom extension to the standard, resource metadata can be configured to include the expected token audience (
`aud`) claim.

If enabled, the metadata response will contain an additional `audience` field containing the configured client ID of the
OIDC provider configuration.

This is designed as an alternative to dynamic client registration to let another client (e.g. a CLI)
use [JWT Exchange](https://datatracker.ietf.org/doc/html/rfc7523#section-8.2) with its own token with the OIDC provider
and
make requests to this server without prior knowledge of this server's OAuth configuration.

```caddyfile
# Include the expected audience field in the metadata
protected_resource_metadata {
    audience
}
```

## Handler Directive

The handler directive is placed on routes to provide authentication and authorization for that route.
Requests are authenticated according to the configured OIDC provider and then authorized according to access policy
rules configured in the directive.

The handler directive **must** contain at least one `allow` rule.

```caddyfile
# Allow any valid authenticated user

example.com {
    oidc example {
        allow {
            user *
        }
    }
    reverse_proxy localhost:8080
}
```

### Access Rules

Each access rule can be either `allow` or `deny`. Inspired by AWS IAM policies, each request must match at least one
`allow` rule to be authorized.
If a request matches any `deny` rule then the request is denied.

```caddyfile
# Allow any authenticated user from example.com except from steve

oidc example {
    allow {
        user *@example.com
    }
    deny {
        user steve@example.com
    }
}
```

Multiple conditions for a single rule are a logical AND.

```caddyfile
# Allow unauthenticated access from the local network

oidc example {
    allow {
        anonymous
        client 192.168.0.0/24
    }
}
```

#### user

The `user` rule can be used to match authenticated users by their username. The username is extracted from the OIDC
claims according to the provider configuration.
One or more usernames can be specified in a space separated list and supports wildcard `*` matching.

#### anonymous

An anonymous request is one that does not contain an authentication cookie or bearer token.
This allows clients to make anonymous requests to the server where desired.

#### client

The `client` rule can be used to match requests from a specific IP address or subnet.
Supplied as a space-separated list of CIDR notation subnets or IP addresses.

#### query

The `query` rule can be used to match requests based on query parameters, either by existence or wildcard matched value.

```caddyfile
# Allow requests having api-key=xyz and/or public

allow {
    query api-key=xyz public
}
```

#### header

The `header` rule can be used to match requests based on HTTP header values, either by existence or wildcard matched
value.
The header name is case-insensitive and normalized to the canonical form specified in RFC 7230.

> [!CAUTION]
> Headers are controlled by the client and can be easily spoofed.

```caddyfile
# Allow requests having X-Api-Key=xyz

allow {
    header X-Api-Key=xyz
}
```

```caddyfile
# Allow requests having any Referer like https://example.com/*
allow {
    header Referer=https://example.com/*
}
```

#### claim

Match requests based on the value of a claim in the ID token or session cookie.
The oidc provider global directive must be configured to copy claims from the ID token.

If the ID token claims are an array, the rule matches if any of the array values match. Each claim value must be a
string.

Standard claims (i.e. `exp`, `aud`, `iat`) are always validated.

```caddyfile
# Allow requests having the claim role=read

allow {
    claim role=read
}
```

Multiple values for a single claim directive are a logical AND

```caddyfile
# Allow requests having the claim role=read AND role=admin

allow {
    claim role=read role=admin
}
```

Claim restrictions are wildcard matched against the claim value.

```caddyfile
# Allow requests having the claim where any role value starts with read:

allow {
    claim role=read:*
}
```
