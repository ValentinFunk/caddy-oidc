# Caddy OIDC

A Caddy plugin for OIDC authentication and authorization.

Inspired by [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) but instead of requiring each application to be
configured individually, perform authentication and authorization at the Caddy level.

## Advantages over oauth2-proxy

- Avoids the need to configure each application individually, with N+1 oauth2 proxies per application
- Centralized access logging that includes user ID
- Easier integration with security tools like fail2ban, etc
- Anonymous access and client ip-based authorization rules
- Support for RFC9728 (OAuth 2.0 Protected Resource Metadata)

# Installation

Installation can be done either via the provided Docker image (Caddy with only caddy-oidc installed)

```
ghcr.io/relvacode/caddy-oidc:latest
```

Or by building caddy with this plugin via [xcaddy](https://github.com/caddyserver/xcaddy)

```Dockerfile
FROM caddy:builder AS builder
RUN xcaddy build \
    --with github.com/relvacode/caddy-oidc
```

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

## Global Directive

| Option                        | Description                                                                                                                                                 | Default            |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| `issuer`                      | The OIDC issuer URL                                                                                                                                         |                    |
| `client_id`                   | The OIDC client ID                                                                                                                                          |                    |
| `secret_key`                  | A secret key used to sign cookies with, must be either 32 or 64 bytes long                                                                                  |                    |
| `redirect_url`                | (optional) The URL to redirect to after authentication. If the URL is relative, the fully qualified URL is constructed using the request host and protocol. | `/oauth2/callback` |
| `tls_insecure_skip_verify`    | (optional) Skip TLS certificate verification with the OIDC provider.                                                                                        |                    |
| `scope`                       | (optional) The scope to request from the OIDC provider.                                                                                                     | `openid`           |
| `username`                    | (optional) The claim to use as the username.                                                                                                                | `sub`              |
| `claim`                       | (optional) A list of claims to include in the session. Used for request authorization. Any access policy rules that use a claim must be configured here.    |                    |
| `cookie`                      | (optional) Configures the cookie used to store the authentication state.                                                                                    |                    |
| `protected_resource_metadata` | (optional) Configure or disable RFC9728 support.                                                                                                            |                    |

### Cookie

Cookie configuration is used to control how the authentication session cookie is set.
The session cookie is a signed cookie containing minimal state about the user's authentication.

| Option      | Description                                 |
|-------------|---------------------------------------------|
| `name`      | The name of the cookie.                     |
| `domain`    | (optional) The domain of the cookie.        |
| `path`      | (optional) The path of the cookie.          |
| `insecure`  | (optional) Disable secure cookies.          |
| `same_site` | (optional) The samesite mode of the cookie. |

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

If the request is unauthenticated, and there is not an explicit `allow` or `deny` rule that matches the request,
and the request is made by a browser, then the browser will be automatically redirected to the OIDC provider for
authentication.

### Access Rules

Each access rule can be either `allow` or `deny`. Inspired by AWS IAM policies, each request must match at least one
`allow` rule to be authorized.

Access rules match using Caddy's regular [request matchers](https://caddyserver.com/docs/caddyfile/matchers).
Additional [HTTP matchers](#http-matchers) are provided for authentication-specific request matching.

> [!CAUTION]
> Without an explicit [user](#user) match in an `allow` policy rule, all requests will be allowed, even anonymous
> requests.

If a request matches any `deny` rule then the request is denied, even if another `allow` rule matches.

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

## HTTP Matchers

In addition to the standard Caddy request matchers, the following matchers are provided.
These matchers are only compatible with HTTP requests handled by the handler directive.

### User

Matches the username of the authenticated user. A user match will never match an anonymous user.

```caddyfile
# Allow any authenticated user

allow {
    user *
}
```

```caddyfile
# Allow any authenticated user from example.com

allow {
    user *@example.com
}
```

```caddyfile
# Allow multiple users

allow {
    user steve
    user bob
    user john
}
```

### Anonymous

Matches request sessions that are anonymous.
Anonymous sessions are sessions that have not been authenticated by the OIDC provider.

```caddyfile
# Allow anonymous requests to /healthcheck

allow {
    anonymous
    path /healthcheck
}
```

### Claim

Matches claims in the request session.

If the session claim is an array, then the request must match at least one value in the array.
Any non-string claim values are ignored and will not match.

Different claim names are evaluated as a logical AND.
Multiple values for the same claim name are evaluated as a logical OR.

> [!NOTE]
> Any claims must be configured in the `oidc` directive `claim` option.

```caddyfile
# Allow requests containing role = write

allow {
    claim role write
}
```

```caddyfile
# Allow requests containing role = read OR role = write

allow {
    claim role read
    claim role write
}
```

```caddyfile
# Allow requests containing sub = steve@example.com AND role = read

allow {
    claim sub steve@example.com
    claim role read
}
```

Replacer variables are supported in both claim name and claim value.

```caddyfile
# Allow requests containing host = {http.host}

allow {
    claim host {http.host}
}
```

Wildcard matching is also supported in claim values.

```caddyfile
# Allow requests where the role claim starts with "read:"

allow {
    claim role read:*
}
```


