# Popup Login for Iframe Authentication

This guide explains how to use caddy-oidc's popup login flow to authenticate users inside cross-origin iframes.

## The Problem

When your OIDC-protected site (e.g., `preview-abc123.my-app.com`) is embedded in an iframe on a different origin (e.g., `orchestrator.web.dev`):

1. The OIDC redirect flow doesn't work — most IdPs block their login page from being framed (`X-Frame-Options: DENY`).
2. Session cookies set on the preview domain are considered **third-party** by the browser, because the top-level page is on a different site. Browsers increasingly block third-party cookies by default.

caddy-oidc solves this by automatically detecting iframe requests and presenting a popup-based login flow instead of the usual redirect.

## How It Works

```
orchestrator.web.dev
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  <iframe src="preview-abc123.my-app.com">                │
│  ┌────────────────────────────────────────────────────┐  │
│  │                                                    │  │
│  │  1. Loads in iframe → no session cookie            │  │
│  │  2. caddy-oidc detects Sec-Fetch-Dest: iframe      │  │
│  │  3. Returns "Login Required" HTML page              │  │
│  │  4. User clicks "Sign In" → opens popup ───────────┼──┼──► popup window
│  │                                                    │  │    preview-abc123.my-app.com
│  │                                                    │  │    ┌──────────────────────┐
│  │                                                    │  │    │ 5. Redirects to IdP  │
│  │                                                    │  │    │ 6. User logs in      │
│  │                                                    │  │    │    (or instant if     │
│  │                                                    │  │    │    session exists)    │
│  │                                                    │  │    │ 7. Callback sets     │
│  │                                                    │  │    │    session cookie     │
│  │  9. requestStorageAccess() grants cookie access    │  │    │ 8. postMessage →     │
│  │ 10. Iframe reloads → authenticated ✓              │  │    │    window.close()     │
│  │                                                    │  │    └──────────────────────┘
│  └────────────────────────────────────────────────────┘  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

The popup opens a **top-level window** on the preview's origin, so:

- The IdP login page is not framed (no `X-Frame-Options` issues)
- The session cookie is set in a **first-party context** (reliable cookie storage)
- After the popup completes, the iframe uses the **Storage Access API** to unlock access to the cookie

If the user already has an active session at the IdP (e.g., from a prior login on the orchestrator), the popup flow is instant — the IdP redirects back immediately without user interaction.

## Configuration

### 1. Authentication Methods

If your iframe also needs to accept Bearer tokens (e.g., from a Frontegg-issued JWT), add `bearer` alongside `cookie` in the `authenticate` block. The first authenticator to succeed wins.

```caddyfile
{
    oidc my_provider {
        issuer https://your-app.frontegg.com
        client_id "<your-frontegg-client-id>"
        username email

        authenticate {
            bearer
            cookie {
                name     my_session
                secret   {env.COOKIE_SECRET}
                same_site none
            }
        }
    }
}

your-domain.com {
    oidc my_provider {
        allow {
            claim email *@company.com
        }
    }
    reverse_proxy localhost:8080
}
```

- **`bearer`** — validates JWTs from the `Authorization: Bearer <token>` header against the OIDC provider's signing keys (discovered via the issuer URL)
- **`client_id`** — must match the `aud` claim in the JWT
- **`username email`** — extracts `{http.auth.user.id}` from the `email` claim instead of default `sub`
- **`claim email *@company.com`** — wildcard-matches the email domain in the JWT claims

### 2. Cookie Settings (caddy-oidc)

The session cookie **must** be configured with `SameSite=None` and `Secure` for the browser to send it in a cross-origin iframe context.

```caddyfile
oidc my_provider {
    # ... issuer, client_id, etc.

    cookie {
        name     my_session
        secret   {env.COOKIE_SECRET}
        same_site none
        # Secure is the default (do NOT set "insecure")

        # Optional: inject OAuth2 tokens into localStorage for SPA use.
        # The popup callback will write tokens with this prefix to localStorage.
        # Since the popup and iframe share the same origin, the SPA can read them.
        popup_storage_prefix myapp-auth
    }
}
```

When `popup_storage_prefix` is set, the popup callback page writes the following keys to `localStorage`:

| Key | Value |
|-----|-------|
| `{prefix}access_token` | The OAuth2 access token |
| `{prefix}id_token` | The OIDC ID token (JWT) |
| `{prefix}refresh_token` | The refresh token (if issued by the IdP) |
| `{prefix}expires_at` | Token expiry as a Unix timestamp |
| `{prefix}token_type` | Token type (typically `Bearer`) |

The SPA can then use these tokens for its own API calls, e.g.:

```js
const token = localStorage.getItem("myapp-authaccess_token");
fetch("/api/data", { headers: { Authorization: `Bearer ${token}` } });
```

> **Why `same_site none`?**
> When `orchestrator.web.dev` embeds `preview-abc123.my-app.com` in an iframe, the browser considers the preview's cookies as third-party. `SameSite=Lax` (the browser default) blocks cookies on cross-site iframe requests. `SameSite=None; Secure` tells the browser to send the cookie in all contexts, including third-party iframes.

### 3. Iframe Element (embedding page)

On the page that embeds the iframe (e.g., `orchestrator.web.dev`), configure the `<iframe>` element with the necessary permissions:

```html
<iframe
  src="https://preview-abc123.my-app.com"
  allow="storage-access"
></iframe>
```

The `allow="storage-access"` attribute grants the embedded content permission to use the Storage Access API. Without it, the browser may block `document.requestStorageAccess()` calls.

#### If using the `sandbox` attribute

If you apply `sandbox` restrictions to the iframe, you **must** include these tokens:

```html
<iframe
  src="https://preview-abc123.my-app.com"
  sandbox="allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-storage-access-by-user-activation"
  allow="storage-access"
></iframe>
```

| Token | Why it's needed |
|-------|----------------|
| `allow-scripts` | The login page needs to run JavaScript to open the popup and handle `postMessage` |
| `allow-same-origin` | Required for the iframe to access its own cookies and use the Storage Access API |
| `allow-popups` | The login flow opens a popup window via `window.open()` |
| `allow-popups-to-escape-sandbox` | The popup must not inherit sandbox restrictions, otherwise the OIDC redirect flow inside it won't work |
| `allow-storage-access-by-user-activation` | Enables the Storage Access API within the sandboxed iframe |

### 4. HTTP Headers (server)

If your server sets a `Permissions-Policy` header, ensure `storage-access` is not blocked:

```
Permissions-Policy: storage-access=(self "https://preview-abc123.my-app.com")
```

If you don't set a `Permissions-Policy` header, `storage-access` is allowed by default.

## Storage Access API Details

After the popup sets the session cookie and closes, the iframe calls [`document.requestStorageAccess()`](https://developer.mozilla.org/en-US/docs/Web/API/Document/requestStorageAccess) before reloading. This is handled automatically by the login page that caddy-oidc serves.

### Prerequisites for `requestStorageAccess()` to succeed

1. **User interaction**: The API requires [transient activation](https://developer.mozilla.org/en-US/docs/Glossary/Transient_activation) (a user gesture like a click). The popup flow satisfies this because the user clicked "Sign In".

2. **Prior first-party interaction**: The popup window satisfies this requirement — the OIDC flow in the popup is a top-level visit to `preview-abc123.my-app.com`.

3. **HTTPS**: The Storage Access API is only available in [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).

4. **`SameSite=None; Secure` on cookies**: Chrome specifically requires cookies to have `SameSite=None` set explicitly and the `Secure` flag. This is configured via the caddy-oidc cookie settings above.

### Browser-specific behavior

| Browser | Behavior |
|---------|----------|
| **Chrome** | Grants access automatically if the user interacted with the site in a popup. Access expires after 30 days without interaction. |
| **Safari** | May prompt the user on first request. Access expires after 30 days of browser usage without interaction. |

### Permission lifetime

Once granted, the storage access permission is stored with the key `<top-level site, embedded site>`:

- Permission granted for `<web.dev, my-app.com>` means **any** page on `*.my-app.com` embedded in **any** page on `*.web.dev` can call `requestStorageAccess()` and have it resolve immediately (without a prompt).
- The iframe still needs to call `requestStorageAccess()` in each new browsing context (new tab, new page load) to **activate** the permission, but this happens automatically without user interaction once granted.

## Automatic vs. Manual Login

caddy-oidc serves a minimal HTML page with a **"Sign In" button** when it detects an unauthenticated iframe request. The page also attempts to open the popup automatically via JavaScript on load, but browsers typically block popups that aren't triggered by a user gesture. The button ensures the user can always initiate login manually if the automatic popup is blocked.

## No Changes Needed on the Embedding Page

The popup login flow is **entirely self-contained** within the iframe. The embedding page (`orchestrator.web.dev`) does not need any JavaScript to coordinate the login — caddy-oidc's login page inside the iframe handles:

1. Opening the popup
2. Listening for the `postMessage` from the popup callback
3. Calling `requestStorageAccess()`
4. Reloading the iframe content

The only requirement on the embedding side is the correct `<iframe>` attributes as documented above.

## Troubleshooting

### Popup is blocked

Browsers block `window.open()` calls that aren't triggered by user interaction. The login page includes a "Sign In" button as a fallback. Ensure the iframe has `allow-popups` if using the `sandbox` attribute.

### Cookie not sent after login

- Verify the cookie is configured with `same_site none` (not `lax` or `strict`)
- Verify the cookie has `Secure` set (the default; don't use `insecure`)
- Verify the iframe has `allow="storage-access"` set
- Check the browser console for Storage Access API errors
- If using `sandbox`, ensure `allow-storage-access-by-user-activation` is included

### `requestStorageAccess()` is rejected

- The user must have interacted with the embedded site in a first-party context (the popup satisfies this)
- The call must happen with transient activation (the `postMessage` handler propagates activation from the user's click)
- Check that `Permissions-Policy: storage-access` is not blocking the iframe's origin

### Login page appears but no popup opens

- Check for `allow-popups` in the iframe's `sandbox` attribute
- Check browser popup blocker settings
- Click the "Sign In" button manually
