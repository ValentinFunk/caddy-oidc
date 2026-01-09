package caddy_oidc

import (
	"net/http"
	"net/url"

	"github.com/munnerz/goautoneg"
)

// RequestUrl returns the original fully qualified request URL made by the client before any intermediate proxies.
// Assumes that Caddy has already sanitized any X-Forwarded-* headers.
func RequestUrl(r *http.Request) *url.URL {
	var u = new(url.URL)
	*u = *r.URL

	u.Scheme = "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		u.Scheme = "https"
	}

	u.Host = r.Host
	if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
		u.Host = forwardedHost
	}

	return u
}

// ShouldStartLogin returns true if the request should start the authorization flow on a failed authentication attempt
// based on if the request is likely coming from a browser.
func ShouldStartLogin(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}

	dest := r.Header.Get("Sec-Fetch-Dest")
	if dest != "" {
		return dest == "document" || dest == "iframe"
	}

	// Fallback for older browsers: check Accept header for HTML.
	// If the browser doesn't send Sec-Fetch-Dest, we check if it's looking for HTML.
	return goautoneg.Negotiate(r.Header.Get("Accept"), []string{"text/html"}) == "text/html"
}
