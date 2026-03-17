// Package request provides utilities for working with HTTP requests.
package request

import (
	"net/http"
	"net/url"

	"github.com/munnerz/goautoneg"
)

// URL returns the original fully qualified request URL made by the client before any intermediate proxies.
// Assumes that Caddy has already sanitized any X-Forwarded-* headers.
func URL(r *http.Request) *url.URL {
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

// IsIframe returns true if the request is coming from an iframe based on the Sec-Fetch-Dest header.
func IsIframe(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Dest") == "iframe"
}

// IsBrowserInteractive returns true if the request is likely coming from a browser.
func IsBrowserInteractive(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	if dest != "" {
		return dest == "document" || dest == "iframe"
	}

	// Fallback for older browsers: check Accept header for HTML.
	// If the browser doesn't send Sec-Fetch-Dest, we check if it's looking for HTML.
	return goautoneg.Negotiate(r.Header.Get("Accept"), []string{"text/html"}) == "text/html"
}
