package request

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		request  func() *http.Request
		expected string
	}{
		{
			name: "basic http",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://localhost/path?query=1", nil)

				return r
			},
			expected: "http://localhost/path?query=1",
		},
		{
			name: "https via TLS",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
				r.TLS = &tls.ConnectionState{}

				return r
			},
			expected: "https://localhost/",
		},
		{
			name: "https via X-Forwarded-Proto",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
				r.Header.Set("X-Forwarded-Proto", "https")

				return r
			},
			expected: "https://localhost/",
		},
		{
			name: "host from X-Forwarded-Host",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				r.Header.Set("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "http://example.com/foo",
		},
		{
			name: "complex proxy headers",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "http://internal-ip:8080/api", nil)
				r.Host = "internal-ip:8080"
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "public.example.com")

				return r
			},
			expected: "https://public.example.com/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := tt.request()
			got := URL(req)
			assert.Equal(t, tt.expected, got.String())
		})
	}
}

func TestIsIframe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		dest   string
		expect bool
	}{
		{name: "iframe", dest: "iframe", expect: true},
		{name: "document", dest: "document", expect: false},
		{name: "empty", dest: "", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.dest != "" {
				r.Header.Set("Sec-Fetch-Dest", tt.dest)
			}

			assert.Equal(t, tt.expect, IsIframe(r))
		})
	}
}

func TestShouldStartLogin(t *testing.T) {
	t.Parallel()

	t.Run("incorrect method", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodPost, "/", nil)
		assert.False(t, IsBrowserInteractive(r))
	})
	t.Run("can't accept", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "application/json")
		assert.False(t, IsBrowserInteractive(r))
	})
	t.Run("Sec-Fetch-Dest", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Sec-Fetch-Dest", "document")
		assert.True(t, IsBrowserInteractive(r))
	})
	t.Run("accept HTML", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "text/html")
		assert.True(t, IsBrowserInteractive(r))
	})
}
