package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// maskSensitive replaces occurrences of the apiKey and bearer tokens in s
// with a redacted placeholder. If apiKey is empty it still masks any
// 'Bearer <token>' occurrences when logging headers.
func maskSensitive(apiKey, s string) string {
	if apiKey != "" {
		s = strings.ReplaceAll(s, apiKey, "[REDACTED]")
		// also redact Bearer <apiKey>
		s = strings.ReplaceAll(s, "Bearer "+apiKey, "Bearer [REDACTED]")
	}
	// a generic redaction for Bearer tokens in case a client-supplied token
	// is present (we don't know it) - replace "Bearer <...>" patterns
	// conservatively by replacing the word "Bearer " followed by up to 200
	// non-space characters.
	// Keep this simple: mask any remaining occurrences of 'Bearer ' tokens
	if strings.Contains(s, "Bearer ") {
		parts := strings.Split(s, "Bearer ")
		for i := 1; i < len(parts); i++ {
			part := parts[i]
			// find first whitespace or end
			end := strings.IndexAny(part, " \t\n\r")
			if end == -1 {
				parts[i] = "[REDACTED]"
			} else {
				parts[i] = "[REDACTED]" + part[end:]
			}
		}
		s = strings.Join(parts, "Bearer ")
	}
	return s
}

// NewReverseProxy returns a reverse proxy that forwards to target while
// preserving path, headers and body. It sets Host and X-Forwarded-* headers
// and uses a reasonable Transport with TLS verification enabled. It can also
// inject an Authorization: Bearer <key> header if apiKey is provided.
func NewReverseProxy(target *url.URL, apiKey string, preserveAuth bool, verbose bool) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	const maxLogBody = 1 << 20 // 1MB

	orig := proxy.Director
	proxy.Director = func(r *http.Request) {
		orig(r) // sets scheme/host/path
		// Ensure Host header matches target host
		r.Host = target.Host

		// X-Forwarded headers
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			r.Header.Set("X-Forwarded-For", prior[0]+", "+r.RemoteAddr)
		} else {
			r.Header.Set("X-Forwarded-For", r.RemoteAddr)
		}
		r.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
		r.Header.Set("X-Forwarded-Host", r.Host)

		// Authorization injection: inject apiKey as Bearer token by default,
		// unless preserveAuth is true and client provided an Authorization header.
		if apiKey != "" {
			if !(preserveAuth && r.Header.Get("Authorization") != "") {
				token := apiKey
				if len(token) >= 7 && token[:7] == "Bearer " {
					r.Header.Set("Authorization", token)
				} else {
					r.Header.Set("Authorization", "Bearer "+token)
				}
			}
		}

		// Verbose logging: capture and log request headers and body with redaction
		if verbose {
			// copy and sanitize headers
			sanitized := make(http.Header)
			for k, v := range r.Header {
				if k == "Authorization" {
					sanitized[k] = []string{"Bearer [REDACTED]"}
				} else {
					sanitized[k] = v
				}
			}

			var bodyStr string
			if r.Body != nil {
				b, _ := io.ReadAll(io.LimitReader(r.Body, maxLogBody+1))
				trunc := false
				if len(b) > maxLogBody {
					b = b[:maxLogBody]
					trunc = true
				}
				// restore body for proxy transport
				r.Body = io.NopCloser(bytes.NewReader(b))
				bodyStr = maskSensitive(apiKey, string(b))
				if trunc {
					bodyStr += "...[truncated]"
				}
			}

			log.Printf("-> request %s %s headers=%v body=%s", r.Method, r.URL.String(), sanitized, bodyStr)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if verbose {
			// copy and sanitize response headers
			sanitized := make(http.Header)
			for k, v := range resp.Header {
				if k == "Authorization" {
					sanitized[k] = []string{"Bearer [REDACTED]"}
				} else {
					sanitized[k] = v
				}
			}

			var bodyStr string
			if resp.Body != nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, maxLogBody+1))
				trunc := false
				if len(b) > maxLogBody {
					b = b[:maxLogBody]
					trunc = true
				}
				resp.Body = io.NopCloser(bytes.NewReader(b))
				bodyStr = maskSensitive(apiKey, string(b))
				if trunc {
					bodyStr += "...[truncated]"
				}
			}

			log.Printf("<- response status=%s headers=%v body=%s", resp.Status, sanitized, bodyStr)
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	proxy.Transport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        100,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}

	return proxy
}
