package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
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
func NewReverseProxy(target *url.URL, apiKey string, preserveAuth bool, versionFallback string) *httputil.ReverseProxy {
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

	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// If upstream is using chunked transfer encoding, ensure we do not
		// forward a Content-Length header which can confuse clients and lead
		// to ERR_INCOMPLETE_CHUNKED_ENCODING when the lengths don't match.
		if len(resp.TransferEncoding) > 0 {
			for _, te := range resp.TransferEncoding {
				if strings.EqualFold(te, "chunked") {
					resp.Header.Del("Content-Length")
					resp.ContentLength = -1
					break
				}
			}
		}

		// Diagnostic logging: if the response is chunked or an error status,
		// capture a small snippet of the body and headers to help debug
		// intermittent upstream truncation or rate-limiting issues.
		var isChunked bool
		for _, te := range resp.TransferEncoding {
			if strings.EqualFold(te, "chunked") {
				isChunked = true
				break
			}
		}
		if isChunked || resp.StatusCode >= 400 {
			// read up to maxLogBody bytes for logging and then restore the body
			if resp.Body != nil {
				snippetLimit := int64(maxLogBody)
				b, _ := io.ReadAll(io.LimitReader(resp.Body, snippetLimit))
				// mask sensitive content
				bodySnippet := maskSensitive(apiKey, string(b))

				// headers
				var hdrs []string
				for k, vv := range resp.Header {
					hdrs = append(hdrs, k+": "+strings.Join(vv, ","))
				}
				headerStr := maskSensitive(apiKey, strings.Join(hdrs, "; "))

				if resp.Request != nil {
					log.Printf("upstream %s %s -> %d; headers=%s; body_snippet=%s",
						resp.Request.Method, resp.Request.URL.String(), resp.StatusCode, headerStr, bodySnippet)
				} else {
					log.Printf("upstream -> %d; headers=%s; body_snippet=%s",
						resp.StatusCode, headerStr, bodySnippet)
				}

				// restore body so normal proxy behavior continues
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), resp.Body))
			} else {
				log.Printf("upstream: status=%d (no body)", resp.StatusCode)
			}
		}
		// Quick fix: if upstream /api/version returns an invalid version like
		// "0.0.0" or "0.0.0.0", replace it with a compatible version
		// (0.15.2) so clients that validate the version can continue.
		if resp.Request != nil && strings.HasSuffix(resp.Request.URL.Path, "/api/version") {
			if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
				if resp.Body != nil {
					b, err := io.ReadAll(resp.Body)
					if err == nil {
						var m map[string]any
						if json.Unmarshal(b, &m) == nil {
							fallback := versionFallback
							if fallback == "" {
								fallback = "0.15.2"
							}
							if v, ok := m["version"].(string); ok && (v == "0.0.0" || v == "0.0.0.0") {
								m["version"] = fallback
								nb, _ := json.Marshal(m)
								resp.Body = io.NopCloser(bytes.NewReader(nb))
								resp.ContentLength = int64(len(nb))
								resp.Header.Set("Content-Length", strconv.Itoa(len(nb)))
								// If upstream used chunked encoding, remove it to avoid
								// conflicting headers when we set Content-Length.
								resp.Header.Del("Transfer-Encoding")
								resp.TransferEncoding = nil
								log.Printf("fixed /api/version value to %s", fallback)
							} else {
								// restore original body
								resp.Body = io.NopCloser(bytes.NewReader(b))
							}
						} else {
							resp.Body = io.NopCloser(bytes.NewReader(b))
						}
					}
				}
			}
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
