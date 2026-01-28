package proxy

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// NewReverseProxy returns a reverse proxy that forwards to target while
// preserving path, headers and body. It sets Host and X-Forwarded-* headers
// and uses a reasonable Transport with TLS verification enabled. It can also
// inject an Authorization: Bearer <key> header if apiKey is provided.
func NewReverseProxy(target *url.URL, apiKey string, preserveAuth bool) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

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
