package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yeti47/ollama-proxy/internal/health"
	"github.com/yeti47/ollama-proxy/internal/proxy"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:11434", "listen address (e.g. 127.0.0.1:11434)")
	target := flag.String("target", "https://ollama.com", "upstream target URL")
	apiKey := flag.String("api-key", "", "Ollama API key to inject as Authorization: Bearer <key> (can also set OLLAMA_API_KEY env var)")
	preserveAuth := flag.Bool("preserve-auth", false, "do not overwrite client Authorization header if present")
	versionFallback := flag.String("version-fallback", "", "fallback version to return for /api/version when upstream reports 0.0.0 (can also set PROXY_VERSION_FALLBACK env var)")
	flag.Parse()

	// compute effective fallback value
	fallback := *versionFallback
	if fallback == "" {
		fallback = os.Getenv("PROXY_VERSION_FALLBACK")
		if fallback == "" {
			fallback = "0.15.2"
		}
	}

	// prefer env var if flag not provided
	key := *apiKey
	if key == "" {
		key = os.Getenv("OLLAMA_API_KEY")
	}

	u, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("invalid target url: %v", err)
	}

	p := proxy.NewReverseProxy(u, key, *preserveAuth, fallback)
	// don't log the API key; only log whether it's present
	log.Printf("api-key present=%t preserve-auth=%t version-fallback=%s", key != "", *preserveAuth, fallback)

	mux := http.NewServeMux()
	mux.Handle("/", loggingMiddleware(p))
	mux.HandleFunc("/healthz", health.HealthHandler)

	srv := &http.Server{
		Addr:         *listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// graceful shutdown
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	log.Printf("ollama-proxy listening on %s forwarding to %s", *listen, u.String())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe(): %v", err)
	}
	<-idleConnsClosed
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.String())
		next.ServeHTTP(w, r)
		log.Printf("completed in %s", time.Since(start))
	})
}
