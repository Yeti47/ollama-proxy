package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestAuthorizationInjectionAndPreserve(t *testing.T) {
	t.Run("injects when absent", func(t *testing.T) {
		ch := make(chan string, 1)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ch <- r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		defer upstream.Close()

		u, _ := url.Parse(upstream.URL)
		p := NewReverseProxy(u, "sk-test", false)
		proxySrv := httptest.NewServer(p)
		defer proxySrv.Close()

		resp, err := http.Get(proxySrv.URL + "/api/tags")
		if err != nil {
			t.Fatalf("get error: %v", err)
		}
		resp.Body.Close()

		select {
		case got := <-ch:
			want := "Bearer sk-test"
			if got != want {
				t.Fatalf("expected %q got %q", want, got)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for upstream request")
		}
	})

	t.Run("preserve client auth when preserveAuth true", func(t *testing.T) {
		ch := make(chan string, 1)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ch <- r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer upstream.Close()

		u, _ := url.Parse(upstream.URL)
		p := NewReverseProxy(u, "sk-test", true)
		proxySrv := httptest.NewServer(p)
		defer proxySrv.Close()

		req, _ := http.NewRequest("GET", proxySrv.URL+"/api/tags", nil)
		req.Header.Set("Authorization", "Bearer client-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do error: %v", err)
		}
		resp.Body.Close()

		select {
		case got := <-ch:
			want := "Bearer client-token"
			if got != want {
				t.Fatalf("expected %q got %q", want, got)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for upstream request")
		}
	})
}
