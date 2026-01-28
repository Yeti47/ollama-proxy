package proxy

import (
	"encoding/json"
	"io"
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
		p := NewReverseProxy(u, "sk-test", false, "")
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
		p := NewReverseProxy(u, "sk-test", true, "")
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

func TestVersionFixup(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"0.0.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	p := NewReverseProxy(u, "", false, "0.15.2")
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/api/version")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if v, ok := m["version"].(string); !ok || v != "0.15.2" {
		t.Fatalf("expected version 0.15.2 got %v", m["version"])
	}
}

func TestVersionCustomFallback(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"0.0.0.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	p := NewReverseProxy(u, "", false, "9.9.9")
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/api/version")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if v, ok := m["version"].(string); !ok || v != "9.9.9" {
		t.Fatalf("expected version 9.9.9 got %v", m["version"])
	}
}
func TestStreamingResponsePreserved(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream ResponseWriter is not a Flusher")
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("part1\n"))
		flusher.Flush()
		// simulate streaming delay
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("part2\n"))
		flusher.Flush()
		// return to close
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	p := NewReverseProxy(u, "", false, "")
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/stream")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(b) != "part1\npart2\n" {
		t.Fatalf("unexpected body: %q", string(b))
	}
}
