package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		wantOK bool
	}{
		{"healthy", http.StatusOK, true},
		{"unavailable", http.StatusServiceUnavailable, false},
		{"redirect_is_not_healthy", http.StatusFound, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Errorf("unexpected health path: %s", r.URL.Path)
				}
				w.Header().Set("Location", "/healthz")
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			t.Setenv("LISTEN", strings.TrimPrefix(server.URL, "http://"))
			if err := healthcheck(); (err == nil) != tc.wantOK {
				t.Fatalf("healthcheck() = %v, want success %v", err, tc.wantOK)
			}
		})
	}
	t.Run("invalid_address", func(t *testing.T) {
		t.Setenv("LISTEN", "invalid")
		if healthcheck() == nil {
			t.Fatal("invalid address was accepted")
		}
	})
}
