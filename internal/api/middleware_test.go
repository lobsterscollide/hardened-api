package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lobsterscollide/hardened-api/internal/config"
)

func do(h http.Handler, method, path, key, remote string) int {
	req := httptest.NewRequest(method, path, strings.NewReader(`{"actions":[],"dry_run":true}`))
	req.RemoteAddr = remote
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Harden-Confirm", "yes")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestHardenKeyIsSeparate(t *testing.T) {
	h := NewRouter(&config.Config{APIKey: "read", HardenKey: "apply", RateLimit: 100}, nil)
	const ip = "127.0.0.1:1"

	if got := do(h, "GET", "/api/v1/harden/actions", "read", ip); got != http.StatusOK {
		t.Errorf("read key on read route: got %d, want 200", got)
	}
	if got := do(h, "POST", "/api/v1/harden", "read", ip); got != http.StatusUnauthorized {
		t.Errorf("read key on harden route: got %d, want 401", got)
	}
	if got := do(h, "POST", "/api/v1/harden", "apply", ip); got != http.StatusOK {
		t.Errorf("harden key on harden route: got %d, want 200", got)
	}
}

func TestRateLimitIgnoresSourcePort(t *testing.T) {
	h := NewRouter(&config.Config{APIKey: "k", HardenKey: "k", RateLimit: 2}, nil)
	codes := []int{
		do(h, "GET", "/api/v1/harden/actions", "k", "10.0.0.1:1001"),
		do(h, "GET", "/api/v1/harden/actions", "k", "10.0.0.1:1002"),
		do(h, "GET", "/api/v1/harden/actions", "k", "10.0.0.1:1003"),
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("third request from same IP on a new port: got %d, want 429 (codes %v)", codes[2], codes)
	}
	if got := do(h, "GET", "/api/v1/harden/actions", "k", "10.0.0.2:1001"); got != http.StatusOK {
		t.Errorf("different IP: got %d, want 200", got)
	}
}
