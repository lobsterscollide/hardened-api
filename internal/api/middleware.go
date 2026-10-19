package api

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

func recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "panic", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func authMiddleware(apiKey string) func(http.Handler) http.Handler {
	keyBytes := []byte(apiKey)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if len(token) <= len(prefix) || token[:len(prefix)] != prefix {
				writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
				return
			}
			provided := []byte(token[len(prefix):])
			if subtle.ConstantTimeCompare(provided, keyBytes) != 1 {
				writeError(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
	limit   int
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
	}
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		now := time.Now()
		window := now.Add(-time.Minute)

		rl.mu.Lock()
		times := rl.windows[ip]
		// Evict old entries
		fresh := times[:0]
		for _, t := range times {
			if t.After(window) {
				fresh = append(fresh, t)
			}
		}
		fresh = append(fresh, now)
		rl.windows[ip] = fresh
		count := len(fresh)
		rl.mu.Unlock()

		if count > rl.limit {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
