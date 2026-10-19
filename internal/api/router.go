package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/checks"
	"github.com/lobsterscollide/hardened-api/internal/config"
	"github.com/lobsterscollide/hardened-api/internal/harden"
)

type server struct {
	cfg      *config.Config
	checkers map[string]checks.Checker
	auditLog *slog.Logger
}

func NewRouter(cfg *config.Config, checkerMap map[string]checks.Checker) http.Handler {
	auditLog := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	s := &server{
		cfg:      cfg,
		checkers: checkerMap,
		auditLog: auditLog,
	}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Authenticated routes
	auth := authMiddleware(cfg.APIKey)
	rl := newRateLimiter(cfg.RateLimit)

	protected := func(method, pattern string, h http.HandlerFunc) {
		mux.Handle(method+" "+pattern, chain(h, recovery, requestLogger, rl.middleware, auth))
	}

	protected("GET", "/api/v1/checks", s.handleAllChecks)
	protected("GET", "/api/v1/checks/ssh", s.handleCheck("ssh"))
	protected("GET", "/api/v1/checks/firewall", s.handleCheck("firewall"))
	protected("GET", "/api/v1/checks/fileperm", s.handleCheck("fileperm"))
	protected("GET", "/api/v1/checks/ports", s.handleCheck("ports"))
	protected("GET", "/api/v1/checks/sysctl", s.handleCheck("sysctl"))
	protected("GET", "/api/v1/checks/users", s.handleCheck("users"))
	protected("GET", "/api/v1/checks/services", s.handleCheck("services"))
	protected("GET", "/api/v1/checks/chkrootkit", s.handleCheck("chkrootkit"))
	protected("GET", "/api/v1/checks/rkhunter", s.handleCheck("rkhunter"))
	protected("GET", "/api/v1/checks/clamscan", s.handleCheck("clamscan"))
	protected("GET", "/api/v1/checks/packages", s.handleCheck("packages"))
	protected("GET", "/api/v1/checks/aide", s.handleCheck("aide"))
	protected("GET", "/api/v1/checks/suid", s.handleCheck("suid"))
	protected("GET", "/api/v1/plan", s.handlePlan)
	protected("GET", "/api/v1/harden/actions", s.handleListActions)
	// Applying actions uses HARDENED_API_HARDEN_KEY (defaults to HARDENED_API_KEY).
	mux.Handle("POST /api/v1/harden", chain(http.HandlerFunc(s.handleHarden), recovery, requestLogger, rl.middleware, authMiddleware(cfg.HardenKey)))

	// Agent lifecycle (platform control API — stubs pending loa-finn integration)
	protected("GET", "/api/v1/agents", s.handleListAgents)
	protected("POST", "/api/v1/agents", s.handleSpawnAgent)
	protected("GET", "/api/v1/agents/{id}", s.handleGetAgent)
	protected("POST", "/api/v1/agents/{id}/kill", s.handleKillAgent)

	return mux
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleCheck(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.checkers[name]
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Sprintf("unknown check: %s", name))
			return
		}
		writeJSON(w, http.StatusOK, c.Run())
	}
}

// checkerTimeout caps how long a single checker can block the aggregate
// endpoint. Slow scanners (rkhunter, clamscan) that exceed this are marked
// as timed out; their findings do not affect overall_severity.
const checkerTimeout = 10 * time.Minute

func (s *server) handleAllChecks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hostname, _ := os.Hostname()
	results := make([]checks.CheckResult, 0, len(s.checkers))

	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, c := range s.checkers {
		wg.Add(1)
		go func(name string, c checks.Checker) {
			defer wg.Done()

			done := make(chan checks.CheckResult, 1)
			go func() { done <- c.Run() }()

			var res checks.CheckResult
			select {
			case res = <-done:
				// completed normally
			case <-time.After(checkerTimeout):
				res = checks.CheckResult{
					Check: name,
					OK:    false,
					Error: fmt.Sprintf("timed out after %s", checkerTimeout),
					RunAt: time.Now(),
				}
			case <-ctx.Done():
				// client disconnected — drop this result
				return
			}

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(name, c)
	}
	wg.Wait()

	overall := checks.SeverityInfo
	for _, res := range results {
		if res.Error != "" {
			continue // don't escalate severity for errored/timed-out checks
		}
		for _, f := range res.Findings {
			overall = checks.WorstSeverity(overall, f.Severity)
		}
	}

	writeJSON(w, http.StatusOK, checks.SummaryResult{
		Hostname:        hostname,
		RunAt:           time.Now(),
		OverallSeverity: overall,
		Results:         results,
	})
}

func (s *server) handleListActions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"actions": harden.List()})
}

func (s *server) handleHarden(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Harden-Confirm") != "yes" {
		writeError(w, http.StatusBadRequest, "header X-Harden-Confirm: yes is required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req harden.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate all action IDs before applying any
	var unknown []string
	for _, id := range req.Actions {
		if _, ok := harden.Lookup(id); !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":           "unknown action IDs",
			"unknown_actions": unknown,
		})
		return
	}

	result := harden.Result{
		DryRun: req.DryRun,
		RunAt:  time.Now(),
	}

	for _, id := range req.Actions {
		action, _ := harden.Lookup(id)
		record := harden.ActionRecord{
			ActionID:    id,
			Description: action.Description,
		}

		if !req.DryRun {
			before, after, err := action.Apply()
			record.Before = before
			record.After = after
			if err != nil {
				record.Error = err.Error()
			} else {
				record.Applied = true
			}
		} else {
			record.Before = "(dry-run)"
			record.After = "(dry-run)"
		}

		result.Actions = append(result.Actions, record)
	}

	s.auditLog.Info("harden",
		"dry_run", req.DryRun,
		"actions", req.Actions,
		"remote", r.RemoteAddr,
		"applied", !req.DryRun,
	)

	writeJSON(w, http.StatusOK, result)
}
