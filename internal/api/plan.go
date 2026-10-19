package api

import (
	"net/http"
	"time"
)

type planItem struct {
	ActionID    string `json:"action_id,omitempty"`
	Description string `json:"description"`
	LynisTest   string `json:"lynis_test,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type agentPlan struct {
	Role     string     `json:"role"`
	Pending  []planItem `json:"pending"`
	Deferred []planItem `json:"deferred"`
}

type planResponse struct {
	AsOf   time.Time `json:"as_of"`
	Score  int       `json:"lynis_score_baseline"`
	Loa    agentPlan `json:"loa"`
	Claude agentPlan `json:"claude"`
}

// currentPlan is the hand-maintained hardening plan served at /api/v1/plan.
// Example only: fill Pending/Deferred with your own outstanding actions.
var currentPlan = planResponse{
	AsOf: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	Loa: agentPlan{
		Role:     "audit and apply hardening actions via the API",
		Pending:  []planItem{},
		Deferred: []planItem{},
	},
	Claude: agentPlan{
		Role:     "build and maintain the hardened-api; add new actions for Loa to apply",
		Pending:  []planItem{},
		Deferred: []planItem{},
	},
}

func (s *server) handlePlan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, currentPlan)
}
