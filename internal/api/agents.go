package api

import (
	"net/http"
)

// Agent lifecycle endpoints — Layer 4 platform control API.
// These stubs define the contract; implementation follows once loa-finn is wired up.
//
// Routes registered in router.go:
//   GET  /api/v1/agents          — list all agents
//   POST /api/v1/agents          — spawn a new agent
//   GET  /api/v1/agents/{id}     — get agent status
//   POST /api/v1/agents/{id}/kill — kill a running agent

func (s *server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	// TODO: query loa-finn runtime for active agents
	writeJSON(w, http.StatusOK, map[string]any{
		"agents": []any{},
		"note":   "agent lifecycle management not yet wired to loa-finn runtime",
	})
}

func (s *server) handleSpawnAgent(w http.ResponseWriter, r *http.Request) {
	// TODO: validate SpawnRequest, derive systemd unit constraints from risk tier,
	// launch via loa-finn, return agent ID and initial state
	writeError(w, http.StatusNotImplemented, "agent spawn not yet implemented — awaiting loa-finn integration")
}

func (s *server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	// TODO: look up agent by ID from loa-finn runtime state
	writeError(w, http.StatusNotImplemented, "agent status not yet implemented — awaiting loa-finn integration")
}

func (s *server) handleKillAgent(w http.ResponseWriter, r *http.Request) {
	// TODO: validate KillRequest, send SIGTERM/SIGKILL via loa-finn, update audit log
	writeError(w, http.StatusNotImplemented, "agent kill not yet implemented — awaiting loa-finn integration")
}
