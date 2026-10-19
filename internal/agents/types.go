// Package agents defines the agent lifecycle types for the platform control API.
// This is the groundwork for Layer 4 of the platform architecture:
// spawn, constrain, audit, and kill agent processes via the hardened-api.
package agents

import (
	"path/filepath"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// RiskTier classifies agents by their access level and blast radius.
type RiskTier string

const (
	RiskTierLow      RiskTier = "low"      // read-only, no external access
	RiskTierMedium   RiskTier = "medium"   // local writes, no financial ops
	RiskTierHigh     RiskTier = "high"     // external API access, financial read
	RiskTierCritical RiskTier = "critical" // financial writes, production systems
)

// AgentState represents the current lifecycle state of an agent.
type AgentState string

const (
	AgentStateSpawning  AgentState = "spawning"
	AgentStateRunning   AgentState = "running"
	AgentStatePaused    AgentState = "paused"
	AgentStateKilled    AgentState = "killed"
	AgentStateCompleted AgentState = "completed"
	AgentStateFailed    AgentState = "failed"
)

// Agent represents a running or historical agent instance.
type Agent struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	RiskTier    RiskTier          `json:"risk_tier"`
	State       AgentState        `json:"state"`
	Constraints AgentConstraints  `json:"constraints"`
	SpawnedAt   time.Time         `json:"spawned_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ExitCode    *int              `json:"exit_code,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// AgentConstraints defines the sandbox boundaries for an agent.
// These map to systemd unit hardening options applied at spawn time.
type AgentConstraints struct {
	AllowNetwork      bool     `json:"allow_network"`
	AllowedPaths      []string `json:"allowed_paths"`       // read+write
	ReadOnlyPaths     []string `json:"read_only_paths"`     // read only
	AllowedSyscalls   []string `json:"allowed_syscalls"`    // systemd SystemCallFilter
	MaxRuntimeSeconds int      `json:"max_runtime_seconds"` // 0 = unlimited
	MemoryLimitMB     int      `json:"memory_limit_mb"`     // 0 = unlimited
	CPUQuotaPct       int      `json:"cpu_quota_pct"`       // 0 = unlimited
}

// SpawnRequest is the payload for POST /api/v1/agents.
type SpawnRequest struct {
	Name        string            `json:"name"`
	RiskTier    RiskTier          `json:"risk_tier"`
	Command     []string          `json:"command"`
	Constraints AgentConstraints  `json:"constraints"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// KillRequest is the payload for POST /api/v1/agents/{id}/kill.
type KillRequest struct {
	Reason string `json:"reason"`
	Force  bool   `json:"force"` // SIGKILL vs SIGTERM
}

// defaultConstraints returns safe defaults per risk tier.
func DefaultConstraints(tier RiskTier) AgentConstraints {
	base := AgentConstraints{
		MaxRuntimeSeconds: 1800, // 30 minutes default
		MemoryLimitMB:     512,
		CPUQuotaPct:       50,
	}
	switch tier {
	case RiskTierLow:
		base.AllowNetwork = false
		base.ReadOnlyPaths = []string{filepath.Join(sysutil.TargetHome(), "Work")}
		base.MaxRuntimeSeconds = 300
	case RiskTierMedium:
		base.AllowNetwork = false
		base.AllowedPaths = []string{filepath.Join(sysutil.TargetHome(), "Work")}
	case RiskTierHigh:
		base.AllowNetwork = true
		base.AllowedPaths = []string{filepath.Join(sysutil.TargetHome(), "Work")}
		base.MaxRuntimeSeconds = 3600
	case RiskTierCritical:
		base.AllowNetwork = true
		base.MaxRuntimeSeconds = 7200
		base.MemoryLimitMB = 1024
	}
	return base
}
