package harden

import "time"

type Request struct {
	Actions []string `json:"actions"`
	DryRun  bool     `json:"dry_run"`
}

type ActionRecord struct {
	ActionID    string `json:"action_id"`
	Description string `json:"description"`
	Before      string `json:"before"`
	After       string `json:"after"`
	Applied     bool   `json:"applied"`
	Error       string `json:"error,omitempty"`
}

type Result struct {
	DryRun  bool           `json:"dry_run"`
	RunAt   time.Time      `json:"run_at"`
	Actions []ActionRecord `json:"actions"`
}
