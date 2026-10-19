package checks

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInfo:     1,
	SeverityWarning:  2,
	SeverityCritical: 3,
}

func WorstSeverity(a, b Severity) Severity {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}

type Finding struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Severity     Severity `json:"severity"`
	Remediation  string   `json:"remediation,omitempty"`
	CurrentValue string   `json:"current_value,omitempty"`
}

type CheckResult struct {
	Check    string    `json:"check"`
	OK       bool      `json:"ok"`
	Findings []Finding `json:"findings"`
	RunAt    time.Time `json:"run_at"`
	Error    string    `json:"error,omitempty"`
}

type SummaryResult struct {
	Hostname        string        `json:"hostname"`
	RunAt           time.Time     `json:"run_at"`
	OverallSeverity Severity      `json:"overall_severity"`
	Results         []CheckResult `json:"results"`
}

type Checker interface {
	Run() CheckResult
}
