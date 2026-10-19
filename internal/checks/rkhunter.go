package checks

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

type RkhunterChecker struct{}

func (r *RkhunterChecker) Run() CheckResult {
	result := CheckResult{
		Check: "rkhunter",
		RunAt: time.Now(),
	}

	if _, err := exec.LookPath("rkhunter"); err != nil {
		result.Error = "rkhunter not installed"
		result.OK = false
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// --sk: skip keypress prompts
	// --nocolors: no ANSI escape codes
	// --report-warnings-only: only print warnings/infections (empty = clean)
	// --no-summary: suppress the counts summary block
	cmd := exec.CommandContext(ctx, "rkhunter", "--check", "--sk", "--nocolors", "--report-warnings-only", "--no-summary") // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() != nil {
		result.Error = "rkhunter timed out"
		result.OK = false
		return result
	}

	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)

		// Only act on actual Warning: lines — everything else is noise
		if !strings.HasPrefix(line, "Warning:") {
			continue
		}

		lower := strings.ToLower(line)
		sev := SeverityWarning
		if strings.Contains(lower, "infected") || strings.Contains(lower, "rootkit found") {
			sev = SeverityCritical
		}

		findings = append(findings, Finding{
			ID:          "rkhunter.warning",
			Title:       "rkhunter warning",
			Description: line,
			Severity:    sev,
			Remediation: "Review /var/log/rkhunter.log for full context.",
		})
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}
