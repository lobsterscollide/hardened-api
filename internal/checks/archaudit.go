package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const archAuditBin = "/usr/bin/arch-audit"

type ArchAuditChecker struct{}

// archAuditEntry is one advisory entry from arch-audit --json output.
type archAuditEntry struct {
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
	Status   string   `json:"status"`
	Type     string   `json:"type"`
	Severity string   `json:"severity"`
	Fixed    *string  `json:"fixed"`
	Issues   []string `json:"issues"`
}

func (c *ArchAuditChecker) Run() CheckResult {
	result := CheckResult{
		Check: "packages",
		RunAt: time.Now(),
	}

	if _, err := exec.LookPath(archAuditBin); err != nil {
		result.Error = "arch-audit not installed"
		result.OK = false
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, archAuditBin, "--json") // #nosec G204
	out, err := cmd.Output()
	if err != nil && ctx.Err() != nil {
		result.Error = "arch-audit timed out"
		result.OK = false
		return result
	}
	// arch-audit exits non-zero when vulnerabilities are found — that's expected.

	var entries []archAuditEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		result.Error = fmt.Sprintf("failed to parse arch-audit output: %v", err)
		result.OK = false
		return result
	}

	var findings []Finding
	for _, e := range entries {
		sev := archAuditSeverity(e.Severity)
		pkgs := strings.Join(e.Packages, ", ")
		cves := strings.Join(e.Issues, ", ")

		desc := fmt.Sprintf("%s (%s): %s", pkgs, e.Name, e.Type)
		if cves != "" {
			desc += " — " + cves
		}

		remediation := "Run: sudo pacman -Syu"
		if e.Fixed != nil {
			remediation = fmt.Sprintf("Update %s to %s or later: sudo pacman -Syu", pkgs, *e.Fixed)
		} else {
			remediation = fmt.Sprintf("No fix available yet for %s (%s). Monitor %s.",
				pkgs, cves, "https://security.archlinux.org/"+e.Name)
		}

		findings = append(findings, Finding{
			ID:          "packages." + strings.ToLower(e.Name),
			Title:       fmt.Sprintf("Vulnerable package: %s", pkgs),
			Description: desc,
			Severity:    sev,
			Remediation: remediation,
		})
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

func archAuditSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "high", "critical":
		return SeverityCritical
	case "medium":
		return SeverityWarning
	default:
		return SeverityInfo
	}
}
