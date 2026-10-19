package checks

import (
	"os/exec"
	"strings"
	"time"
)

// clamscanTargets are directories scanned on each check run.
// Limited to in-memory volatile areas that scan in seconds.
// /tmp and /var/tmp are excluded — they can be large (CI artifacts,
// session files) and malware there is cleared on reboot anyway.
// For a full-filesystem scan, run clamscan manually with freshclam first.
var clamscanTargets = []string{
	"/dev/shm",
	"/run/user",
}

type ClamscanChecker struct{}

func (c *ClamscanChecker) Run() CheckResult {
	result := CheckResult{
		Check: "clamscan",
		RunAt: time.Now(),
	}

	if _, err := exec.LookPath("clamscan"); err != nil {
		result.Error = "clamscan not installed"
		result.OK = false
		return result
	}

	args := []string{
		"--infected",   // only print infected files, suppress clean-file lines
		"--recursive",  // recurse into subdirectories
		"--no-summary", // suppress the counts summary at the end
	}
	args = append(args, clamscanTargets...)

	cmd := exec.Command("clamscan", args...) // #nosec G204
	out, _ := cmd.CombinedOutput()

	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Database/engine errors — surface as a warning so they don't
		// silently degrade scan coverage.
		if strings.HasPrefix(line, "ERROR:") || strings.Contains(line, "No such file") {
			findings = append(findings, Finding{
				ID:          "clamscan.error",
				Title:       "ClamAV scan error",
				Description: line,
				Severity:    SeverityWarning,
				Remediation: "Run: sudo freshclam  to update the virus database, then retry.",
			})
			continue
		}

		// Infected file: "/path/to/file: Signature-Name FOUND"
		if strings.HasSuffix(line, "FOUND") {
			findings = append(findings, Finding{
				ID:          "clamscan.infected",
				Title:       "Malware detected",
				Description: line,
				Severity:    SeverityCritical,
				Remediation: "Quarantine or delete the file. Verify with: clamscan --verbose <path>",
			})
		}
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}
