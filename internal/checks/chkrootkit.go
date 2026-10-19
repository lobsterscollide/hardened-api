package checks

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const chkrootkitBin = "/usr/bin/chkrootkit"
const chkrootkitLibDir = "/usr/lib/chkrootkit"

type ChkrootkitChecker struct{}

func (c *ChkrootkitChecker) Run() CheckResult {
	result := CheckResult{
		Check: "chkrootkit",
		RunAt: time.Now(),
	}

	if _, err := exec.LookPath(chkrootkitBin); err != nil {
		result.Error = "chkrootkit not installed"
		result.OK = false
		return result
	}

	// -p points at the helper binaries installed by the Arch package
	// -q quiet mode: only prints warnings, skips "not infected" lines
	cmd := exec.Command(chkrootkitBin, "-p", chkrootkitLibDir, "-q") // #nosec G204
	out, _ := cmd.CombinedOutput()

	var findings []Finding
	var suspiciousFiles []string

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Filter known noise from hardened kernel
		if strings.Contains(line, "RTNETLINK answers") {
			continue
		}

		// INFECTED is the only real alarm signal
		if strings.Contains(line, "INFECTED") {
			findings = append(findings, Finding{
				ID:          "chkrootkit.infected",
				Title:       "Rootkit signature detected",
				Description: line,
				Severity:    SeverityCritical,
				Remediation: "Investigate immediately. Consider booting from trusted media for offline analysis.",
			})
			continue
		}

		// Suspicious files: hidden-file paths in common dirs — Arch false positives.
		if strings.Contains(line, "/.") &&
			(strings.HasPrefix(line, "/usr/") || strings.HasPrefix(line, "/var/") ||
				strings.HasPrefix(line, "/tmp/") || strings.HasPrefix(line, "/home/")) {
			suspiciousFiles = append(suspiciousFiles, strings.Fields(line)...)
			continue
		}

		// "not tested" lines — note skipped checks
		if strings.HasPrefix(line, "not tested") {
			findings = append(findings, Finding{
				ID:          "chkrootkit.skipped",
				Title:       "Check skipped",
				Description: line,
				Severity:    SeverityInfo,
				Remediation: "Review skipped checks manually if needed.",
			})
			continue
		}
	}

	// Suspicious files: always present on Arch due to dotfiles in package dirs.
	// Report as info only — these are overwhelmingly false positives.
	if len(suspiciousFiles) > 0 {
		findings = append(findings, Finding{
			ID:          "chkrootkit.suspicious_files",
			Title:       fmt.Sprintf("Suspicious hidden files (%d)", len(suspiciousFiles)),
			Description: "chkrootkit flagged hidden files in system dirs. On Arch Linux these are typically package dotfiles (node_modules, Qt build artifacts, kernel headers). Review manually if unexpected.",
			Severity:    SeverityInfo,
			Remediation: "Verify flagged paths belong to known packages: pacman -Qo <path>",
		})
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}
