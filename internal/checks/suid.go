package checks

import (
	"fmt"
	"os"
	"time"
)

// unnecessarySUIDs lists SUID/SGID binaries commonly installed on Arch that are
// unnecessary on a hardened headless server. Safe to strip the setuid/setgid bit.
var unnecessarySUIDs = []struct {
	Path   string
	Reason string
}{
	{"/usr/bin/ksu", "Kerberos su — not needed without a Kerberos infrastructure"},
	{"/usr/bin/mount.cifs", "CIFS/SMB mounting — setuid unnecessary if no CIFS mounts are in use"},
	{"/usr/bin/pkexec", "Polkit execute — desktop privilege-escalation tool; unnecessary on headless server (prior CVE-2021-4034)"},
	{"/usr/bin/wall", "Write-to-all-terminals — inter-user messaging utility, not needed on a single-user server"},
	{"/usr/bin/write", "Write-to-terminal — inter-user messaging utility, not needed on a single-user server"},
}

// SUIDBinChecker reports SUID/SGID binaries that are installed but unnecessary
// on a hardened server and should have their setuid/setgid bits removed.
type SUIDBinChecker struct{}

func (c *SUIDBinChecker) Run() CheckResult {
	result := CheckResult{
		Check: "suid",
		RunAt: time.Now(),
	}

	var findings []Finding

	for _, entry := range unnecessarySUIDs {
		info, err := os.Stat(entry.Path)
		if err != nil {
			// Not installed — nothing to flag.
			continue
		}

		mode := info.Mode()
		hasSUID := mode&os.ModeSetuid != 0
		hasSGID := mode&os.ModeSetgid != 0

		if !hasSUID && !hasSGID {
			continue
		}

		bit := "setuid"
		switch {
		case hasSUID && hasSGID:
			bit = "setuid+setgid"
		case hasSGID:
			bit = "setgid"
		}

		findings = append(findings, Finding{
			ID:          fmt.Sprintf("suid.unnecessary.%s", sanitizeID(entry.Path)),
			Title:       fmt.Sprintf("Unnecessary %s binary: %s", bit, entry.Path),
			Description: entry.Reason,
			Severity:    SeverityWarning,
			Remediation: fmt.Sprintf(
				"Apply action: suid.remove_unnecessary (or run: chmod a-s %s)", entry.Path,
			),
			CurrentValue: fmt.Sprintf("%04o", mode.Perm()),
		})
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}
