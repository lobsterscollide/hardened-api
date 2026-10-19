package checks

import (
	"bufio"
	"os"
	"strings"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// ServicesChecker verifies that hardened service state is maintained.
// Checks: avahi disabled, cups disabled, fail2ban active, AppArmor active, no PAM nullok.
type ServicesChecker struct{}

func (c *ServicesChecker) Run() CheckResult {
	result := CheckResult{
		Check: "services",
		RunAt: time.Now(),
	}

	var findings []Finding

	findings = append(findings, checkServiceDisabled("avahi-daemon",
		"avahi.running",
		"avahi-daemon is running",
		"mDNS/DNS-SD service discovery is enabled — not needed on a hardened desktop.",
		"Run: systemctl disable --now avahi-daemon avahi-daemon.socket",
		SeverityWarning)...)

	findings = append(findings, checkServiceDisabled("cups",
		"cups.running",
		"CUPS print spooler is running",
		"CUPS is active but no printing is needed on this system.",
		"Run: systemctl disable --now cups",
		SeverityWarning)...)

	findings = append(findings, checkServiceActive("fail2ban",
		"fail2ban.inactive",
		"fail2ban is not running",
		"fail2ban is not active — brute-force protection for SSH is disabled.",
		"Run: systemctl enable --now fail2ban",
		SeverityWarning)...)

	findings = append(findings, checkServiceActive("apparmor",
		"apparmor.inactive",
		"AppArmor is not running",
		"AppArmor MAC enforcement is not active.",
		"Run: systemctl enable --now apparmor (and ensure apparmor=1 security=apparmor in kernel cmdline)",
		SeverityWarning)...)

	findings = append(findings, checkNullok()...)

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

func checkServiceDisabled(unit, id, title, desc, remediation string, sev Severity) []Finding {
	active := serviceIsActive(unit)
	if !active {
		return nil
	}
	return []Finding{{
		ID:           id,
		Title:        title,
		Description:  desc,
		Severity:     sev,
		Remediation:  remediation,
		CurrentValue: "active",
	}}
}

func checkServiceActive(unit, id, title, desc, remediation string, sev Severity) []Finding {
	if serviceIsActive(unit) {
		return nil
	}
	return []Finding{{
		ID:           id,
		Title:        title,
		Description:  desc,
		Severity:     sev,
		Remediation:  remediation,
		CurrentValue: "inactive",
	}}
}

func serviceIsActive(unit string) bool {
	out, err := sysutil.Run("systemctl", "is-active", unit)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "active"
}

func checkNullok() []Finding {
	paths := []string{
		"/etc/pam.d/system-auth",
		"/etc/pam.d/common-auth",
	}
	for _, p := range paths {
		if fileContains(p, "nullok") {
			return []Finding{{
				ID:           "pam.nullok_present",
				Title:        "PAM nullok allows empty-password logins",
				Description:  "The 'nullok' option in " + p + " permits login without a password.",
				Severity:     SeverityWarning,
				Remediation:  "Remove 'nullok' from pam_unix.so lines in " + p,
				CurrentValue: p + " contains nullok",
			}}
		}
	}
	return nil
}

func fileContains(path, substr string) bool {
	f, err := os.Open(path) // #nosec G304 — fixed known paths
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), substr) {
			return true
		}
	}
	return false
}
