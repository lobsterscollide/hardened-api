package checks

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

type AIDEChecker struct{}

func (a *AIDEChecker) Run() CheckResult {
	result := CheckResult{
		Check: "aide",
		RunAt: time.Now(),
	}

	if _, err := exec.LookPath("aide"); err != nil {
		result.OK = false
		result.Error = "aide not installed"
		return result
	}

	// Check that a database exists — if not, init is required before checks make sense.
	dbPath := aideActiveDB()
	if _, err := os.Stat(dbPath); err != nil {
		result.OK = false
		result.Findings = []Finding{{
			ID:          "aide.database_missing",
			Title:       "AIDE database not initialised",
			Description: "No AIDE baseline database found at " + dbPath + ". Integrity monitoring is inactive.",
			Severity:    SeverityWarning,
			Remediation: "Apply action: fint.init_aide_db",
		}}
		return result
	}

	// Query the last result of aide.service from systemd.
	out, err := exec.Command( // #nosec G204
		"systemctl", "show", "aide.service",
		"--property=ActiveState,Result,ExecMainStatus",
	).Output()
	if err != nil {
		// systemd unavailable — fall back to "we can't tell"
		result.OK = true
		return result
	}

	props := parseKeyValueLines(string(out))
	activeState := props["ActiveState"]
	svcResult := props["Result"]
	exitStatus := props["ExecMainStatus"]

	switch {
	case activeState == "active" || svcResult == "success" || exitStatus == "0":
		// Last run was clean.
		result.OK = true

	case exitStatus == "7":
		// aide --check exits 7 when it detects changes — DB is stale.
		result.OK = false
		result.Findings = []Finding{{
			ID:    "aide.database_stale",
			Title: "AIDE database stale — changes detected since last baseline",
			Description: "aide.service exited 7 (changes found). This is expected after a kernel or " +
				"major system update. The baseline database must be updated to reflect current system state.",
			Severity:    SeverityWarning,
			Remediation: "Apply action: fint.update_aide_db",
		}}

	case svcResult == "" && activeState == "inactive":
		// Timer installed but service has never run yet — not a problem.
		result.OK = true

	default:
		result.OK = false
		result.Findings = []Finding{{
			ID:          "aide.service_failed",
			Title:       "aide.service failed unexpectedly",
			Description: "aide.service result=" + svcResult + " ActiveState=" + activeState + " ExitStatus=" + exitStatus,
			Severity:    SeverityCritical,
			Remediation: "Review: journalctl -u aide.service",
		}}
	}

	return result
}

// aideActiveDB reads /etc/aide.conf for the database= path; falls back to the
// conventional location if the config is unreadable.
// Handles AIDE macro expansion: @@define VARNAME value → @@{VARNAME} substitution.
func aideActiveDB() string {
	data, err := os.ReadFile("/etc/aide.conf")
	if err != nil {
		return "/var/lib/aide/aide.db.gz"
	}

	macros := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "@@define ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				macros[parts[1]] = parts[2]
			}
		}
	}

	expand := func(s string) string {
		for k, v := range macros {
			s = strings.ReplaceAll(s, "@@{"+k+"}", v)
		}
		return s
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "database=") {
			val := expand(strings.TrimPrefix(strings.TrimPrefix(line, "database="), "file:"))
			if val != "" {
				return val
			}
		}
	}
	return "/var/lib/aide/aide.db.gz"
}

// parseKeyValueLines parses "Key=Value\n" output (e.g. systemctl show).
func parseKeyValueLines(out string) map[string]string {
	props := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		if idx := strings.IndexByte(line, '='); idx > 0 {
			props[line[:idx]] = line[idx+1:]
		}
	}
	return props
}
