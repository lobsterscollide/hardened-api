package checks

import (
	"strings"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

type FirewallChecker struct{}

func (c *FirewallChecker) Run() CheckResult {
	result := CheckResult{
		Check: "firewall",
		RunAt: time.Now(),
	}

	var findings []Finding

	// Check nftables first — preferred firewall on this system
	nftOut, nftErr := sysutil.Run("nft", "list", "ruleset")
	if nftErr == nil && hasNftRules(nftOut) {
		// nftables is active with rules — firewall is healthy
		result.Findings = findings
		result.OK = true
		return result
	}

	// nftables not active — check ufw
	ufwOut, ufwErr := sysutil.Run("ufw", "status", "verbose")
	if ufwErr == nil {
		if strings.Contains(ufwOut, "Status: inactive") {
			findings = append(findings, Finding{
				ID:          "firewall.ufw_inactive",
				Title:       "ufw is installed but inactive",
				Description: "The Uncomplicated Firewall is present but not running.",
				Severity:    SeverityCritical,
				Remediation: "Run: sudo ufw enable",
			})
		} else if strings.Contains(ufwOut, "Status: active") {
			if strings.Contains(ufwOut, "Default: allow") {
				findings = append(findings, Finding{
					ID:          "firewall.default_allow",
					Title:       "ufw default policy is ALLOW",
					Description: "Incoming traffic is allowed by default; only explicitly blocked ports are dropped.",
					Severity:    SeverityWarning,
					Remediation: "Run: sudo ufw default deny incoming",
				})
			}
		}
	} else {
		// Neither nftables nor ufw — check iptables
		iptOut, iptErr := sysutil.Run("iptables", "-L", "-n")
		if iptErr != nil || isDefaultIptables(iptOut) {
			findings = append(findings, Finding{
				ID:          "firewall.no_firewall",
				Title:       "No active firewall detected",
				Description: "No active nftables, ufw, or iptables rules were found.",
				Severity:    SeverityCritical,
				Remediation: "Enable nftables: sudo systemctl enable --now nftables",
			})
		}
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

// hasNftRules returns true when nft output contains at least one rule (non-empty ruleset).
func hasNftRules(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "table") && !strings.HasPrefix(line, "chain") &&
			line != "{" && line != "}" {
			return true
		}
	}
	return false
}

// isDefaultIptables returns true when iptables output looks like a bare default (no custom rules).
func isDefaultIptables(out string) bool {
	lines := strings.Split(out, "\n")
	ruleLines := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "Chain") || strings.HasPrefix(l, "target") {
			continue
		}
		ruleLines++
	}
	return ruleLines == 0
}
