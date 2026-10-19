package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const sshdConfig = "/etc/ssh/sshd_config"

type SSHChecker struct{}

func (c *SSHChecker) Run() CheckResult {
	result := CheckResult{
		Check: "ssh",
		RunAt: time.Now(),
	}

	params, err := parseSSHConfig(sshdConfig)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read sshd_config: %v", err)
		result.OK = false
		return result
	}

	get := func(key, def string) string {
		if v, ok := params[strings.ToLower(key)]; ok {
			return v
		}
		return def
	}

	var findings []Finding

	// PermitRootLogin
	prl := strings.ToLower(get("PermitRootLogin", "prohibit-password"))
	if prl == "yes" || prl == "without-password" {
		findings = append(findings, Finding{
			ID:           "ssh.permit_root_login",
			Title:        "Root login permitted",
			Description:  "sshd allows direct root login which bypasses audit trails.",
			Severity:     SeverityCritical,
			Remediation:  "Set PermitRootLogin no in sshd_config.",
			CurrentValue: prl,
		})
	}

	// PasswordAuthentication
	pa := strings.ToLower(get("PasswordAuthentication", "yes"))
	if pa == "yes" {
		findings = append(findings, Finding{
			ID:          "ssh.password_auth",
			Title:       "Password authentication enabled",
			Description: "Password-based SSH logins are susceptible to brute-force attacks.",
			Severity:    SeverityWarning,
			Remediation: "Set PasswordAuthentication no and use key-based authentication.",
		})
	}

	// PermitEmptyPasswords
	pep := strings.ToLower(get("PermitEmptyPasswords", "no"))
	if pep == "yes" {
		findings = append(findings, Finding{
			ID:          "ssh.permit_empty_passwords",
			Title:       "Empty passwords permitted",
			Description: "Accounts with empty passwords can log in via SSH without credentials.",
			Severity:    SeverityCritical,
			Remediation: "Set PermitEmptyPasswords no in sshd_config.",
		})
	}

	// X11Forwarding
	x11 := strings.ToLower(get("X11Forwarding", "no"))
	if x11 == "yes" {
		findings = append(findings, Finding{
			ID:          "ssh.x11_forwarding",
			Title:       "X11 forwarding enabled",
			Description: "X11 forwarding exposes the local display and can be used for privilege escalation.",
			Severity:    SeverityWarning,
			Remediation: "Set X11Forwarding no in sshd_config.",
		})
	}

	// MaxAuthTries
	matStr := get("MaxAuthTries", "6")
	if mat, err := strconv.Atoi(matStr); err == nil && mat > 3 {
		findings = append(findings, Finding{
			ID:           "ssh.max_auth_tries",
			Title:        "MaxAuthTries too high",
			Description:  "A high MaxAuthTries value allows more brute-force attempts per connection.",
			Severity:     SeverityWarning,
			Remediation:  "Set MaxAuthTries 3 or lower in sshd_config.",
			CurrentValue: matStr,
		})
	}

	// LoginGraceTime
	lgtStr := get("LoginGraceTime", "120")
	lgtStr = strings.TrimSuffix(lgtStr, "s")
	if lgt, err := strconv.Atoi(lgtStr); err == nil && lgt > 60 {
		findings = append(findings, Finding{
			ID:           "ssh.login_grace_time",
			Title:        "LoginGraceTime too long",
			Description:  "A long grace time keeps unauthenticated connections open, enabling DoS.",
			Severity:     SeverityWarning,
			Remediation:  "Set LoginGraceTime 30 in sshd_config.",
			CurrentValue: lgtStr,
		})
	}

	// AllowTcpForwarding
	atf := strings.ToLower(get("AllowTcpForwarding", "yes"))
	if atf == "yes" {
		findings = append(findings, Finding{
			ID:          "ssh.allow_tcp_forwarding",
			Title:       "TCP forwarding enabled",
			Description: "TCP forwarding can be used to pivot to internal services.",
			Severity:    SeverityInfo,
			Remediation: "Set AllowTcpForwarding no if tunneling is not required.",
		})
	}

	// Weak ciphers
	if ciphers, ok := params["ciphers"]; ok {
		weak := []string{"arcfour", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"}
		for _, w := range weak {
			if strings.Contains(strings.ToLower(ciphers), w) {
				findings = append(findings, Finding{
					ID:           "ssh.weak_cipher",
					Title:        "Weak cipher configured",
					Description:  fmt.Sprintf("Cipher %q is considered weak.", w),
					Severity:     SeverityCritical,
					Remediation:  "Remove weak ciphers from the Ciphers directive.",
					CurrentValue: ciphers,
				})
				break
			}
		}
	}

	// Weak MACs
	if macs, ok := params["macs"]; ok {
		if strings.Contains(strings.ToLower(macs), "md5") {
			findings = append(findings, Finding{
				ID:           "ssh.weak_mac",
				Title:        "MD5-based MAC configured",
				Description:  "MD5-based MACs are cryptographically broken.",
				Severity:     SeverityWarning,
				Remediation:  "Remove MD5-based MACs from the MACs directive.",
				CurrentValue: macs,
			})
		}
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

func parseSSHConfig(path string) (map[string]string, error) {
	params := make(map[string]string)
	if err := parseSSHFileRecursive(path, params); err != nil {
		return nil, err
	}
	return params, nil
}

// parseSSHFileRecursive parses an sshd_config file, processing Include directives
// inline at the position they appear — matching how sshd itself resolves precedence.
// First occurrence of a directive wins (sshd semantics).
func parseSSHFileRecursive(path string, params map[string]string) error {
	f, err := os.Open(path) // #nosec G304 — path is a fixed constant or glob result
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.Join(parts[1:], " ")

		if key == "include" {
			// Expand glob and recurse immediately — preserves sshd precedence order.
			matches, _ := filepath.Glob(val)
			for _, m := range matches {
				_ = parseSSHFileRecursive(m, params)
			}
			continue
		}

		if _, exists := params[key]; !exists {
			params[key] = val
		}
	}
	return scanner.Err()
}

func hasCriticalOrWarning(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityWarning {
			return true
		}
	}
	return false
}
