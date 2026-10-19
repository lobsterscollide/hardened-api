package checks

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type UserChecker struct{}

func (c *UserChecker) Run() CheckResult {
	result := CheckResult{
		Check: "users",
		RunAt: time.Now(),
	}

	passwdEntries, err := parsePasswd("/etc/passwd")
	if err != nil {
		result.Error = fmt.Sprintf("failed to read /etc/passwd: %v", err)
		result.OK = false
		return result
	}

	shadowEntries, shadowErr := parseShadow("/etc/shadow")

	var findings []Finding

	for _, entry := range passwdEntries {
		// Root UID collision
		if entry.UID == 0 && entry.Username != "root" {
			findings = append(findings, Finding{
				ID:           fmt.Sprintf("users.root_uid_collision.%s", entry.Username),
				Title:        fmt.Sprintf("Non-root user has UID 0: %s", entry.Username),
				Description:  fmt.Sprintf("User %q has UID 0, giving it full root privileges.", entry.Username),
				Severity:     SeverityCritical,
				Remediation:  fmt.Sprintf("Assign a non-zero UID to %s or remove the account.", entry.Username),
				CurrentValue: fmt.Sprintf("uid=%d", entry.UID),
			})
		}

		// Interactive system accounts (UID < 1000 with real shell)
		if entry.UID > 0 && entry.UID < 1000 && isInteractiveShell(entry.Shell) {
			findings = append(findings, Finding{
				ID:           fmt.Sprintf("users.interactive_system_account.%s", entry.Username),
				Title:        fmt.Sprintf("System account with interactive shell: %s", entry.Username),
				Description:  fmt.Sprintf("System user %q (UID %d) has an interactive shell %q.", entry.Username, entry.UID, entry.Shell),
				Severity:     SeverityWarning,
				Remediation:  fmt.Sprintf("Run: usermod -s /usr/sbin/nologin %s", entry.Username),
				CurrentValue: entry.Shell,
			})
		}

		// Check shadow entries for this user
		if shadowErr == nil {
			if shadow, ok := shadowEntries[entry.Username]; ok {
				// Empty password
				if shadow.PasswordHash == "" {
					findings = append(findings, Finding{
						ID:          fmt.Sprintf("users.empty_password.%s", entry.Username),
						Title:       fmt.Sprintf("Empty password for user: %s", entry.Username),
						Description: fmt.Sprintf("User %q has no password set, allowing passwordless login.", entry.Username),
						Severity:    SeverityCritical,
						Remediation: fmt.Sprintf("Lock the account: passwd -l %s", entry.Username),
					})
				}

				// Weak password hash (MD5 = $1$)
				if strings.HasPrefix(shadow.PasswordHash, "$1$") {
					findings = append(findings, Finding{
						ID:          fmt.Sprintf("users.weak_password_hash.%s", entry.Username),
						Title:       fmt.Sprintf("Weak password hash (MD5) for user: %s", entry.Username),
						Description: fmt.Sprintf("User %q uses MD5-based password hashing, which is cryptographically broken.", entry.Username),
						Severity:    SeverityWarning,
						Remediation: "Force a password reset and ensure PAM uses sha512 or yescrypt.",
					})
				}

				// No password expiry for human accounts
				if entry.UID >= 1000 && shadow.MaxDays == -1 {
					findings = append(findings, Finding{
						ID:          fmt.Sprintf("users.no_password_expiry.%s", entry.Username),
						Title:       fmt.Sprintf("No password expiry for user: %s", entry.Username),
						Description: fmt.Sprintf("User %q has no maximum password age configured.", entry.Username),
						Severity:    SeverityInfo,
						Remediation: fmt.Sprintf("Run: chage -M 90 %s", entry.Username),
					})
				}
			}
		}
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

type passwdEntry struct {
	Username string
	UID      int
	GID      int
	Shell    string
}

func parsePasswd(path string) ([]passwdEntry, error) {
	f, err := os.Open(path) // #nosec G304 — fixed path
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []passwdEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		entries = append(entries, passwdEntry{
			Username: parts[0],
			UID:      uid,
			GID:      gid,
			Shell:    parts[6],
		})
	}
	return entries, scanner.Err()
}

type shadowEntry struct {
	PasswordHash string
	MaxDays      int
}

func parseShadow(path string) (map[string]shadowEntry, error) {
	f, err := os.Open(path) // #nosec G304 — fixed path
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries := make(map[string]shadowEntry)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 5 {
			continue
		}
		maxDays := -1
		if n, err := strconv.Atoi(parts[4]); err == nil {
			maxDays = n
		}
		entries[parts[0]] = shadowEntry{
			PasswordHash: parts[1],
			MaxDays:      maxDays,
		}
	}
	return entries, scanner.Err()
}

func isInteractiveShell(shell string) bool {
	nonInteractive := []string{"nologin", "false", "sync", "halt", "shutdown"}
	for _, s := range nonInteractive {
		if strings.HasSuffix(shell, s) {
			return false
		}
	}
	return shell != ""
}
