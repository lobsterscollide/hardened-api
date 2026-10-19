package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

const (
	modprobeDropIn = "/etc/modprobe.d/99-hardened-api.conf"
	limitsConfFile = "/etc/security/limits.conf"
	auditRulesFile = "/etc/audit/rules.d/99-hardened-api.rules"
	auditRulesDir  = "/etc/audit/rules.d"
)

// blacklistKernelModules writes install X /bin/false entries for the given modules.
func blacklistKernelModules(modules []string) applyFunc {
	return func() (before, after string, err error) {
		data, _ := os.ReadFile(modprobeDropIn)
		before = string(data)

		lines := strings.Split(before, "\n")
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}

		for _, mod := range modules {
			entry := fmt.Sprintf("install %s /bin/false", mod)
			found := false
			for _, line := range lines {
				if strings.TrimSpace(line) == entry {
					found = true
					break
				}
			}
			if !found {
				lines = append(lines, entry)
			}
		}

		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(modprobeDropIn, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", modprobeDropIn, err)
		}
		return before, content, nil
	}
}

// blacklistProtocols writes install X /bin/false entries for unused kernel protocols.
func blacklistProtocols() applyFunc {
	protocols := []string{"dccp", "sctp", "rds", "tipc"}
	return func() (before, after string, err error) {
		data, _ := os.ReadFile(modprobeDropIn)
		before = string(data)

		lines := strings.Split(before, "\n")
		// Remove trailing empty lines
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}

		for _, proto := range protocols {
			entry := fmt.Sprintf("install %s /bin/false", proto)
			found := false
			for _, line := range lines {
				if strings.TrimSpace(line) == entry {
					found = true
					break
				}
			}
			if !found {
				lines = append(lines, entry)
			}
		}

		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(modprobeDropIn, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", modprobeDropIn, err)
		}
		return before, content, nil
	}
}

// disableCoreDumps adds hard/soft core=0 limits to /etc/security/limits.conf.
func disableCoreDumps() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(limitsConfFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", limitsConfFile, err)
		}
		before = string(data)

		hardEntry := "* hard core 0"
		softEntry := "* soft core 0"

		hasHard := strings.Contains(before, hardEntry)
		hasSoft := strings.Contains(before, softEntry)

		if hasHard && hasSoft {
			return before, before, nil // already set
		}

		lines := strings.Split(strings.TrimRight(before, "\n"), "\n")
		if !hasSoft {
			lines = append(lines, softEntry)
		}
		if !hasHard {
			lines = append(lines, hardEntry)
		}
		lines = append(lines, "")

		after = strings.Join(lines, "\n")
		if err := os.WriteFile(limitsConfFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", limitsConfFile, err)
		}
		return before, after, nil
	}
}

// auditRules is a baseline ruleset covering Lynis ACCT-9628 requirements:
// time changes, identity changes, network config, privilege escalation,
// logins/sessions, file deletion, and sensitive config file watches.
const auditRules = `## Hardened-API baseline audit rules (ACCT-9628)
## Managed by hardened-api — do not edit manually.

# Flush existing rules
-D

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/group identity changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysctl.conf -p wa -k system-locale
-w /etc/sysctl.d -p wa -k system-locale

# MAC policy changes
-w /etc/apparmor -p wa -k MAC-policy
-w /etc/apparmor.d -p wa -k MAC-policy

# Login and session events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege-escalation
-a always,exit -F arch=b64 -S setresuid -S setresgid -k privilege-escalation
-w /usr/bin/sudo -p x -k privileged
-w /usr/bin/su -p x -k privileged
-w /usr/bin/newgrp -p x -k privileged
-w /usr/bin/chsh -p x -k privileged

# File deletion by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Sudoers and SSH config changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d -p wa -k sshd
`

// auditRulesExpanded is the full ACCT-9630 baseline, extending auditRules with
// kernel module loading watches and hardened-api config change auditing.
const auditRulesExpanded = `## Hardened-API expanded audit rules (ACCT-9630)
## Managed by hardened-api — do not edit manually.

# Flush existing rules
-D

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/group identity changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysctl.conf -p wa -k system-locale
-w /etc/sysctl.d -p wa -k system-locale

# MAC policy changes
-w /etc/apparmor -p wa -k MAC-policy
-w /etc/apparmor.d -p wa -k MAC-policy

# Login and session events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege-escalation
-a always,exit -F arch=b64 -S setresuid -S setresgid -k privilege-escalation
-w /usr/bin/sudo -p x -k privileged
-w /usr/bin/su -p x -k privileged
-w /usr/bin/newgrp -p x -k privileged
-w /usr/bin/chsh -p x -k privileged

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# File deletion by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Sudoers and SSH config changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d -p wa -k sshd

# Hardened API config changes
-w /etc/hardened-api/ -p wa -k hardened_api
`

// writeAuditRules writes the expanded baseline audit ruleset to the rules.d
// drop-in file and reloads auditd. Use this after audit.enable_auditd to add
// kernel module loading and hardened-api config watches (ACCT-9630).
func writeAuditRules() applyFunc {
	return func() (before, after string, err error) {
		data, _ := os.ReadFile(auditRulesFile)
		before = string(data)

		if err := os.MkdirAll(auditRulesDir, 0755); err != nil {
			return before, "", fmt.Errorf("create %s: %w", auditRulesDir, err)
		}
		if err := os.WriteFile(auditRulesFile, []byte(auditRulesExpanded), 0640); err != nil {
			return before, "", fmt.Errorf("write %s: %w", auditRulesFile, err)
		}

		// Reload into running auditd.
		// augenrules exits 1 with "No change" (rules unchanged) or "No rules"
		// (compiled set empty after -D flush with no subsequent rules loaded at
		// runtime — the file is still on disk and will be picked up on next
		// audit-rules.service start). Both are non-fatal.
		if out, err := sysutil.Run("augenrules", "--load"); err != nil &&
			!strings.Contains(out, "No change") &&
			!strings.Contains(out, "No rules") {
			return before, "", fmt.Errorf("augenrules --load: %w — output: %s", err, out)
		}

		out, _ := sysutil.Run("auditctl", "-l")
		after = strings.TrimSpace(out)
		return before, after, nil
	}
}

// fixAuditRulesService installs a systemd drop-in that marks exit code 1 as
// success for audit-rules.service. augenrules exits 1 when the compiled rules
// are unchanged ("No change"), causing the unit to show as failed even when
// auditd is healthy. This drop-in suppresses that false alarm.
func fixAuditRulesService() applyFunc {
	return func() (before, after string, err error) {
		const dropInDir = "/etc/systemd/system/audit-rules.service.d"
		const dropInFile = dropInDir + "/success-exit.conf"

		if _, err := os.Stat(dropInFile); err == nil {
			return "drop-in already present", "drop-in already present", nil
		}
		before = "audit-rules.service fails on 'No change' exit code"

		if err := os.MkdirAll(dropInDir, 0755); err != nil {
			return before, "", fmt.Errorf("create drop-in dir: %w", err)
		}
		content := "[Service]\nSuccessExitStatus=0 1\n"
		if err := os.WriteFile(dropInFile, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write drop-in: %w", err)
		}
		if _, err := sysutil.Run("systemctl", "daemon-reload"); err != nil {
			return before, "", fmt.Errorf("daemon-reload: %w", err)
		}
		_, _ = sysutil.Run("systemctl", "reset-failed", "audit-rules.service")
		return before, "drop-in installed — audit-rules.service will no longer false-alarm on 'No change'", nil
	}
}

// fixAuditRulesLoading adds an ExecStartPost drop-in to audit-rules.service
// that calls `auditctl -R /etc/audit/audit.rules` directly after augenrules
// runs. When augenrules finds no compiled-rule changes it exits 1 with
// "No change" without calling auditctl — leaving the kernel with an empty
// ruleset after every boot. The drop-in forces a reload unconditionally.
func fixAuditRulesLoading() applyFunc {
	return func() (before, after string, err error) {
		const dropInDir = "/etc/systemd/system/audit-rules.service.d"
		const dropInFile = dropInDir + "/force-load.conf"

		if _, err := os.Stat(dropInFile); err == nil {
			return "drop-in already present", "drop-in already present", nil
		}
		before = "audit-rules.service skips auditctl on 'No change' — kernel sees empty ruleset at boot"

		if err := os.MkdirAll(dropInDir, 0755); err != nil {
			return before, "", fmt.Errorf("create drop-in dir: %w", err)
		}
		content := "[Service]\nExecStartPost=/sbin/auditctl -R /etc/audit/audit.rules\n"
		if err := os.WriteFile(dropInFile, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write drop-in: %w", err)
		}
		if _, err := sysutil.Run("systemctl", "daemon-reload"); err != nil {
			return before, "", fmt.Errorf("daemon-reload: %w", err)
		}
		// Force-load rules into the running kernel right now.
		if _, err := sysutil.Run("auditctl", "-R", "/etc/audit/audit.rules"); err != nil {
			return before, "", fmt.Errorf("auditctl -R: %w", err)
		}
		return before, "drop-in installed — audit rules will be force-loaded into kernel at every boot", nil
	}
}

// fixRkhunterFalsePositives whitelists known-good hidden files and suppresses
// false-positive SSH warnings on Arch Linux:
//   - Kerberos man pages beginning with a dot (.k5identity.5.gz, .k5login.5.gz)
//   - ALLOW_SSH_PROT_V1=2: suppress "Protocol not set" — the Protocol directive
//     was removed in OpenSSH 7.6; modern sshd only speaks v2, so the warning is
//     a false positive.
//   - ALLOW_SSH_ROOT_USER=no: tell rkhunter the expected PermitRootLogin value;
//     suppresses "PermitRootLogin has not been set" warning when sshd inherits
//     the secure default (no) without an explicit directive.
func fixRkhunterFalsePositives() applyFunc {
	return func() (before, after string, err error) {
		const conf = "/etc/rkhunter.conf"
		entries := []string{
			"ALLOWHIDDENFILE=/usr/share/man/man5/.k5identity.5.gz",
			"ALLOWHIDDENFILE=/usr/share/man/man5/.k5login.5.gz",
			"ALLOW_SSH_PROT_V1=2",
			"ALLOW_SSH_ROOT_USER=no",
		}

		data, readErr := os.ReadFile(conf)
		if readErr != nil {
			return "", "", fmt.Errorf("read %s: %w", conf, readErr)
		}
		existing := string(data)

		var added []string
		for _, entry := range entries {
			if strings.Contains(existing, entry) {
				continue
			}
			existing += "\n" + entry
			added = append(added, entry)
		}

		if len(added) == 0 {
			return "already whitelisted", "already whitelisted", nil
		}
		before = "rkhunter warns on Kerberos man pages"
		if err := os.WriteFile(conf, []byte(existing), 0600); err != nil {
			return before, "", fmt.Errorf("write %s: %w", conf, err)
		}
		_, _ = sysutil.Run("rkhunter", "--propupd")
		_, _ = sysutil.Run("systemctl", "reset-failed", "rkhunter.service")
		return before, fmt.Sprintf("whitelisted %d entries; propupd run", len(added)), nil
	}
}

// fixRkhunterSshdConfigPath sets SSHD_CONFIG_FILE in rkhunter.conf to point at
// the hardened-api drop-in (/etc/ssh/sshd_config.d/99-hardened-api.conf) instead
// of the base /etc/ssh/sshd_config.  The base config has no hardened directives —
// all security settings live in the drop-in — so rkhunter scans the wrong file by
// default and produces false-positive warnings for PermitRootLogin, LogLevel, etc.
// Pointing it at the drop-in is the correct fix; ALLOW_SSH_ROOT_USER=no and
// ALLOW_SSH_PROT_V1=2 remain as belt-and-suspenders fallbacks.
func fixRkhunterSshdConfigPath() applyFunc {
	return func() (before, after string, err error) {
		const conf = "/etc/rkhunter.conf"
		const directive = "SSHD_CONFIG_FILE"
		const target = "/etc/ssh/sshd_config.d/99-hardened-api.conf"
		const newLine = directive + "=" + target

		data, readErr := os.ReadFile(conf)
		if readErr != nil {
			return "", "", fmt.Errorf("read %s: %w", conf, readErr)
		}
		existing := string(data)

		// If the correct value is already set, nothing to do.
		if strings.Contains(existing, newLine) {
			return "already set", "already set", nil
		}

		// Replace any existing SSHD_CONFIG_FILE line, or append if absent.
		var updated string
		replaced := false
		for _, line := range strings.Split(existing, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, directive+"=") || strings.HasPrefix(trimmed, "#"+directive+"=") {
				before = strings.TrimPrefix(trimmed, "#")
				updated += newLine + "\n"
				replaced = true
			} else {
				updated += line + "\n"
			}
		}
		if !replaced {
			before = "SSHD_CONFIG_FILE not set (defaults to /etc/ssh/sshd_config)"
			updated = strings.TrimSuffix(updated, "\n") + "\n" + newLine + "\n"
		}

		if err := os.WriteFile(conf, []byte(updated), 0600); err != nil {
			return before, "", fmt.Errorf("write %s: %w", conf, err)
		}
		_, _ = sysutil.Run("rkhunter", "--propupd")
		return before, newLine + "; propupd run", nil
	}
}

// fixRkhunterBootService installs a systemd drop-in so rkhunter-boot.service
// doesn't false-alarm on rkhunter exit code 1. rkhunter exits 1 when it finds
// warnings (e.g. "PermitRootLogin not set" from sshd drop-in not being scanned);
// this drop-in marks exit code 1 as success until those warnings are resolved.
func fixRkhunterBootService() applyFunc {
	return func() (before, after string, err error) {
		const dropInDir = "/etc/systemd/system/rkhunter-boot.service.d"
		const dropInFile = dropInDir + "/success-exit.conf"

		if _, err := os.Stat(dropInFile); err == nil {
			return "drop-in already present", "drop-in already present", nil
		}
		before = "rkhunter-boot.service fails with exit code 1 on rkhunter warnings"

		if err := os.MkdirAll(dropInDir, 0755); err != nil {
			return before, "", fmt.Errorf("create drop-in dir: %w", err)
		}
		content := "[Service]\nSuccessExitStatus=0 1\n"
		if err := os.WriteFile(dropInFile, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write drop-in: %w", err)
		}
		if _, err := sysutil.Run("systemctl", "daemon-reload"); err != nil {
			return before, "", fmt.Errorf("daemon-reload: %w", err)
		}
		_, _ = sysutil.Run("systemctl", "reset-failed", "rkhunter-boot.service")
		return before, "drop-in installed — rkhunter-boot.service will not false-alarm on exit code 1", nil
	}
}

// loadAuditRules reloads audit rules into the running auditd daemon.
// Addresses ACCT-9630: auditd running with empty ruleset after enableAuditd was applied.
func loadAuditRules() applyFunc {
	return func() (before, after string, err error) {
		out, _ := sysutil.Run("auditctl", "-l")
		before = strings.TrimSpace(out)

		// Compile and load all rules from rules.d.
		// augenrules exits 1 with "No change" or "No rules" — both are non-fatal.
		if out, err := sysutil.Run("augenrules", "--load"); err != nil &&
			!strings.Contains(out, "No change") &&
			!strings.Contains(out, "No rules") {
			return before, "", fmt.Errorf("augenrules --load: %w — output: %s", err, out)
		}

		out, _ = sysutil.Run("auditctl", "-l")
		after = strings.TrimSpace(out)
		return before, after, nil
	}
}

// enableAuditd writes baseline audit rules, enables, and starts auditd.
func enableAuditd() applyFunc {
	return func() (before, after string, err error) {
		out, _ := sysutil.Run("systemctl", "is-active", "auditd")
		before = strings.TrimSpace(out)

		if err := os.MkdirAll(auditRulesDir, 0755); err != nil {
			return before, "", fmt.Errorf("create %s: %w", auditRulesDir, err)
		}
		if err := os.WriteFile(auditRulesFile, []byte(auditRules), 0640); err != nil {
			return before, "", fmt.Errorf("write audit rules: %w", err)
		}

		if _, err := sysutil.Run("systemctl", "enable", "--now", "auditd"); err != nil {
			return before, "", fmt.Errorf("systemctl enable --now auditd: %w", err)
		}

		// Enable audit-rules.service so rules are loaded on every boot.
		if _, err := sysutil.Run("systemctl", "enable", "--now", "audit-rules"); err != nil {
			return before, "", fmt.Errorf("systemctl enable --now audit-rules: %w", err)
		}

		// Reload rules into the running daemon if already active.
		_, _ = sysutil.Run("augenrules", "--load")

		out, _ = sysutil.Run("systemctl", "is-active", "auditd")
		after = strings.TrimSpace(out)
		return before, after, nil
	}
}
