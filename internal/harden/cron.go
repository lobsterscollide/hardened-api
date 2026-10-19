package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// hardenCrontab implements SCHD-7704 (cron access control) and CIS cron hardening:
//
//  1. Creates /etc/cron.allow containing only "root" — when this file exists, only
//     listed users may submit user crontabs. cron.deny is ignored when cron.allow exists.
//  2. Sets /var/spool/cron permissions to 700 root:root — user crontab spool directory
//     must not be world-readable.
//  3. Sets /etc/crontab permissions to 600 root:root — system crontab writable only by root.
//  4. Sets /etc/cron.d permissions to 755 root:root — drop-in directory, readable but
//     not writable by non-root.
func hardenCrontab() applyFunc {
	return func() (before, after string, err error) {
		var beforeParts []string

		// --- /etc/cron.allow ---
		cronAllow := "/etc/cron.allow"
		existing, readErr := os.ReadFile(cronAllow)
		if readErr == nil {
			beforeParts = append(beforeParts, fmt.Sprintf("cron.allow: %q", strings.TrimSpace(string(existing))))
		} else {
			beforeParts = append(beforeParts, "cron.allow: missing")
		}

		if readErr != nil || strings.TrimSpace(string(existing)) != "root" {
			if err := os.WriteFile(cronAllow, []byte("root\n"), 0644); err != nil {
				return strings.Join(beforeParts, "; "), "", fmt.Errorf("write %s: %w", cronAllow, err)
			}
		}

		// --- /var/spool/cron: 0700 root:root ---
		spoolDir := "/var/spool/cron"
		if info, statErr := os.Stat(spoolDir); statErr == nil {
			beforeParts = append(beforeParts, fmt.Sprintf("spool: %04o", info.Mode().Perm()))
			if err := os.Chmod(spoolDir, 0700); err != nil {
				return strings.Join(beforeParts, "; "), "", fmt.Errorf("chmod %s: %w", spoolDir, err)
			}
			if _, err := sysutil.Run("chown", "root:root", spoolDir); err != nil {
				return strings.Join(beforeParts, "; "), "", fmt.Errorf("chown %s: %w", spoolDir, err)
			}
		} else {
			beforeParts = append(beforeParts, "spool: missing")
		}

		// --- /etc/crontab: 0600 root:root ---
		crontab := "/etc/crontab"
		if info, statErr := os.Stat(crontab); statErr == nil {
			beforeParts = append(beforeParts, fmt.Sprintf("crontab: %04o", info.Mode().Perm()))
			if err := os.Chmod(crontab, 0600); err != nil {
				return strings.Join(beforeParts, "; "), "", fmt.Errorf("chmod %s: %w", crontab, err)
			}
			if _, err := sysutil.Run("chown", "root:root", crontab); err != nil {
				return strings.Join(beforeParts, "; "), "", fmt.Errorf("chown %s: %w", crontab, err)
			}
		} else {
			beforeParts = append(beforeParts, "crontab: missing")
		}

		// --- /etc/cron.d: 0755 root:root ---
		cronD := "/etc/cron.d"
		if info, statErr := os.Stat(cronD); statErr == nil {
			beforeParts = append(beforeParts, fmt.Sprintf("cron.d: %04o", info.Mode().Perm()))
			if err := os.Chmod(cronD, 0755); err != nil {
				return strings.Join(beforeParts, "; "), "", fmt.Errorf("chmod %s: %w", cronD, err)
			}
			if _, err := sysutil.Run("chown", "root:root", cronD); err != nil {
				return strings.Join(beforeParts, "; "), "", fmt.Errorf("chown %s: %w", cronD, err)
			}
		}

		before = strings.Join(beforeParts, "; ")
		after = "cron.allow: root only; /var/spool/cron: 0700 root:root; /etc/crontab: 0600 root:root; /etc/cron.d: 0755 root:root"
		return before, after, nil
	}
}
