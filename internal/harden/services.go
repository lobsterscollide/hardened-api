package harden

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

func disableService(unit string) applyFunc {
	return func() (before, after string, err error) {
		out, _ := sysutil.Run("systemctl", "is-active", unit)
		before = strings.TrimSpace(out)

		if before == "inactive" || before == "failed" {
			// May still be enabled — disable so it won't start on boot
			_, _ = sysutil.Run("systemctl", "disable", unit)
			_, _ = sysutil.Run("systemctl", "is-enabled", unit)
			return before, "disabled", nil
		}

		if _, err := sysutil.Run("systemctl", "disable", "--now", unit); err != nil {
			return before, "", fmt.Errorf("systemctl disable --now %s: %w", unit, err)
		}

		out, _ = sysutil.Run("systemctl", "is-active", unit)
		after = strings.TrimSpace(out)
		return before, after, nil
	}
}

// installRkhunterTimer writes rkhunter.service and rkhunter.timer unit files
// to /etc/systemd/system/ and enables the weekly timer.
func installRkhunterTimer() applyFunc {
	return func() (before, after string, err error) {
		const serviceUnit = `/etc/systemd/system/rkhunter.service`
		const timerUnit = `/etc/systemd/system/rkhunter.timer`

		serviceContent := `[Unit]
Description=Rootkit Hunter weekly scan
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/rkhunter --check --skip-keypress --report-warnings-only
StandardOutput=journal
StandardError=journal
`
		timerContent := `[Unit]
Description=Weekly Rootkit Hunter scan

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
`
		before = "rkhunter timer not installed"

		if err := os.WriteFile(serviceUnit, []byte(serviceContent), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", serviceUnit, err)
		}
		if err := os.WriteFile(timerUnit, []byte(timerContent), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", timerUnit, err)
		}

		if _, err := sysutil.Run("systemctl", "daemon-reload"); err != nil {
			return before, "", fmt.Errorf("daemon-reload: %w", err)
		}
		if _, err := sysutil.Run("systemctl", "enable", "--now", "rkhunter.timer"); err != nil {
			return before, "", fmt.Errorf("enable rkhunter.timer: %w", err)
		}

		return before, "rkhunter.timer enabled (weekly Sunday 03:00)", nil
	}
}

// rkhunterPropupd initializes or updates the rkhunter file properties database.
// Uses /var/tmp to avoid failures when /tmp is mounted noexec.
// Timeout is 5 minutes — propupd scans the full filesystem.
func rkhunterPropupd() applyFunc {
	return func() (before, after string, err error) {
		before = "rkhunter database not initialized"
		if _, err := sysutil.RunWithEnv(5*time.Minute, []string{"TMPDIR=/var/tmp"}, "rkhunter", "--propupd"); err != nil {
			return before, "", fmt.Errorf("rkhunter --propupd: %w", err)
		}
		return before, "rkhunter database initialized", nil
	}
}

// installChkrootkit installs chkrootkit via pacman.
func installChkrootkit() applyFunc {
	return func() (before, after string, err error) {
		_, qErr := sysutil.Run("pacman", "-Q", "chkrootkit")
		if qErr == nil {
			return "already installed", "already installed", nil
		}
		before = "not installed"
		if _, err := sysutil.RunWithEnv(2*time.Minute, nil, "pacman", "-S", "--noconfirm", "chkrootkit"); err != nil {
			return before, "", fmt.Errorf("pacman install chkrootkit: %w", err)
		}
		return before, "installed", nil
	}
}

func installArchAudit() applyFunc {
	return func() (before, after string, err error) {
		_, qErr := sysutil.Run("pacman", "-Q", "arch-audit")
		if qErr == nil {
			return "already installed", "already installed", nil
		}
		before = "not installed"
		if _, err := sysutil.RunWithEnv(2*time.Minute, nil, "pacman", "-S", "--noconfirm", "arch-audit"); err != nil {
			return before, "", fmt.Errorf("pacman install arch-audit: %w", err)
		}
		return before, "installed", nil
	}
}

func installPacmanContrib() applyFunc {
	return func() (before, after string, err error) {
		_, qErr := sysutil.Run("pacman", "-Q", "pacman-contrib")
		if qErr == nil {
			return "already installed", "already installed", nil
		}
		before = "not installed"
		if _, err := sysutil.RunWithEnv(2*time.Minute, nil, "pacman", "-S", "--noconfirm", "pacman-contrib"); err != nil {
			return before, "", fmt.Errorf("pacman install pacman-contrib: %w", err)
		}
		return before, "installed", nil
	}
}

// disableAvahi disables avahi-daemon and its socket unit.
func disableAvahi() applyFunc {
	return func() (before, after string, err error) {
		out, _ := sysutil.Run("systemctl", "is-active", "avahi-daemon")
		before = strings.TrimSpace(out)

		for _, unit := range []string{"avahi-daemon", "avahi-daemon.socket"} {
			if _, err := sysutil.Run("systemctl", "disable", "--now", unit); err != nil {
				// Socket may not exist on all configurations — treat as non-fatal
				if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "does not exist") {
					return before, "", fmt.Errorf("systemctl disable --now %s: %w", unit, err)
				}
			}
		}

		out, _ = sysutil.Run("systemctl", "is-active", "avahi-daemon")
		after = strings.TrimSpace(out)
		return before, after, nil
	}
}
