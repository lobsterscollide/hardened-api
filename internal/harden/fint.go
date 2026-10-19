package harden

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// installAIDE builds aide from the AUR and initialises the baseline database.
//
// aide is not in the official Arch repos — it must be built from the AUR.
// Because the API runs as root and AUR helpers refuse to run as root, we:
//  1. Install build dependencies with pacman (root is fine here)
//  2. Download the AUR snapshot and run makepkg as HARDENED_API_USER via runuser
//  3. Install the resulting package with pacman -U (root is fine here too)
//  4. Run aide --init to build the baseline database (can take several minutes)
func installAIDE() applyFunc {
	return func() (before, after string, err error) {
		out, qErr := sysutil.Run("pacman", "-Q", "aide")
		if qErr == nil && strings.Contains(out, "aide ") {
			before = "already installed"
		} else {
			before = "not installed"
			if err := buildInstallAUR("aide"); err != nil {
				return before, "", err
			}
		}

		const newDB = "/var/lib/aide/aide.db.new.gz"
		const activeDB = "/var/lib/aide/aide.db.gz"

		if _, err := os.Stat(activeDB); err == nil {
			return before, "already initialised (aide.db.gz exists)", nil
		}

		if err := os.MkdirAll("/var/lib/aide", 0700); err != nil {
			return before, "", fmt.Errorf("mkdir /var/lib/aide: %w", err)
		}

		// aide --init scans the full filesystem — allow up to 10 minutes
		if _, err := sysutil.RunWithEnv(10*time.Minute, nil, "aide", "--init"); err != nil {
			return before, "", fmt.Errorf("aide --init: %w", err)
		}

		if err := os.Rename(newDB, activeDB); err != nil {
			return before, "", fmt.Errorf("activate aide database: %w", err)
		}

		return before, "installed and database initialised", nil
	}
}

// initAideDB initialises the AIDE baseline database if it doesn't already exist.
// Unlike installAIDE, this action reads the actual database paths from
// /etc/aide.conf at runtime, so it works regardless of AUR package conventions.
// Run this after fint.install_aide if the database is missing.
func initAideDB() applyFunc {
	return func() (before, after string, err error) {
		// Read /etc/aide.conf to find database_out and database paths.
		newDB, activeDB := aideDBPaths()

		if _, err := os.Stat(activeDB); err == nil {
			return "already initialised (" + activeDB + " exists)", "already initialised", nil
		}
		before = "database missing (" + activeDB + " not found)"

		if err := os.MkdirAll("/var/lib/aide", 0700); err != nil {
			return before, "", fmt.Errorf("mkdir /var/lib/aide: %w", err)
		}

		// Full filesystem scan — allow up to 15 minutes.
		if out, runErr := sysutil.RunWithEnv(15*time.Minute, nil, "aide", "--init"); runErr != nil {
			return before, "", fmt.Errorf("aide --init: %w — %s", runErr, out)
		}

		if _, err := os.Stat(newDB); err != nil {
			return before, "", fmt.Errorf("aide --init completed but %s not found", newDB)
		}

		if err := os.Rename(newDB, activeDB); err != nil {
			return before, "", fmt.Errorf("rename %s → %s: %w", newDB, activeDB, err)
		}

		return before, "database initialised at " + activeDB, nil
	}
}

// updateAideDB refreshes the AIDE baseline after a system change (e.g. kernel upgrade).
// Unlike initAideDB, this action always runs aide --update to capture current state and
// then promotes the new database to active. It is safe to run whenever aide --check exits 7.
//
// aide --update exit codes:
//
//	0 — no changes found (rare in practice when called post-update)
//	7 — changes found and recorded (expected — this is the whole point)
//	other — real error
func updateAideDB() applyFunc {
	return func() (before, after string, err error) {
		newDB, activeDB := aideDBPaths()

		if _, err := os.Stat(activeDB); err != nil {
			return "", "", fmt.Errorf("no active AIDE database at %s — run fint.init_aide_db first", activeDB)
		}
		before = "database present at " + activeDB

		// aide --update scans the filesystem and writes aide.db.new.gz.
		// Exit 7 means "changes found" — expected post-update, not an error here.
		out, runErr := sysutil.RunWithEnv(15*time.Minute, nil, "aide", "--update")
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				if exitErr.ExitCode() != 7 {
					return before, "", fmt.Errorf("aide --update exited %d: %s", exitErr.ExitCode(), out)
				}
				// exit 7 = changes recorded — proceed to promote
			} else {
				return before, "", fmt.Errorf("aide --update: %w", runErr)
			}
		}

		if _, err := os.Stat(newDB); err != nil {
			return before, "", fmt.Errorf("aide --update completed but %s not found", newDB)
		}

		if err := os.Rename(newDB, activeDB); err != nil {
			return before, "", fmt.Errorf("promote %s → %s: %w", newDB, activeDB, err)
		}

		return before, "database updated — new baseline active at " + activeDB, nil
	}
}

// aideDBPaths reads /etc/aide.conf and extracts database_out and database paths.
// Falls back to the conventional paths if the config is unreadable.
// Handles AIDE macro expansion: @@define VARNAME value → @@{VARNAME} substitution.
func aideDBPaths() (newDB, activeDB string) {
	newDB = "/var/lib/aide/aide.db.new.gz"
	activeDB = "/var/lib/aide/aide.db.gz"

	data, err := os.ReadFile("/etc/aide.conf")
	if err != nil {
		return
	}

	// First pass: collect @@define macros.
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

	// Second pass: extract database paths and expand macros.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "database_out=") {
			val := expand(strings.TrimPrefix(strings.TrimPrefix(line, "database_out="), "file:"))
			if val != "" {
				newDB = val
			}
		} else if strings.HasPrefix(line, "database=") {
			val := expand(strings.TrimPrefix(strings.TrimPrefix(line, "database="), "file:"))
			if val != "" {
				activeDB = val
			}
		}
	}
	return
}

// installAIDETimer writes aide.service + aide.timer to /etc/systemd/system/
// and enables a daily 02:00 integrity check.
func installAIDETimer() applyFunc {
	return func() (before, after string, err error) {
		const serviceUnit = `/etc/systemd/system/aide.service`
		const timerUnit = `/etc/systemd/system/aide.timer`

		serviceContent := `[Unit]
Description=AIDE file integrity check
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
StandardOutput=journal
StandardError=journal
`
		timerContent := `[Unit]
Description=Daily AIDE file integrity check

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
`
		before = "aide timer not installed"

		if err := os.WriteFile(serviceUnit, []byte(serviceContent), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", serviceUnit, err)
		}
		if err := os.WriteFile(timerUnit, []byte(timerContent), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", timerUnit, err)
		}

		if _, err := sysutil.Run("systemctl", "daemon-reload"); err != nil {
			return before, "", fmt.Errorf("daemon-reload: %w", err)
		}
		if _, err := sysutil.Run("systemctl", "enable", "--now", "aide.timer"); err != nil {
			return before, "", fmt.Errorf("enable aide.timer: %w", err)
		}

		return before, "aide.timer enabled (daily 02:00)", nil
	}
}
