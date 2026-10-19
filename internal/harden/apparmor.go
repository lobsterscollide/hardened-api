package harden

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

const limineCmdlineFile = "/etc/default/limine"

// appArmorParams are the kernel params needed to enable AppArmor.
const appArmorParams = "apparmor=1 security=apparmor"

func enableAppArmor() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(limineCmdlineFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", limineCmdlineFile, err)
		}

		content := string(data)
		before = content

		// Check if already present
		if strings.Contains(content, "apparmor=1") {
			return before, before, nil
		}

		// Append apparmor params to the KERNEL_CMDLINE[default] line
		lines := strings.Split(content, "\n")
		found := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, `KERNEL_CMDLINE[default]="`) && strings.HasSuffix(trimmed, `"`) {
				// Insert before closing quote
				lines[i] = line[:len(line)-1] + " " + appArmorParams + `"`
				found = true
				break
			}
		}

		if !found {
			return before, "", fmt.Errorf("could not find KERNEL_CMDLINE[default] line in %s", limineCmdlineFile)
		}

		after = strings.Join(lines, "\n")
		if err := os.WriteFile(limineCmdlineFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", limineCmdlineFile, err)
		}

		// Regenerate limine config so the new params take effect on next boot
		if _, err := sysutil.Run("limine-update"); err != nil {
			return before, after, fmt.Errorf("wrote cmdline but limine-update failed: %w", err)
		}

		return before, after, nil
	}
}

// loadAppArmorProfiles installs the apparmor package (which populates
// /etc/apparmor.d/), enables the service, and loads all profiles into the
// running kernel via apparmor_parser. Addresses the gap where AppArmor is
// present in the kernel cmdline but 0 profiles are actually loaded.
func loadAppArmorProfiles() applyFunc {
	return func() (before, after string, err error) {
		// Capture current profile count for before/after comparison.
		out, _ := sysutil.Run("aa-status", "--json")
		before = strings.TrimSpace(out)
		if before == "" {
			before = "0 profiles loaded"
		}

		// Install apparmor package (idempotent — pacman skips if already installed).
		// Use a 5-minute timeout: download + install can be slow.
		if out, err := sysutil.RunWithEnv(5*time.Minute, nil, "pacman", "-S", "--noconfirm", "--needed", "apparmor"); err != nil {
			return before, "", fmt.Errorf("pacman install apparmor: %w — %s", err, out)
		}

		// Enable and start the service (idempotent).
		if _, err := sysutil.Run("systemctl", "enable", "--now", "apparmor"); err != nil {
			return before, "", fmt.Errorf("systemctl enable --now apparmor: %w", err)
		}

		// Parse and load all profiles from /etc/apparmor.d/ into the kernel.
		// Use a 3-minute timeout: many profiles can take time to compile.
		if out, err := sysutil.RunWithEnv(3*time.Minute, nil, "apparmor_parser", "-r", "/etc/apparmor.d/"); err != nil {
			// apparmor_parser exits non-zero on individual profile warnings; only
			// treat as failure if the output contains no profiles at all.
			if !strings.Contains(out, "profile") {
				return before, "", fmt.Errorf("apparmor_parser: %w — %s", err, out)
			}
		}

		out, _ = sysutil.Run("aa-status", "--json")
		after = strings.TrimSpace(out)
		if after == "" {
			after = "aa-status unavailable — check: aa-status | grep 'profiles are loaded'"
		}
		return before, after, nil
	}
}

func enableAppArmorService() applyFunc {
	return func() (before, after string, err error) {
		out, _ := sysutil.Run("systemctl", "is-enabled", "apparmor")
		before = strings.TrimSpace(out)

		if _, err := sysutil.Run("systemctl", "enable", "apparmor"); err != nil {
			return before, "", fmt.Errorf("systemctl enable apparmor: %w", err)
		}

		out, _ = sysutil.Run("systemctl", "is-enabled", "apparmor")
		after = strings.TrimSpace(out)
		return before, after, nil
	}
}
