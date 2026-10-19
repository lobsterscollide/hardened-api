package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// serviceDropIn writes a systemd drop-in file for the given unit and runs daemon-reload.
func serviceDropIn(unit, content string) applyFunc {
	return func() (before, after string, err error) {
		dir := "/etc/systemd/system/" + unit + ".d"
		path := dir + "/99-hardened-api.conf"

		data, _ := os.ReadFile(path)
		before = string(data)

		if before == content {
			return before, before, nil // idempotent
		}

		if err := os.MkdirAll(dir, 0755); err != nil {
			return before, "", fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", path, err)
		}
		if _, err := sysutil.Run("systemctl", "daemon-reload"); err != nil {
			return before, "", fmt.Errorf("daemon-reload: %w", err)
		}
		return before, content, nil
	}
}

const kernelHardenParams = "init_on_alloc=1 init_on_free=1 vsyscall=none"

// hardenKernelBootParams appends init_on_alloc, init_on_free, and vsyscall=none
// to the limine kernel cmdline and runs limine-update.
func hardenKernelBootParams() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(limineCmdlineFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", limineCmdlineFile, err)
		}
		content := string(data)
		before = content

		// Check if already applied
		if strings.Contains(content, "init_on_alloc=1") {
			return before, before, nil
		}

		// Append to the KERNEL_CMDLINE[default]+= line (the "quiet splash" line).
		// If it doesn't exist, append to the base KERNEL_CMDLINE[default]= line.
		lines := strings.Split(content, "\n")
		found := false

		// Prefer the += line so security params are grouped separately
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, `KERNEL_CMDLINE[default]+="`) && strings.HasSuffix(trimmed, `"`) {
				lines[i] = line[:len(line)-1] + " " + kernelHardenParams + `"`
				found = true
				break
			}
		}

		// Fall back to the base = line
		if !found {
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, `KERNEL_CMDLINE[default]="`) && strings.HasSuffix(trimmed, `"`) {
					lines[i] = line[:len(line)-1] + " " + kernelHardenParams + `"`
					found = true
					break
				}
			}
		}

		if !found {
			return before, "", fmt.Errorf("could not find KERNEL_CMDLINE line in %s", limineCmdlineFile)
		}

		after = strings.Join(lines, "\n")
		if err := os.WriteFile(limineCmdlineFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", limineCmdlineFile, err)
		}

		if _, err := sysutil.Run("limine-update"); err != nil {
			return before, after, fmt.Errorf("wrote cmdline but limine-update failed: %w", err)
		}

		return before, after, nil
	}
}
