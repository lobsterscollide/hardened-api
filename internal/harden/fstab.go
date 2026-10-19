package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

const fstabFile = "/etc/fstab"

// hardenHomeFstab adds nodev and nosuid mount options to the /home fstab entry
// and remounts immediately so the change takes effect without a reboot.
func hardenHomeFstab() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(fstabFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", fstabFile, err)
		}
		content := string(data)
		before = content

		lines := strings.Split(content, "\n")
		changed := false

		for i, line := range lines {
			fields := strings.Fields(line)
			// fstab: <fs> <mountpoint> <type> <options> <dump> <pass>
			if len(fields) < 4 || fields[1] != "/home" {
				continue
			}

			opts := fields[3]
			newOpts := addMountOpts(opts, []string{"nodev", "nosuid"})
			if newOpts == opts {
				// already present
				return before, before, nil
			}

			// Replace only the options field in the line, preserving whitespace
			lines[i] = strings.Replace(line, opts, newOpts, 1)
			changed = true
			break
		}

		if !changed {
			return before, "", fmt.Errorf("could not find /home entry in %s", fstabFile)
		}

		after = strings.Join(lines, "\n")
		if err := os.WriteFile(fstabFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", fstabFile, err)
		}

		// Remount immediately — no reboot needed
		if _, err := sysutil.Run("mount", "-o", "remount", "/home"); err != nil {
			return before, after, fmt.Errorf("fstab updated but remount failed: %w", err)
		}

		return before, after, nil
	}
}

// hardenTmpNoexec adds noexec to the /tmp fstab entry (adding the entry if absent)
// and remounts immediately. Reversible by removing the fstab entry or the noexec flag.
func hardenTmpNoexec() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(fstabFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", fstabFile, err)
		}
		content := string(data)
		before = content

		lines := strings.Split(content, "\n")

		// Check if /tmp already has an fstab entry
		for i, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[1] != "/tmp" {
				continue
			}
			opts := fields[3]
			newOpts := addMountOpts(opts, []string{"noexec", "nosuid", "nodev"})
			if newOpts == opts {
				return before, before, nil
			}
			lines[i] = strings.Replace(line, opts, newOpts, 1)
			after = strings.Join(lines, "\n")
			if err := os.WriteFile(fstabFile, []byte(after), 0644); err != nil {
				return before, "", fmt.Errorf("write %s: %w", fstabFile, err)
			}
			if _, err := sysutil.Run("mount", "-o", "remount", "/tmp"); err != nil {
				return before, after, fmt.Errorf("fstab updated but remount failed: %w", err)
			}
			return before, after, nil
		}

		// No /tmp entry — add one
		entry := "tmpfs\t/tmp\ttmpfs\tdefaults,noexec,nosuid,nodev,size=2G\t0 0\n"
		after = content + entry
		if err := os.WriteFile(fstabFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", fstabFile, err)
		}
		if _, err := sysutil.Run("mount", "-o", "remount,noexec,nosuid,nodev", "/tmp"); err != nil {
			return before, after, fmt.Errorf("fstab updated but remount failed: %w", err)
		}
		return before, after, nil
	}
}

// addMountOpts appends opts that are not already present in the options string.
func addMountOpts(opts string, add []string) string {
	existing := strings.Split(opts, ",")
	existingSet := make(map[string]bool, len(existing))
	for _, o := range existing {
		existingSet[strings.TrimSpace(o)] = true
	}

	for _, o := range add {
		if !existingSet[o] {
			existing = append(existing, o)
		}
	}
	return strings.Join(existing, ",")
}
