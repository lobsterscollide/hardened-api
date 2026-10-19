package harden

import (
	"fmt"
	"os"
	"strings"
)

// suIDTargets mirrors the list in checks/suid.go — binaries that are
// installed on Arch but unnecessary on a hardened headless server.
var suIDTargets = []string{
	"/usr/bin/ksu",
	"/usr/bin/mount.cifs",
	"/usr/bin/pkexec",
	"/usr/bin/wall",
	"/usr/bin/write",
}

// removeSUIDBits strips the setuid and setgid bits from each target binary
// that is installed and currently has either bit set.
// Uses mode.Perm() (lower 9 bits only) which drops setuid/setgid automatically.
func removeSUIDBits() applyFunc {
	return func() (before, after string, err error) {
		var beforeParts, afterParts []string

		for _, path := range suIDTargets {
			info, statErr := os.Stat(path)
			if statErr != nil {
				// Not installed — skip silently.
				continue
			}

			mode := info.Mode()
			hasSUID := mode&os.ModeSetuid != 0
			hasSGID := mode&os.ModeSetgid != 0

			if !hasSUID && !hasSGID {
				beforeParts = append(beforeParts, fmt.Sprintf("%s: already clean", path))
				afterParts = append(afterParts, fmt.Sprintf("%s: unchanged", path))
				continue
			}

			beforeParts = append(beforeParts, fmt.Sprintf("%s: %04o", path, mode.Perm()))

			// Perm() returns m & 0777 — strips setuid, setgid, and sticky bits.
			if chmodErr := os.Chmod(path, mode.Perm()); chmodErr != nil {
				return strings.Join(beforeParts, "; "), "",
					fmt.Errorf("chmod a-s %s: %w", path, chmodErr)
			}

			afterParts = append(afterParts, fmt.Sprintf("%s: %04o (bits stripped)", path, mode.Perm()))
		}

		if len(beforeParts) == 0 {
			return "no targets installed", "no changes needed", nil
		}

		return strings.Join(beforeParts, "; "), strings.Join(afterParts, "; "), nil
	}
}
