package harden

import (
	"fmt"
	"os/user"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

func fixUserShell(username, shell string) applyFunc {
	return func() (before, after string, err error) {
		u, err := user.Lookup(username)
		if err != nil {
			return "", "", fmt.Errorf("lookup user %s: %w", username, err)
		}

		// Read current shell from /etc/passwd
		out, err := sysutil.Run("getent", "passwd", username)
		if err != nil {
			return "", "", fmt.Errorf("getent passwd %s: %w", username, err)
		}
		parts := strings.Split(strings.TrimSpace(out), ":")
		if len(parts) < 7 {
			return "", "", fmt.Errorf("unexpected passwd format for %s", username)
		}
		before = parts[6]

		if before == shell {
			return before, shell, nil // already correct
		}

		if _, err := sysutil.Run("usermod", "-s", shell, u.Username); err != nil {
			return before, "", fmt.Errorf("usermod -s %s %s: %w", shell, username, err)
		}
		return before, shell, nil
	}
}

func fixPasswordExpiry(username string, maxDays int) applyFunc {
	return func() (before, after string, err error) {
		out, err := sysutil.Run("chage", "-l", username)
		if err != nil {
			return "", "", fmt.Errorf("chage -l %s: %w", username, err)
		}

		before = "(see chage -l output)"
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(strings.ToLower(line), "maximum number of days") {
				before = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				break
			}
		}

		afterVal := fmt.Sprintf("%d", maxDays)
		if _, err := sysutil.Run("chage", "-M", afterVal, username); err != nil {
			return before, "", fmt.Errorf("chage -M %d %s: %w", maxDays, username, err)
		}
		return before, afterVal, nil
	}
}
