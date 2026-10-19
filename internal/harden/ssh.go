package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

const sshdDropIn = "/etc/ssh/sshd_config.d/99-hardened-api.conf"

func sshdSet(directive, value string) applyFunc {
	return func() (before, after string, err error) {
		current := readDropInDirective(directive)
		before = current

		if err := writeDropInDirective(directive, value); err != nil {
			return before, "", err
		}

		// Validate config before reloading — roll back on failure.
		if out, err := sysutil.Run("sshd", "-t"); err != nil {
			_ = writeDropInDirective(directive, before)
			return before, "", fmt.Errorf("sshd config test failed: %s", out)
		}
		if _, err := sysutil.Run("systemctl", "reload", "sshd"); err != nil {
			return before, "", fmt.Errorf("reload sshd: %w", err)
		}

		return before, value, nil
	}
}

func readDropInDirective(directive string) string {
	data, err := os.ReadFile(sshdDropIn)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(directive)+" ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

func writeDropInDirective(directive, value string) error {
	data, _ := os.ReadFile(sshdDropIn)
	lines := strings.Split(string(data), "\n")

	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), strings.ToLower(directive)+" ") {
			lines[i] = fmt.Sprintf("%s %s", directive, value)
			replaced = true
			break
		}
	}

	if !replaced {
		if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
			lines = append(lines, "")
		}
		lines = append(lines, fmt.Sprintf("%s %s", directive, value))
	}

	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	return os.WriteFile(sshdDropIn, []byte(content), 0600)
}
