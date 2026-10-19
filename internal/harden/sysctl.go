package harden

import (
	"fmt"
	"os"
	"strings"
)

const sysctlPersistFile = "/etc/sysctl.d/99-hardened-api.conf"

func sysctlApply(key, value string) applyFunc {
	return func() (before, after string, err error) {
		procPath := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")

		data, err := os.ReadFile(procPath)
		if err != nil {
			return "", "", fmt.Errorf("read current value: %w", err)
		}
		before = strings.TrimSpace(string(data))

		// Apply at runtime via /proc/sys
		if err := os.WriteFile(procPath, []byte(value+"\n"), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", procPath, err)
		}

		// Persist across reboots via sysctl.d
		if err := persistSysctl(key, value); err != nil {
			return before, value, fmt.Errorf("applied runtime but failed to persist: %w", err)
		}

		// For net.ipv4.conf.all.* keys, also apply and persist the default counterpart.
		// When network interfaces are brought up after systemd-sysctl runs, they inherit
		// from net.ipv4.conf.default.*, which can override the all.* values.
		if defaultKey, ok := allToDefault(key); ok {
			defaultProc := "/proc/sys/" + strings.ReplaceAll(defaultKey, ".", "/")
			_ = os.WriteFile(defaultProc, []byte(value+"\n"), 0644)
			_ = persistSysctl(defaultKey, value)
		}

		return before, value, nil
	}
}

// allToDefault converts net.ipv4.conf.all.X → net.ipv4.conf.default.X.
func allToDefault(key string) (string, bool) {
	const prefix = "net.ipv4.conf.all."
	if strings.HasPrefix(key, prefix) {
		return "net.ipv4.conf.default." + key[len(prefix):], true
	}
	return "", false
}

func persistSysctl(key, value string) error {
	data, _ := os.ReadFile(sysctlPersistFile)
	lines := strings.Split(string(data), "\n")

	// Remove trailing empty lines
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	entry := key + " = " + value
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+" ") ||
			strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			lines[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, entry)
	}

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(sysctlPersistFile, []byte(content), 0644)
}
