package harden

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

const dockerDaemonPath = "/etc/docker/daemon.json"

// hardenDockerDaemon merges security-hardening flags into /etc/docker/daemon.json
// and restarts the Docker daemon to apply them.
//
// Flags added:
//   - no-new-privileges: true  — prevents container processes gaining privileges via setuid/setgid
//   - userland-proxy: false    — use kernel iptables/nft directly instead of docker-proxy (TOCTOU reduction)
//   - live-restore: true       — containers keep running if dockerd restarts (availability + auditability)
//   - icc: false               — disable inter-container communication by default; must be explicit
func hardenDockerDaemon() applyFunc {
	return func() (before, after string, err error) {
		// Read existing config
		raw, readErr := os.ReadFile(dockerDaemonPath)
		if readErr != nil && !os.IsNotExist(readErr) {
			return "", "", fmt.Errorf("read %s: %w", dockerDaemonPath, readErr)
		}

		cfg := make(map[string]interface{})
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return "", "", fmt.Errorf("parse %s: %w", dockerDaemonPath, err)
			}
		}

		beforeBytes, _ := json.MarshalIndent(cfg, "", "\t")
		before = string(beforeBytes)

		// Check if already hardened
		if v, ok := cfg["no-new-privileges"]; ok {
			if b, ok := v.(bool); ok && b {
				if v2, ok2 := cfg["icc"]; ok2 {
					if b2, ok2 := v2.(bool); ok2 && !b2 {
						return before, before, nil
					}
				}
			}
		}

		// Merge hardening flags — preserve all existing settings
		cfg["no-new-privileges"] = true
		cfg["userland-proxy"] = false
		cfg["live-restore"] = true
		cfg["icc"] = false

		afterBytes, err := json.MarshalIndent(cfg, "", "\t")
		if err != nil {
			return before, "", fmt.Errorf("marshal daemon.json: %w", err)
		}

		if err := os.WriteFile(dockerDaemonPath, afterBytes, 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", dockerDaemonPath, err)
		}

		// Restart docker to apply — live-restore means containers survive the restart
		if _, err := sysutil.Run("systemctl", "restart", "docker"); err != nil {
			return before, "", fmt.Errorf("restart docker: %w", err)
		}

		return before, string(afterBytes), nil
	}
}
