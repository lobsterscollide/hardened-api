package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// disableLLMNR disables Link-Local Multicast Name Resolution (port 5355).
// LLMNR is a name poisoning vector and not needed when DNS is already configured.
// Sets LLMNR=no in /etc/systemd/resolved.conf.d/99-hardened-api.conf and restarts resolved.
func disableLLMNR() applyFunc {
	return func() (before, after string, err error) {
		const dropInDir = "/etc/systemd/resolved.conf.d"
		const dropInFile = "/etc/systemd/resolved.conf.d/99-hardened-api.conf"

		// Read current state
		out, _ := sysutil.Run("resolvectl", "status")
		if strings.Contains(out, "LLMNR=no") {
			return "already disabled", "already disabled", nil
		}
		before = "enabled"

		if err := os.MkdirAll(dropInDir, 0755); err != nil {
			return before, "", fmt.Errorf("mkdir %s: %w", dropInDir, err)
		}

		content := "[Resolve]\nLLMNR=no\nMulticastDNS=no\n"
		if err := os.WriteFile(dropInFile, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", dropInFile, err)
		}

		if _, err := sysutil.Run("systemctl", "restart", "systemd-resolved"); err != nil {
			return before, "", fmt.Errorf("restart systemd-resolved: %w", err)
		}

		return before, "LLMNR and mDNS disabled via resolved drop-in", nil
	}
}

// bindAPIToLocalhost sets HARDENED_API_BIND=127.0.0.1:8080 in /etc/hardened-api/env
// so the API is only reachable from this machine, not the network.
func bindAPIToLocalhost() applyFunc {
	return func() (before, after string, err error) {
		const envFile = "/etc/hardened-api/env"

		raw, err := os.ReadFile(envFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", envFile, err)
		}

		content := string(raw)
		if strings.Contains(content, "HARDENED_API_BIND=127.0.0.1") {
			return "already localhost", "already localhost", nil
		}

		before = ":8080 (all interfaces)"

		// Replace or append the bind setting
		lines := strings.Split(content, "\n")
		found := false
		for i, line := range lines {
			if strings.HasPrefix(line, "HARDENED_API_BIND=") {
				lines[i] = "HARDENED_API_BIND=127.0.0.1:8080"
				found = true
				break
			}
		}
		if !found {
			lines = append(lines, "HARDENED_API_BIND=127.0.0.1:8080")
		}

		if err := os.WriteFile(envFile, []byte(strings.Join(lines, "\n")), 0600); err != nil {
			return before, "", fmt.Errorf("write %s: %w", envFile, err)
		}

		// Restart the service to pick up the new bind address
		if _, err := sysutil.Run("systemctl", "restart", "hardened-api"); err != nil {
			return before, "", fmt.Errorf("restart hardened-api: %w", err)
		}

		return before, "127.0.0.1:8080 (localhost only)", nil
	}
}

// setResolvedDNS hardens systemd-resolved: sets quad9+cloudflare DNS, enables
// opportunistic DNS-over-TLS and DNSSEC, and disables LLMNR/mDNS. Opportunistic
// (not mandatory) DoT allows fallback to plain DNS when traffic is routed through
// tunnels like Nym that don't reliably forward port 853. Writes a comprehensive
// drop-in that supersedes the LLMNR-only one if already present.
func setResolvedDNS() applyFunc {
	return func() (before, after string, err error) {
		const dropInDir = "/etc/systemd/resolved.conf.d"
		const dropInFile = "/etc/systemd/resolved.conf.d/99-hardened-api.conf"

		raw, _ := os.ReadFile(dropInFile)
		before = strings.TrimSpace(string(raw))
		if before == "" {
			before = "(no drop-in)"
		}

		const want = "[Resolve]\nDNS=9.9.9.9 1.1.1.1 2620:fe::fe 2606:4700:4700::1111\nDNSOverTLS=opportunistic\nDNSSEC=yes\nLLMNR=no\nMulticastDNS=no\n"
		if strings.TrimSpace(string(raw)) == strings.TrimSpace(want) {
			return before, "already configured", nil
		}

		if err := os.MkdirAll(dropInDir, 0755); err != nil {
			return before, "", fmt.Errorf("mkdir %s: %w", dropInDir, err)
		}
		if err := os.WriteFile(dropInFile, []byte(want), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", dropInFile, err)
		}
		if _, err := sysutil.Run("systemctl", "restart", "systemd-resolved"); err != nil {
			return before, "", fmt.Errorf("restart systemd-resolved: %w", err)
		}

		return before, "DNS=Quad9+Cloudflare, DNSOverTLS=opportunistic, DNSSEC=yes, LLMNR=no, mDNS=no", nil
	}
}

// allowDockerForwarding adds nftables rules to the forward chain so Docker
// bridge container traffic can flow through the host. The base nftables config
// has `policy drop` on the forward chain with no exceptions; this blocks all
// Docker container networking. This action inserts:
//   - ct state {established, related} accept  — return traffic for existing conns
//   - ip saddr 172.16.0.0/12 accept           — Docker bridge subnets (outgoing)
//   - ip daddr 172.16.0.0/12 accept           — Docker bridge subnets (incoming)
//
// 172.16.0.0/12 covers Docker's default range (172.17–172.31.x.x).
// The rules are idempotent — re-running is safe.
func allowDockerForwarding() applyFunc {
	return func() (before, after string, err error) {
		const conf = "/etc/nftables.conf"

		raw, err := os.ReadFile(conf)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", conf, err)
		}
		content := string(raw)
		before = content

		if strings.Contains(content, "docker-forward") {
			return "already configured", "already configured", nil
		}

		// Find the forward chain's closing brace and insert rules before it.
		lines := strings.Split(content, "\n")
		var out []string
		inForward := false
		depth := 0
		inserted := false

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(line, "chain forward {") {
				inForward = true
				depth = 1
			} else if inForward {
				for _, ch := range line {
					if ch == '{' {
						depth++
					} else if ch == '}' {
						depth--
					}
				}
				if depth == 0 && !inserted {
					out = append(out,
						"\t\t# Allow Docker bridge forwarding (docker-forward)",
						"\t\tct state {established, related} accept",
						"\t\tip saddr 172.16.0.0/12 accept",
						"\t\tip daddr 172.16.0.0/12 accept",
					)
					inForward = false
					inserted = true
				}
			}
			_ = trimmed
			out = append(out, line)
		}

		if !inserted {
			return before, "", fmt.Errorf("could not locate forward chain in %s", conf)
		}

		after = strings.Join(out, "\n")
		if err := os.WriteFile(conf, []byte(after), 0600); err != nil {
			return before, "", fmt.Errorf("write %s: %w", conf, err)
		}

		if _, err := sysutil.Run("systemctl", "restart", "nftables"); err != nil {
			// Attempt rollback
			_ = os.WriteFile(conf, raw, 0600)
			return before, "", fmt.Errorf("restart nftables (rolled back): %w", err)
		}

		return before, "Docker bridge forwarding allowed (172.16.0.0/12, established/related)", nil
	}
}

// enableFleetMonitor opens hardened-api to the WireGuard fleet subnet (10.10.0.0/24)
// so a management workstation on the fleet subnet can reach GET /checks and POST /harden on this machine.
//
// Two changes are made:
//  1. nftables input chain: insert `ip saddr 10.10.0.0/24 tcp dport 8080 accept`
//     before the rate-limit/reject line, so fleet traffic is admitted but the
//     default-drop policy still blocks all other sources.
//  2. /etc/hardened-api/env: set HARDENED_API_BIND=:8080 (bind all interfaces —
//     nftables above restricts access to WireGuard subnet only).
//
// Idempotent — re-running is safe. Requires WireGuard to be up on the machine
// before fleet queries will actually reach the API.
func enableFleetMonitor() applyFunc {
	return func() (before, after string, err error) {
		const conf = "/etc/nftables.conf"
		const envFile = "/etc/hardened-api/env"
		const marker = "fleet-monitor"

		// ── Step 1: nftables rule ────────────────────────────────────────────
		raw, err := os.ReadFile(conf)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", conf, err)
		}
		content := string(raw)
		before = content

		if !strings.Contains(content, marker) {
			lines := strings.Split(content, "\n")
			var out []string
			inInput := false
			depth := 0
			inserted := false

			for _, line := range lines {
				if strings.Contains(line, "chain input {") {
					inInput = true
					depth = 1
				} else if inInput {
					for _, ch := range line {
						if ch == '{' {
							depth++
						} else if ch == '}' {
							depth--
						}
					}
					// Insert before the rate-limit/reject or closing brace
					if !inserted && (strings.Contains(line, "limit rate") || strings.Contains(line, "reject") || (depth == 0)) {
						out = append(out,
							"\t\t# Fleet Monitor: allow hardened-api from WireGuard subnet (fleet-monitor)",
							"\t\tip saddr 10.10.0.0/24 tcp dport 8080 accept",
						)
						inserted = true
					}
					if depth == 0 {
						inInput = false
					}
				}
				out = append(out, line)
			}

			if !inserted {
				return before, "", fmt.Errorf("could not locate input chain in %s", conf)
			}

			newContent := strings.Join(out, "\n")
			if err := os.WriteFile(conf, []byte(newContent), 0600); err != nil {
				return before, "", fmt.Errorf("write %s: %w", conf, err)
			}
			if _, err := sysutil.Run("systemctl", "restart", "nftables"); err != nil {
				_ = os.WriteFile(conf, raw, 0600)
				return before, "", fmt.Errorf("restart nftables (rolled back): %w", err)
			}
		}

		// ── Step 2: hardened-api bind address ───────────────────────────────
		envRaw, err := os.ReadFile(envFile)
		if err != nil {
			return before, "", fmt.Errorf("read %s: %w", envFile, err)
		}

		envContent := string(envRaw)
		lines := strings.Split(envContent, "\n")
		found := false
		for i, line := range lines {
			if strings.HasPrefix(line, "HARDENED_API_BIND=") {
				lines[i] = "HARDENED_API_BIND=:8080"
				found = true
				break
			}
		}
		if !found {
			lines = append(lines, "HARDENED_API_BIND=:8080")
		}

		newEnv := strings.Join(lines, "\n")
		if newEnv != envContent {
			if err := os.WriteFile(envFile, []byte(newEnv), 0600); err != nil {
				return before, "", fmt.Errorf("write %s: %w", envFile, err)
			}
			if _, err := sysutil.Run("systemctl", "restart", "hardened-api"); err != nil {
				return before, "", fmt.Errorf("restart hardened-api: %w", err)
			}
		}

		return before, "fleet monitor enabled: port 8080 open to 10.10.0.0/24, HARDENED_API_BIND=:8080", nil
	}
}

// enableWireGuardOutput adds an nftables output chain that accepts all traffic
// leaving through the wg0 interface and accepts WireGuard UDP (port 51820) on
// the external interface.  Without this, some kernel configurations produce
// EPERM on sendmsg when traffic is sent through wg0 even though no output chain
// is explicitly defined — the WireGuard kernel module's packet path can hit
// implicit conntrack rules that reject untracked new flows.
//
// The action is idempotent and rolls back nftables on failure.
func enableWireGuardOutput() applyFunc {
	return func() (before, after string, err error) {
		const conf = "/etc/nftables.conf"
		const marker = "wireguard-output"

		raw, err := os.ReadFile(conf)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", conf, err)
		}
		content := string(raw)
		before = content

		if strings.Contains(content, marker) {
			return "already configured", "already configured", nil
		}

		// Append an output chain to the inet filter table, before the closing
		// brace of the table block.
		outputChain := `
  chain output {
    type filter hook output priority filter
    policy accept
    # Allow WireGuard UDP out and all wg0 interface traffic (wireguard-output)
    oifname "wg0" accept
    udp dport 51820 accept
  }
`
		// Insert before the final closing brace of the table block.
		lastBrace := strings.LastIndex(content, "}")
		if lastBrace == -1 {
			return before, "", fmt.Errorf("could not locate table closing brace in %s", conf)
		}
		newContent := content[:lastBrace] + outputChain + content[lastBrace:]

		if err := os.WriteFile(conf, []byte(newContent), 0600); err != nil {
			return before, "", fmt.Errorf("write %s: %w", conf, err)
		}
		if _, err := sysutil.Run("systemctl", "restart", "nftables"); err != nil {
			_ = os.WriteFile(conf, raw, 0600)
			return before, "", fmt.Errorf("restart nftables (rolled back): %w", err)
		}

		return before, "output chain added: wg0 accept + udp 51820 accept", nil
	}
}

// restrictSSHToLocalhost binds sshd to 127.0.0.1 only.
// Use when this machine is not accessed remotely — keeps SSH available for
// local tooling while removing it from the network attack surface.
func restrictSSHToLocalhost() applyFunc {
	return func() (before, after string, err error) {
		const dropIn = "/etc/ssh/sshd_config.d/99-localhost-only.conf"

		if _, err := os.Stat(dropIn); err == nil {
			return "already localhost only", "already localhost only", nil
		}
		before = "0.0.0.0 + :: (all interfaces)"

		content := "# Bind sshd to localhost only — no remote access needed on this machine\nListenAddress 127.0.0.1\nListenAddress ::1\n"
		if err := os.WriteFile(dropIn, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", dropIn, err)
		}

		if out, err := sysutil.Run("sshd", "-t"); err != nil {
			os.Remove(dropIn)
			return before, "", fmt.Errorf("sshd config invalid: %s", out)
		}

		if _, err := sysutil.Run("systemctl", "reload", "sshd"); err != nil {
			return before, "", fmt.Errorf("reload sshd: %w", err)
		}

		return before, "127.0.0.1 + ::1 (localhost only)", nil
	}
}
