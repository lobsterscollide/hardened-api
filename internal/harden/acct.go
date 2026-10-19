package harden

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

const loginBanner = `*******************************************************************
* Authorized access only. All activity is monitored and logged. *
* Unauthorized access is a violation of applicable laws.        *
*******************************************************************
`

// enablePsacct builds the acct package from the AUR (not in official Arch repos)
// and enables the acct service for process accounting (ACCT-9622).
func enablePsacct() applyFunc {
	return func() (before, after string, err error) {
		_, qErr := sysutil.Run("pacman", "-Q", "acct")
		if qErr != nil {
			before = "not installed"
			if err := buildInstallAUR("acct"); err != nil {
				return before, "", fmt.Errorf("build acct from AUR: %w", err)
			}
		} else {
			out, _ := sysutil.Run("systemctl", "is-active", "acct")
			before = strings.TrimSpace(out)
		}

		if _, err := sysutil.Run("systemctl", "enable", "--now", "acct"); err != nil {
			return before, "", fmt.Errorf("systemctl enable --now acct: %w", err)
		}

		out, _ := sysutil.Run("systemctl", "is-active", "acct")
		return before, strings.TrimSpace(out), nil
	}
}

// enableSysstat installs the sysstat package and enables the sysstat service
// for system activity accounting (ACCT-9626).
func enableSysstat() applyFunc {
	return func() (before, after string, err error) {
		_, qErr := sysutil.Run("pacman", "-Q", "sysstat")
		if qErr != nil {
			before = "not installed"
			if _, err := sysutil.RunWithEnv(2*time.Minute, nil, "pacman", "-S", "--noconfirm", "sysstat"); err != nil {
				return before, "", fmt.Errorf("pacman install sysstat: %w", err)
			}
		} else {
			out, _ := sysutil.Run("systemctl", "is-active", "sysstat")
			before = strings.TrimSpace(out)
		}

		if _, err := sysutil.Run("systemctl", "enable", "--now", "sysstat"); err != nil {
			return before, "", fmt.Errorf("systemctl enable --now sysstat: %w", err)
		}

		out, _ := sysutil.Run("systemctl", "is-active", "sysstat")
		return before, strings.TrimSpace(out), nil
	}
}

// addLoginBanner writes a legal warning to /etc/issue (BANN-7126).
func addLoginBanner() applyFunc {
	return func() (before, after string, err error) {
		data, _ := os.ReadFile("/etc/issue")
		before = string(data)

		if strings.Contains(before, "Authorized access only") {
			return before, before, nil
		}

		if err := os.WriteFile("/etc/issue", []byte(loginBanner), 0644); err != nil {
			return before, "", fmt.Errorf("write /etc/issue: %w", err)
		}
		return before, loginBanner, nil
	}
}

// addIssueNetBanner writes the same legal warning to /etc/issue.net (CIS benchmark).
// /etc/issue covers local console logins; /etc/issue.net covers network (SSH) logins
// when sshd Banner is set — both are required for full CIS compliance.
func addIssueNetBanner() applyFunc {
	return func() (before, after string, err error) {
		data, _ := os.ReadFile("/etc/issue.net")
		before = string(data)

		if strings.Contains(before, "Authorized access only") {
			return before, before, nil
		}

		if err := os.WriteFile("/etc/issue.net", []byte(loginBanner), 0644); err != nil {
			return before, "", fmt.Errorf("write /etc/issue.net: %w", err)
		}
		return before, loginBanner, nil
	}
}

// addHostnameToHosts adds the machine hostname and FQDN to /etc/hosts (NAME-4404).
func addHostnameToHosts() applyFunc {
	return func() (before, after string, err error) {
		hostname, err := os.Hostname()
		if err != nil {
			return "", "", fmt.Errorf("get hostname: %w", err)
		}

		data, err := os.ReadFile("/etc/hosts")
		if err != nil {
			return "", "", fmt.Errorf("read /etc/hosts: %w", err)
		}
		before = string(data)

		// If hostname already present, skip
		if strings.Contains(before, hostname) {
			return before, before, nil
		}

		// Resolve the primary non-loopback IP for the hostname entry
		ip := "127.0.1.1"
		if addrs, lookupErr := net.LookupHost(hostname); lookupErr == nil {
			for _, a := range addrs {
				if a != "127.0.0.1" && a != "::1" {
					ip = a
					break
				}
			}
		}

		fqdn := hostname + ".local"
		entry := fmt.Sprintf("%s\t%s %s\n", ip, hostname, fqdn)

		content := strings.TrimRight(before, "\n") + "\n" + entry
		if err := os.WriteFile("/etc/hosts", []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write /etc/hosts: %w", err)
		}
		return before, entry, nil
	}
}
