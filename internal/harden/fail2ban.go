package harden

import (
	"os"
	"strings"
)

const fail2banJailLocal = "/etc/fail2ban/jail.local"

const fail2banJailContent = `[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
`

func fail2banEnableSSH() applyFunc {
	return func() (before, after string, err error) {
		data, readErr := os.ReadFile(fail2banJailLocal)
		if readErr == nil {
			before = string(data)
		} else {
			before = ""
		}

		if strings.Contains(before, fail2banJailContent) {
			return before, before, nil
		}

		if err := os.WriteFile(fail2banJailLocal, []byte(fail2banJailContent), 0644); err != nil {
			return before, "", err
		}
		return before, fail2banJailContent, nil
	}
}
