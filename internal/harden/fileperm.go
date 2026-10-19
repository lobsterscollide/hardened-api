package harden

import (
	"fmt"
	"os"
)

// fixSshdConfig ensures /etc/ssh/sshd_config has permissions 0600.
// Lynis and CIS both require this — the file contains no secrets but
// stricter perms prevent casual inspection of directives.
func fixSshdConfig() applyFunc {
	return func() (before, after string, err error) {
		const path = "/etc/ssh/sshd_config"
		info, err := os.Stat(path)
		if err != nil {
			return "", "", fmt.Errorf("stat %s: %w", path, err)
		}
		before = fmt.Sprintf("%04o", info.Mode().Perm())

		const want os.FileMode = 0600
		if info.Mode().Perm() == want {
			return before, before, nil
		}

		if err := os.Chmod(path, want); err != nil {
			return before, "", fmt.Errorf("chmod %s: %w", path, err)
		}
		return before, fmt.Sprintf("%04o", want), nil
	}
}

// fixEtcGroup ensures /etc/group has permissions 0644 (FILE-7524).
// Lynis reports this as a finding when the mode exceeds 644.
func fixEtcGroup() applyFunc {
	return func() (before, after string, err error) {
		const path = "/etc/group"
		info, err := os.Stat(path)
		if err != nil {
			return "", "", fmt.Errorf("stat %s: %w", path, err)
		}
		before = fmt.Sprintf("%04o", info.Mode().Perm())

		const want os.FileMode = 0644
		if info.Mode().Perm() == want {
			return before, before, nil
		}

		if err := os.Chmod(path, want); err != nil {
			return before, "", fmt.Errorf("chmod %s: %w", path, err)
		}
		return before, fmt.Sprintf("%04o", want), nil
	}
}
