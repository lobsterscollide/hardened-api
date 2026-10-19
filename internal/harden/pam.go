package harden

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

const (
	systemAuthFile = "/etc/pam.d/system-auth"
	pwqualityFile  = "/etc/security/pwquality.conf"
	loginDefsFile  = "/etc/login.defs"
	sddmConfFile   = "/etc/sddm.conf.d/autologin.conf"
)

var nullokRe = regexp.MustCompile(`\s+nullok(?:_secure)?`)

func removeNullok() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(systemAuthFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", systemAuthFile, err)
		}
		content := string(data)
		before = content

		if !strings.Contains(content, "nullok") {
			return before, before, nil // already clean
		}

		lines := strings.Split(content, "\n")
		for i, line := range lines {
			if strings.Contains(line, "pam_unix.so") {
				lines[i] = nullokRe.ReplaceAllString(line, "")
			}
		}
		after = strings.Join(lines, "\n")

		if err := os.WriteFile(systemAuthFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", systemAuthFile, err)
		}
		return before, after, nil
	}
}

func setUmask() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(loginDefsFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", loginDefsFile, err)
		}
		before = string(data)

		if err := upsertConfLines(loginDefsFile, map[string]string{
			"UMASK": "027",
		}); err != nil {
			return before, "", fmt.Errorf("update %s: %w", loginDefsFile, err)
		}
		after = "UMASK 027"
		return before, after, nil
	}
}

func setPasswordPolicy() applyFunc {
	return func() (before, after string, err error) {
		// --- pwquality.conf ---
		if err := upsertConfLines(pwqualityFile, map[string]string{
			"minlen":    "12",
			"minclass":  "3",
			"maxrepeat": "2",
		}); err != nil {
			return "", "", fmt.Errorf("update %s: %w", pwqualityFile, err)
		}

		// --- login.defs ---
		if err := upsertConfLines(loginDefsFile, map[string]string{
			"PASS_MAX_DAYS": "365",
			"PASS_MIN_DAYS": "1",
			"PASS_WARN_AGE": "14",
		}); err != nil {
			return "", "", fmt.Errorf("update %s: %w", loginDefsFile, err)
		}

		// Apply max age to the primary user account
		if _, err := sysutil.Run("chage", "-M", "365", sysutil.TargetUser); err != nil {
			return "", "", fmt.Errorf("chage -M 365 %s: %w", sysutil.TargetUser, err)
		}

		before = "(see pwquality.conf and login.defs)"
		after = "minlen=12 minclass=3 maxrepeat=2 PASS_MAX_DAYS=365"
		return before, after, nil
	}
}

// setHashingRounds configures SHA512 with 65536 rounds in login.defs and PAM.
// Addresses AUTH-9229 (PAM rounds) and AUTH-9230 (login.defs rounds).
func setHashingRounds() applyFunc {
	return func() (before, after string, err error) {
		if err := upsertConfLines(loginDefsFile, map[string]string{
			"ENCRYPT_METHOD":       "SHA512",
			"SHA_CRYPT_MIN_ROUNDS": "65536",
		}); err != nil {
			return "", "", fmt.Errorf("update %s: %w", loginDefsFile, err)
		}

		data, err := os.ReadFile(systemAuthFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", systemAuthFile, err)
		}
		before = string(data)

		lines := strings.Split(before, "\n")
		for i, line := range lines {
			if strings.Contains(line, "pam_unix.so") && strings.HasPrefix(strings.TrimSpace(line), "password") {
				if !strings.Contains(line, "rounds=") {
					lines[i] = strings.TrimRight(line, " ") + " rounds=65536"
				}
			}
		}
		after = strings.Join(lines, "\n")

		if err := os.WriteFile(systemAuthFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", systemAuthFile, err)
		}
		return before, "SHA512 rounds=65536 in PAM + login.defs", nil
	}
}

// disableSDDMAutologin removes the [Autologin] section from /etc/sddm.conf so that
// SDDM falls back to the interactive login screen (password + YubiKey via pam_u2f).
func disableSDDMAutologin() applyFunc {
	return func() (before, after string, err error) {
		data, err := os.ReadFile(sddmConfFile)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", sddmConfFile, err)
		}
		before = string(data)

		if !strings.Contains(before, "[Autologin]") {
			return before, before, nil // already clean
		}

		lines := strings.Split(before, "\n")
		var result []string
		inAutologin := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "[Autologin]" {
				inAutologin = true
				continue
			}
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				inAutologin = false
			}
			if !inAutologin {
				result = append(result, line)
			}
		}

		// Strip trailing blank lines, ensure single trailing newline
		for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
			result = result[:len(result)-1]
		}
		result = append(result, "")
		after = strings.Join(result, "\n")

		if err := os.WriteFile(sddmConfFile, []byte(after), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", sddmConfFile, err)
		}
		return before, after, nil
	}
}

// setProfileUmask sets umask 027 in /etc/profile.
// CIS benchmark requires umask hardening in both /etc/login.defs (covered by
// pam.set_umask) and /etc/profile — this covers the latter.
func setProfileUmask() applyFunc {
	return func() (before, after string, err error) {
		const path = "/etc/profile"
		data, err := os.ReadFile(path)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", path, err)
		}
		before = string(data)

		if strings.Contains(before, "umask 027") {
			return before, before, nil
		}

		lines := strings.Split(before, "\n")
		replaced := false
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "umask ") {
				lines[i] = "umask 027"
				replaced = true
				break
			}
		}
		if !replaced {
			for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
				lines = lines[:len(lines)-1]
			}
			lines = append(lines, "umask 027", "")
		}

		content := strings.Join(lines, "\n")
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return before, "", fmt.Errorf("write %s: %w", path, err)
		}
		return before, "umask 027", nil
	}
}

// upsertConfLines updates or appends key=value / key value pairs in a config file.
// It handles both "key = value" and "key value" formats by matching on the key.
func upsertConfLines(path string, settings map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	applied := make(map[string]bool)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		// Match "KEY = val", "KEY=val", or "KEY val" (login.defs style)
		for key, val := range settings {
			if keyMatches(trimmed, key) {
				lines[i] = formatEntry(path, key, val)
				applied[key] = true
				break
			}
		}
	}

	// Append any keys not already present
	for key, val := range settings {
		if !applied[key] {
			lines = append(lines, formatEntry(path, key, val))
		}
	}

	// Remove trailing blank lines, add one
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, "")

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func keyMatches(line, key string) bool {
	rest := strings.TrimPrefix(line, key)
	if len(rest) == len(line) {
		return false
	}
	if len(rest) == 0 {
		return true
	}
	return rest[0] == ' ' || rest[0] == '\t' || rest[0] == '='
}

func formatEntry(path, key, val string) string {
	// login.defs uses "KEY VALUE" style; pwquality.conf uses "key = value"
	if strings.Contains(path, "login.defs") {
		return key + " " + val
	}
	return key + " = " + val
}
