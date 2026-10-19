package checks

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

type fileRule struct {
	Path     string
	MaxMode  os.FileMode
	OwnerUID uint32
	Required bool
	ActionID string // hardened-api action that fixes this finding, if one exists
}

var sensitiveFiles = []fileRule{
	{Path: "/etc/passwd", MaxMode: 0644, OwnerUID: 0, Required: true},
	{Path: "/etc/shadow", MaxMode: 0640, OwnerUID: 0, Required: true},
	{Path: "/etc/gshadow", MaxMode: 0640, OwnerUID: 0, Required: false},
	{Path: "/etc/sudoers", MaxMode: 0440, OwnerUID: 0, Required: false},
	{Path: "/etc/ssh/sshd_config", MaxMode: 0600, OwnerUID: 0, Required: false, ActionID: "fileperm.fix_sshd_config"},
	{Path: "/etc/crontab", MaxMode: 0600, OwnerUID: 0, Required: false},
	{Path: "/boot/grub/grub.cfg", MaxMode: 0600, OwnerUID: 0, Required: false},
}

type FilePermChecker struct{}

func (c *FilePermChecker) Run() CheckResult {
	result := CheckResult{
		Check: "fileperm",
		RunAt: time.Now(),
	}

	var findings []Finding

	for _, rule := range sensitiveFiles {
		info, err := os.Stat(rule.Path)
		if err != nil {
			if os.IsNotExist(err) {
				if rule.Required {
					findings = append(findings, Finding{
						ID:          fmt.Sprintf("fileperm.missing.%s", sanitizeID(rule.Path)),
						Title:       fmt.Sprintf("Required file missing: %s", rule.Path),
						Description: fmt.Sprintf("The file %s was not found.", rule.Path),
						Severity:    SeverityWarning,
					})
				}
			}
			continue
		}

		mode := info.Mode().Perm()

		// World-writable check
		if mode&0002 != 0 {
			findings = append(findings, Finding{
				ID:           fmt.Sprintf("fileperm.world_writable.%s", sanitizeID(rule.Path)),
				Title:        fmt.Sprintf("World-writable: %s", rule.Path),
				Description:  fmt.Sprintf("%s is writable by all users.", rule.Path),
				Severity:     SeverityCritical,
				Remediation:  fmt.Sprintf("Run: chmod o-w %s", rule.Path),
				CurrentValue: fmt.Sprintf("%04o", mode),
			})
		} else if mode > rule.MaxMode {
			remediation := fmt.Sprintf("Run: chmod %04o %s", rule.MaxMode, rule.Path)
			if rule.ActionID != "" {
				remediation = fmt.Sprintf("Apply action: %s (or run: chmod %04o %s)", rule.ActionID, rule.MaxMode, rule.Path)
			}
			findings = append(findings, Finding{
				ID:           fmt.Sprintf("fileperm.too_permissive.%s", sanitizeID(rule.Path)),
				Title:        fmt.Sprintf("Overly permissive: %s", rule.Path),
				Description:  fmt.Sprintf("%s has mode %04o, expected at most %04o.", rule.Path, mode, rule.MaxMode),
				Severity:     SeverityWarning,
				Remediation:  remediation,
				CurrentValue: fmt.Sprintf("%04o", mode),
			})
		}

		// Owner check
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if stat.Uid != rule.OwnerUID {
				findings = append(findings, Finding{
					ID:           fmt.Sprintf("fileperm.wrong_owner.%s", sanitizeID(rule.Path)),
					Title:        fmt.Sprintf("Wrong owner: %s", rule.Path),
					Description:  fmt.Sprintf("%s is owned by UID %d, expected UID %d.", rule.Path, stat.Uid, rule.OwnerUID),
					Severity:     SeverityCritical,
					Remediation:  fmt.Sprintf("Run: chown root %s", rule.Path),
					CurrentValue: fmt.Sprintf("uid=%d", stat.Uid),
				})
			}
		}
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

func sanitizeID(path string) string {
	result := ""
	for _, ch := range path {
		if ch == '/' || ch == '.' {
			result += "_"
		} else {
			result += string(ch)
		}
	}
	return result
}
