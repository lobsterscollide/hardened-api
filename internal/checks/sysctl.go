package checks

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type sysctlRule struct {
	ID       string
	Key      string
	ProcPath string
	Want     string
	Severity Severity
	Title    string
}

var sysctlRules = []sysctlRule{
	{
		ID: "sysctl.tcp_syncookies", Key: "net.ipv4.tcp_syncookies",
		ProcPath: "net/ipv4/tcp_syncookies", Want: "1",
		Severity: SeverityCritical, Title: "TCP SYN cookies disabled",
	},
	{
		ID: "sysctl.accept_redirects_ipv4", Key: "net.ipv4.conf.all.accept_redirects",
		ProcPath: "net/ipv4/conf/all/accept_redirects", Want: "0",
		Severity: SeverityWarning, Title: "IPv4 ICMP redirects accepted",
	},
	{
		ID: "sysctl.accept_redirects_ipv6", Key: "net.ipv6.conf.all.accept_redirects",
		ProcPath: "net/ipv6/conf/all/accept_redirects", Want: "0",
		Severity: SeverityWarning, Title: "IPv6 ICMP redirects accepted",
	},
	{
		ID: "sysctl.send_redirects", Key: "net.ipv4.conf.all.send_redirects",
		ProcPath: "net/ipv4/conf/all/send_redirects", Want: "0",
		Severity: SeverityWarning, Title: "ICMP send redirects enabled",
	},
	{
		ID: "sysctl.log_martians", Key: "net.ipv4.conf.all.log_martians",
		ProcPath: "net/ipv4/conf/all/log_martians", Want: "1",
		Severity: SeverityWarning, Title: "Martian packet logging disabled",
	},
	{
		ID: "sysctl.rp_filter", Key: "net.ipv4.conf.all.rp_filter",
		ProcPath: "net/ipv4/conf/all/rp_filter", Want: "1",
		Severity: SeverityWarning, Title: "Reverse path filtering disabled",
	},
	{
		ID: "sysctl.icmp_ignore_broadcasts", Key: "net.ipv4.icmp_echo_ignore_broadcasts",
		ProcPath: "net/ipv4/icmp_echo_ignore_broadcasts", Want: "1",
		Severity: SeverityWarning, Title: "ICMP broadcast echo not ignored",
	},
	{
		ID: "sysctl.randomize_va_space", Key: "kernel.randomize_va_space",
		ProcPath: "kernel/randomize_va_space", Want: "2",
		Severity: SeverityCritical, Title: "ASLR not fully enabled",
	},
	{
		ID: "sysctl.dmesg_restrict", Key: "kernel.dmesg_restrict",
		ProcPath: "kernel/dmesg_restrict", Want: "1",
		Severity: SeverityWarning, Title: "dmesg unrestricted for unprivileged users",
	},
	{
		ID: "sysctl.kptr_restrict", Key: "kernel.kptr_restrict",
		ProcPath: "kernel/kptr_restrict", Want: "2",
		Severity: SeverityWarning, Title: "Kernel pointer exposure not restricted",
	},
	{
		ID: "sysctl.ptrace_scope", Key: "kernel.yama.ptrace_scope",
		ProcPath: "kernel/yama/ptrace_scope", Want: "1",
		Severity: SeverityWarning, Title: "ptrace scope too permissive",
	},
	{
		ID: "sysctl.suid_dumpable", Key: "fs.suid_dumpable",
		ProcPath: "fs/suid_dumpable", Want: "0",
		Severity: SeverityWarning, Title: "Core dumps enabled for setuid programs",
	},
}

type SysctlChecker struct{}

func (c *SysctlChecker) Run() CheckResult {
	result := CheckResult{
		Check: "sysctl",
		RunAt: time.Now(),
	}

	var findings []Finding

	for _, rule := range sysctlRules {
		val, err := readProcSys(rule.ProcPath)
		if err != nil {
			// Not all kernel versions have all parameters; skip silently
			continue
		}

		// For ptrace_scope, accept 1 or 2
		if rule.ID == "sysctl.ptrace_scope" {
			if val != "1" && val != "2" {
				findings = append(findings, Finding{
					ID:           rule.ID,
					Title:        rule.Title,
					Description:  fmt.Sprintf("%s is %q, expected 1 or 2.", rule.Key, val),
					Severity:     rule.Severity,
					Remediation:  fmt.Sprintf("Run: sysctl -w %s=1", rule.Key),
					CurrentValue: val,
				})
			}
			continue
		}

		if val != rule.Want {
			findings = append(findings, Finding{
				ID:           rule.ID,
				Title:        rule.Title,
				Description:  fmt.Sprintf("%s is %q, expected %q.", rule.Key, val, rule.Want),
				Severity:     rule.Severity,
				Remediation:  fmt.Sprintf("Run: sysctl -w %s=%s", rule.Key, rule.Want),
				CurrentValue: val,
			})
		}
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

func readProcSys(procPath string) (string, error) {
	path := "/proc/sys/" + procPath
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
