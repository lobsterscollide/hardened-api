package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

var highRiskPorts = map[int]string{
	21:   "FTP",
	23:   "Telnet",
	512:  "rexec",
	513:  "rlogin",
	514:  "rsh",
	1099: "Java RMI",
	2049: "NFS",
}

type PortsChecker struct {
	WhitelistPorts []int
}

type listeningPort struct {
	Port    int
	Address string
	Process string
}

func (c *PortsChecker) Run() CheckResult {
	result := CheckResult{
		Check: "ports",
		RunAt: time.Now(),
	}

	ports, err := getListeningPorts()
	if err != nil {
		result.Error = fmt.Sprintf("failed to enumerate ports: %v", err)
		result.OK = false
		return result
	}

	whiteset := make(map[int]bool)
	for _, p := range c.WhitelistPorts {
		whiteset[p] = true
	}

	var findings []Finding

	for _, p := range ports {
		// High-risk ports
		if svc, bad := highRiskPorts[p.Port]; bad {
			findings = append(findings, Finding{
				ID:           fmt.Sprintf("ports.high_risk.%d", p.Port),
				Title:        fmt.Sprintf("High-risk port open: %d (%s)", p.Port, svc),
				Description:  fmt.Sprintf("Port %d (%s) is listening on %s.", p.Port, svc, p.Address),
				Severity:     SeverityCritical,
				Remediation:  fmt.Sprintf("Disable the %s service if not required.", svc),
				CurrentValue: fmt.Sprintf("%s:%d", p.Address, p.Port),
			})
			continue
		}

		// Unexpected listeners on all interfaces
		if !whiteset[p.Port] && (p.Address == "0.0.0.0" || p.Address == "::") {
			severity := SeverityWarning
			if p.Port < 1024 {
				severity = SeverityWarning
			}
			findings = append(findings, Finding{
				ID:           fmt.Sprintf("ports.unexpected.%d", p.Port),
				Title:        fmt.Sprintf("Unexpected listener on port %d", p.Port),
				Description:  fmt.Sprintf("Port %d is listening on all interfaces (%s) and is not in the whitelist.", p.Port, p.Address),
				Severity:     severity,
				Remediation:  "Restrict or disable this service if not required.",
				CurrentValue: fmt.Sprintf("%s:%d process=%s", p.Address, p.Port, p.Process),
			})
		}
	}

	result.Findings = findings
	result.OK = !hasCriticalOrWarning(findings)
	return result
}

func getListeningPorts() ([]listeningPort, error) {
	out, err := sysutil.Run("ss", "-tlnup")
	if err != nil {
		return nil, err
	}

	var ports []listeningPort
	for _, line := range strings.Split(out, "\n") {
		p, ok := parseSSLine(line)
		if ok {
			ports = append(ports, p)
		}
	}

	// Also check UDP
	udpOut, err := sysutil.Run("ss", "-ulnup")
	if err == nil {
		for _, line := range strings.Split(udpOut, "\n") {
			p, ok := parseSSLine(line)
			if ok {
				ports = append(ports, p)
			}
		}
	}

	return ports, nil
}

func parseSSLine(line string) (listeningPort, bool) {
	fields := strings.Fields(line)
	// ss output: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port [Process]
	if len(fields) < 5 {
		return listeningPort{}, false
	}
	state := fields[0]
	if state != "LISTEN" && state != "UNCONN" {
		return listeningPort{}, false
	}

	localAddr := fields[4]
	lastColon := strings.LastIndex(localAddr, ":")
	if lastColon < 0 {
		return listeningPort{}, false
	}

	addrPart := localAddr[:lastColon]
	portStr := localAddr[lastColon+1:]

	// Strip brackets from IPv6 addresses
	addrPart = strings.Trim(addrPart, "[]")

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return listeningPort{}, false
	}

	process := ""
	for _, f := range fields[5:] {
		if strings.HasPrefix(f, "users:") {
			process = f
			break
		}
	}

	return listeningPort{Port: port, Address: addrPart, Process: process}, true
}
