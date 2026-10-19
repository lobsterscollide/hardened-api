package harden

type applyFunc func() (before, after string, err error)

type Action struct {
	ID          string
	Description string
	Category    string
	Apply       applyFunc
}

var registry map[string]Action

func init() {
	actions := []Action{
		{
			ID:          "sysctl.enable_tcp_syncookies",
			Description: "Enable TCP SYN cookies (net.ipv4.tcp_syncookies=1)",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv4.tcp_syncookies", "1"),
		},
		{
			ID:          "sysctl.disable_accept_redirects_ipv4",
			Description: "Disable IPv4 ICMP redirect acceptance",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv4.conf.all.accept_redirects", "0"),
		},
		{
			ID:          "sysctl.disable_accept_redirects_ipv6",
			Description: "Disable IPv6 ICMP redirect acceptance",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv6.conf.all.accept_redirects", "0"),
		},
		{
			ID:          "sysctl.disable_send_redirects",
			Description: "Disable ICMP redirect sending",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv4.conf.all.send_redirects", "0"),
		},
		{
			ID:          "sysctl.enable_log_martians",
			Description: "Enable logging of martian packets",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv4.conf.all.log_martians", "1"),
		},
		{
			ID:          "sysctl.enable_rp_filter",
			Description: "Enable reverse path filtering",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv4.conf.all.rp_filter", "1"),
		},
		{
			ID:          "sysctl.set_randomize_va_space",
			Description: "Enable full ASLR (kernel.randomize_va_space=2)",
			Category:    "sysctl",
			Apply:       sysctlApply("kernel.randomize_va_space", "2"),
		},
		{
			ID:          "sysctl.set_dmesg_restrict",
			Description: "Restrict dmesg to privileged users",
			Category:    "sysctl",
			Apply:       sysctlApply("kernel.dmesg_restrict", "1"),
		},
		{
			ID:          "sysctl.set_kptr_restrict",
			Description: "Restrict kernel pointer exposure",
			Category:    "sysctl",
			Apply:       sysctlApply("kernel.kptr_restrict", "2"),
		},
		{
			ID:          "sysctl.disable_suid_dumpable",
			Description: "Disable core dumps for setuid programs",
			Category:    "sysctl",
			Apply:       sysctlApply("fs.suid_dumpable", "0"),
		},
		{
			ID:          "ssh.disable_x11_forwarding",
			Description: "Disable X11 forwarding in sshd",
			Category:    "ssh",
			Apply:       sshdSet("X11Forwarding", "no"),
		},
		{
			ID:          "ssh.set_max_auth_tries",
			Description: "Set MaxAuthTries to 3 in sshd",
			Category:    "ssh",
			Apply:       sshdSet("MaxAuthTries", "3"),
		},
		{
			ID:          "ssh.disable_tcp_forwarding",
			Description: "Disable TCP forwarding in sshd",
			Category:    "ssh",
			Apply:       sshdSet("AllowTcpForwarding", "no"),
		},
		{
			ID:          "ssh.disable_password_auth",
			Description: "Disable password authentication in sshd (key-based auth only)",
			Category:    "ssh",
			Apply:       sshdSet("PasswordAuthentication", "no"),
		},
		{
			ID:          "ssh.set_login_grace_time",
			Description: "Set LoginGraceTime to 30 seconds in sshd",
			Category:    "ssh",
			Apply:       sshdSet("LoginGraceTime", "30"),
		},
		{
			ID:          "ssh.disable_root_login",
			Description: "Disable root login via SSH (PermitRootLogin no)",
			Category:    "ssh",
			Apply:       sshdSet("PermitRootLogin", "no"),
		},
		{
			ID:          "ssh.set_protocol_2",
			Description: "Enforce SSH protocol version 2 only",
			Category:    "ssh",
			Apply:       sshdSet("Protocol", "2"),
		},
		{
			ID:          "apparmor.enable_boot_params",
			Description: "Add apparmor=1 security=apparmor to kernel cmdline and run limine-update",
			Category:    "apparmor",
			Apply:       enableAppArmor(),
		},
		{
			ID:          "apparmor.enable_service",
			Description: "Enable AppArmor systemd service (takes effect after reboot with boot params)",
			Category:    "apparmor",
			Apply:       enableAppArmorService(),
		},
		{
			ID:          "apparmor.load_profiles",
			Description: "Install apparmor package, enable service, and load all profiles from /etc/apparmor.d/ into the kernel",
			Category:    "apparmor",
			Apply:       loadAppArmorProfiles(),
		},
		{
			ID:          "fail2ban.enable_sshd_jail",
			Description: "Write /etc/fail2ban/jail.local enabling the sshd jail (bantime 1h, maxretry 5)",
			Category:    "fail2ban",
			Apply:       fail2banEnableSSH(),
		},
		{
			ID:          "users.fix_git_shell",
			Description: "Lock git system account shell to /usr/sbin/nologin",
			Category:    "users",
			Apply:       fixUserShell("git", "/usr/sbin/nologin"),
		},
		{
			ID:          "users.fix_nobody_expiry",
			Description: "Set password expiry to 90 days for nobody account",
			Category:    "users",
			Apply:       fixPasswordExpiry("nobody", 90),
		},
		{
			ID:          "services.disable_avahi",
			Description: "Disable avahi-daemon and avahi-daemon.socket (mDNS not needed on hardened desktop)",
			Category:    "services",
			Apply:       disableAvahi(),
		},
		{
			ID:          "services.disable_cups_browsed",
			Description: "Disable cups-browsed (remote printer discovery)",
			Category:    "services",
			Apply:       disableService("cups-browsed"),
		},
		{
			ID:          "services.disable_cups",
			Description: "Disable cups print spooler entirely (use only if no printing needed)",
			Category:    "services",
			Apply:       disableService("cups"),
		},
		{
			ID:          "pam.remove_nullok",
			Description: "Remove nullok from pam_unix.so in /etc/pam.d/system-auth (disallow empty-password logins)",
			Category:    "pam",
			Apply:       removeNullok(),
		},
		{
			ID:          "pam.set_password_policy",
			Description: "Set password complexity (minlen=12, minclass=3) and max age (365 days) in pwquality.conf and login.defs",
			Category:    "pam",
			Apply:       setPasswordPolicy(),
		},
		{
			ID:          "fstab.harden_home",
			Description: "Add nodev,nosuid to /home fstab entry and remount",
			Category:    "fstab",
			Apply:       hardenHomeFstab(),
		},
		{
			ID:          "services.install_rkhunter_timer",
			Description: "Install rkhunter.service + rkhunter.timer units and enable weekly Sunday 03:00 scan",
			Category:    "services",
			Apply:       installRkhunterTimer(),
		},
		{
			ID:          "services.rkhunter_propupd",
			Description: "Initialize or refresh rkhunter file properties database (run after rkhunter install or package updates)",
			Category:    "services",
			Apply:       rkhunterPropupd(),
		},
		{
			ID:          "services.install_chkrootkit",
			Description: "Install chkrootkit rootkit scanner via pacman",
			Category:    "services",
			Apply:       installChkrootkit(),
		},
		// PKGS-7322: CVE scanning
		{
			ID:          "system.install_arch_audit",
			Description: "Install arch-audit for CVE scanning of installed packages",
			Category:    "system",
			Apply:       installArchAudit(),
		},
		{
			ID:          "fstab.harden_tmp_noexec",
			Description: "Add noexec,nosuid,nodev to /tmp fstab entry and remount (reversible)",
			Category:    "fstab",
			Apply:       hardenTmpNoexec(),
		},
		{
			ID:          "boot.harden_kernel_params",
			Description: "Add init_on_alloc=1 init_on_free=1 vsyscall=none to limine kernel cmdline",
			Category:    "boot",
			Apply:       hardenKernelBootParams(),
		},
		// SSH-7408: additional SSH hardening
		{
			ID:          "ssh.set_client_alive_count_max",
			Description: "Set ClientAliveCountMax to 2 in sshd (reduce idle session timeout)",
			Category:    "ssh",
			Apply:       sshdSet("ClientAliveCountMax", "2"),
		},
		{
			ID:          "ssh.set_log_level",
			Description: "Set LogLevel to VERBOSE in sshd (log key fingerprints)",
			Category:    "ssh",
			Apply:       sshdSet("LogLevel", "VERBOSE"),
		},
		{
			ID:          "ssh.set_max_sessions",
			Description: "Set MaxSessions to 2 in sshd",
			Category:    "ssh",
			Apply:       sshdSet("MaxSessions", "2"),
		},
		{
			ID:          "ssh.disable_tcp_keepalive",
			Description: "Set TCPKeepAlive to no in sshd (rely on ClientAlive instead)",
			Category:    "ssh",
			Apply:       sshdSet("TCPKeepAlive", "no"),
		},
		{
			ID:          "ssh.disable_agent_forwarding",
			Description: "Disable SSH agent forwarding (AllowAgentForwarding no)",
			Category:    "ssh",
			Apply:       sshdSet("AllowAgentForwarding", "no"),
		},
		// CIS: show /etc/issue.net banner on SSH login
		{
			ID:          "ssh.set_banner",
			Description: "Set Banner /etc/issue.net in sshd — displays legal warning on network login (CIS; pair with system.add_issue_net_banner)",
			Category:    "ssh",
			Apply:       sshdSet("Banner", "/etc/issue.net"),
		},
		// NETW-3200: blacklist unused kernel protocols
		{
			ID:          "kernel.blacklist_unused_protocols",
			Description: "Blacklist unused kernel protocols (dccp, sctp, rds, tipc) via modprobe.d",
			Category:    "kernel",
			Apply:       blacklistProtocols(),
		},
		// KRNL-5820: core dumps via limits.conf
		{
			ID:          "kernel.disable_core_dumps",
			Description: "Disable core dumps in /etc/security/limits.conf (hard+soft core=0)",
			Category:    "kernel",
			Apply:       disableCoreDumps(),
		},
		// ACCT-9628: enable auditd
		{
			ID:          "audit.enable_auditd",
			Description: "Enable and start auditd service for system call auditing",
			Category:    "audit",
			Apply:       enableAuditd(),
		},
		// HRDN-7222: restrict compiler access
		{
			ID:          "compiler.restrict_access",
			Description: "Remove world-execute bit from compiler binaries (gcc, cc, g++, as, ld)",
			Category:    "compiler",
			Apply:       restrictCompilerAccess(),
		},
		// AUTH-9286: umask
		{
			ID:          "pam.set_umask",
			Description: "Set UMASK to 027 in /etc/login.defs (restrict new file permissions)",
			Category:    "pam",
			Apply:       setUmask(),
		},
		// CIS: umask in /etc/profile (login.defs covers PAM sessions; /etc/profile covers sh logins)
		{
			ID:          "pam.set_profile_umask",
			Description: "Set umask 027 in /etc/profile — CIS requires both login.defs and /etc/profile (pair with pam.set_umask)",
			Category:    "pam",
			Apply:       setProfileUmask(),
		},
		// AUTH-9229 / AUTH-9230: password hashing rounds
		{
			ID:          "pam.set_hashing_rounds",
			Description: "Set SHA512 with 65536 rounds in login.defs and PAM (AUTH-9229, AUTH-9230)",
			Category:    "pam",
			Apply:       setHashingRounds(),
		},
		{
			ID:          "pam.disable_sddm_autologin",
			Description: "Remove [Autologin] block from /etc/sddm.conf — require password + YubiKey at login screen",
			Category:    "pam",
			Apply:       disableSDDMAutologin(),
		},
		// KRNL-6000: sysctl values differing from Lynis profile
		{
			ID:          "sysctl.disable_sysrq",
			Description: "Disable SysRq key (kernel.sysrq=0)",
			Category:    "sysctl",
			Apply:       sysctlApply("kernel.sysrq", "0"),
		},
		{
			ID:          "sysctl.set_tty_ldisc_autoload",
			Description: "Disable TTY line discipline autoload (dev.tty.ldisc_autoload=0) — KRNL-6000",
			Category:    "sysctl",
			Apply:       sysctlApply("dev.tty.ldisc_autoload", "0"),
		},
		{
			ID:          "sysctl.set_protected_fifos",
			Description: "Protect FIFOs in world-writable dirs (fs.protected_fifos=2) — KRNL-6000",
			Category:    "sysctl",
			Apply:       sysctlApply("fs.protected_fifos", "2"),
		},
		{
			ID:          "sysctl.set_protected_regular",
			Description: "Protect regular files in world-writable dirs (fs.protected_regular=2) — KRNL-6000",
			Category:    "sysctl",
			Apply:       sysctlApply("fs.protected_regular", "2"),
		},
		{
			ID:          "sysctl.harden_bpf_jit",
			Description: "Harden BPF JIT compiler (net.core.bpf_jit_harden=2)",
			Category:    "sysctl",
			Apply:       sysctlApply("net.core.bpf_jit_harden", "2"),
		},
		{
			ID:          "sysctl.disable_default_redirects_ipv4",
			Description: "Disable IPv4 ICMP redirect acceptance on default interface (net.ipv4.conf.default.accept_redirects=0)",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv4.conf.default.accept_redirects", "0"),
		},
		{
			ID:          "sysctl.disable_default_redirects_ipv6",
			Description: "Disable IPv6 ICMP redirect acceptance on default interface (net.ipv6.conf.default.accept_redirects=0)",
			Category:    "sysctl",
			Apply:       sysctlApply("net.ipv6.conf.default.accept_redirects", "0"),
		},
		// STRG-1846: blacklist firewire storage modules
		{
			ID:          "kernel.blacklist_firewire",
			Description: "Blacklist firewire storage modules (ohci1394, sbp2, firewire-ohci, firewire-sbp2) via modprobe.d",
			Category:    "kernel",
			Apply:       blacklistKernelModules([]string{"firewire-ohci", "firewire-sbp2", "ohci1394", "sbp2", "dv1394", "raw1394"}),
		},
		// ACCT-9622: process accounting
		{
			ID:          "acct.enable_psacct",
			Description: "Install acct package and enable process accounting service (ACCT-9622)",
			Category:    "acct",
			Apply:       enablePsacct(),
		},
		// ACCT-9626: sysstat
		{
			ID:          "acct.enable_sysstat",
			Description: "Install sysstat package and enable system activity accounting (ACCT-9626)",
			Category:    "acct",
			Apply:       enableSysstat(),
		},
		// ACCT-9630: reload audit rules into running auditd
		{
			ID:          "audit.load_rules",
			Description: "Reload audit rules into running auditd via augenrules --load (ACCT-9630)",
			Category:    "audit",
			Apply:       loadAuditRules(),
		},
		// ACCT-9630: write expanded baseline ruleset then reload
		{
			ID:          "audit.write_rules",
			Description: "Write expanded baseline audit rules (modules, hardened-api watches) and reload via augenrules (ACCT-9630)",
			Category:    "audit",
			Apply:       writeAuditRules(),
		},
		// BANN-7126: login banner
		{
			ID:          "system.add_login_banner",
			Description: "Write legal warning to /etc/issue for unauthorized access deterrence (BANN-7126)",
			Category:    "system",
			Apply:       addLoginBanner(),
		},
		// CIS: /etc/issue.net banner for network (SSH) logins
		{
			ID:          "system.add_issue_net_banner",
			Description: "Write legal warning to /etc/issue.net — required by CIS for network login banner (pair with ssh.set_banner)",
			Category:    "system",
			Apply:       addIssueNetBanner(),
		},
		// NAME-4404: hostname in /etc/hosts
		{
			ID:          "system.add_hostname_hosts",
			Description: "Add machine hostname and FQDN to /etc/hosts for proper name resolving (NAME-4404)",
			Category:    "system",
			Apply:       addHostnameToHosts(),
		},
		// BOOT-5264: systemd service unit hardening
		{
			ID:          "boot.harden_hardened_api_service",
			Description: "Add systemd security drop-in to hardened-api.service (BOOT-5264)",
			Category:    "boot",
			Apply: serviceDropIn("hardened-api", "[Service]\n"+
				"NoNewPrivileges=yes\n"+
				"PrivateTmp=yes\n"+
				"LockPersonality=yes\n"+
				"RestrictRealtime=yes\n"+
				"ProtectClock=yes\n"+
				"ProtectKernelLogs=yes\n"+
				"RestrictNamespaces=yes\n"),
		},
		{
			ID:          "boot.harden_fail2ban_service",
			Description: "Add systemd security drop-in to fail2ban.service (BOOT-5264)",
			Category:    "boot",
			Apply: serviceDropIn("fail2ban", "[Service]\n"+
				"NoNewPrivileges=yes\n"+
				"PrivateTmp=yes\n"+
				"PrivateDevices=yes\n"+
				"ProtectHome=yes\n"+
				"LockPersonality=yes\n"+
				"RestrictRealtime=yes\n"+
				"ProtectClock=yes\n"+
				"ProtectKernelLogs=yes\n"),
		},
		{
			ID:          "boot.harden_sshd_service",
			Description: "Add systemd security drop-in to sshd.service (BOOT-5264)",
			Category:    "boot",
			Apply: serviceDropIn("sshd", "[Service]\n"+
				"PrivateTmp=yes\n"+
				"LockPersonality=yes\n"+
				"RestrictRealtime=yes\n"+
				"ProtectClock=yes\n"+
				"ProtectKernelLogs=yes\n"),
		},
		{
			ID:          "boot.harden_auditd_service",
			Description: "Add systemd security drop-in to auditd.service (BOOT-5264)",
			Category:    "boot",
			Apply: serviceDropIn("auditd", "[Service]\n"+
				"NoNewPrivileges=yes\n"+
				"PrivateTmp=yes\n"+
				"ProtectHome=yes\n"+
				"LockPersonality=yes\n"+
				"RestrictRealtime=yes\n"+
				"ProtectClock=yes\n"),
		},
		// PKGS-7322: arch-audit CVE scanner
		{
			ID:          "system.install_arch_audit",
			Description: "Install arch-audit for CVE scanning of installed packages",
			Category:    "system",
			Apply:       installArchAudit(),
		},
		// FINT-4350: AIDE file integrity monitoring
		{
			ID:          "fint.install_aide",
			Description: "Install AIDE file integrity monitor and initialise baseline database",
			Category:    "fint",
			Apply:       installAIDE(),
		},
		{
			ID:          "fint.install_aide_timer",
			Description: "Install aide.service + aide.timer for daily 02:00 integrity checks",
			Category:    "fint",
			Apply:       installAIDETimer(),
		},
		// AIDE database missing — run if fint.install_aide completed but db was never initialised
		{
			ID:          "fint.init_aide_db",
			Description: "Initialise AIDE baseline database (reads actual db path from /etc/aide.conf, safe to re-run)",
			Category:    "fint",
			Apply:       initAideDB(),
		},
		// AIDE database stale — run after any kernel or major system update
		{
			ID:          "fint.update_aide_db",
			Description: "Refresh AIDE baseline after system changes (aide --update + promote db). Run after kernel updates when aide.service exits 7.",
			Category:    "fint",
			Apply:       updateAideDB(),
		},
		// Startup suite dependencies
		{
			ID:          "system.install_pacman_contrib",
			Description: "Install pacman-contrib (provides checkupdates for pending update count in startup)",
			Category:    "system",
			Apply:       installPacmanContrib(),
		},
		// Service false-alarm fixes
		{
			ID:          "audit.fix_rules_service",
			Description: "Install systemd drop-in so audit-rules.service doesn't false-alarm on 'No change' exit code",
			Category:    "audit",
			Apply:       fixAuditRulesService(),
		},
		{
			ID:          "audit.fix_rules_loading",
			Description: "Add ExecStartPost drop-in to audit-rules.service so audit rules are force-loaded into the kernel at every boot (fixes 'No change' skip — ACCT-9630)",
			Category:    "audit",
			Apply:       fixAuditRulesLoading(),
		},
		{
			ID:          "rkhunter.whitelist_false_positives",
			Description: "Fix rkhunter false positives: whitelist Kerberos man pages, suppress 'Protocol not set' (OpenSSH 7.6+), set ALLOW_SSH_ROOT_USER=no",
			Category:    "rkhunter",
			Apply:       fixRkhunterFalsePositives(),
		},
		{
			ID:          "rkhunter.fix_sshd_config_path",
			Description: "Point rkhunter SSHD_CONFIG_FILE at the hardened-api drop-in (/etc/ssh/sshd_config.d/99-hardened-api.conf) so rkhunter scans actual hardened settings instead of the empty base config",
			Category:    "rkhunter",
			Apply:       fixRkhunterSshdConfigPath(),
		},
		{
			ID:          "rkhunter.fix_boot_service",
			Description: "Add SuccessExitStatus=0 1 drop-in to rkhunter-boot.service — stops boot failure noise while SSH drop-in false positives are unresolved",
			Category:    "rkhunter",
			Apply:       fixRkhunterBootService(),
		},
		// DNS hardening
		{
			ID:          "dns.set_resolved_config",
			Description: "Harden systemd-resolved: Quad9+Cloudflare DNS, DNS-over-TLS, DNSSEC, disable LLMNR/mDNS",
			Category:    "dns",
			Apply:       setResolvedDNS(),
		},
		// Network exposure reduction
		{
			ID:          "network.enable_wireguard_output",
			Description: "Add nftables output chain accepting wg0 traffic and WireGuard UDP (51820) — fixes EPERM/sendmsg errors when sending through WireGuard interface",
			Category:    "network",
			Apply:       enableWireGuardOutput(),
		},
		{
			ID:          "network.enable_fleet_monitor",
			Description: "Open hardened-api (port 8080) to WireGuard fleet subnet (10.10.0.0/24) — nftables input rule + HARDENED_API_BIND=:8080. Requires WireGuard to be up.",
			Category:    "network",
			Apply:       enableFleetMonitor(),
		},
		{
			ID:          "network.allow_docker_forwarding",
			Description: "Add nftables forward chain rules for Docker bridge subnets (172.16.0.0/12) — fixes container networking when forward policy is drop",
			Category:    "network",
			Apply:       allowDockerForwarding(),
		},
		{
			ID:          "network.disable_llmnr",
			Description: "Disable LLMNR and mDNS (port 5355) via systemd-resolved drop-in — name poisoning vector, not needed",
			Category:    "network",
			Apply:       disableLLMNR(),
		},
		{
			ID:          "network.bind_api_localhost",
			Description: "Bind hardened-api to 127.0.0.1:8080 only — removes it from network attack surface",
			Category:    "network",
			Apply:       bindAPIToLocalhost(),
		},
		{
			ID:          "network.restrict_ssh_localhost",
			Description: "Bind sshd to localhost only (127.0.0.1 + ::1) — no remote SSH needed on this machine",
			Category:    "network",
			Apply:       restrictSSHToLocalhost(),
		},
		// FILE-7524: fix /etc/group permissions to 644
		{
			ID:          "fileperm.fix_etc_group",
			Description: "Set /etc/group permissions to 644 (FILE-7524 — Lynis expects exactly 644)",
			Category:    "fileperm",
			Apply:       fixEtcGroup(),
		},
		// sshd_config world-readable — new finding 2026-04-13
		{
			ID:          "fileperm.fix_sshd_config",
			Description: "Set /etc/ssh/sshd_config permissions to 0600 (CIS + Lynis)",
			Category:    "fileperm",
			Apply:       fixSshdConfig(),
		},
		// CONT-8004: Docker daemon hardening
		{
			ID:          "docker.harden_daemon",
			Description: "Harden Docker daemon: no-new-privileges, disable userland-proxy, disable ICC, enable live-restore",
			Category:    "docker",
			Apply:       hardenDockerDaemon(),
		},
		// SCHD-7704: cron access control and file permissions (CIS)
		{
			ID:          "cron.harden_crontab_permissions",
			Description: "Create /etc/cron.allow (root only), set /var/spool/cron 0700, /etc/crontab 0600, /etc/cron.d 0755 (SCHD-7704)",
			Category:    "cron",
			Apply:       hardenCrontab(),
		},
		// Browser hardening
		{
			ID:          "browser.harden_firefox",
			Description: "Write hardened user.js to all Firefox profiles (general search — minimal, privacy-first)",
			Category:    "browser",
			Apply:       hardenFirefox(),
		},
		{
			ID:          "browser.harden_brave",
			Description: "Write managed policy to Brave (Claude/AI accounts + crypto — strong privacy, account-compatible)",
			Category:    "browser",
			Apply:       hardenBrave(),
		},
		{
			ID:          "browser.harden_chromium",
			Description: "Write managed policy to Chromium (dev/server/builds — functional with telemetry off)",
			Category:    "browser",
			Apply:       hardenChromium(),
		},
		// FILE-7524 / CIS: unnecessary SUID/SGID binaries
		{
			ID:          "suid.remove_unnecessary",
			Description: "Strip setuid/setgid bits from binaries unnecessary on a headless server: ksu, mount.cifs, pkexec, wall, write",
			Category:    "fileperm",
			Apply:       removeSUIDBits(),
		},
	}

	registry = make(map[string]Action, len(actions))
	for _, a := range actions {
		registry[a.ID] = a
	}
}

// List returns all registered action IDs and descriptions.
func List() []map[string]string {
	result := make([]map[string]string, 0, len(registry))
	for _, a := range registry {
		result = append(result, map[string]string{
			"id":          a.ID,
			"description": a.Description,
			"category":    a.Category,
		})
	}
	return result
}

// Lookup returns an action by ID.
func Lookup(id string) (Action, bool) {
	a, ok := registry[id]
	return a, ok
}
