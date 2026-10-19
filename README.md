# hardened-api

> Linux hardening checks and fixes, exposed as a small local API that an AI agent (or you, with `curl`) can drive.

[![CI](https://github.com/lobsterscollide/hardened-api/actions/workflows/ci.yml/badge.svg)](https://github.com/lobsterscollide/hardened-api/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## The idea

Hardening a workstation usually means running one-off scripts and hoping you remember what changed.
hardened-api turns every check and every fix into a named API action instead. An agent reads the
checks, picks actions, dry-runs them, and applies them one at a time — and every applied action
records its before/after state. The agent never gets a shell; it only gets a menu of vetted changes.

Built for a single-user Arch Linux + `linux-hardened` workstation, driven largely by Lynis findings.

## What's inside

| Path | What it is |
|------|------------|
| `cmd/server/` | Entry point |
| `internal/api/` | HTTP routes, auth, rate limiting, audit logging |
| `internal/checks/` | 13 read-only checks: ssh, firewall, ports, sysctl, users, services, file permissions, SUID, AIDE, ClamAV, rkhunter, chkrootkit, arch-audit |
| `internal/harden/` | 93 hardening actions (sysctl, sshd, PAM, fstab, AppArmor, auditd, kernel modules, systemd sandboxing, browsers, …) |
| `internal/agents/` | Types for a planned agent-lifecycle API (endpoints are stubs) |
| `scripts/scan.sh` | Standalone ClamAV + rkhunter + chkrootkit + arch-audit wrapper |
| `hardened-api.service` | systemd unit |

## Quick start

```sh
go build -o hardened-api ./cmd/server
sudo install -m 0755 hardened-api /usr/local/bin/
sudo install -D -m 0600 /dev/null /etc/hardened-api/env
sudoedit /etc/hardened-api/env
#   HARDENED_API_KEY=<openssl rand -hex 32>         read-only routes
#   HARDENED_API_HARDEN_KEY=<a different random key> required to apply actions
#   HARDENED_API_USER=<your unprivileged username>
sudo install -m 0644 hardened-api.service /etc/systemd/system/
sudo systemctl enable --now hardened-api

curl -s -H @- localhost:8080/api/v1/checks <<<"Authorization: Bearer $HARDENED_API_KEY" | jq .
```

Apply an action (dry-run first):

```sh
curl -s -X POST -H @- -H 'X-Harden-Confirm: yes' localhost:8080/api/v1/harden \
  -d '{"actions":["sysctl.set_kptr_restrict"],"dry_run":true}' \
  <<<"Authorization: Bearer $HARDENED_API_HARDEN_KEY" | jq .
```

## How it works

| Route | Key | Purpose |
|-------|-----|---------|
| `GET /healthz` | none | Liveness |
| `GET /api/v1/checks`, `/api/v1/checks/<name>` | read | Run all checks, or one |
| `GET /api/v1/harden/actions` | read | List every action ID and what it does |
| `POST /api/v1/harden` | harden | Apply (or `dry_run`) a list of action IDs; needs `X-Harden-Confirm: yes` |
| `GET /api/v1/plan` | read | A hand-maintained list of outstanding work (edit `internal/api/plan.go`) |

Action IDs are validated against the built-in registry before anything runs; requests carry no
other input, so there is no path from the API to an arbitrary command. Every request is logged.

Settings (env): `HARDENED_API_KEY`, `HARDENED_API_HARDEN_KEY` (falls back to the read key),
`HARDENED_API_USER`, `HARDENED_API_BIND` (default `127.0.0.1:8080`), `HARDENED_API_RATE_LIMIT`
(requests/minute per client IP, default 60), `HARDENED_API_LOG_LEVEL`, `HARDENED_API_WHITELIST_PORTS`.

## Requirements

- Arch Linux (uses `pacman`, the AUR and `arch-audit`); Limine bootloader for the boot actions
- Go (current release — older toolchains carry standard-library CVEs into the binary)
- Runs as root via systemd

## Security notes

- It runs as **root** and changes system configuration. Read the actions you apply.
- It speaks plain HTTP. Keep the default `127.0.0.1` bind, or only widen it onto a trusted tunnel
  such as WireGuard (the `network.enable_fleet_monitor` action does exactly that).
- Use a separate `HARDENED_API_HARDEN_KEY` so a read-only agent can inspect but not change the system.
- The AIDE and `acct` actions build AUR packages as `HARDENED_API_USER` with `makepkg --skippgpcheck`
  and install them as root — the same trust as `makepkg -si`. Install those yourself if that isn't acceptable.
- Some actions are opinionated for a single-user desktop (`/tmp` noexec, Firefox lockdown,
  password ageing) and will break other setups.

## Status

Complete and shared as a reference; not actively maintained. The agent-lifecycle endpoints are stubs.

## Part of a set

| Project | What it is |
|---------|------------|
| [railed](https://github.com/lobsterscollide/railed) | Operating discipline for AI agents with real tool access, built from documented failures |
| **hardened-api** | Linux hardening checks and fixes as an API an agent can drive |
| [usb-triage](https://github.com/lobsterscollide/usb-triage) | Run-from-USB security audit for Linux, macOS and Windows |
| [workstation-scripts](https://github.com/lobsterscollide/workstation-scripts) | Daily → quarterly security routine for an Arch workstation |
| [a2a-schemas](https://github.com/lobsterscollide/a2a-schemas) | Permission boundaries and handoffs between a "build" agent and an "apply" agent |

## License

[MIT](LICENSE)
