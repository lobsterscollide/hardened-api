#!/usr/bin/env bash
# scan.sh — unified security scan: clamscan + rkhunter + chkrootkit + arch-audit
# Exits 0 = clean, 1 = findings, 2 = scan error
# Usage: sudo ./scripts/scan.sh

set -euo pipefail

BOLD='\033[1m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
RESET='\033[0m'

FINDINGS=0
ERRORS=0

header() { echo -e "\n${BOLD}=== $1 ===${RESET}"; }
ok()     { echo -e "  ${GREEN}✓${RESET} $1"; }
warn()   { echo -e "  ${YELLOW}⚠${RESET}  $1"; FINDINGS=$((FINDINGS + 1)); }
error()  { echo -e "  ${RED}✗${RESET}  $1"; ERRORS=$((ERRORS + 1)); }

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 2
fi

# ── ClamAV ────────────────────────────────────────────────────────────────────
header "ClamAV — malware scan (/home /tmp)"

if ! command -v clamscan &>/dev/null; then
  error "clamscan not found — install clamav"
else
  CLAM_OUT=$(clamscan --infected --recursive --no-summary /home /tmp 2>&1) || true
  INFECTED=$(echo "$CLAM_OUT" | grep -v "^$" | grep -v "^/" | grep "FOUND" || true)
  if [[ -n "$INFECTED" ]]; then
    while IFS= read -r line; do warn "$line"; done <<< "$INFECTED"
  else
    ok "No infected files found"
  fi
fi

# ── rkhunter ──────────────────────────────────────────────────────────────────
header "rkhunter — rootkit/backdoor scan"

if ! command -v rkhunter &>/dev/null; then
  error "rkhunter not found — install rkhunter"
else
  # Run scan, capture warnings only
  RKH_OUT=$(rkhunter --check --skip-keypress --report-warnings-only 2>&1) || true
  WARNINGS=$(echo "$RKH_OUT" | grep -E "^\[ *Warning\]|Warning:" || true)
  if [[ -n "$WARNINGS" ]]; then
    while IFS= read -r line; do warn "$line"; done <<< "$WARNINGS"
    echo -e "\n  Remediation hint: run 'sudo rkhunter --propupd' if the warning is"
    echo    "  due to a legitimate system update, then re-run this scan."
  else
    ok "No warnings"
  fi
fi

# ── chkrootkit ────────────────────────────────────────────────────────────────
header "chkrootkit — classic rootkit scan"

if ! command -v chkrootkit &>/dev/null; then
  error "chkrootkit not found — install via: pacman -S chkrootkit"
else
  CKR_OUT=$(chkrootkit 2>&1) || true
  INFECTED=$(echo "$CKR_OUT" | grep -iE "^INFECTED" || true)
  if [[ -n "$INFECTED" ]]; then
    while IFS= read -r line; do warn "$line"; done <<< "$INFECTED"
    echo -e "\n  Remediation hint: investigate each INFECTED result — some may be false"
    echo    "  positives (e.g. packet sniffer on a VPN interface). Cross-check with rkhunter."
  else
    ok "No rootkits found"
  fi
fi

# ── arch-audit ────────────────────────────────────────────────────────────────
header "arch-audit — CVE check on installed packages"

if ! command -v arch-audit &>/dev/null; then
  error "arch-audit not found — install via: pacman -S arch-audit"
else
  AA_OUT=$(arch-audit 2>&1) || true
  if [[ -n "$AA_OUT" ]]; then
    while IFS= read -r line; do warn "$line"; done <<< "$AA_OUT"
    echo -e "\n  Remediation hint: update affected packages with 'pacman -Syu'."
  else
    ok "No vulnerable packages found"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ $ERRORS -gt 0 ]]; then
  echo -e "${RED}${BOLD}SCAN ERRORS: $ERRORS tool(s) failed to run.${RESET}"
  exit 2
elif [[ $FINDINGS -gt 0 ]]; then
  echo -e "${YELLOW}${BOLD}FINDINGS: $FINDINGS item(s) require attention.${RESET}"
  exit 1
else
  echo -e "${GREEN}${BOLD}CLEAN — no findings.${RESET}"
  exit 0
fi
