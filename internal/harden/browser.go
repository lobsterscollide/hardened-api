package harden

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

var firefoxProfilesDir = filepath.Join(sysutil.TargetHome(), ".mozilla/firefox")
var firefoxProfilesIni = filepath.Join(firefoxProfilesDir, "profiles.ini")

// firefoxUserJS is written to every Firefox profile.
// Firefox is dedicated to: general search — minimal, locked down.
// Settings are aggressive since no account logins are expected.
const firefoxUserJS = `// hardened-api: Firefox hardening — general search profile
// Applied automatically. Do not edit — will be overwritten on next apply.

// ── Telemetry & data collection ───────────────────────────────────────────────
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);
user_pref("dom.crashreports.success_delay", 0);

// ── Tracking protection ───────────────────────────────────────────────────────
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.letterboxing", true);

// ── Cookies ───────────────────────────────────────────────────────────────────
user_pref("network.cookie.cookieBehavior", 1);           // block third-party
user_pref("network.cookie.lifetimePolicy", 2);           // expire at session end
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.history", false);     // keep history for usability

// ── DNS over HTTPS ────────────────────────────────────────────────────────────
user_pref("network.trr.mode", 2);                        // DoH with fallback
user_pref("network.trr.uri", "https://dns.quad9.net/dns-query");

// ── WebRTC — disable to prevent IP leaks ──────────────────────────────────────
user_pref("media.peerconnection.enabled", false);

// ── Prefetching & speculative connections ─────────────────────────────────────
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("network.http.speculative-parallel-limit", 4);  // 0 hurts perf; 4 is a reasonable privacy/speed tradeoff
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.places.speculativeConnect.enabled", false);

// ── Referer headers ───────────────────────────────────────────────────────────
user_pref("network.http.sendRefererHeader", 0);
user_pref("network.http.referer.XOriginPolicy", 2);      // only send to same origin

// ── Hardware & sensor APIs ────────────────────────────────────────────────────
user_pref("dom.battery.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("dom.vr.enabled", false);
user_pref("geo.enabled", false);
user_pref("browser.send_pings", false);

// ── Media — camera & microphone ───────────────────────────────────────────────
user_pref("media.navigator.enabled", false);
user_pref("permissions.default.camera", 2);              // block
user_pref("permissions.default.microphone", 2);          // block

// ── Password manager — use 1Password instead ──────────────────────────────────
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);

// ── Mozilla services ──────────────────────────────────────────────────────────
user_pref("browser.pocket.enabled", false);
user_pref("extensions.pocket.enabled", false);
user_pref("identity.fxaccounts.enabled", false);         // no Firefox account sync
user_pref("browser.tabs.firefox-view", false);

// ── HTTPS-only mode ───────────────────────────────────────────────────────────
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_pbm", true);      // also in private browsing

// ── TLS hardening ─────────────────────────────────────────────────────────────
user_pref("security.tls.version.min", 3);                 // TLS 1.2 minimum
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.OCSP.enabled", 1);
user_pref("security.OCSP.require", true);                 // hard-fail on OCSP error

// ── Disk cache — off for privacy ──────────────────────────────────────────────
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.offline.enable", false);

// ── Hardware acceleration ─────────────────────────────────────────────────────
user_pref("layers.acceleration.force-enabled", true);
user_pref("gfx.webrender.all", true);

// ── UI — minimal new tab page ─────────────────────────────────────────────────
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
user_pref("browser.startup.homepage", "about:blank");
`

// bravePolicy is written to /etc/brave/policies/managed/hardening.json.
// Brave is dedicated to: Claude/AI accounts + crypto (transition from Chromium).
// Strong privacy, but permissive enough for account-based services.
const bravePolicy = `{
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "PasswordManagerEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "MetricsReportingEnabled": false,
  "CloudReportingEnabled": false,
  "SafeBrowsingEnabled": true,
  "SafeBrowsingExtendedReportingEnabled": false,
  "DnsOverHttpsMode": "secure",
  "DnsOverHttpsTemplates": "https://dns.quad9.net/dns-query",
  "BlockThirdPartyCookies": true,
  "DefaultNotificationsSetting": 2,
  "DefaultGeolocationSetting": 2,
  "VideoCaptureAllowed": false,
  "AudioCaptureAllowed": false,
  "BrowserLabsEnabled": false,
  "SpellCheckServiceEnabled": false,
  "TranslateEnabled": false,
  "BackgroundModeEnabled": false,
  "PromotionalTabsEnabled": false,
  "NewTabPageLocation": "about:blank",
  "HttpsOnlyMode": "force_enabled",
  "SSLErrorOverrideAllowed": false,
  "HardwareAccelerationModeEnabled": true
}
`

// chromiumPolicy is written to /etc/chromium/policies/managed/hardening.json.
// Chromium is dedicated to: personal server access + website builds.
// Kept more permissive than Brave/Firefox since dev tools need full fidelity.
const chromiumPolicy = `{
  "BrowserSignin": 0,
  "SyncDisabled": true,
  "PasswordManagerEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,
  "MetricsReportingEnabled": false,
  "CloudReportingEnabled": false,
  "SafeBrowsingEnabled": true,
  "SafeBrowsingExtendedReportingEnabled": false,
  "DnsOverHttpsMode": "secure",
  "DnsOverHttpsTemplates": "https://dns.quad9.net/dns-query",
  "DefaultNotificationsSetting": 2,
  "DefaultGeolocationSetting": 2,
  "SpellCheckServiceEnabled": false,
  "TranslateEnabled": false,
  "BackgroundModeEnabled": false,
  "HttpsOnlyMode": "force_enabled",
  "SSLErrorOverrideAllowed": false,
  "HardwareAccelerationModeEnabled": true
}
`

func hardenFirefox() applyFunc {
	return func() (before, after string, err error) {
		profiles, err := findFirefoxProfiles()
		if err != nil {
			return "", "", fmt.Errorf("find firefox profiles: %w", err)
		}
		if len(profiles) == 0 {
			return "", "", fmt.Errorf("no Firefox profiles found in %s", firefoxProfilesDir)
		}

		var applied []string
		for _, p := range profiles {
			dest := filepath.Join(p, "user.js")
			existing := "(none)"
			if _, e := os.Stat(dest); e == nil {
				existing = "exists"
			}
			before = existing
			// Write as the profile owner, not root: profile paths come from the
			// user's profiles.ini and may be symlinks to files root must not touch.
			cmd := exec.Command("runuser", "-u", sysutil.TargetUser, "--", "sh", "-c", `cat > "$1"`, "sh", dest)
			cmd.Stdin = strings.NewReader(firefoxUserJS)
			if out, err := cmd.CombinedOutput(); err != nil {
				return before, "", fmt.Errorf("write user.js to %s: %w: %s", p, err, out)
			}
			applied = append(applied, filepath.Base(p))
		}

		return before, fmt.Sprintf("user.js written to profiles: %s", strings.Join(applied, ", ")), nil
	}
}

func hardenBrave() applyFunc {
	return func() (before, after string, err error) {
		const policyPath = "/etc/brave/policies/managed/hardening.json"
		before = "(none)"
		if _, e := os.Stat(policyPath); e == nil {
			before = "policy exists"
		}
		if err := os.WriteFile(policyPath, []byte(bravePolicy), 0644); err != nil {
			return before, "", fmt.Errorf("write brave policy: %w", err)
		}
		return before, "policy written — restart Brave to apply", nil
	}
}

func hardenChromium() applyFunc {
	return func() (before, after string, err error) {
		const policyPath = "/etc/chromium/policies/managed/hardening.json"
		before = "(none)"
		if _, e := os.Stat(policyPath); e == nil {
			before = "policy exists"
		}
		if err := os.WriteFile(policyPath, []byte(chromiumPolicy), 0644); err != nil {
			return before, "", fmt.Errorf("write chromium policy: %w", err)
		}
		return before, "policy written — restart Chromium to apply", nil
	}
}

// findFirefoxProfiles returns paths to all profile directories in profiles.ini.
func findFirefoxProfiles() ([]string, error) {
	f, err := os.Open(firefoxProfilesIni)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var profiles []string
	var currentPath string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Path=") {
			currentPath = strings.TrimPrefix(line, "Path=")
		}
		if line == "" && currentPath != "" {
			full := filepath.Join(firefoxProfilesDir, currentPath)
			if info, err := os.Stat(full); err == nil && info.IsDir() {
				profiles = append(profiles, full)
			}
			currentPath = ""
		}
	}
	// Catch last entry if file doesn't end with blank line
	if currentPath != "" {
		full := filepath.Join(firefoxProfilesDir, currentPath)
		if info, err := os.Stat(full); err == nil && info.IsDir() {
			profiles = append(profiles, full)
		}
	}

	return profiles, scanner.Err()
}
