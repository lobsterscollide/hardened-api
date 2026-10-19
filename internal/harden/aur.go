package harden

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// buildInstallAUR fetches the named package PKGBUILD from the AUR, builds it
// as HARDENED_API_USER (makepkg refuses root), and installs the result as root.
//
// Notes on the environment:
//   - PATH is set explicitly because systemd strips it when the service forks.
//   - TMPDIR is /var/tmp because /tmp is mounted noexec (fstab hardening),
//     which prevents autoconf configure tests from executing.
//   - The build dir gets a random name: /var/tmp is world-writable, and a
//     predictable path would let another user plant a symlink for chown to follow.
//   - The package is built by HARDENED_API_USER and installed by root, so this
//     trusts that account exactly as `makepkg -si` would.
func buildInstallAUR(pkgName string) error {
	buildDir, err := os.MkdirTemp("/var/tmp", pkgName+"-aur-")
	if err != nil {
		return fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)
	if _, err := sysutil.Run("chown", sysutil.TargetUser+":"+sysutil.TargetUser, buildDir); err != nil {
		return fmt.Errorf("chown build dir: %w", err)
	}

	// Install base build toolchain (root-safe)
	if _, err := sysutil.Run("pacman", "-S", "--noconfirm", "--needed", "base-devel"); err != nil {
		return fmt.Errorf("install base-devel: %w", err)
	}

	script := fmt.Sprintf(
		`export PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl && `+
			`export TMPDIR=/var/tmp && `+
			`curl -fsSL 'https://aur.archlinux.org/cgit/aur.git/snapshot/%s.tar.gz' `+
			`| tar -xz -C '%s' --strip-components=1 && `+
			`cd '%s' && makepkg --noconfirm --noprogressbar --skippgpcheck`,
		pkgName, buildDir, buildDir,
	)
	if _, err := sysutil.RunWithEnv(10*time.Minute, nil,
		"runuser", "-u", sysutil.TargetUser, "--", "bash", "-c", script,
	); err != nil {
		return fmt.Errorf("makepkg %s: %w", pkgName, err)
	}

	matches, err := filepath.Glob(filepath.Join(buildDir, pkgName+"-*.pkg.tar.zst"))
	if err != nil || len(matches) == 0 {
		return fmt.Errorf("built package not found in %s", buildDir)
	}
	if _, err := sysutil.Run("pacman", append([]string{"-U", "--noconfirm"}, matches...)...); err != nil {
		return fmt.Errorf("pacman -U %s: %w", pkgName, err)
	}
	return nil
}
