package harden

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/lobsterscollide/hardened-api/internal/sysutil"
)

// compilerBinaries is the list of compiler and toolchain executables to restrict.
var compilerBinaries = []string{
	// GCC toolchain
	"/usr/bin/gcc",
	"/usr/bin/cc",
	"/usr/bin/g++",
	"/usr/bin/c++",
	"/usr/bin/gfortran",
	"/usr/bin/as",
	"/usr/bin/ld",
	"/usr/bin/ar",
	"/usr/bin/ranlib",
	"/usr/bin/nm",
	"/usr/bin/objdump",
	"/usr/bin/objcopy",
	// LLVM/Clang toolchain
	"/usr/bin/clang",
	"/usr/bin/clang++",
	"/usr/bin/lld",
	"/usr/bin/llvm-ar",
	"/usr/bin/llvm-nm",
	"/usr/bin/llvm-objdump",
	"/usr/bin/llvm-objcopy",
}

// restrictCompilerAccess removes world-execute permission from compiler binaries.
// A "build" group is created and all human users (uid >= 1000) are added to it.
// Compilers are chowned to root:build with mode 750 — satisfies Lynis HRDN-7222
// while allowing human users to run AUR builds via makepkg.
func restrictCompilerAccess() applyFunc {
	return func() (before, after string, err error) {
		// Ensure the build group exists
		if _, err := sysutil.Run("getent", "group", "build"); err != nil {
			if _, err := sysutil.Run("groupadd", "--system", "build"); err != nil {
				return "", "", fmt.Errorf("create build group: %w", err)
			}
		}

		// Add all human users (uid >= 1000) to the build group
		if addErr := addHumanUsersToBuildGroup(); addErr != nil {
			return "", "", fmt.Errorf("add users to build group: %w", addErr)
		}

		var beforeParts, afterParts []string

		for _, path := range compilerBinaries {
			info, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					continue // not installed, skip
				}
				return strings.Join(beforeParts, ", "), "", fmt.Errorf("stat %s: %w", path, err)
			}

			stat := info.Sys().(*syscall.Stat_t)
			beforeParts = append(beforeParts, fmt.Sprintf("%s:%04o(gid=%d)", path, info.Mode().Perm(), stat.Gid))

			// Resolve build group GID
			gidOut, err := sysutil.Run("getent", "group", "build")
			if err != nil {
				return strings.Join(beforeParts, ", "), "", fmt.Errorf("resolve build gid: %w", err)
			}
			var buildGID int
			fmt.Sscanf(strings.Split(gidOut, ":")[2], "%d", &buildGID)

			// chown root:build
			if err := os.Lchown(path, 0, buildGID); err != nil {
				return strings.Join(beforeParts, ", "), "", fmt.Errorf("chown %s: %w", path, err)
			}
			// 750: owner=rwx, group=r-x, world=---
			if err := os.Chmod(path, 0o750); err != nil {
				return strings.Join(beforeParts, ", "), "", fmt.Errorf("chmod %s: %w", path, err)
			}
			afterParts = append(afterParts, fmt.Sprintf("%s:0750(root:build)", path))
		}

		if len(beforeParts) == 0 {
			return "(no compilers found)", "(no compilers found)", nil
		}
		return strings.Join(beforeParts, ", "), strings.Join(afterParts, ", "), nil
	}
}

// addHumanUsersToBuildGroup adds all users with uid >= 1000 to the build group.
func addHumanUsersToBuildGroup() error {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		var uid int
		if _, err := fmt.Sscanf(fields[2], "%d", &uid); err != nil || uid < 1000 {
			continue
		}
		username := fields[0]
		// gpasswd -a is idempotent — safe to re-run
		if _, err := sysutil.Run("gpasswd", "-a", username, "build"); err != nil {
			return fmt.Errorf("add %s to build: %w", username, err)
		}
	}
	return scanner.Err()
}
