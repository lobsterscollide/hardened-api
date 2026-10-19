package sysutil

import "os"

// TargetUser is the unprivileged account that per-user hardening actions
// (password ageing, AUR builds, browser profiles) apply to. Set via HARDENED_API_USER.
var TargetUser = os.Getenv("HARDENED_API_USER")

// TargetHome returns TargetUser's home directory.
func TargetHome() string { return "/home/" + TargetUser }
