package sysutil

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

const defaultTimeout = 5 * time.Second

// Run executes a command with a timeout and returns combined stdout output.
// args must be a complete argument list — never constructed from user input.
func Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return RunContext(ctx, name, args...)
}

// RunContext executes a command with the given context.
func RunContext(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// RunWithEnv executes a command with a custom timeout and additional environment
// variables appended to the current process environment.
func RunWithEnv(timeout time.Duration, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}
