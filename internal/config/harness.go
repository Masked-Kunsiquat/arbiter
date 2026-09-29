package config

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// windowsShimExts are extensions that resolve on Windows PATH but launch
// through cmd.exe rather than exec'ing natively. Spec §9.A requires
// harness.command to resolve to a native .exe: a .cmd/.bat shim means the
// prompt (piped on stdin, §9.A) goes through cmd.exe's 8,191-character
// command-line limit and quoting rules instead of the native process's.
var windowsShimExts = map[string]bool{
	".cmd": true,
	".bat": true,
}

// ErrHarnessShim is returned when harness.command resolves to a .cmd/.bat
// shim on Windows.
var ErrHarnessShim = errors.New("config: harness command resolves to a .cmd/.bat shim, not a native executable")

// ResolveHarnessCommand resolves cmd (spec §9.C harness.command) via PATH
// lookup and, on Windows, rejects a resolved .cmd/.bat shim. It returns the
// resolved absolute path on success.
func ResolveHarnessCommand(cmd string) (string, error) {
	if strings.TrimSpace(cmd) == "" {
		return "", errors.New("config: harness.command is empty")
	}

	resolved, err := exec.LookPath(cmd)
	if err != nil {
		return "", fmt.Errorf("config: harness.command %q: %w", cmd, err)
	}

	if runtime.GOOS == "windows" {
		ext := strings.ToLower(filepath.Ext(resolved))
		if windowsShimExts[ext] {
			return "", fmt.Errorf("%w: %q resolved to %s", ErrHarnessShim, cmd, resolved)
		}
	}

	return resolved, nil
}
