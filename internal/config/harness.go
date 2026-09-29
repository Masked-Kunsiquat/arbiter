package config

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)


// ErrHarnessShim is returned when harness.command resolves to a non-native
// executable on Windows (anything other than a .exe).
var ErrHarnessShim = errors.New("config: harness command does not resolve to a native .exe on Windows")

// ResolveHarnessCommand resolves cmd (spec §9.C harness.command) via PATH
// lookup and, on Windows, rejects any resolved path that is not a .exe.
// It returns the resolved absolute path on success.
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
		if ext != ".exe" {
			return "", fmt.Errorf("%w: %q resolved to %s", ErrHarnessShim, cmd, resolved)
		}
	}

	return resolved, nil
}
