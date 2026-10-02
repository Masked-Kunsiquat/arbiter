package main

import (
	"os"
	"testing"
)

// TestMain points HOME (USERPROFILE on Windows) at a temporary directory, so
// commands that host the core generate its supervisor key there and never in
// the developer's ~/.config/arbiter. Tests that need their own home still
// override it with t.Setenv.
func TestMain(m *testing.M) {
	os.Exit(runIsolated(m))
}

func runIsolated(m *testing.M) int {
	home, err := os.MkdirTemp("", "arbiter-cli-home-")
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		return 2
	}
	defer os.RemoveAll(home)
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	return m.Run()
}
