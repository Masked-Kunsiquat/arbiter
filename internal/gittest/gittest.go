// Package gittest holds helpers for tests that run git.
package gittest

import (
	"os"
	"path/filepath"
	"testing"
)

// Isolate points git at an empty global config and no system config for the
// rest of the test, so the developer's settings (commit signing, hooks,
// default branch, autocrlf) can't change what the test sees or hang it
// waiting on a signing agent (#57). It uses tb.Setenv, so the test can't run
// in parallel.
func Isolate(tb testing.TB) {
	tb.Helper()
	empty := filepath.Join(tb.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		tb.Fatal(err)
	}
	tb.Setenv("GIT_CONFIG_GLOBAL", empty)
	tb.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}
