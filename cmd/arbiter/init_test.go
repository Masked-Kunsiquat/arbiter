package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInitAndSeatsIntegration(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// Create fake claude executable on PATH so config.Validate accepts harness.command = "claude".
	binDir := t.TempDir()
	var binName, binContent string
	if runtime.GOOS == "windows" {
		binName, binContent = "claude.exe", "not a real PE, just needs to be a .exe"
	} else {
		binName, binContent = "claude", "#!/bin/sh\nexit 0\n"
	}
	if err := os.WriteFile(filepath.Join(binDir, binName), []byte(binContent), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Create go.mod marker so Detect finds Go ecosystem
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.27\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// 1. Running seats before init must fail with run 'arbiter init' first
	if err := run(ctx, []string{"seats"}); err == nil {
		t.Fatal("seats before init: want error, got nil")
	}

	// 2. Run init
	if err := run(ctx, []string{"init"}); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Verify state.db and config.toml exist
	stateDB := filepath.Join(dir, ".arbiter", "state.db")
	if _, err := os.Stat(stateDB); err != nil {
		t.Errorf("stat state.db: %v", err)
	}
	cfgPath := filepath.Join(dir, ".arbiter", "config.toml")
	if _, err := os.Stat(cfgPath); err != nil {
		t.Errorf("stat config.toml: %v", err)
	}

	// 3. Running seats after init should pass and find no seats
	if err := run(ctx, []string{"seats"}); err != nil {
		t.Fatalf("seats after init: %v", err)
	}

	// 4. Corrupting config.toml should cause seats to fail startup validation
	if err := os.WriteFile(cfgPath, []byte("[harness]\ncommand = \"claude\"\nbad_key = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"seats"}); err == nil {
		t.Fatal("seats with corrupt config: want error, got nil")
	}
}
