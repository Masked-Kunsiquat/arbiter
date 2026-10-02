package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	// Keep init's supervisor key out of the real ~/.config/arbiter, and give
	// it a git signing setup to read the human's key from.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	humanKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpMwJr2xbTU6EeLA/jRDAPyfR2axz6o1zx1Nz0P+fh8"
	gitconfig := filepath.Join(home, "gitconfig")
	cfg := "[gpg]\n\tformat = ssh\n[user]\n\temail = human@example.com\n\tname = Human\n\tsigningkey = " + humanKey + "\n"
	if err := os.WriteFile(gitconfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", gitconfig)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

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

	// allowed_signers has the supervisor line (git + ledger namespaces) and the human's (git only).
	signers, err := os.ReadFile(filepath.Join(dir, ".arbiter", "ledger", "allowed_signers"))
	if err != nil {
		t.Fatalf("read allowed_signers: %v", err)
	}
	if !strings.Contains(string(signers), `namespaces="git,arbiter-ledger" ssh-ed25519 `) {
		t.Errorf("allowed_signers lacks the supervisor line:\n%s", signers)
	}
	if !strings.Contains(string(signers), `human@example.com namespaces="git" `+humanKey) {
		t.Errorf("allowed_signers lacks the human line:\n%s", signers)
	}
	if err := run(ctx, []string{"init", "--force"}); err != nil {
		t.Fatalf("second init: %v", err)
	}
	if again, _ := os.ReadFile(filepath.Join(dir, ".arbiter", "ledger", "allowed_signers")); string(again) != string(signers) {
		t.Errorf("second init changed allowed_signers:\n%s", again)
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
