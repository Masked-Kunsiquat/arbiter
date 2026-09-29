package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
	"github.com/Masked-Kunsiquat/arbiter/internal/stack"
)

func TestWriteLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	eco := stack.Ecosystem{Name: "go"}
	eco.Adversary.Pattern = "**/*_adversary_test.go"
	eco.Test.All = "go test ./..."
	eco.Test.Build = "go build ./..."
	eco.Test.Reporter = "go-json"
	cfg := config.FromEcosystem(eco)

	path := filepath.Join(dir, "config.toml")
	if err := config.Write(cfg, path, false); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Adversary.Pattern != cfg.Adversary.Pattern {
		t.Errorf("Adversary.Pattern = %q, want %q", got.Adversary.Pattern, cfg.Adversary.Pattern)
	}
	if got.Limits.MaxAttempts != 6 {
		t.Errorf("Limits.MaxAttempts = %d, want 6", got.Limits.MaxAttempts)
	}
	if len(got.Protected.Paths) != 2 {
		t.Errorf("Protected.Paths = %v, want 2 default entries", got.Protected.Paths)
	}
}

func TestWrite_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := config.FromEcosystem(stack.Ecosystem{Name: "go"})

	if err := config.Write(cfg, path, false); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := config.Write(cfg, path, false); err == nil {
		t.Fatal("second Write without force: want error, got nil")
	}
	if err := config.Write(cfg, path, true); err != nil {
		t.Fatalf("Write with force: %v", err)
	}
}

func TestLoad_RejectsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[harness]\ncommand = \"claude\"\nbogus_key = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("Load with unknown key: want error, got nil")
	}
}

func TestLoad_RejectsMalformedTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[harness\ncommand = "), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("Load with malformed TOML: want error, got nil")
	}
}

func TestScaffold_CreatesExpectedDirsAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	arbiterDir, err := config.Scaffold(dir)
	if err != nil {
		t.Fatalf("Scaffold: %v", err)
	}
	for _, name := range []string{"worktrees", "prds", "ledger"} {
		info, err := os.Stat(filepath.Join(arbiterDir, name))
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", name)
		}
	}

	// Re-running must not fail or wipe anything.
	marker := filepath.Join(arbiterDir, "prds", "keep-me.md")
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Scaffold(dir); err != nil {
		t.Fatalf("second Scaffold: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("second Scaffold removed existing file: %v", err)
	}
}

func TestEnsureGitattributes_CreatesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	if err := config.EnsureGitattributes(dir); err != nil {
		t.Fatalf("EnsureGitattributes: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".gitattributes"))
	if err != nil {
		t.Fatalf("reading .gitattributes: %v", err)
	}
	if string(data) != "*.jsonl text eol=lf\n" {
		t.Errorf(".gitattributes = %q", data)
	}

	// Second call must not duplicate the line.
	if err := config.EnsureGitattributes(dir); err != nil {
		t.Fatalf("second EnsureGitattributes: %v", err)
	}
	data2, err := os.ReadFile(filepath.Join(dir, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data2) != string(data) {
		t.Errorf("second call changed file: got %q, want %q", data2, data)
	}
}

func TestEnsureGitattributes_AppendsToExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitattributes")
	if err := os.WriteFile(path, []byte("*.png binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := config.EnsureGitattributes(dir); err != nil {
		t.Fatalf("EnsureGitattributes: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "*.png binary\n*.jsonl text eol=lf\n"
	if string(data) != want {
		t.Errorf(".gitattributes = %q, want %q", data, want)
	}
}
