package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/Masked-Kunsiquat/arbiter/internal/stack"
)

// scaffoldDirs are the directories arbiter init creates under .arbiter/
// (spec §9.C CLI command suite, "arbiter init").
var scaffoldDirs = []string{"worktrees", "prds", "ledger"}

// DefaultProtectedPaths are the gate-code paths spec §13 requires always
// route to awaiting_human, regardless of blast radius.
var DefaultProtectedPaths = []string{"internal/gate/**", "internal/ledger/**"}

// Scaffold creates .arbiter/{worktrees,prds,ledger}/ under repoRoot. It is
// idempotent: existing directories are left as-is.
func Scaffold(repoRoot string) (arbiterDir string, err error) {
	arbiterDir = filepath.Join(repoRoot, ".arbiter")
	for _, name := range scaffoldDirs {
		dir := filepath.Join(arbiterDir, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("config: creating %s: %w", dir, err)
		}
	}
	return arbiterDir, nil
}

// FromEcosystem builds a default Config for a detected ecosystem, with
// harness/limits fields set to the spec §9.C reference defaults.
func FromEcosystem(eco stack.Ecosystem) *Config {
	cfg := &Config{
		Harness: Harness{
			Command:         "claude",
			RingleaderModel: "claude-opus-5-5",
			WorkerModel:     "claude-opus-5-5",
			AdversaryModel:  "claude-sonnet-5",
			JudgeModel:      "claude-opus-5-5",
			ShellAllow:      eco.Harness.ShellAllow,
		},
		Limits: Limits{
			MaxAttempts:          6,
			LeaseMinutes:         15,
			LeaseCeilingMinutes:  60,
			JudgeBundleTokens:    60000,
			AttackTimeoutSeconds: 120,
		},
		Test: Test{
			Build:     eco.Test.Build,
			All:       eco.Test.All,
			Files:     eco.Test.Files,
			Reporter:  eco.Test.Reporter,
			JUnitPath: eco.Test.JUnitPath,
		},
		Adversary: Adversary{
			Pattern: eco.Adversary.Pattern,
		},
		Deps: Deps{
			Install:   eco.Deps.Install,
			Lockfiles: eco.Deps.Lockfiles,
			Keep:      eco.Deps.Keep,
		},
		BlastRadius: BlastRadius{
			HighRisk: []string{"**/migrations/**", ".github/**", "**/auth/config*"},
		},
		Protected: Protected{
			Paths: append([]string(nil), DefaultProtectedPaths...),
		},
	}
	return cfg
}

// Write renders cfg as TOML and writes it to path. It refuses to overwrite
// an existing file unless force is true, since config.toml is committed
// (spec §9.C) and a re-run of arbiter init shouldn't silently clobber
// hand-edited settings.
func Write(cfg *Config, path string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("config: %s already exists (use --force to overwrite)", path)
		}
	}

	var buf bytes.Buffer
	buf.WriteString("# Arbiter project configuration (spec §9.C). Committed with the repo.\n\n")
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("config: encoding %s: %w", path, err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("config: writing %s: %w", path, err)
	}
	return nil
}

// gitattributesEntry is the line spec issue #1 requires: *.jsonl (the
// ledger format, §8.B) must have LF line endings even on a Windows
// checkout, since the ledger's hash chain is computed over exact bytes.
const gitattributesEntry = "*.jsonl text eol=lf\n"

// EnsureGitattributes appends gitattributesEntry to repoRoot/.gitattributes,
// creating the file if needed. It's a no-op if the exact line is already
// present, so re-running arbiter init doesn't duplicate the entry.
func EnsureGitattributes(repoRoot string) (retErr error) {
	path := filepath.Join(repoRoot, ".gitattributes")

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("config: reading %s: %w", path, err)
	}
	if bytes.Contains(existing, []byte(gitattributesEntry)) {
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("config: opening %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("config: closing %s: %w", path, cerr)
		}
	}()

	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		if _, err := f.WriteString("\n"); err != nil {
			return fmt.Errorf("config: writing %s: %w", path, err)
		}
	}
	if _, err := f.WriteString(gitattributesEntry); err != nil {
		return fmt.Errorf("config: writing %s: %w", path, err)
	}
	return nil
}
