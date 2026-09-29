// Package config loads and validates Arbiter's project configuration
// (spec §9.C, .arbiter/config.toml).
//
// Startup validation fails loudly (spec §13): a bad harness command, a
// .cmd/.bat shim on Windows, git older than 2.31, or an adversary pattern
// the project's test runner won't discover all return an error instead of
// producing a half-working install.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config mirrors .arbiter/config.toml (spec §9.C). Field names match the
// TOML keys via struct tags rather than Go's default case-insensitive
// matching, so a typo'd key in the file is a silent zero-value instead of a
// startup failure only if BurntSushi/toml's MetadataUndecoded is checked.
type Config struct {
	Harness     Harness     `toml:"harness"`
	Limits      Limits      `toml:"limits"`
	Test        Test        `toml:"test"`
	Adversary   Adversary   `toml:"adversary"`
	Deps        Deps        `toml:"deps"`
	BlastRadius BlastRadius `toml:"blast_radius"`
	Protected   Protected   `toml:"protected"`
}

type Harness struct {
	Command         string `toml:"command"`
	RingleaderModel string `toml:"ringleader_model"`
	WorkerModel     string `toml:"worker_model"`
	AdversaryModel  string `toml:"adversary_model"`
	JudgeModel      string `toml:"judge_model"`
	ShellAllow      []string `toml:"shell_allow"`
}

type Limits struct {
	MaxAttempts         int `toml:"max_attempts"`
	LeaseMinutes        int `toml:"lease_minutes"`
	LeaseCeilingMinutes int `toml:"lease_ceiling_minutes"`
	JudgeBundleTokens   int `toml:"judge_bundle_tokens"`
	AttackTimeoutSeconds int `toml:"attack_timeout_seconds"`
}

type Test struct {
	Build      string `toml:"build"`
	All        string `toml:"all"`
	Files      string `toml:"files"`
	Reporter   string `toml:"reporter"`
	JUnitPath  string `toml:"junit_path"`
}

type Adversary struct {
	Pattern string `toml:"pattern"`
}

type Deps struct {
	Install   string   `toml:"install"`
	Lockfiles []string `toml:"lockfiles"`
	Keep      []string `toml:"keep"`
}

type BlastRadius struct {
	HighRisk []string `toml:"high_risk"`
}

type Protected struct {
	Paths []string `toml:"paths"`
}

// Load reads and parses config.toml at path. It does not validate; call
// Validate separately so callers can distinguish a malformed file (this
// function) from a valid-but-unusable one (Validate).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	var cfg Config
	meta, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("config: %s: unknown key(s): %v", path, undecoded)
	}
	return &cfg, nil
}

// ConfigPath returns the expected location of config.toml under an
// .arbiter directory rooted at arbiterDir.
func ConfigPath(arbiterDir string) string {
	return filepath.Join(arbiterDir, "config.toml")
}
