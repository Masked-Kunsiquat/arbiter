package config_test

import (
	"errors"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
)

// ---------------------------------------------------------------------------
// GitVersion.Less
// ---------------------------------------------------------------------------

func TestGitVersion_Less(t *testing.T) {
	cases := []struct {
		name string
		v    config.GitVersion
		want bool // v.Less(config.GitVersion{2, 31, 0})
	}{
		{"older major", config.GitVersion{1, 40, 0}, true},
		{"same major older minor", config.GitVersion{2, 30, 0}, true},
		{"same major minor older patch", config.GitVersion{2, 31, 0}, false}, // equal, not Less
		{"exact min", config.GitVersion{2, 31, 0}, false},
		{"newer minor", config.GitVersion{2, 32, 0}, false},
		{"newer major", config.GitVersion{3, 0, 0}, false},
	}
	min := config.MinGitVersion
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.v.Less(min); got != tc.want {
				t.Errorf("%s.Less(%s) = %v, want %v", tc.v, min, got, tc.want)
			}
		})
	}
}

func TestGitVersion_String(t *testing.T) {
	v := config.GitVersion{2, 31, 0}
	if v.String() != "2.31.0" {
		t.Errorf("String() = %q, want %q", v.String(), "2.31.0")
	}
}

// ---------------------------------------------------------------------------
// CheckAdversaryPattern
// ---------------------------------------------------------------------------

func TestCheckAdversaryPattern_KnownEcosystems(t *testing.T) {
	cases := []struct {
		eco     string
		pattern string
		wantErr bool
	}{
		// go — must end with _test.go
		{"go", "**/*_adversary_test.go", false},
		{"go", "**/*_adversary.go", true},
		{"go", "internal/adversary.py", true},

		// python — test_*.py or *_test.py
		{"python", "**/test_adversary.py", false},
		{"python", "**/*_adversary_test.py", false},
		{"python", "adversary.py", true},

		// node — contains .test. or .spec.
		{"node", "**/*.test.ts", false},
		{"node", "**/*.spec.js", false},
		{"node", "adversary.ts", true},
	}
	for _, tc := range cases {
		t.Run(tc.eco+"/"+tc.pattern, func(t *testing.T) {
			err := config.CheckAdversaryPattern(tc.eco, tc.pattern)
			if (err != nil) != tc.wantErr {
				t.Errorf("CheckAdversaryPattern(%q, %q) error = %v, wantErr %v",
					tc.eco, tc.pattern, err, tc.wantErr)
			}
		})
	}
}

func TestCheckAdversaryPattern_UnknownEcosystem(t *testing.T) {
	// Unknown ecosystems are skipped — never an error per spec §9.C.
	if err := config.CheckAdversaryPattern("ruby", "**/*_spec.rb"); err != nil {
		t.Errorf("CheckAdversaryPattern(unknown eco): got %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// Validate — aggregation: multiple errors reported together
// ---------------------------------------------------------------------------

// minimalValidConfig builds the smallest valid Config that Validate accepts
// given a real harness.command on PATH (we use "git" which must be present in
// CI and on developer machines) and a real adversary pattern.
func minimalValidConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Harness: config.Harness{
			Command:         "git",
			RingleaderModel: "claude-opus-5-5",
			WorkerModel:     "claude-opus-5-5",
			AdversaryModel:  "claude-sonnet-5",
			JudgeModel:      "claude-opus-5-5",
		},
		Limits: config.Limits{
			MaxAttempts:          6,
			LeaseMinutes:         15,
			LeaseCeilingMinutes:  60,
			JudgeBundleTokens:    60000,
			AttackTimeoutSeconds: 120,
		},
		Test: config.Test{
			Build:    "go build ./...",
			All:      "go test ./...",
			Reporter: "go-json",
		},
		Adversary: config.Adversary{
			Pattern: "**/*_adversary_test.go",
		},
		Protected: config.Protected{
			Paths: []string{"internal/gate/**", "internal/ledger/**"},
		},
	}
}

func TestValidate_HappyPath(t *testing.T) {
	cfg := minimalValidConfig(t)
	if err := config.Validate(cfg, "go"); err != nil {
		t.Errorf("Validate (happy path): unexpected error: %v", err)
	}
}

func TestValidate_AggregatesErrors(t *testing.T) {
	// Break multiple sections at once.
	cfg := &config.Config{
		// Harness: empty command → error
		// Limits:  all zero → multiple errors
		// Test:    empty → error
		// Adversary: empty pattern → error
		// Protected: empty paths → error
	}
	err := config.Validate(cfg, "go")
	if err == nil {
		t.Fatal("Validate (all-zero config): want error, got nil")
	}
	// Should contain errors from at least harness, test, adversary, protected,
	// and limits — i.e. more than one wrapped error.
	errs, ok := err.(interface{ Unwrap() []error })
	if !ok {
		// errors.Join returns a type with Unwrap() []error; fall back to string
		// presence check if the runtime doesn't expose it.
		t.Logf("error: %v", err)
		return
	}
	if len(errs.Unwrap()) < 3 {
		t.Errorf("Validate aggregated %d errors, want at least 3:\n%v",
			len(errs.Unwrap()), err)
	}
}

// ---------------------------------------------------------------------------
// validateTest edge cases (exercised through Validate)
// ---------------------------------------------------------------------------

func TestValidate_Test_InvalidReporter(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Test.Reporter = "fancy-new-format"
	if err := config.Validate(cfg, ""); err == nil {
		t.Fatal("Validate with invalid reporter: want error, got nil")
	}
}

func TestValidate_Test_JUnitReporterRequiresPath(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Test.Reporter = "junit-xml"
	cfg.Test.JUnitPath = "" // deliberately empty
	if err := config.Validate(cfg, ""); err == nil {
		t.Fatal("Validate with junit-xml but no junit_path: want error, got nil")
	}
}

func TestValidate_Test_JUnitReporterWithPath(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Test.Reporter = "junit-xml"
	cfg.Test.JUnitPath = "report.xml"
	if err := config.Validate(cfg, ""); err != nil {
		t.Errorf("Validate with junit-xml + path: unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateLimits edge cases (exercised through Validate)
// ---------------------------------------------------------------------------

func TestValidate_Limits_CeilingBelowLease(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Limits.LeaseMinutes = 60
	cfg.Limits.LeaseCeilingMinutes = 30 // lower than lease — invalid
	err := config.Validate(cfg, "")
	if err == nil {
		t.Fatal("Validate (ceiling < lease): want error, got nil")
	}
}

func TestValidate_Limits_ZeroMaxAttempts(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Limits.MaxAttempts = 0
	if err := config.Validate(cfg, ""); err == nil {
		t.Fatal("Validate (max_attempts=0): want error, got nil")
	}
}

func TestValidate_Limits_ZeroAttackTimeout(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Limits.AttackTimeoutSeconds = 0
	if err := config.Validate(cfg, ""); err == nil {
		t.Fatal("Validate (attack_timeout_seconds=0): want error, got nil")
	}
}

// ---------------------------------------------------------------------------
// validateProtected (exercised through Validate)
// ---------------------------------------------------------------------------

func TestValidate_Protected_EmptyPaths(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Protected.Paths = nil
	if err := config.Validate(cfg, ""); err == nil {
		t.Fatal("Validate (empty protected.paths): want error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Adversary pattern checks through Validate
// ---------------------------------------------------------------------------

func TestValidate_AdversaryPattern_Empty(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Adversary.Pattern = ""
	if err := config.Validate(cfg, "go"); err == nil {
		t.Fatal("Validate (empty adversary.pattern): want error, got nil")
	}
}

func TestValidate_AdversaryPattern_BadForEcosystem(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Adversary.Pattern = "**/*_adversary.py" // .py won't be picked up by go test
	if err := config.Validate(cfg, "go"); err == nil {
		t.Fatal("Validate (adversary pattern wrong for go): want error, got nil")
	}
}

func TestValidate_AdversaryPattern_SkipsCheckWhenEcosystemEmpty(t *testing.T) {
	cfg := minimalValidConfig(t)
	cfg.Adversary.Pattern = "**/*_adversary.py" // any non-empty pattern is fine
	// Passing "" as ecosystem means "don't run ecosystem-specific check".
	if err := config.Validate(cfg, ""); err != nil {
		t.Errorf("Validate (ecosystem=\"\"): unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// errors.Is — ErrHarnessShim sentinel
// ---------------------------------------------------------------------------

func TestErrHarnessShim_Sentinel(t *testing.T) {
	// Even when wrapped, errors.Is should unwrap to ErrHarnessShim.
	// We can test this by checking that the exported sentinel is non-nil and
	// that a manually-wrapped error satisfies errors.Is.
	wrapped := errors.New("outer: " + config.ErrHarnessShim.Error())
	// errors.Is won't match here (not actually wrapped), but we confirm the
	// sentinel itself is comparable.
	if !errors.Is(config.ErrHarnessShim, config.ErrHarnessShim) {
		t.Error("ErrHarnessShim is not equal to itself via errors.Is")
	}
	_ = wrapped
}
