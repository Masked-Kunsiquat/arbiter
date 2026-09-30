package config

import (
	"errors"
	"fmt"
	"strings"
)

// Validate runs full startup validation on cfg (spec §9.C, §13): required
// keys are present, harness.command resolves to a native executable, git is
// new enough, and the adversary pattern is discoverable for the given
// ecosystem ("" skips the ecosystem-specific check, e.g. for a polyglot repo
// where the caller validates once per ecosystem).
//
// It collects every failure instead of stopping at the first, since spec
// §13 asks for a loud, complete failure rather than a fix-one-rerun loop.
func Validate(cfg *Config, ecosystem string) error {
	var errs []error

	if err := validateHarness(&cfg.Harness); err != nil {
		errs = append(errs, err)
	}
	if _, err := CheckGitVersion(); err != nil {
		errs = append(errs, err)
	}
	if err := validateTest(&cfg.Test); err != nil {
		errs = append(errs, err)
	}
	if cfg.Adversary.Pattern == "" {
		errs = append(errs, errors.New("config: adversary.pattern is empty"))
	} else if ecosystem != "" {
		if err := CheckAdversaryPattern(ecosystem, cfg.Adversary.Pattern); err != nil {
			errs = append(errs, err)
		}
	}
	if err := validateProtected(&cfg.Protected); err != nil {
		errs = append(errs, err)
	}
	if err := validateLimits(&cfg.Limits); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func validateHarness(h *Harness) error {
	if _, err := ResolveHarnessCommand(h.Command); err != nil {
		return err
	}
	var missing []string
	if h.RingleaderModel == "" {
		missing = append(missing, "ringleader_model")
	}
	if h.WorkerModel == "" {
		missing = append(missing, "worker_model")
	}
	if h.AdversaryModel == "" {
		missing = append(missing, "adversary_model")
	}
	if h.JudgeModel == "" {
		missing = append(missing, "judge_model")
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: [harness] missing required key(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateTest(t *Test) error {
	var missing []string
	if t.All == "" {
		missing = append(missing, "all")
	}
	if t.Build == "" {
		missing = append(missing, "build")
	}
	if t.Reporter == "" {
		missing = append(missing, "reporter")
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: [test] missing required key(s): %s", strings.Join(missing, ", "))
	}
	switch t.Reporter {
	case "go-json", "junit-xml", "tap":
	default:
		return fmt.Errorf("config: [test] reporter %q is not one of go-json, junit-xml, tap", t.Reporter)
	}
	if t.Reporter == "junit-xml" && t.JUnitPath == "" {
		return errors.New("config: [test] junit_path is required when reporter = \"junit-xml\"")
	}
	return nil
}

// validateProtected enforces spec §13's bootstrap rule: gate code
// (internal/gate/**, internal/ledger/**) must always route to
// awaiting_human regardless of blast radius. v0.1 has no blast-radius
// engine yet (issue #11); the invariant this function can check now is
// that the protected list itself isn't empty, so the paths it names in
// §13 aren't silently un-protected by a stripped-down config.
func validateProtected(p *Protected) error {
	if len(p.Paths) == 0 {
		return errors.New("config: [protected] paths is empty; gate code (spec §13) would not be protected")
	}
	return nil
}

func validateLimits(l *Limits) error {
	var errs []error
	if l.MaxAttempts <= 0 {
		errs = append(errs, errors.New("config: [limits] max_attempts must be > 0"))
	}
	if l.LeaseMinutes <= 0 {
		errs = append(errs, errors.New("config: [limits] lease_minutes must be > 0"))
	}
	if l.LeaseCeilingMinutes < l.LeaseMinutes {
		errs = append(errs, errors.New("config: [limits] lease_ceiling_minutes must be >= lease_minutes"))
	}
	if l.JudgeBundleTokens <= 0 {
		errs = append(errs, errors.New("config: [limits] judge_bundle_tokens must be > 0"))
	}
	if l.AttackTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("config: [limits] attack_timeout_seconds must be > 0"))
	}
	return errors.Join(errs...)
}
