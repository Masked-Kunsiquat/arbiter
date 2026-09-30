package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// adversaryPatternRules maps an ecosystem (as detected by package stack) to
// a predicate that reports whether a glob pattern's basename shape will be
// discovered by that ecosystem's default test runner (spec §9.C: "must be
// one the project's test runner discovers by default").
//
// Only the basename is checked; the pattern's directory prefix (e.g.
// "**/") is the caller's concern, not the runner's.
var adversaryPatternRules = map[string]func(base string) bool{
	"go": func(base string) bool {
		return strings.HasSuffix(base, "_test.go")
	},
	"python": func(base string) bool {
		return (strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py")) ||
			strings.HasSuffix(base, "_test.py")
	},
	"node": func(base string) bool {
		return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
	},
	"rust": func(base string) bool {
		return strings.HasSuffix(base, "_test.rs") || strings.HasSuffix(base, "_tests.rs") ||
			(strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".rs"))
	},
}

// CheckAdversaryPattern validates that pattern (spec §9.C adversary.pattern)
// matches a basename shape the given ecosystem's default test runner
// discovers. Unknown ecosystems are skipped (return nil): spec §9.C only
// requires the check "for known ecosystems".
func CheckAdversaryPattern(ecosystem, pattern string) error {
	rule, known := adversaryPatternRules[ecosystem]
	if !known {
		return nil
	}

	base := filepath.Base(pattern)
	if !rule(base) {
		return fmt.Errorf("config: adversary.pattern %q won't be discovered by %s's default test runner", pattern, ecosystem)
	}
	return nil
}
