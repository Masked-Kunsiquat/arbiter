package config

import (
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// adversaryPatternRules maps an ecosystem (as detected by package stack) to
// a predicate that reports whether a glob pattern (slash-separated) will be
// discovered by that ecosystem's default test runner (spec §9.C: "must be
// one the project's test runner discovers by default").
//
// Go, Python and Node runners discover by basename anywhere, so only the
// basename is checked there. Cargo discovers by location instead.
var adversaryPatternRules = map[string]func(pattern string) bool{
	"go": func(pattern string) bool {
		return strings.HasSuffix(path.Base(pattern), "_test.go")
	},
	"python": func(pattern string) bool {
		base := path.Base(pattern)
		return (strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py")) ||
			strings.HasSuffix(base, "_test.py")
	},
	"node": func(pattern string) bool {
		base := path.Base(pattern)
		return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
	},
	"rust": rustTestPattern,
}

// rustTestPattern reports whether pattern only matches files Cargo
// auto-discovers as integration tests: tests/<name>.rs, or
// tests/<dir>/main.rs. Any prefix before tests/ is allowed, for workspace
// member crates; "**" from tests/ on is not, since it would also match
// nested files Cargo never builds.
func rustTestPattern(pattern string) bool {
	parts := strings.Split(pattern, "/")
	n := len(parts)
	var tail []string
	switch {
	case n >= 2 && parts[n-2] == "tests" && strings.HasSuffix(parts[n-1], ".rs"):
		tail = parts[n-1:]
	case n >= 3 && parts[n-3] == "tests" && parts[n-1] == "main.rs":
		tail = parts[n-2:]
	default:
		return false
	}
	return !slices.ContainsFunc(tail, func(p string) bool { return strings.Contains(p, "**") })
}

// CheckAdversaryPattern validates that pattern (spec §9.C adversary.pattern)
// only matches files the given ecosystem's default test runner discovers. Unknown ecosystems are skipped (return nil): spec §9.C only
// requires the check "for known ecosystems".
func CheckAdversaryPattern(ecosystem, pattern string) error {
	rule, known := adversaryPatternRules[ecosystem]
	if !known {
		return nil
	}

	if !rule(path.Clean(filepath.ToSlash(pattern))) {
		return fmt.Errorf("config: adversary.pattern %q won't be discovered by %s's default test runner", pattern, ecosystem)
	}
	return nil
}
