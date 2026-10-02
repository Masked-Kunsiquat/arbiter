package prd

import (
	"errors"
	"strings"
	"testing"
)

const testHash = "8f4b2c19e782a10d8e28f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4"

// specExample is the §2.B example PRD with a valid spec_hash.
const specExample = `---
id: PRD-004
title: JWT Refresh Token Rotation & Session Revocation
status: locked
created_by: human:Masked-Kunsiquat
spec_hash: ` + testHash + `
target_branch: feature/auth-rotation
max_budget_usd: 5.00
---

## 1. Intent & Context
Replace static long-lived JWTs with rotating refresh tokens backed by local SQLite storage.
Mitigate replay attacks by revoking the entire token family if a reused token is detected.

## 2. Invariants (Non-Negotiable Constraints)
<!-- Adversary and Judge enforce these across ALL child tasks -->
- [INVARIANT-1] No token secrets may ever be written to plaintext logs.
- [INVARIANT-2] Database queries must use parameterized statements; zero raw string interpolation.
- [INVARIANT-3] Breaking API changes to ` + "`/api/v1/auth/login`" + ` are strictly forbidden.

## 3. Allowed File Boundaries (The Sandbox Scope)
<!-- Enforced by the submit-time diff check and task reservations -->
- ` + "`src/auth/**`" + `
- ` + "`src/db/migrations/**`" + `
- ` + "`tests/auth/**`" + `

## 4. Acceptance Criteria & Testable Outcomes
- [ ] AC-1: POST ` + "`/auth/refresh`" + ` returns a new access/refresh pair and invalidates the old token.
- [x] AC-2: Reusing an invalidated token terminates all active sessions for that user ID.
- [ ] AC-3: Integration tests pass in both native and mock runtimes.
`

// minimal returns a valid PRD with the given section bodies.
func minimal(intent, inv, bound, ac string) string {
	return "---\nid: PRD-001\ntitle: T\ntarget_branch: feat/x\n---\n" +
		"## Intent\n" + intent + "\n## Invariants\n" + inv + "\n## File Boundaries\n" + bound +
		"\n## Acceptance Criteria\n" + ac + "\n"
}

const (
	okIntent = "Do it."
	okInv    = "- [INVARIANT-1] Be safe."
	okBound  = "- `src/**`"
	okAC     = "- [ ] AC-1: Works."
)

func parseErrs(t *testing.T, src string) []LineError {
	t.Helper()
	_, err := Parse([]byte(src))
	if err == nil {
		return nil
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("error is %T, want *ParseError", err)
	}
	return pe.Errs
}

func hasErr(errs []LineError, line int, substr string) bool {
	for _, e := range errs {
		if e.Line == line && strings.Contains(e.Msg, substr) {
			return true
		}
	}
	return false
}

func TestParseSpecExample(t *testing.T) {
	p, err := Parse([]byte(specExample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.ID != "PRD-004" || p.Title != "JWT Refresh Token Rotation & Session Revocation" ||
		p.TargetBranch != "feature/auth-rotation" || p.MaxBudgetUSD != 5.00 ||
		p.Status != StatusLocked || p.SpecHash != testHash || p.CreatedBy != "human:Masked-Kunsiquat" {
		t.Errorf("frontmatter wrong: %+v", p)
	}
	if !strings.HasPrefix(p.Intent, "Replace static") || !strings.HasSuffix(p.Intent, "detected.") {
		t.Errorf("Intent = %q", p.Intent)
	}
	if len(p.Invariants) != 3 || p.Invariants[2].ID != "INVARIANT-3" || p.Invariants[0].Done {
		t.Errorf("Invariants = %+v", p.Invariants)
	}
	if len(p.Boundaries) != 3 || p.Boundaries[1].Pattern != "src/db/migrations/**" {
		t.Errorf("Boundaries = %+v", p.Boundaries)
	}
	if len(p.Criteria) != 3 || p.Criteria[0].Done || !p.Criteria[1].Done || p.Criteria[2].ID != "AC-3" {
		t.Errorf("Criteria = %+v", p.Criteria)
	}
	if p.Invariants[0].Line != 17 || p.Boundaries[0].Line != 23 {
		t.Errorf("lines = %d, %d", p.Invariants[0].Line, p.Boundaries[0].Line)
	}
}

func TestParseDefaultsAndCRLF(t *testing.T) {
	src := minimal(okIntent, okInv, okBound, okAC)
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxBudgetUSD != DefaultMaxBudgetUSD || p.Status != "" || p.SpecHash != "" || p.CreatedBy != "" {
		t.Errorf("defaults wrong: %+v", p)
	}
	for name, v := range map[string]string{
		"crlf": strings.ReplaceAll(src, "\n", "\r\n"),
		"cr":   strings.ReplaceAll(src, "\n", "\r"),
		"bom":  "\ufeff" + src,
	} {
		q, err := Parse([]byte(v))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if q.Boundaries[0].Line != p.Boundaries[0].Line {
			t.Errorf("%s: line %d, want %d", name, q.Boundaries[0].Line, p.Boundaries[0].Line)
		}
	}
}

func TestParseHeadings(t *testing.T) {
	src := "---\nid: PRD-001\ntitle: T\ntarget_branch: b\n---\n" +
		"# Title\n## intent\nWhy.\n### Sub heading\n\n# Another\n" +
		"## 2.1. INVARIANTS and more\n" + okInv + "\n" +
		"## Notes\nanything - at all\n- [bogus\n" +
		"## 3 File Boundaries\n" + okBound + "\n" +
		"## 4.Acceptance Criteria\n" + okAC + "\n"
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Intent != "Why.\n### Sub heading\n\n# Another" {
		t.Errorf("Intent = %q", p.Intent)
	}
}

func TestParseFenceHidesHeadings(t *testing.T) {
	src := minimal("Text\n```md\n## Invariants\n```\n~~~~\n## Intent\n~~~\n## Invariants\n~~~~\nmore", okInv, okBound, okAC)
	// The second "## Invariants" is a real heading only if fences were ignored.
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(p.Intent, "## Invariants") || !strings.Contains(p.Intent, "more") {
		t.Errorf("Intent = %q", p.Intent)
	}
	// A fence in an item section is an error reported once.
	errs := parseErrs(t, minimal(okIntent, "```\n- [INVARIANT-1] x\n```", okBound, okAC))
	if len(errs) != 1 || errs[0].Line != 9 {
		t.Errorf("errs = %v", errs)
	}
}

func TestParseComments(t *testing.T) {
	src := minimal("<!-- c -->\nWhy <!-- x --> now.\n<!--\nmulti\n-->", "<!-- a\nb -->\n"+okInv+" <!-- t -->", okBound, okAC)
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Intent != "Why  now." || p.Invariants[0].Text != "Be safe." {
		t.Errorf("Intent = %q, inv = %+v", p.Intent, p.Invariants)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		line int
		msg  string
	}{
		{"no frontmatter", "## Intent\n", 1, "missing frontmatter"},
		{"unterminated", "---\nid: PRD-001\n", 1, "unterminated frontmatter"},
		{"fence with trailing space", "--- \nid: x\n---\n", 1, "missing frontmatter"},
		{"unknown key", "---\nid: PRD-001\nbogus: 1\ntitle: T\ntarget_branch: b\n---\n", 3, `unknown frontmatter key "bogus"`},
		{"duplicate key", "---\nid: PRD-001\ntitle: T\ntitle: U\ntarget_branch: b\n---\n", 4, "duplicate frontmatter key"},
		{"non-scalar", "---\nid: PRD-001\ntitle: [a]\ntarget_branch: b\n---\n", 3, "must be a scalar"},
		{"yaml syntax", "---\nid: PRD-001\ntitle: [a\ntarget_branch: b\n---\n", 2, "invalid frontmatter YAML"},
		{"not a mapping", "---\n- a\n---\n", 2, "must be a mapping"},
		{"bad id", "---\nid: PRD-4\ntitle: T\ntarget_branch: b\n---\n", 2, "must match"},
		{"empty title", "---\nid: PRD-001\ntitle: '  '\ntarget_branch: b\n---\n", 3, "title must not be empty"},
		{"missing target", "---\nid: PRD-001\ntitle: T\n---\n", 1, "missing required field: target_branch"},
		{"branch space", "---\nid: PRD-001\ntitle: T\ntarget_branch: 'a b'\n---\n", 4, "whitespace"},
		{"branch dotdot", "---\nid: PRD-001\ntitle: T\ntarget_branch: a..b\n---\n", 4, ".."},
		{"branch dash", "---\nid: PRD-001\ntitle: T\ntarget_branch: -a\n---\n", 4, "start"},
		{"branch slash", "---\nid: PRD-001\ntitle: T\ntarget_branch: /a\n---\n", 4, "start"},
		{"branch trailing slash", "---\nid: PRD-001\ntitle: T\ntarget_branch: a/\n---\n", 4, "end"},
		{"branch lock", "---\nid: PRD-001\ntitle: T\ntarget_branch: a.lock\n---\n", 4, "end"},
		{"budget zero", "---\nid: PRD-001\ntitle: T\ntarget_branch: b\nmax_budget_usd: 0\n---\n", 5, "greater than 0"},
		{"budget negative", "---\nid: PRD-001\ntitle: T\ntarget_branch: b\nmax_budget_usd: -1.5\n---\n", 5, "greater than 0"},
		{"budget inf", "---\nid: PRD-001\ntitle: T\ntarget_branch: b\nmax_budget_usd: .inf\n---\n", 5, "greater than 0"},
		{"budget string", "---\nid: PRD-001\ntitle: T\ntarget_branch: b\nmax_budget_usd: '5'\n---\n", 5, "must be a number"},
		{"bad status", "---\nid: PRD-001\ntitle: T\ntarget_branch: b\nstatus: done\n---\n", 5, "invalid status"},
		{"bad hash", "---\nid: PRD-001\ntitle: T\ntarget_branch: b\nspec_hash: ABC\n---\n", 5, "64 lowercase hex"},
		{"empty created_by", "---\nid: PRD-001\ntitle: T\ntarget_branch: b\ncreated_by:\n---\n", 5, "created_by must not be empty"},
		{"empty intent", minimal(" ", okInv, okBound, okAC), 6, "Intent section must not be empty"},
		{"comment-only intent", minimal("<!-- x -->", okInv, okBound, okAC), 6, "must not be empty"},
		{"prose in invariants", minimal(okIntent, "hello", okBound, okAC), 9, `expected "- [INVARIANT-<n>] <text>"`},
		{"nested bullet", minimal(okIntent, okInv+"\n  - [INVARIANT-2] x", okBound, okAC), 10, "expected"},
		{"sub heading in items", minimal(okIntent, okInv+"\n### More", okBound, okAC), 10, "expected"},
		{"leading zero", minimal(okIntent, "- [INVARIANT-01] x", okBound, okAC), 9, "leading zeros"},
		{"duplicate invariant", minimal(okIntent, okInv+"\n"+okInv, okBound, okAC), 10, "first at line 9"},
		{"duplicate AC", minimal(okIntent, okInv, okBound, okAC+"\n"+okAC), 14, "first at line 13"},
		{"ac wrong form", minimal(okIntent, okInv, okBound, "- [ ] AC-1 no colon"), 13, "expected"},
		{"ac bad checkbox", minimal(okIntent, okInv, okBound, "- [X] AC-1: x"), 13, "expected"},
		{"no ACs", minimal(okIntent, okInv, okBound, ""), 12, "at least one criterion"},
		{"no boundaries", minimal(okIntent, okInv, "", okAC), 10, "at least one boundary"},
		{"boundary two globs", minimal(okIntent, okInv, "- `a` `b`", okAC), 11, "expected"},
		{"boundary trailing text", minimal(okIntent, okInv, "- `a` extra", okAC), 11, "expected"},
		{"boundary no ticks", minimal(okIntent, okInv, "- src/**", okAC), 11, "expected"},
		{"boundary backslash", minimal(okIntent, okInv, "- `src\\a`", okAC), 11, "forward slashes"},
		{"boundary absolute", minimal(okIntent, okInv, "- `/src/a`", okAC), 11, "absolute"},
		{"boundary drive", minimal(okIntent, okInv, "- `C:/src`", okAC), 11, "absolute"},
		{"boundary dotdot", minimal(okIntent, okInv, "- `../a`", okAC), 11, `".."`},
		{"boundary dot", minimal(okIntent, okInv, "- `./a`", okAC), 11, `"."`},
		{"boundary empty seg", minimal(okIntent, okInv, "- `a//b`", okAC), 11, "empty path"},
		{"boundary trailing slash", minimal(okIntent, okInv, "- `a/`", okAC), 11, `"/"`},
		{"boundary invalid glob", minimal(okIntent, okInv, "- `a[`", okAC), 11, "not a valid"},
		{"duplicate section", minimal(okIntent, okInv, okBound, okAC) + "## Intent\nagain\n", 14, "first at line 6"},
		{"ambiguous heading", minimal(okIntent, okInv, okBound, okAC) + "## Intent and Invariants\n", 14, "more than one"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := parseErrs(t, tc.src)
			if !hasErr(errs, tc.line, tc.msg) {
				t.Errorf("want line %d containing %q, got %v", tc.line, tc.msg, errs)
			}
		})
	}
}

func TestParseMissingSectionsAndMultipleErrors(t *testing.T) {
	src := "---\nid: nope\nbogus: 1\ntitle: T\ntarget_branch: b\n---\n## Intent\nWhy\n## Invariants\n- [INVARIANT-1] ok\nprose\n- [INVARIANT-1] dup\n"
	_, err := Parse([]byte(src))
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	for _, w := range []struct {
		line int
		msg  string
	}{
		{2, "id"},
		{3, "bogus"},
		{11, "expected"},
		{12, "first at line 10"},
		{0, "missing required section: ## File Boundaries"},
		{0, "missing required section: ## Acceptance Criteria"},
	} {
		if !hasErr(pe.Errs, w.line, w.msg) {
			t.Errorf("missing error line %d %q in %v", w.line, w.msg, pe.Errs)
		}
	}
	// Rendered sorted by line with unlined errors last.
	lines := strings.Split(pe.Error(), "\n")
	if !strings.HasPrefix(lines[0], "line 2: ") || !strings.HasPrefix(lines[len(lines)-1], "missing required section") {
		t.Errorf("Error() =\n%s", pe.Error())
	}
}

func TestLineError(t *testing.T) {
	if got := (LineError{3, "x"}).Error(); got != "line 3: x" {
		t.Errorf("got %q", got)
	}
	if got := (LineError{0, "x"}).Error(); got != "x" {
		t.Errorf("got %q", got)
	}
}

func TestBoundaryMatch(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"src/auth/**", "src/auth/a/b.go", true},
		{"src/auth/**", "src/auth", true},
		{"src/*", "src/a/b.go", false},
		{"src/*", "src/a.go", true},
		{"src/Auth/**", "src/auth/a.go", false},
		{"**/*.md", "docs/x/y.md", true},
		{"a[", "a[", false},
	}
	for _, tc := range tests {
		if got := (Boundary{Pattern: tc.pattern}).Match(tc.path); got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}
