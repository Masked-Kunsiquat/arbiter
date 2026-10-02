package prd

import (
	"strings"
	"testing"
)

func TestTemplateDoesNotParseUntilFilled(t *testing.T) {
	src := Template("PRD-007", "My: feature", "feature/x", "human:me")
	errs := parseErrs(t, string(src))
	if len(errs) != 3 {
		t.Fatalf("errs = %v, want exactly empty intent, no boundaries, no ACs", errs)
	}
	for _, w := range []string{"Intent section must not be empty", "at least one boundary", "at least one criterion"} {
		found := false
		for _, e := range errs {
			found = found || strings.Contains(e.Msg, w)
		}
		if !found {
			t.Errorf("missing error %q in %v", w, errs)
		}
	}

	filled := string(src)
	for heading, item := range map[string]string{
		"## 1. Intent & Context\n":                            "Why.\n",
		"## 3. Allowed File Boundaries (The Sandbox Scope)\n": "- `src/**`\n",
		"## 4. Acceptance Criteria & Testable Outcomes\n":     "- [ ] AC-1: Works.\n",
	} {
		filled = strings.Replace(filled, heading, heading+item, 1)
	}
	p, err := Parse([]byte(filled))
	if err != nil {
		t.Fatalf("filled template: %v", err)
	}
	if p.ID != "PRD-007" || p.Title != "My: feature" || p.TargetBranch != "feature/x" ||
		p.Status != StatusDraft || p.CreatedBy != "human:me" || p.MaxBudgetUSD != 5.00 ||
		len(p.Invariants) != 0 || len(p.Boundaries) != 1 || len(p.Criteria) != 1 {
		t.Errorf("parsed %+v", p)
	}
}

func TestTemplateOptionalCreatedByAndNewlines(t *testing.T) {
	src := string(Template("PRD-001", "a\nb", "x", ""))
	if strings.Contains(src, "created_by") {
		t.Error("created_by should be omitted when empty")
	}
	if !strings.Contains(src, "title: a b\n") {
		t.Errorf("title not flattened:\n%s", src)
	}
}
