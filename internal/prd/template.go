package prd

import (
	"fmt"
	"strings"
)

// Template returns a draft PRD skeleton (§2.B). It deliberately does not
// parse: each section holds only a format comment, so an unedited draft can't
// be locked. Empty createdBy omits that field.
func Template(id, title, targetBranch, createdBy string) []byte {
	scalar := func(s string) string {
		s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
		v, err := yamlScalar(s)
		if err != nil { // unreachable: newlines were removed
			return `""`
		}
		return v
	}
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("id: " + scalar(id) + "\n")
	b.WriteString("title: " + scalar(title) + "\n")
	b.WriteString("status: draft\n")
	if createdBy != "" {
		b.WriteString("created_by: " + scalar(createdBy) + "\n")
	}
	b.WriteString("target_branch: " + scalar(targetBranch) + "\n")
	fmt.Fprintf(&b, "max_budget_usd: %.2f\n", DefaultMaxBudgetUSD)
	b.WriteString("---\n")
	b.WriteString(`
## 1. Intent & Context
<!-- Why this feature exists and what it must achieve, in plain prose. -->

## 2. Invariants (Non-Negotiable Constraints)
<!-- Zero or more, one per line, numbered upward and never renumbered:
- [INVARIANT-1] No token secrets may ever be written to plaintext logs.
-->

## 3. Allowed File Boundaries (The Sandbox Scope)
<!-- At least one, one backticked repo-relative doublestar glob per line:
- ` + "`src/auth/**`" + `
-->

## 4. Acceptance Criteria & Testable Outcomes
<!-- At least one, one per line, numbered upward and never renumbered:
- [ ] AC-1: POST /auth/refresh returns a new access/refresh pair.
-->
`)
	return []byte(b.String())
}
