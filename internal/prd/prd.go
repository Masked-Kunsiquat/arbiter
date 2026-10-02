// Package prd parses PRDs (§2): the strict, line-numbered parser, spec_hash
// canonicalization, lifecycle transitions and amendment checks. It is pure:
// no database, git or other internal imports.
package prd

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/bmatcuk/doublestar/v4"
	"go.yaml.in/yaml/v3"
)

// DefaultMaxBudgetUSD is the budget used when max_budget_usd is absent (§2.C).
const DefaultMaxBudgetUSD = 5.00

// IDRe matches a PRD ID (§2.C).
var IDRe = regexp.MustCompile(`^PRD-\d{3,}$`)

var (
	specHashRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	headingRe   = regexp.MustCompile(`^## (.+)$`)
	numberingRe = regexp.MustCompile(`^\d+(\.\d+)*\.?\s+`)
	invariantRe = regexp.MustCompile(`^- \[(INVARIANT-\d+)\] (.+)$`)
	criterionRe = regexp.MustCompile(`^- \[([ x])\] (AC-\d+): (.+)$`)
	boundaryRe  = regexp.MustCompile("^- `([^`]+)`$")
	driveRe     = regexp.MustCompile(`^[A-Za-z]:`)
	yamlLineRe  = regexp.MustCompile(`line (\d+):\s*`)
)

// Item is an invariant or acceptance criterion.
type Item struct {
	ID   string
	Text string
	Line int
	Done bool // acceptance criterion checkbox is [x]; always false for invariants
}

// Boundary is one allowed-file glob (§2.C).
type Boundary struct {
	Pattern string
	Line    int
}

// Match reports whether path (repo-relative, forward slashes) matches the
// glob. Matching is case-sensitive, as for allow rules (§5.3).
func (b Boundary) Match(path string) bool {
	ok, err := doublestar.Match(b.Pattern, path)
	return err == nil && ok
}

// PRD is a parsed PRD (§2.B).
type PRD struct {
	ID           string
	Title        string
	TargetBranch string
	MaxBudgetUSD float64 // DefaultMaxBudgetUSD when absent
	Status       Status  // "" when absent
	SpecHash     string  // "" when absent
	CreatedBy    string  // "" when absent
	Intent       string  // section body, HTML comments removed, trimmed
	Invariants   []Item
	Boundaries   []Boundary
	Criteria     []Item // acceptance criteria
}

// LineError is a problem at a 1-based line of the (LF-normalized) file; Line 0
// means the problem is not tied to a line.
type LineError struct {
	Line int
	Msg  string
}

func (e LineError) Error() string {
	if e.Line == 0 {
		return e.Msg
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// ParseError holds every problem found, sorted by line (unlined last).
type ParseError struct {
	Errs []LineError
}

func (e *ParseError) Error() string {
	sorted := append([]LineError(nil), e.Errs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i].Line, sorted[j].Line
		if a == 0 || b == 0 {
			return b == 0 && a != 0
		}
		return a < b
	})
	parts := make([]string, len(sorted))
	for i, le := range sorted {
		parts[i] = le.Error()
	}
	return strings.Join(parts, "\n")
}

// Parse strictly parses a PRD (§2.C). The error is always a *ParseError and
// lists every problem found, not just the first.
func Parse(src []byte) (*PRD, error) {
	lines := strings.Split(normalize(src), "\n")
	closeIdx, msg := findClose(lines)
	if msg != "" {
		return nil, &ParseError{Errs: []LineError{{1, msg}}}
	}
	p := &PRD{MaxBudgetUSD: DefaultMaxBudgetUSD}
	var errs []LineError
	parseFrontmatter(p, strings.Join(lines[1:closeIdx], "\n"), &errs)
	parseBody(p, lines, closeIdx+1, &errs)
	if len(errs) > 0 {
		return nil, &ParseError{Errs: errs}
	}
	return p, nil
}

// parseFrontmatter decodes the YAML between the fences. YAML line N is file
// line N+1 (the opening fence is line 1).
func parseFrontmatter(p *PRD, text string, errs *[]LineError) {
	add := func(line int, format string, a ...any) {
		*errs = append(*errs, LineError{line, fmt.Sprintf(format, a...)})
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		msg := strings.TrimPrefix(err.Error(), "yaml: ")
		line := 1
		if m := yamlLineRe.FindStringSubmatchIndex(msg); m != nil {
			n, _ := strconv.Atoi(msg[m[2]:m[3]])
			line = n + 1
			msg = msg[:m[0]] + msg[m[1]:]
		}
		add(line, "invalid frontmatter YAML: %s", strings.TrimSpace(msg))
		return
	}
	if doc.Kind == 0 || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		if doc.Kind != 0 && len(doc.Content) > 0 && doc.Content[0].Kind != yaml.MappingNode {
			add(doc.Content[0].Line+1, "frontmatter must be a mapping of keys to values")
		}
		for _, k := range []string{"id", "title", "target_branch"} {
			add(1, "missing required field: %s", k)
		}
		return
	}

	type field struct {
		node *yaml.Node
		line int
	}
	fields := map[string]field{}
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		line := k.Line + 1
		if k.Kind != yaml.ScalarNode {
			add(line, "frontmatter keys must be plain strings")
			continue
		}
		switch k.Value {
		case "id", "title", "target_branch", "max_budget_usd", "status", "spec_hash", "created_by":
		default:
			add(line, "unknown frontmatter key %q", k.Value)
			continue
		}
		if prev, dup := fields[k.Value]; dup {
			add(line, "duplicate frontmatter key %q (first at line %d)", k.Value, prev.line)
			continue
		}
		if v.Kind != yaml.ScalarNode {
			add(line, "%s must be a scalar value", k.Value)
			continue
		}
		fields[k.Value] = field{v, line}
	}

	str := func(key string) (string, int, bool) {
		f, ok := fields[key]
		if !ok {
			return "", 0, false
		}
		if f.node.ShortTag() == "!!null" {
			return "", f.line, true
		}
		return f.node.Value, f.line, true
	}

	if v, line, ok := str("id"); !ok {
		add(1, "missing required field: id")
	} else if !IDRe.MatchString(v) {
		add(line, "id %q must match %s", v, IDRe)
	} else {
		p.ID = v
	}
	if v, line, ok := str("title"); !ok {
		add(1, "missing required field: title")
	} else if strings.TrimSpace(v) == "" {
		add(line, "title must not be empty")
	} else {
		p.Title = v
	}
	if v, line, ok := str("target_branch"); !ok {
		add(1, "missing required field: target_branch")
	} else if why := badBranch(v); why != "" {
		add(line, "target_branch %q %s", v, why)
	} else {
		p.TargetBranch = v
	}
	if f, ok := fields["max_budget_usd"]; ok {
		var n float64
		tag := f.node.ShortTag()
		switch {
		case tag != "!!int" && tag != "!!float":
			add(f.line, "max_budget_usd must be a number, got %q", f.node.Value)
		case f.node.Decode(&n) != nil || math.IsNaN(n) || math.IsInf(n, 0) || n <= 0:
			add(f.line, "max_budget_usd must be a number greater than 0, got %q", f.node.Value)
		default:
			p.MaxBudgetUSD = n
		}
	}
	if v, line, ok := str("status"); ok {
		if s := Status(v); !s.Valid() {
			add(line, "invalid status %q", v)
		} else {
			p.Status = s
		}
	}
	if v, line, ok := str("spec_hash"); ok {
		if !specHashRe.MatchString(v) {
			add(line, "spec_hash must be 64 lowercase hex digits")
		} else {
			p.SpecHash = v
		}
	}
	if v, line, ok := str("created_by"); ok {
		if v == "" {
			add(line, "created_by must not be empty")
		} else {
			p.CreatedBy = v
		}
	}
}

// badBranch explains why name is not an acceptable target branch, or "".
func badBranch(name string) string {
	switch {
	case name == "":
		return "must not be empty"
	case strings.IndexFunc(name, unicode.IsSpace) >= 0:
		return "must not contain whitespace"
	case strings.Contains(name, ".."):
		return `must not contain ".."`
	case strings.HasPrefix(name, "-"), strings.HasPrefix(name, "/"):
		return `must not start with "-" or "/"`
	case strings.HasSuffix(name, "/"), strings.HasSuffix(name, ".lock"):
		return `must not end with "/" or ".lock"`
	}
	return ""
}

// secLine is one body line of a section. fence is 0 for ordinary lines, 1 for
// a code fence's opening line, 2 for its remaining lines.
type secLine struct {
	no    int
	text  string
	fence int
}

type section struct {
	name  string
	line  int
	lines []secLine
}

var sectionKeywords = []struct{ keyword, name string }{
	{"intent", "Intent"},
	{"invariants", "Invariants"},
	{"file boundaries", "File Boundaries"},
	{"acceptance criteria", "Acceptance Criteria"},
}

// fenceOpen returns the fence character and run length if line opens a code
// fence (up to 3 spaces of indent, then 3+ backticks or tildes).
func fenceOpen(line string) (byte, int) {
	t := strings.TrimLeft(line, " ")
	if len(line)-len(t) > 3 || t == "" || (t[0] != '`' && t[0] != '~') {
		return 0, 0
	}
	n := 0
	for n < len(t) && t[n] == t[0] {
		n++
	}
	if n < 3 {
		return 0, 0
	}
	return t[0], n
}

// fenceCloses reports whether line closes a fence opened with n of ch.
func fenceCloses(line string, ch byte, n int) bool {
	c, k := fenceOpen(line)
	return c == ch && k >= n
}

// parseBody splits lines[from:] into sections and parses the four required ones.
func parseBody(p *PRD, lines []string, from int, errs *[]LineError) {
	add := func(line int, format string, a ...any) {
		*errs = append(*errs, LineError{line, fmt.Sprintf(format, a...)})
	}

	sections := map[string]*section{}
	var cur *section
	var fenceCh byte
	fenceN := 0
	for i := from; i < len(lines); i++ {
		line, no := lines[i], i+1
		if fenceN > 0 {
			if fenceCloses(line, fenceCh, fenceN) {
				fenceN = 0
			}
			if cur != nil {
				cur.lines = append(cur.lines, secLine{no, line, 2})
			}
			continue
		}
		if ch, n := fenceOpen(line); n > 0 {
			fenceCh, fenceN = ch, n
			if cur != nil {
				cur.lines = append(cur.lines, secLine{no, line, 1})
			}
			continue
		}
		if m := headingRe.FindStringSubmatch(line); m != nil {
			cur = nil
			text := strings.TrimSpace(numberingRe.ReplaceAllString(strings.TrimSpace(m[1]), ""))
			lower := strings.ToLower(text)
			var hits []string
			for _, k := range sectionKeywords {
				if strings.Contains(lower, k.keyword) {
					hits = append(hits, k.name)
				}
			}
			switch {
			case len(hits) == 0: // unrecognized section: ignored
			case len(hits) > 1:
				add(no, "heading %q matches more than one section (%s)", text, strings.Join(hits, ", "))
			default:
				if first, dup := sections[hits[0]]; dup {
					add(no, "duplicate section ## %s (first at line %d)", hits[0], first.line)
				} else {
					cur = &section{name: hits[0], line: no}
					sections[hits[0]] = cur
				}
			}
			continue
		}
		if cur != nil {
			cur.lines = append(cur.lines, secLine{no, line, 0})
		}
	}

	for _, k := range sectionKeywords {
		if sections[k.name] == nil {
			add(0, "missing required section: ## %s", k.name)
		}
	}

	if s := sections["Intent"]; s != nil {
		var texts []string
		for _, l := range cleanLines(s.lines) {
			texts = append(texts, l.text)
		}
		p.Intent = strings.TrimSpace(strings.Join(texts, "\n"))
		if p.Intent == "" {
			add(s.line, "Intent section must not be empty")
		}
	}

	if s := sections["Invariants"]; s != nil {
		seen := map[string]int{}
		for _, l := range itemLines(s, errs, `- [INVARIANT-<n>] <text>`) {
			m := invariantRe.FindStringSubmatch(l.text)
			if m == nil {
				add(l.no, "expected %q, got %q", `- [INVARIANT-<n>] <text>`, l.text)
				continue
			}
			if checkID(m[1], l.no, seen, errs) {
				p.Invariants = append(p.Invariants, Item{ID: m[1], Text: strings.TrimSpace(m[2]), Line: l.no})
			}
		}
	}

	if s := sections["File Boundaries"]; s != nil {
		for _, l := range itemLines(s, errs, "- `<glob>`") {
			m := boundaryRe.FindStringSubmatch(l.text)
			if m == nil {
				add(l.no, "expected %q (one backticked glob per bullet), got %q", "- `<glob>`", l.text)
				continue
			}
			if why := badGlob(m[1]); why != "" {
				add(l.no, "boundary %q %s", m[1], why)
				continue
			}
			p.Boundaries = append(p.Boundaries, Boundary{Pattern: m[1], Line: l.no})
		}
		if len(p.Boundaries) == 0 && !hasErrorIn(*errs, s) {
			add(s.line, "File Boundaries section must list at least one boundary")
		}
	}

	if s := sections["Acceptance Criteria"]; s != nil {
		seen := map[string]int{}
		for _, l := range itemLines(s, errs, `- [ ] AC-<n>: <text>`) {
			m := criterionRe.FindStringSubmatch(l.text)
			if m == nil {
				add(l.no, "expected %q, got %q", `- [ ] AC-<n>: <text>`, l.text)
				continue
			}
			if checkID(m[2], l.no, seen, errs) {
				p.Criteria = append(p.Criteria, Item{ID: m[2], Text: strings.TrimSpace(m[3]), Line: l.no, Done: m[1] == "x"})
			}
		}
		if len(p.Criteria) == 0 && !hasErrorIn(*errs, s) {
			add(s.line, "Acceptance Criteria section must list at least one criterion")
		}
	}
}

// hasErrorIn reports whether an error was already recorded inside s, so an
// "at least one" error isn't piled on top of malformed lines.
func hasErrorIn(errs []LineError, s *section) bool {
	if len(s.lines) == 0 {
		return false
	}
	last := s.lines[len(s.lines)-1].no
	for _, e := range errs {
		if e.Line > s.line && e.Line <= last {
			return true
		}
	}
	return false
}

// cleanLines removes HTML comments (which may span lines) from ordinary lines.
// Fenced lines are kept verbatim.
func cleanLines(in []secLine) []secLine {
	out := make([]secLine, 0, len(in))
	inComment := false
	for _, l := range in {
		if l.fence == 0 {
			l.text = stripComments(l.text, &inComment)
		}
		out = append(out, l)
	}
	return out
}

func stripComments(text string, inComment *bool) string {
	var b strings.Builder
	for text != "" {
		if *inComment {
			j := strings.Index(text, "-->")
			if j < 0 {
				break
			}
			text, *inComment = text[j+3:], false
			continue
		}
		j := strings.Index(text, "<!--")
		if j < 0 {
			b.WriteString(text)
			break
		}
		b.WriteString(text[:j])
		text, *inComment = text[j+4:], true
	}
	return b.String()
}

// itemLines returns the non-blank, non-comment lines of an item section with
// trailing spaces/tabs trimmed. A code fence is reported once, at its opening
// line, and its contents skipped.
func itemLines(s *section, errs *[]LineError, form string) []secLine {
	var out []secLine
	for _, l := range cleanLines(s.lines) {
		switch l.fence {
		case 1:
			*errs = append(*errs, LineError{l.no, fmt.Sprintf("expected %q, got a code fence", form)})
			continue
		case 2:
			continue
		}
		l.text = strings.TrimRight(l.text, " \t")
		if strings.TrimSpace(l.text) != "" {
			out = append(out, l)
		}
	}
	return out
}

// checkID rejects leading zeros and duplicates; it records id in seen.
func checkID(id string, line int, seen map[string]int, errs *[]LineError) bool {
	add := func(format string, a ...any) {
		*errs = append(*errs, LineError{line, fmt.Sprintf(format, a...)})
	}
	num := id[strings.LastIndexByte(id, '-')+1:]
	if len(num) > 1 && num[0] == '0' {
		add("%s must not have leading zeros", id)
		return false
	}
	if _, err := strconv.Atoi(num); err != nil {
		add("%s has a number that is too large", id)
		return false
	}
	if first, dup := seen[id]; dup {
		add("duplicate ID %s (first at line %d)", id, first)
		return false
	}
	seen[id] = line
	return true
}

// badGlob explains why pattern is not a valid repo-relative boundary, or "".
func badGlob(pattern string) string {
	switch {
	case strings.Contains(pattern, `\`):
		return "must use forward slashes (no backslashes)"
	case strings.HasPrefix(pattern, "/"), driveRe.MatchString(pattern):
		return "must be repo-relative, not absolute"
	case strings.HasSuffix(pattern, "/"):
		return `must not end with "/"`
	case !doublestar.ValidatePattern(pattern):
		return "is not a valid doublestar glob"
	}
	for _, seg := range strings.Split(pattern, "/") {
		switch seg {
		case "":
			return "must not contain empty path segments"
		case ".", "..":
			return `must not contain "." or ".." segments`
		}
	}
	return ""
}
