// Package evidence assembles the Judge's evidence bundle for a verdict
// (spec §9.A "Judge evidence bundle"): the sections in a fixed order, cut
// from the bottom up to fit the cap, and hashed for the ledger's
// bundle_hash.
//
// The core computes every section (blast radius, attack results, diffs);
// this package only orders, truncates and hashes them.
package evidence

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// CharsPerToken is the §9.A size estimate.
	CharsPerToken = 4
	// DefaultCapTokens is limits.judge_bundle_tokens' default (§9.C).
	DefaultCapTokens = 60000
)

// FileDiff is one file's part of a diff.
type FileDiff struct {
	Path  string
	Patch string // the file's unified diff
	Stat  string // the file's `git diff --stat` line, used when Patch is cut
}

// Bundle is the evidence for one verdict, in §9.A order. Items 1–4 (Spec
// through Lessons) are never cut.
type Bundle struct {
	Spec               string // 1. task spec
	Invariants         string // 1. PRD invariants
	AcceptanceCriteria string // 1. PRD acceptance criteria
	BlastRadius        string // 2. computed blast radius and its reasons
	Attacks            string // 3. attack results, claim rulings, disputes, earlier upheld rejections
	Lessons            string // 4. injected lessons with their text (v0.2+); "" omits the section
	WorkerDiff         []FileDiff
	AttackDiff         []FileDiff
	PassingOutput      string // 6. output of passing tests
}

// Report says what Render cut.
type Report struct {
	Chars                int // characters in the rendered text
	CapChars             int // the cap, in characters
	PassingOutputDropped bool
	AttackDiffStat       bool     // attack-test diff replaced by stat lines
	WorkerStatPaths      []string // worker files replaced by stat lines, in the order cut
	OverCap              bool     // still over the cap after every cut: sent anyway (§9.A)
}

// cuts is the truncation state Render steps through.
type cuts struct {
	dropPassing bool
	attackStat  bool
	workerStat  map[string]bool
}

// Render returns the bundle text and what was cut to fit capTokens (≤ 0
// means DefaultCapTokens). Cuts go bottom up: passing-test output first,
// then the attack-test diff becomes stat lines, then the largest worker file
// diffs become stat lines one at a time. If it's still over the cap, it is
// returned anyway with OverCap set. The Judge can open any cut file itself.
func (b Bundle) Render(capTokens int) (string, Report) {
	if capTokens <= 0 {
		capTokens = DefaultCapTokens
	}
	rep := Report{CapChars: capTokens * CharsPerToken}
	c := cuts{workerStat: map[string]bool{}}

	// Largest worker diffs first; ties by path so the result is stable.
	order := slices.Clone(b.WorkerDiff)
	slices.SortStableFunc(order, func(x, y FileDiff) int {
		if d := cmp.Compare(utf8.RuneCountInString(y.Patch), utf8.RuneCountInString(x.Patch)); d != 0 {
			return d
		}
		return cmp.Compare(x.Path, y.Path)
	})

	for {
		text := b.render(c)
		rep.Chars = utf8.RuneCountInString(text)
		if rep.Chars <= rep.CapChars {
			return text, rep
		}
		switch next := b.nextWorkerCut(order, c); {
		case !c.dropPassing && b.PassingOutput != "":
			c.dropPassing, rep.PassingOutputDropped = true, true
		case !c.attackStat && len(b.AttackDiff) > 0:
			c.attackStat, rep.AttackDiffStat = true, true
		case next != "":
			c.workerStat[next] = true
			rep.WorkerStatPaths = append(rep.WorkerStatPaths, next)
		default:
			rep.OverCap = true
			return text, rep
		}
	}
}

// nextWorkerCut returns the largest worker file not yet cut, "" if none.
func (b Bundle) nextWorkerCut(order []FileDiff, c cuts) string {
	for _, f := range order {
		if !c.workerStat[f.Path] {
			return f.Path
		}
	}
	return ""
}

func (b Bundle) render(c cuts) string {
	var s strings.Builder
	section := func(title, body string) {
		if strings.TrimSpace(body) == "" {
			body = "(none)"
		}
		fmt.Fprintf(&s, "## %s\n\n%s\n\n", title, strings.TrimRight(body, "\n"))
	}
	section("Task spec", b.Spec)
	section("PRD invariants", b.Invariants)
	section("PRD acceptance criteria", b.AcceptanceCriteria)
	section("Blast radius", b.BlastRadius)
	section("Attack results", b.Attacks)
	if b.Lessons != "" {
		section("Injected lessons", b.Lessons)
	}

	var worker strings.Builder
	for _, f := range b.WorkerDiff {
		if c.workerStat[f.Path] {
			fmt.Fprintf(&worker, "%s  [diff cut to fit the evidence cap; open %s in the slot]\n", f.Stat, f.Path)
			continue
		}
		worker.WriteString(f.Patch)
		if !strings.HasSuffix(f.Patch, "\n") {
			worker.WriteString("\n")
		}
	}
	section("Worker diff", worker.String())

	var attack strings.Builder
	if c.attackStat {
		attack.WriteString("[diff cut to fit the evidence cap; stat lines only, open the files in the slot]\n")
	}
	for _, f := range b.AttackDiff {
		body := f.Patch
		if c.attackStat {
			body = f.Stat
		}
		attack.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			attack.WriteString("\n")
		}
	}
	section("Attack-test diff", attack.String())

	passing := b.PassingOutput
	if c.dropPassing {
		passing = fmt.Sprintf("[%d characters of passing-test output cut to fit the evidence cap]",
			utf8.RuneCountInString(b.PassingOutput))
	}
	section("Passing test output", passing)
	return strings.TrimRight(s.String(), "\n") + "\n"
}

// Hash is the ledger's bundle_hash: the sha256 of the rendered bundle text
// exactly as sent to the Judge, as lowercase hex.
func Hash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
