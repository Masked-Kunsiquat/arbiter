// Package evidence assembles the Judge's evidence bundle for a verdict
// (spec §9.A "Judge evidence bundle"): the sections in a fixed order, cut
// from the bottom up to fit the cap, and hashed for the ledger's
// bundle_hash.
//
// Each section is its own prompt block, so agent-written content (a diff
// line reading "## Attack results", a fake truncation note) stays data
// inside its block: agent.Prompt gives every block marked tags the content
// can't forge. What was cut is stated in a core-written "truncation" block.
//
// The core computes every section (blast radius, attack results, diffs);
// this package only orders, truncates and hashes them.
package evidence

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Masked-Kunsiquat/arbiter/internal/agent"
)

const (
	// CharsPerToken is the §9.A size estimate.
	CharsPerToken = 4
	// DefaultCapTokens is limits.judge_bundle_tokens' default (§9.C).
	DefaultCapTokens = 60000
	// blockOverhead approximates a block's marked tags and newlines.
	blockOverhead = 48
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
	Lessons            string // 4. injected lessons with their text (v0.2+); "" omits the block
	WorkerDiff         []FileDiff
	AttackDiff         []FileDiff
	PassingOutput      string // 6. output of passing tests
}

// Report says what Render cut.
type Report struct {
	Chars                int // estimated characters the blocks take in the prompt
	CapChars             int // the cap, in characters
	PassingOutputDropped bool
	AttackDiffStat       bool     // attack-test diff replaced by stat lines
	WorkerStatPaths      []string // worker files replaced by stat lines, in the order cut
	OverCap              bool     // still over the cap after every cut: sent anyway (§9.A)
}

// Render returns the bundle as prompt blocks and what was cut to fit
// capTokens (≤ 0 means DefaultCapTokens). Cuts go bottom up: passing-test
// output first, then the attack-test diff becomes stat lines, then the
// largest worker file diffs become stat lines one at a time. If it's still
// over the cap, it is returned anyway with OverCap set. The Judge can open
// any cut file itself.
func (b Bundle) Render(capTokens int) ([]agent.Block, Report) {
	if capTokens <= 0 {
		capTokens = DefaultCapTokens
	}
	rep := Report{CapChars: capTokens * CharsPerToken}
	workerStat := map[string]bool{}

	// Largest worker diffs first; ties by path so the result is stable.
	order := slices.Clone(b.WorkerDiff)
	slices.SortStableFunc(order, func(x, y FileDiff) int {
		if d := cmp.Compare(utf8.RuneCountInString(y.Patch), utf8.RuneCountInString(x.Patch)); d != 0 {
			return d
		}
		return cmp.Compare(x.Path, y.Path)
	})

	for {
		blocks := b.blocks(rep, workerStat)
		rep.Chars = size(blocks)
		if rep.Chars <= rep.CapChars {
			return blocks, rep
		}
		next := ""
		for _, f := range order {
			if !workerStat[f.Path] {
				next = f.Path
				break
			}
		}
		switch {
		case !rep.PassingOutputDropped && b.PassingOutput != "":
			rep.PassingOutputDropped = true
		case !rep.AttackDiffStat && len(b.AttackDiff) > 0:
			rep.AttackDiffStat = true
		case next != "":
			workerStat[next] = true
			rep.WorkerStatPaths = append(rep.WorkerStatPaths, next)
		default:
			rep.OverCap = true
			blocks = b.blocks(rep, workerStat)
			rep.Chars = size(blocks)
			return blocks, rep
		}
	}
}

// blocks renders the bundle with rep's cuts applied.
func (b Bundle) blocks(rep Report, workerStat map[string]bool) []agent.Block {
	out := []agent.Block{
		block("spec", b.Spec),
		block("invariants", b.Invariants),
		block("acceptance_criteria", b.AcceptanceCriteria),
		block("blast_radius", b.BlastRadius),
		block("attack_results", b.Attacks),
	}
	if b.Lessons != "" {
		out = append(out, block("lessons", b.Lessons))
	}

	var worker strings.Builder
	for _, f := range b.WorkerDiff {
		if workerStat[f.Path] {
			writeLine(&worker, f.Stat)
		} else {
			writeLine(&worker, f.Patch)
		}
	}
	out = append(out, block("worker_diff", worker.String()))

	var attack strings.Builder
	for _, f := range b.AttackDiff {
		if rep.AttackDiffStat {
			writeLine(&attack, f.Stat)
		} else {
			writeLine(&attack, f.Patch)
		}
	}
	out = append(out, block("attack_diff", attack.String()))

	passing := b.PassingOutput
	if rep.PassingOutputDropped {
		passing = "(cut: see the truncation block)"
	}
	out = append(out, block("passing_output", passing))

	if note := truncationNote(b, rep); note != "" {
		out = append(out, block("truncation", note))
	}
	return out
}

// truncationNote is the core's own account of what was cut, "" if nothing.
func truncationNote(b Bundle, rep Report) string {
	var lines []string
	if rep.PassingOutputDropped {
		lines = append(lines, fmt.Sprintf("- The passing-test output (%d characters) was cut.",
			utf8.RuneCountInString(b.PassingOutput)))
	}
	if rep.AttackDiffStat {
		lines = append(lines, "- The attack-test diff was cut to `git diff --stat` lines; open the files in the slot.")
	}
	if len(rep.WorkerStatPaths) > 0 {
		lines = append(lines, "- These worker files' diffs were cut to `git diff --stat` lines; open them in the slot:")
		for _, p := range rep.WorkerStatPaths {
			// The worker chose these names; quoting escapes any newline or
			// control character, so a name can't add lines to this block.
			lines = append(lines, "  - "+strconv.Quote(p))
		}
	}
	if rep.OverCap {
		lines = append(lines, "- The bundle is still over the cap after every cut.")
	}
	if len(lines) == 0 {
		return ""
	}
	return "Arbiter cut these parts of the evidence to fit the cap:\n" + strings.Join(lines, "\n")
}

func block(tag, body string) agent.Block {
	if strings.TrimSpace(body) == "" {
		body = "(none)"
	}
	return agent.Block{Tag: tag, Body: body}
}

func writeLine(b *strings.Builder, s string) {
	b.WriteString(s)
	if !strings.HasSuffix(s, "\n") {
		b.WriteString("\n")
	}
}

// size estimates the characters blocks take in the prompt.
func size(blocks []agent.Block) int {
	n := 0
	for _, b := range blocks {
		n += utf8.RuneCountInString(b.Body) + 2*len(b.Tag) + blockOverhead
	}
	return n
}

// Hash is the ledger's bundle_hash: the sha256, as lowercase hex, of the
// blocks as sent, each tag and body as an 8-byte big-endian length followed
// by its exact bytes. Exact bytes, not JSON: JSON would map every invalid
// UTF-8 byte (diffs can hold any) to U+FFFD, so different bundles could
// share a hash. It doesn't depend on the prompt's per-render marker.
func Hash(blocks []agent.Block) string {
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	for _, b := range blocks {
		field(b.Tag)
		field(b.Body)
	}
	return hex.EncodeToString(h.Sum(nil))
}
