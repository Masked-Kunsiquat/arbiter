package gitsign

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const ledgerTrailer = "Arbiter-Ledger: "

var (
	ledgerPathRe = regexp.MustCompile(`^\.arbiter/ledger/(global|PRD-\d{3,})\.jsonl$`)
	// pinRe splits "<path>#seq=<n> sha256:<hex>"; the path is checked separately.
	pinRe = regexp.MustCompile(`^([^#\s]+)#seq=(0|[1-9][0-9]*) sha256:([0-9a-f]{64})$`)
)

// LedgerPin is the value of an Arbiter-Ledger trailer (§8.D): the exported chain's path and its head.
type LedgerPin struct {
	Path string
	Seq  int64
	Hash string
}

// String renders the trailer value, e.g. ".arbiter/ledger/PRD-004.jsonl#seq=148 sha256:<64 hex>".
func (p LedgerPin) String() string {
	return fmt.Sprintf("%s#seq=%d sha256:%s", p.Path, p.Seq, p.Hash)
}

// Chain is the chain name taken from Path: "PRD-004" or "global".
func (p LedgerPin) Chain() string {
	return strings.TrimSuffix(strings.TrimPrefix(p.Path, ".arbiter/ledger/"), ".jsonl")
}

// ParseLedgerPin parses an Arbiter-Ledger trailer value strictly: a canonical ledger path,
// a canonical positive decimal seq, a single space, and a lowercase sha256 hex head.
func ParseLedgerPin(v string) (LedgerPin, error) {
	m := pinRe.FindStringSubmatch(v)
	if m == nil || !ledgerPathRe.MatchString(m[1]) {
		return LedgerPin{}, fmt.Errorf("gitsign: malformed Arbiter-Ledger value %q", v)
	}
	seq, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil || seq < 1 {
		return LedgerPin{}, fmt.Errorf("gitsign: Arbiter-Ledger seq %q must be a positive integer", m[2])
	}
	return LedgerPin{Path: m[1], Seq: seq, Hash: m[3]}, nil
}

// LedgerPins returns every Arbiter-Ledger trailer line of a commit message, in order. A line
// that starts with the trailer key but is malformed is an error (fail closed).
func LedgerPins(msg string) ([]LedgerPin, error) {
	var pins []LedgerPin
	for _, line := range strings.Split(strings.ReplaceAll(msg, "\r\n", "\n"), "\n") {
		v, ok := strings.CutPrefix(line, ledgerTrailer)
		if !ok {
			continue
		}
		p, err := ParseLedgerPin(v)
		if err != nil {
			return nil, err
		}
		pins = append(pins, p)
	}
	return pins, nil
}

// TaskTrailers are the attribution trailers of a task's squash commit (§8.D).
type TaskTrailers struct {
	PRDID        string
	LockVersion  int
	TaskID       string
	SpecRevision int
	// Worker, Adversary and Judge are preformatted trailer values, e.g.
	// "PRD-004/TASK-101/worker.2~7f3a cred:claude-code/claude-opus-5-5 (launched)".
	Worker, Adversary, Judge string
	ApprovedBy               string // "" omits Arbiter-Approved-By (only HITL tasks have it)
	Ledger                   LedgerPin
	CoAuthors                []string // each "Name <email>"
}

// TaskMessage builds a task squash commit message: the subject, a blank line, then the
// §8.D trailers in order. It is used by the integration gate's squash commit (issue #12); the
// supervisor signature covers the trailers, so attribution can't be edited without breaking it.
func TaskMessage(subject string, t TaskTrailers) (string, error) {
	subject = strings.TrimRight(strings.ReplaceAll(subject, "\r\n", "\n"), "\n")
	if strings.TrimSpace(subject) == "" {
		return "", errors.New("gitsign: task message needs a subject")
	}
	for _, line := range strings.Split(subject, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "arbiter-") {
			return "", fmt.Errorf("gitsign: message line %q looks like an Arbiter trailer", line)
		}
	}
	switch {
	case !prdIDRe.MatchString(t.PRDID):
		return "", fmt.Errorf("gitsign: invalid PRD id %q", t.PRDID)
	case t.LockVersion < 1:
		return "", fmt.Errorf("gitsign: lock version %d must be at least 1", t.LockVersion)
	case t.TaskID == "":
		return "", errors.New("gitsign: task message needs a task id")
	case t.SpecRevision < 1:
		return "", fmt.Errorf("gitsign: spec revision %d must be at least 1", t.SpecRevision)
	case t.Worker == "" || t.Adversary == "" || t.Judge == "":
		return "", errors.New("gitsign: task message needs worker, adversary and judge trailers")
	case t.Ledger.Seq < 1:
		return "", fmt.Errorf("gitsign: ledger pin seq %d must be at least 1", t.Ledger.Seq)
	}
	pin := t.Ledger.String()
	if rt, err := ParseLedgerPin(pin); err != nil || rt != t.Ledger {
		return "", fmt.Errorf("gitsign: invalid ledger pin %q", pin)
	}

	trailers := [][2]string{
		{"Arbiter-PRD", fmt.Sprintf("%s@v%d (tag arbiter/prd/%s/v%d)", t.PRDID, t.LockVersion, t.PRDID, t.LockVersion)},
		{"Arbiter-Task", fmt.Sprintf("%s (spec rev %d)", t.TaskID, t.SpecRevision)},
		{"Arbiter-Worker", t.Worker},
		{"Arbiter-Adversary", t.Adversary},
		{"Arbiter-Judge", t.Judge},
	}
	if t.ApprovedBy != "" {
		trailers = append(trailers, [2]string{"Arbiter-Approved-By", t.ApprovedBy})
	}
	trailers = append(trailers, [2]string{"Arbiter-Ledger", pin})
	for _, c := range t.CoAuthors {
		trailers = append(trailers, [2]string{"Co-Authored-By", c})
	}

	var b strings.Builder
	b.WriteString(subject + "\n\n")
	for _, kv := range trailers {
		if strings.ContainsAny(kv[1], "\r\n") {
			return "", fmt.Errorf("gitsign: %s value contains a newline", kv[0])
		}
		b.WriteString(kv[0] + ": " + kv[1] + "\n")
	}
	return b.String(), nil
}
