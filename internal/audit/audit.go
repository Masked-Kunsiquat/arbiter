// Package audit implements `arbiter audit verify` (spec §8.D "Verification"). It reads git
// only: commit signatures are checked against allowed_signers, every committed ledger chain is
// recomputed and its entries' signatures verified, and each Arbiter-Ledger trailer must pin
// exactly the head of the chain committed alongside it. The tip's ledger files must still
// contain every head pinned anywhere in its history, so a later commit can't truncate, rewrite
// or delete a pinned chain (§8.D: truncating the tail breaks the signature that pinned it).
//
// The verifying keys come from one allowed_signers file: the one committed at the audited tip.
// Never the working tree, and never a per-commit copy (a commit could otherwise authorize its
// own key).
package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/gitsign"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

const (
	signersPath = ".arbiter/" + allowedsigners.RelPath
	ledgerDir   = ".arbiter/ledger/"
)

// Result is the outcome for one commit or ledger file. Subject is "<short sha> <commit
// subject>" for a commit, or the ledger path.
type Result struct {
	Subject string
	Err     error
}

// Report holds one Result per checked commit and per committed ledger file at the tip.
type Report struct {
	Commits, Ledgers []Result
}

// OK reports whether every check passed.
func (r *Report) OK() bool {
	for _, group := range [][]Result{r.Commits, r.Ledgers} {
		for _, res := range group {
			if res.Err != nil {
				return false
			}
		}
	}
	return true
}

// Verify audits rev in the repository at repoDir. The error is for setup failures (bad rev,
// missing allowed_signers, git failing); verification failures land in the Report.
func Verify(ctx context.Context, repoDir, rev string) (*Report, error) {
	g := gitRunner{dir: repoDir}
	// Paths below are repo-relative, so run every command from the top level.
	top, err := g.run(ctx, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("audit: not in a git repository: %w", err)
	}
	g.dir = strings.TrimSpace(string(top))
	out, err := g.run(ctx, "rev-parse", "--verify", "--end-of-options", rev+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("audit: resolve %q: %w", rev, err)
	}
	tip := strings.TrimSpace(string(out))

	data, err := g.run(ctx, "cat-file", "blob", tip+":"+signersPath)
	if err != nil {
		return nil, fmt.Errorf("audit: read %s at %.8s: %w", signersPath, tip, err)
	}
	signers, err := allowedsigners.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("audit: %s at %.8s: %w", signersPath, tip, err)
	}
	v := &verifier{g: g, signers: signers, pins: map[gitsign.LedgerPin]string{}}

	out, err = g.run(ctx, "log", "--format=%H", "-E", "--grep=^Arbiter-(PRD|Ledger): ", tip)
	if err != nil {
		return nil, fmt.Errorf("audit: list commits: %w", err)
	}
	rep := &Report{}
	for _, sha := range strings.Fields(string(out)) {
		subject, err := v.commit(ctx, sha)
		rep.Commits = append(rep.Commits, Result{Subject: subject, Err: err})
	}

	out, err = g.run(ctx, "ls-tree", "-z", "--full-tree", "--name-only", tip, "--", ledgerDir)
	if err != nil {
		return nil, fmt.Errorf("audit: list ledgers: %w", err)
	}
	atTip := map[string]bool{}
	for _, path := range strings.Split(string(out), "\x00") {
		if !strings.HasSuffix(path, ".jsonl") {
			continue
		}
		atTip[path] = true
		entries, err := v.chain(ctx, tip, path)
		if err == nil {
			err = v.checkPins(path, entries)
		}
		rep.Ledgers = append(rep.Ledgers, Result{Subject: path, Err: err})
	}
	// A pinned chain deleted since: nothing at the tip vouches for the pinned entries.
	missing := map[string]string{}
	for pin, by := range v.pins {
		if !atTip[pin.Path] {
			missing[pin.Path] = by
		}
	}
	for _, path := range slices.Sorted(maps.Keys(missing)) {
		rep.Ledgers = append(rep.Ledgers, Result{Subject: path, Err: fmt.Errorf("pinned by %s but missing at the tip", missing[path])})
	}
	return rep, nil
}

// checkPins requires the tip's chain at path to still hold every head pinned for it: at least
// pin.Seq entries, with entry pin.Seq hashing to pin.Hash. The chain links make that entry
// vouch for everything before it.
func (v *verifier) checkPins(path string, entries []ledger.Entry) error {
	for pin, by := range v.pins {
		if pin.Path != path {
			continue
		}
		if int64(len(entries)) < pin.Seq || entries[pin.Seq-1].EntryHash != pin.Hash {
			return fmt.Errorf("does not contain seq %d sha256:%s pinned by %s (truncated or rewritten since)", pin.Seq, pin.Hash, by)
		}
	}
	return nil
}

type verifier struct {
	g       gitRunner
	signers *allowedsigners.File
	pins    map[gitsign.LedgerPin]string // every verified pin -> the commit that pinned it
}

var committerRe = regexp.MustCompile(`^committer .* <([^<>]*)> (\d+) [+-]\d{4}$`)

// commit checks one commit's signature and the ledger pins in its message. The returned
// subject is "<short sha> <subject line>".
func (v *verifier) commit(ctx context.Context, sha string) (string, error) {
	subject := sha[:min(8, len(sha))]
	raw, err := v.g.run(ctx, "cat-file", "commit", sha)
	if err != nil {
		return subject, err
	}
	c, err := parseCommit(raw)
	if err != nil {
		return subject, err
	}
	subject += " " + c.subject
	if c.sig == "" {
		return subject, errors.New("commit is not signed")
	}
	sig, err := ledger.ParseSSHSig(c.sig)
	if err != nil {
		return subject, err
	}
	if sig.Namespace != gitsign.Namespace {
		return subject, fmt.Errorf("signature namespace %q, want %q", sig.Namespace, gitsign.Namespace)
	}
	at := time.Unix(c.committed, 0)
	if v.signers.IsSupervisorKey(sig.PublicKey) {
		// The supervisor signs task squash commits and ledger exports, both single-parent;
		// merges, and above all the final merge (Arbiter-PRD without Arbiter-Task), are the
		// human's approval (§8.C).
		if c.parents > 1 {
			return subject, errors.New("merge commit is signed by Arbiter's supervisor key, not a human")
		}
		if hasTrailer(c.message, "Arbiter-PRD") && !hasTrailer(c.message, "Arbiter-Task") {
			return subject, errors.New("final merge is signed by Arbiter's supervisor key, not a human")
		}
		// The supervisor's principal (arbiter@<host>) is not the committer's email.
		err = v.signers.AuthorizeKey(gitsign.Namespace, sig.PublicKey, at)
	} else {
		err = v.signers.Authorize(c.email, gitsign.Namespace, sig.PublicKey, at)
	}
	if err != nil {
		return subject, err
	}
	if err := ledger.VerifySSHSig(sig.PublicKey, gitsign.Namespace, c.payload, c.sig); err != nil {
		return subject, err
	}
	pins, err := gitsign.LedgerPins(c.message)
	if err != nil {
		return subject, err
	}
	for _, pin := range pins {
		entries, err := v.chain(ctx, sha, pin.Path)
		if err != nil {
			return subject, fmt.Errorf("%s: %w", pin.Path, err)
		}
		seq, head := int64(0), ledger.ZeroHash
		if n := len(entries); n > 0 {
			seq, head = entries[n-1].Seq, entries[n-1].EntryHash
		}
		if err := ledger.VerifyHead(seq, head, pin.Seq, pin.Hash); err != nil {
			return subject, fmt.Errorf("%s: %w", pin.Path, err)
		}
	}
	for _, pin := range pins {
		v.pins[pin] = sha[:min(8, len(sha))]
	}
	return subject, nil
}

// hasTrailer reports whether msg has a line starting "<key>: ".
func hasTrailer(msg, key string) bool {
	for line := range strings.Lines(msg) {
		if strings.HasPrefix(line, key+": ") {
			return true
		}
	}
	return false
}

// chain verifies the exported chain at path as committed in rev and returns its entries. The
// chain name comes from the file name. v1 has one signing key per chain (the supervisor's), so
// the key is taken from the first entry's signature; it must be marked as Arbiter's in
// allowed_signers (a human key on a line without namespaces= would otherwise pass) and
// authorized for the arbiter-ledger namespace at that entry's time. ledger.Verify then requires
// every entry to verify under it.
func (v *verifier) chain(ctx context.Context, rev, path string) ([]ledger.Entry, error) {
	data, err := v.g.run(ctx, "cat-file", "blob", rev+":"+path)
	if err != nil {
		return nil, err
	}
	entries, err := ledger.ReadJSONL(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	name := strings.TrimSuffix(path[strings.LastIndex(path, "/")+1:], ".jsonl")
	sig, err := ledger.ParseSSHSig(entries[0].Signature)
	if err != nil {
		return nil, fmt.Errorf("ledger: %s seq 1: %w", name, err)
	}
	createdAt, err := time.Parse(ledger.TimeFormat, entries[0].CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("ledger: %s seq 1: created_at: %w", name, err)
	}
	if !v.signers.IsSupervisorKey(sig.PublicKey) {
		return nil, fmt.Errorf("ledger: %s is signed by a key allowed_signers doesn't mark as Arbiter's", name)
	}
	if err := v.signers.AuthorizeKey(ledger.Namespace, sig.PublicKey, createdAt); err != nil {
		return nil, err
	}
	if _, _, err := ledger.Verify(entries, name, sig.PublicKey); err != nil {
		return nil, err
	}
	return entries, nil
}

// commitInfo is a commit object split into what verification needs.
type commitInfo struct {
	payload   []byte // the commit as it was signed: the object without its gpgsig header
	sig       string // armored signature, "" if unsigned
	message   string
	subject   string
	email     string // committer email
	committed int64  // committer timestamp, unix seconds
	parents   int
}

// parseCommit splits a raw commit object, rebuilding the signed payload exactly (the inverse of
// gitsign.AttachCommitSig): the gpgsig or gpgsig-sha256 header and its space-indented
// continuation lines are removed.
func parseCommit(raw []byte) (*commitInfo, error) {
	end := bytes.Index(raw, []byte("\n\n"))
	if end < 0 {
		return nil, errors.New("malformed commit object: no header/message separator")
	}
	c := &commitInfo{message: string(raw[end+2:])}
	c.subject, _, _ = strings.Cut(c.message, "\n")

	var kept, sig []string
	inSig, sigs := false, 0
	for _, line := range strings.Split(string(raw[:end]), "\n") {
		switch {
		case inSig && strings.HasPrefix(line, " "):
			sig = append(sig, line[1:])
			continue
		case strings.HasPrefix(line, "gpgsig ") || strings.HasPrefix(line, "gpgsig-sha256 "):
			_, first, _ := strings.Cut(line, " ")
			sig = append(sig, first)
			inSig = true
			sigs++
			continue
		}
		inSig = false
		kept = append(kept, line)
		if strings.HasPrefix(line, "parent ") {
			c.parents++
		}
		if m := committerRe.FindStringSubmatch(line); m != nil {
			c.email = m[1]
			c.committed, _ = strconv.ParseInt(m[2], 10, 64)
		}
	}
	if sigs > 1 {
		return nil, errors.New("commit has more than one signature header")
	}
	if c.email == "" {
		return nil, errors.New("malformed commit object: no committer")
	}
	c.sig = strings.Join(sig, "\n")
	c.payload = []byte(strings.Join(kept, "\n") + "\n\n" + c.message)
	return c, nil
}

type gitRunner struct{ dir string }

func (g gitRunner) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-c", "core.fsmonitor=false"}, args...)...)
	cmd.Dir = g.dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
