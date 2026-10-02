// Package audit implements `arbiter audit verify` (spec §8.D "Verification"). It reads git
// only: commit signatures are checked against allowed_signers, every committed ledger chain is
// recomputed and its entries' signatures verified, and each Arbiter-Ledger trailer must pin
// exactly the head of the chain committed alongside it (which is what catches truncation).
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
	"os/exec"
	"regexp"
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
	v := &verifier{g: g, signers: signers}

	out, err = g.run(ctx, "log", "--format=%H", "-E", "--grep=^Arbiter-(PRD|Ledger): ", tip)
	if err != nil {
		return nil, fmt.Errorf("audit: list commits: %w", err)
	}
	rep := &Report{}
	for _, sha := range strings.Fields(string(out)) {
		subject, err := v.commit(ctx, sha)
		rep.Commits = append(rep.Commits, Result{Subject: subject, Err: err})
	}

	out, err = g.run(ctx, "ls-tree", "-z", "--name-only", tip, "--", ledgerDir)
	if err != nil {
		return nil, fmt.Errorf("audit: list ledgers: %w", err)
	}
	for _, path := range strings.Split(string(out), "\x00") {
		if !strings.HasSuffix(path, ".jsonl") {
			continue
		}
		_, _, err := v.chain(ctx, tip, path)
		rep.Ledgers = append(rep.Ledgers, Result{Subject: path, Err: err})
	}
	return rep, nil
}

type verifier struct {
	g       gitRunner
	signers *allowedsigners.File
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
		seq, head, err := v.chain(ctx, sha, pin.Path)
		if err != nil {
			return subject, fmt.Errorf("%s: %w", pin.Path, err)
		}
		if err := ledger.VerifyHead(seq, head, pin.Seq, pin.Hash); err != nil {
			return subject, fmt.Errorf("%s: %w", pin.Path, err)
		}
	}
	return subject, nil
}

// chain verifies the exported chain at path as committed in rev and returns its head. The
// chain name comes from the file name. v1 has one signing key per chain (the supervisor's), so
// the key is taken from the first entry's signature and must be authorized in allowed_signers
// for the arbiter-ledger namespace at that entry's time; ledger.Verify then requires every
// entry to verify under it.
func (v *verifier) chain(ctx context.Context, rev, path string) (int64, string, error) {
	data, err := v.g.run(ctx, "cat-file", "blob", rev+":"+path)
	if err != nil {
		return 0, "", err
	}
	entries, err := ledger.ReadJSONL(bytes.NewReader(data))
	if err != nil {
		return 0, "", err
	}
	if len(entries) == 0 {
		return 0, ledger.ZeroHash, nil
	}
	name := strings.TrimSuffix(path[strings.LastIndex(path, "/")+1:], ".jsonl")
	sig, err := ledger.ParseSSHSig(entries[0].Signature)
	if err != nil {
		return 0, "", fmt.Errorf("ledger: %s seq 1: %w", name, err)
	}
	createdAt, err := time.Parse(ledger.TimeFormat, entries[0].CreatedAt)
	if err != nil {
		return 0, "", fmt.Errorf("ledger: %s seq 1: created_at: %w", name, err)
	}
	if err := v.signers.AuthorizeKey(ledger.Namespace, sig.PublicKey, createdAt); err != nil {
		return 0, "", err
	}
	return ledger.Verify(entries, name, sig.PublicKey)
}

// commitInfo is a commit object split into what verification needs.
type commitInfo struct {
	payload   []byte // the commit as it was signed: the object without its gpgsig header
	sig       string // armored signature, "" if unsigned
	message   string
	subject   string
	email     string // committer email
	committed int64  // committer timestamp, unix seconds
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
