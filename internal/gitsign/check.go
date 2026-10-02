package gitsign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// The checks below run in the CLI, before it asks the human to sign. Signing
// client-side only protects against a compromised or remote core (§8.A, §10)
// if the client knows what it is signing, so the CLI re-derives every field
// that matters from its own checkout and refuses a payload that differs.

var identTailRe = regexp.MustCompile(`^\d+ [+-]\d{4}$`)

// splitObject returns a payload's header lines and message.
func splitObject(payload []byte) ([]string, string, error) {
	head, msg, ok := bytes.Cut(payload, []byte("\n\n"))
	if !ok {
		return nil, "", errors.New("gitsign: payload has no header/message separator")
	}
	return strings.Split(string(head), "\n"), string(msg), nil
}

// expectHeaders checks lines against want exactly, in order: each want entry
// is "<key> <value>", or "<key> " + ident prefix for ident lines (identKeys).
func expectHeaders(lines []string, want []string, identKeys map[string]bool) error {
	if len(lines) != len(want) {
		return fmt.Errorf("gitsign: core's object has %d header lines, want %d:\n%s", len(lines), len(want), strings.Join(lines, "\n"))
	}
	for i, w := range want {
		key, _, _ := strings.Cut(w, " ")
		if identKeys[key] {
			tail, ok := strings.CutPrefix(lines[i], w)
			if !ok || !identTailRe.MatchString(tail) {
				return fmt.Errorf("gitsign: core's object has %q, want %q<time> <zone>", lines[i], w)
			}
			continue
		}
		if lines[i] != w {
			return fmt.Errorf("gitsign: core's object has %q, want %q", lines[i], w)
		}
	}
	return nil
}

func identPrefix(i Ident) string { return fmt.Sprintf("%s <%s> ", i.Name, i.Email) }

// CheckLock verifies, client-side, that prep is the lock tag req asked for:
// it tags the commit req names in this checkout, has the expected name and
// version, and names the signer as tagger.
func CheckLock(ctx context.Context, arbiterDir string, req LockRequest, prep *Prepared) error {
	local := NewService(arbiterDir)
	rev := req.Commit
	if rev == "" {
		rev = "HEAD"
	}
	commit, err := local.revParse(ctx, rev+"^{commit}")
	if err != nil {
		return err
	}
	lines, _, err := splitObject(prep.Payload)
	if err != nil {
		return err
	}
	if len(lines) < 3 {
		return errors.New("gitsign: core's tag object is too short")
	}
	tag := strings.TrimPrefix(lines[2], "tag ")
	prefix := "arbiter/prd/" + req.PRDID + "/v"
	n, err := strconv.Atoi(strings.TrimPrefix(tag, prefix))
	switch {
	case !strings.HasPrefix(tag, prefix) || err != nil || strconv.Itoa(n) != strings.TrimPrefix(tag, prefix):
		return fmt.Errorf("gitsign: core's tag is %q, want %s<n>", tag, prefix)
	case !req.Amend && n != 1, req.Amend && n < 2:
		return fmt.Errorf("gitsign: core's tag is %q, which is the wrong version for a lock (amend=%v)", tag, req.Amend)
	}
	if prep.Ref != "refs/tags/"+tag {
		return fmt.Errorf("gitsign: core would write ref %q for tag %q", prep.Ref, tag)
	}
	return expectHeaders(lines, []string{
		"object " + commit,
		"type commit",
		"tag " + tag,
		"tagger " + identPrefix(req.Signer.Ident),
	}, map[string]bool{"tagger": true})
}

// CheckMerge verifies, client-side, that prep is the merge req asked for:
// parents are the target and source heads in this checkout, the tree is the
// one this checkout's `git merge-tree` produces, the signer is author and
// committer, and the message (with its Arbiter-PRD and Arbiter-Ledger
// trailers) is the one this checkout builds.
func CheckMerge(ctx context.Context, arbiterDir string, req MergeRequest, prep *Prepared) error {
	local := NewService(arbiterDir)
	targetRef := "refs/heads/" + req.Target
	if prep.Ref != targetRef {
		return fmt.Errorf("gitsign: core would move %q, want %q", prep.Ref, targetRef)
	}
	target, err := local.revParse(ctx, targetRef+"^{commit}")
	if err != nil {
		return err
	}
	source, err := local.revParse(ctx, req.Source+"^{commit}")
	if err != nil {
		return err
	}
	tree, err := local.mergeTree(ctx, target, source)
	if err != nil {
		return fmt.Errorf("gitsign: checking the core's merge locally: %w", err)
	}
	lines, msg, err := splitObject(prep.Payload)
	if err != nil {
		return err
	}
	// The trailers pin the lock version and the ledger head (§8.D), so the
	// whole message must be what this checkout produces.
	want, _, err := local.mergeMessage(ctx, req, source)
	if err != nil {
		return fmt.Errorf("gitsign: checking the core's merge message locally: %w", err)
	}
	if msg != message(want) {
		return fmt.Errorf("gitsign: core's merge message differs from this checkout's:\n%s\n--- want ---\n%s", msg, message(want))
	}
	return expectHeaders(lines, []string{
		"tree " + tree,
		"parent " + target,
		"parent " + source,
		"author " + identPrefix(req.Signer.Ident),
		"committer " + identPrefix(req.Signer.Ident),
	}, map[string]bool{"author": true, "committer": true})
}

// MergeCheck is CheckMerge plus a check on the core's ledger export. The
// core may move the source branch during PrepareMerge by committing the
// ledger export on top of it (§8.D), and CheckMerge alone would then trust
// whatever that commit contains. So the CLI snapshots the source tip before
// asking the core to prepare, and Check accepts a moved tip only if it is a
// single commit on top of the snapshot that touches nothing but
// .arbiter/ledger/<PRD>.jsonl and only appends verifying entries to it.
type MergeCheck struct {
	arbiterDir string
	req        MergeRequest
	source     string
}

// NewMergeCheck snapshots req.Source in this checkout. Call it before
// PrepareMerge.
func NewMergeCheck(ctx context.Context, arbiterDir string, req MergeRequest) (*MergeCheck, error) {
	source, err := NewService(arbiterDir).revParse(ctx, req.Source+"^{commit}")
	if err != nil {
		return nil, err
	}
	return &MergeCheck{arbiterDir: arbiterDir, req: req, source: source}, nil
}

// Check verifies prep against this checkout (CheckMerge), after checking any
// export commit the core added to the source branch.
func (m *MergeCheck) Check(ctx context.Context, prep *Prepared) error {
	local := NewService(m.arbiterDir)
	source, err := local.revParse(ctx, m.req.Source+"^{commit}")
	if err != nil {
		return err
	}
	if source != m.source {
		if err := local.checkExportCommit(ctx, m.req, m.source, source); err != nil {
			return err
		}
	}
	return CheckMerge(ctx, m.arbiterDir, m.req, prep)
}

func (s *Service) checkExportCommit(ctx context.Context, req MergeRequest, oldTip, newTip string) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("gitsign: %s moved from %s to %s during prepare, and not by a ledger export: %s",
			req.Source, short(oldTip), short(newTip), fmt.Sprintf(format, a...))
	}
	parents, err := s.git(ctx, s.RepoDir, nil, "rev-list", "--parents", "-n", "1", newTip)
	if err != nil {
		return err
	}
	if f := strings.Fields(parents); len(f) != 2 || f[1] != oldTip {
		return fail("its parents are %v", f[1:])
	}
	path := ".arbiter/ledger/" + req.PRDID + ".jsonl"
	changed, err := s.git(ctx, s.RepoDir, nil, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", oldTip, newTip)
	if err != nil {
		return err
	}
	if c := strings.TrimRight(changed, "\x00"); c != path {
		return fail("it changes %q", strings.Split(c, "\x00"))
	}
	before, err := s.exportedHead(ctx, oldTip, req.PRDID)
	if err != nil {
		return err
	}
	after, err := s.exportedHead(ctx, newTip, req.PRDID)
	if err != nil {
		return err
	}
	if !after.present || after.seq <= before.seq {
		return fail("the ledger did not grow")
	}
	target, err := s.revParse(ctx, "refs/heads/"+req.Target+"^{commit}")
	if err != nil {
		return err
	}
	signers, err := s.signersAt(ctx, target)
	if err != nil {
		return err
	}
	sig, err := ledger.ParseSSHSig(after.entries[0].Signature)
	if err != nil {
		return fail("%v", err)
	}
	if err := supervisorAuthorized(signers, sig.PublicKey, time.Now()); err != nil {
		return fail("the ledger key: %v", err)
	}
	if _, _, err := ledger.Verify(after.entries, req.PRDID, sig.PublicKey); err != nil {
		return fail("%v", err)
	}
	return checkPrefix(req.PRDID, before.entries, after.entries)
}
