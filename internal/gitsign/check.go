package gitsign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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
// one this checkout's `git merge-tree` produces, and the signer is author and
// committer.
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
	lines, _, err := splitObject(prep.Payload)
	if err != nil {
		return err
	}
	return expectHeaders(lines, []string{
		"tree " + tree,
		"parent " + target,
		"parent " + source,
		"author " + identPrefix(req.Signer.Ident),
		"committer " + identPrefix(req.Signer.Ident),
	}, map[string]bool{"author": true, "committer": true})
}
