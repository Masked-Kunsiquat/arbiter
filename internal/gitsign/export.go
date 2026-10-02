package gitsign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// LedgerEntries returns every entry of a live ledger chain in seq order. The
// core's audit_log store implements it; the export before the final merge
// writes these entries to the feature branch.
type LedgerEntries interface {
	Entries(ctx context.Context, chain string) ([]ledger.Entry, error)
}

// ensureExport brings the PRD's committed ledger export on the feature branch
// up to the live chain before the final merge is prepared (§8.D "Human
// capstone"). If entries were appended since the last export, it writes
// .arbiter/ledger/<PRD>.jsonl in a supervisor-signed commit on top of source,
// advances the branch, and returns the new commit; otherwise it returns
// source unchanged. Without Heads, Entries and Supervisor it does nothing and
// checkExportCurrent decides.
func (s *Service) ensureExport(ctx context.Context, req MergeRequest, source string, now time.Time) (string, error) {
	if s.Heads == nil || s.Entries == nil || s.Supervisor == nil {
		return source, nil
	}
	seq, hash, err := s.Heads.Head(ctx, req.PRDID)
	if err != nil {
		return "", fmt.Errorf("gitsign: reading the %s ledger head: %w", req.PRDID, err)
	}
	if seq == 0 {
		return source, nil
	}
	head, err := s.exportedHead(ctx, source, req.PRDID)
	if err != nil {
		return "", err
	}
	switch {
	case head.present && head.seq == seq && head.hash == hash:
		return source, nil
	case head.present && head.seq > seq:
		// Overwriting would truncate a committed chain; the live store lost
		// entries (a replaced state.db?) and a human has to look.
		return "", fmt.Errorf("gitsign: the %s ledger committed on the feature branch is at seq %d, ahead of the live chain at seq %d; refusing to export over it",
			req.PRDID, head.seq, seq)
	}

	branchRef := "refs/heads/" + req.Source
	if tip, err := s.revParse(ctx, branchRef+"^{commit}"); err != nil || tip != source {
		return "", fmt.Errorf("gitsign: the %s ledger needs exporting before the final merge, which needs the source %q to be a branch", req.PRDID, req.Source)
	}

	entries, err := s.Entries.Entries(ctx, req.PRDID)
	if err != nil {
		return "", fmt.Errorf("gitsign: reading the %s ledger: %w", req.PRDID, err)
	}
	gotSeq, gotHash, err := ledger.Verify(entries, req.PRDID, s.Supervisor.PublicKey())
	if err != nil {
		return "", fmt.Errorf("gitsign: the live %s ledger does not verify; not exporting it: %w", req.PRDID, err)
	}
	if gotSeq != seq || gotHash != hash {
		return "", fmt.Errorf("gitsign: the %s ledger changed while exporting it (head seq %d, now seq %d); prepare the merge again", req.PRDID, seq, gotSeq)
	}

	var jsonl bytes.Buffer
	if err := ledger.WriteJSONL(&jsonl, entries); err != nil {
		return "", err
	}
	tree, err := s.treeWithFile(ctx, source, head.path, jsonl.Bytes())
	if err != nil {
		return "", err
	}
	pin := LedgerPin{Path: head.path, Seq: seq, Hash: hash}
	msg := fmt.Sprintf("Export %s ledger through seq %d\n\nArbiter-Ledger: %s\n", req.PRDID, seq, pin)

	// GitHub shows Verified only when the committer's email belongs to the
	// account that registered the signing key, so the human commits and
	// Arbiter authors, as for task commits (§8.D).
	author := s.SupervisorIdent
	if author.Name == "" || author.Email == "" {
		author = req.Signer.Ident
	}
	payload := CommitPayload(tree, []string{source}, author, req.Signer.Ident, now, msg)
	sig, err := s.Supervisor.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("gitsign: signing the %s ledger export: %w", req.PRDID, err)
	}
	header, err := s.sigHeader(ctx)
	if err != nil {
		return "", err
	}
	obj, err := AttachCommitSig(payload, sig, header)
	if err != nil {
		return "", err
	}
	sha, err := s.writeObject(ctx, "commit", obj)
	if err != nil {
		return "", err
	}
	if err := s.advanceBranch(ctx, req.Source, source, sha); err != nil {
		return "", err
	}
	return sha, nil
}

// treeWithFile returns the tree of commit with path (a slash path from the
// repo root) set to content, built in a throwaway index so neither the
// working tree nor the real index is touched.
func (s *Service) treeWithFile(ctx context.Context, commit, path string, content []byte) (string, error) {
	blob, err := s.git(ctx, s.RepoDir, content, "hash-object", "-t", "blob", "-w", "--stdin")
	if err != nil {
		return "", fmt.Errorf("gitsign: writing %s: %w", path, err)
	}
	dir, err := os.MkdirTemp("", "arbiter-index-")
	if err != nil {
		return "", fmt.Errorf("gitsign: temporary index: %w", err)
	}
	defer os.RemoveAll(dir)
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(dir, "index")}
	if _, err := s.gitEnv(ctx, s.RepoDir, env, nil, "read-tree", commit+"^{tree}"); err != nil {
		return "", err
	}
	if _, err := s.gitEnv(ctx, s.RepoDir, env, nil, "update-index", "--add", "--cacheinfo", "100644,"+strings.TrimSpace(blob)+","+path); err != nil {
		return "", err
	}
	tree, err := s.gitEnv(ctx, s.RepoDir, env, nil, "write-tree")
	if err != nil {
		return "", err
	}
	tree = strings.TrimSpace(tree)
	if tree == "" {
		return "", errors.New("gitsign: git write-tree returned no tree")
	}
	return tree, nil
}

// sigHeader is the commit header that carries a signature: "gpgsig" in SHA-1
// repositories, "gpgsig-sha256" in SHA-256 ones.
func (s *Service) sigHeader(ctx context.Context) (string, error) {
	format, err := s.git(ctx, s.RepoDir, nil, "rev-parse", "--show-object-format")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(format) == "sha256" {
		return "gpgsig-sha256", nil
	}
	return "gpgsig", nil
}
