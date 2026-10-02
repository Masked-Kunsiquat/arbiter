package gitsign

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// LedgerHeads reports the live head of a ledger chain (§8.B): the last
// entry's seq and entry_hash, (0, "") for an empty chain. The real
// implementation reads audit_log and lands with the ledger (issue #19); until
// then a nil LedgerHeads skips the check that the committed export is current.
type LedgerHeads interface {
	Head(ctx context.Context, chain string) (seq int64, entryHash string, err error)
}

// ledgerHead is the head of a chain as exported into a commit's tree.
type ledgerHead struct {
	path    string
	present bool
	seq     int64
	hash    string
}

// exportedHead reads .arbiter/ledger/<prdID>.jsonl at commit. A missing or
// empty file has present == false.
func (s *Service) exportedHead(ctx context.Context, commit, prdID string) (ledgerHead, error) {
	h := ledgerHead{path: ".arbiter/ledger/" + prdID + ".jsonl"}
	listed, err := s.git(ctx, s.RepoDir, nil, "ls-tree", "--name-only", commit, "--", h.path)
	if err != nil {
		return h, err
	}
	if strings.TrimSpace(listed) == "" {
		return h, nil
	}
	out, err := s.git(ctx, s.RepoDir, nil, "cat-file", "blob", commit+":"+h.path)
	if err != nil {
		return h, err
	}
	entries, err := ledger.ReadJSONL(strings.NewReader(out))
	if err != nil {
		return h, fmt.Errorf("gitsign: %s at %s: %w", h.path, short(commit), err)
	}
	if len(entries) == 0 {
		return h, nil
	}
	last := entries[len(entries)-1]
	if last.Chain != prdID || last.Seq != int64(len(entries)) {
		return h, fmt.Errorf("gitsign: %s at %s ends with chain %q seq %d after %d lines", h.path, short(commit), last.Chain, last.Seq, len(entries))
	}
	h.present, h.seq, h.hash = true, last.Seq, last.EntryHash
	return h, nil
}

// mergeMessage builds the final merge's message (§8.D "Human capstone"): the
// subject (req.Message, or a default) followed by the Arbiter-PRD trailer
// naming the latest lock version and, once the PRD has a ledger, the
// Arbiter-Ledger trailer pinning the head of the chain exported at source.
// The core and the CLI both build it, so the CLI can check the core's.
func (s *Service) mergeMessage(ctx context.Context, req MergeRequest, source string) (string, ledgerHead, error) {
	subject := strings.TrimRight(strings.ReplaceAll(req.Message, "\r\n", "\n"), "\n")
	if subject == "" {
		subject = fmt.Sprintf("Merge %s (%s) into %s", req.PRDID, req.Source, req.Target)
	}
	for line := range strings.Lines(subject) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "arbiter-") {
			return "", ledgerHead{}, errors.New("gitsign: the merge message may not contain Arbiter- trailers; Arbiter adds them")
		}
	}
	version, err := s.latestLockVersion(ctx, req.PRDID)
	if err != nil {
		return "", ledgerHead{}, err
	}
	if version == 0 {
		return "", ledgerHead{}, fmt.Errorf("gitsign: %s has no lock tag; lock the PRD before merging it", req.PRDID)
	}
	head, err := s.exportedHead(ctx, source, req.PRDID)
	if err != nil {
		return "", ledgerHead{}, err
	}

	var b strings.Builder
	b.WriteString(subject)
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "Arbiter-PRD: %s@v%d (tag arbiter/prd/%s/v%d)\n", req.PRDID, version, req.PRDID, version)
	if head.present {
		fmt.Fprintf(&b, "Arbiter-Ledger: %s\n", LedgerPin{Path: head.path, Seq: head.seq, Hash: head.hash})
	}
	return b.String(), head, nil
}

// checkExportCurrent refuses a merge whose committed ledger export lags the
// live chain: the human signature must pin every entry (§8.B, §8.D).
func (s *Service) checkExportCurrent(ctx context.Context, prdID string, head ledgerHead) error {
	if s.Heads == nil {
		return nil
	}
	seq, hash, err := s.Heads.Head(ctx, prdID)
	if err != nil {
		return fmt.Errorf("gitsign: reading the %s ledger head: %w", prdID, err)
	}
	if seq == 0 && !head.present {
		return nil
	}
	if head.present && head.seq == seq && head.hash != hash {
		return fmt.Errorf("gitsign: the %s ledger committed on the feature branch diverges from the live chain at seq %d (entry_hash %s, live %s); the export was rewritten, so re-export it from the core",
			prdID, seq, short(head.hash), short(hash))
	}
	if !head.present || head.seq != seq {
		return fmt.Errorf("gitsign: the %s ledger committed on the feature branch is at seq %d, but the live chain is at seq %d; export it before the final merge",
			prdID, head.seq, seq)
	}
	return nil
}
