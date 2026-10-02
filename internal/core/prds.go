package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Masked-Kunsiquat/arbiter/internal/prd"
)

// PRDState is one PRD's row in state.db, as served by MethodPRDGet. A PRD
// has no row until its first lock tag exists, so Status is empty for a
// draft or an unknown id.
type PRDState struct {
	ID           string     `json:"id"`
	Title        string     `json:"title,omitempty"`
	Status       prd.Status `json:"status,omitempty"`
	SpecHash     string     `json:"spec_hash,omitempty"`
	LockTag      string     `json:"lock_tag,omitempty"`
	TargetBranch string     `json:"target_branch,omitempty"`
	MaxBudgetUSD float64    `json:"max_budget_usd,omitempty"`
	SpentUSD     float64    `json:"spent_usd,omitempty"`
}

// GetPRDParams are the params of MethodPRDGet.
type GetPRDParams struct {
	PRDID string `json:"prd_id"`
}

func getPRD(ctx context.Context, raw *sql.DB, id string) (PRDState, error) {
	st := PRDState{ID: id}
	var lockTag sql.NullString
	var budget sql.NullFloat64
	err := raw.QueryRowContext(ctx, `
		SELECT title, status, spec_hash, lock_tag, target_branch, max_budget_usd, spent_usd
		FROM prds WHERE id = ?`, id).
		Scan(&st.Title, &st.Status, &st.SpecHash, &lockTag, &st.TargetBranch, &budget, &st.SpentUSD)
	if errors.Is(err, sql.ErrNoRows) {
		return PRDState{ID: id}, nil
	}
	if err != nil {
		return PRDState{}, fmt.Errorf("core: reading %s from state.db: %w", id, err)
	}
	st.LockTag, st.MaxBudgetUSD = lockTag.String, budget.Float64
	return st, nil
}

// prdStore implements gitsign.PRDStore over the prds table: it enforces the
// §2.A lifecycle and the §2.C parser rules before the human signs, and
// records the outcome once the tag or merge exists.
type prdStore struct{ db *sql.DB }

func prdPath(id string) string { return ".arbiter/prds/" + id + ".md" }

func (s prdStore) CheckLock(ctx context.Context, prdID string, n int, content []byte, prior [][]byte) error {
	p, err := prd.Parse(content)
	if err != nil {
		return fmt.Errorf("core: %s does not parse:\n%w", prdPath(prdID), err)
	}
	if p.ID != prdID {
		return fmt.Errorf("core: %s has id %s in its frontmatter", prdPath(prdID), p.ID)
	}
	if p.SpecHash != "" {
		h, err := prd.SpecHash(content)
		if err != nil {
			return fmt.Errorf("core: spec_hash of %s: %w", prdPath(prdID), err)
		}
		if p.SpecHash != h {
			return fmt.Errorf("core: %s records spec_hash %s, but its content hashes to %s (arbiter prd lock rewrites it)", prdPath(prdID), p.SpecHash, h)
		}
	}

	st, err := getPRD(ctx, s.db, prdID)
	if err != nil {
		return err
	}
	if n == 1 {
		if st.Status != "" && st.Status != prd.StatusDraft {
			return fmt.Errorf("core: %s has no lock tag, but state.db has it %s", prdID, st.Status)
		}
		return nil
	}
	if st.Status == "" {
		return fmt.Errorf("core: %s has lock tags but no row in state.db", prdID)
	}
	if !prd.CanTransition(st.Status, prd.StatusLocked) {
		return fmt.Errorf("core: %s is %s; it can be amended only while locked or amendment_needed (§2.A)", prdID, st.Status)
	}
	versions := make([]*prd.PRD, 0, len(prior))
	for i, c := range prior {
		v, err := prd.Parse(c)
		if err != nil {
			return fmt.Errorf("core: %s as locked at v%d does not parse:\n%w", prdPath(prdID), i+1, err)
		}
		versions = append(versions, v)
	}
	if err := prd.CheckAmendment(versions, p); err != nil {
		return fmt.Errorf("core: %s:\n%w", prdPath(prdID), err)
	}
	return nil
}

func (s prdStore) RecordLock(ctx context.Context, prdID, tag string, content []byte, specHash string) error {
	p, err := prd.Parse(content)
	if err != nil {
		return fmt.Errorf("core: %s does not parse: %w", prdPath(prdID), err)
	}
	if specHash == "" {
		if specHash, err = prd.SpecHash(content); err != nil {
			return err
		}
	}
	// The WHERE re-checks the lifecycle: a racing transition between
	// prepare and complete leaves the row alone and reports it.
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO prds (id, title, file_path, spec_hash, lock_tag, status, target_branch, max_budget_usd)
		VALUES (?, ?, ?, ?, ?, 'locked', ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title = excluded.title, file_path = excluded.file_path, spec_hash = excluded.spec_hash,
			lock_tag = excluded.lock_tag, status = 'locked', target_branch = excluded.target_branch,
			max_budget_usd = excluded.max_budget_usd, updated_at = CURRENT_TIMESTAMP
		WHERE prds.status IN ('draft', 'locked', 'amendment_needed')`,
		prdID, p.Title, prdPath(prdID), specHash, tag, p.TargetBranch, p.MaxBudgetUSD)
	if err != nil {
		return fmt.Errorf("core: recording %s: %w", tag, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("core: %s changed state while %s was being signed", prdID, tag)
	}
	return nil
}

func (s prdStore) CheckMerge(ctx context.Context, prdID string) error {
	st, err := getPRD(ctx, s.db, prdID)
	if err != nil {
		return err
	}
	if st.Status != prd.StatusCompleted {
		status := string(st.Status)
		if status == "" {
			status = "not locked"
		}
		return fmt.Errorf("core: %s is %s; the final merge waits until every task is done (§5.8)", prdID, status)
	}
	return nil
}

func (s prdStore) RecordMerge(ctx context.Context, prdID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE prds SET status = 'archived', updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'completed'`, prdID)
	if err != nil {
		return fmt.Errorf("core: archiving %s: %w", prdID, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("core: %s changed state while its final merge was being signed", prdID)
	}
	return nil
}

// GetPRD returns prdID's state.db row (MethodPRDGet).
func (s *Session) GetPRD(ctx context.Context, prdID string) (PRDState, error) {
	var st PRDState
	err := s.Call(ctx, MethodPRDGet, GetPRDParams{PRDID: prdID}, &st)
	return st, err
}
