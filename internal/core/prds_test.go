package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/gitsign"
	"github.com/Masked-Kunsiquat/arbiter/internal/ipc"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
	"github.com/Masked-Kunsiquat/arbiter/internal/prd"
)

// validPRD returns a PRD that parses (§2.C): id PRD-001, one invariant, one
// boundary and one acceptance criterion.
func validPRD(t *testing.T) []byte {
	t.Helper()
	return []byte(`---
id: PRD-001
title: Token refresh
target_branch: feature/prd-001
max_budget_usd: 7.50
---

## 1. Intent & Context
Keep sessions alive across access-token expiry.

## 2. Invariants (Non-Negotiable Constraints)
- [INVARIANT-1] No token secrets may ever be written to plaintext logs.

## 3. Allowed File Boundaries (The Sandbox Scope)
- ` + "`src/auth/**`" + `

## 4. Acceptance Criteria & Testable Outcomes
- [ ] AC-1: POST /auth/refresh returns a new access/refresh pair.
`)
}

// withCriteria returns content with its acceptance criteria replaced by
// AC-<n> for each given n.
func withCriteria(t *testing.T, content []byte, nums ...string) []byte {
	t.Helper()
	const line = "- [ ] AC-1: POST /auth/refresh returns a new access/refresh pair.\n"
	if !bytes.Contains(content, []byte(line)) {
		t.Fatal("fixture has no AC-1 line")
	}
	var b strings.Builder
	for _, n := range nums {
		b.WriteString("- [ ] AC-" + n + ": criterion " + n + ".\n")
	}
	return bytes.Replace(content, []byte(line), []byte(b.String()), 1)
}

// prdEnv is a repo with a core, allowed_signers listing the human's key, and
// a way to commit and lock PRD-001.
type prdEnv struct {
	dir, repo string
	s         *Session
	signer    gitsign.Signer
	sign      SignFunc
}

func newPRDEnv(t *testing.T) *prdEnv {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	dir := newArbiterDir(t)
	repo := filepath.Dir(dir)
	gitIn(t, repo, "init", "-q", "-b", "main")
	gitIn(t, repo, "config", "user.name", "Human")
	gitIn(t, repo, "config", "user.email", "human@example.com")

	human, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	signersPath := filepath.Join(dir, filepath.FromSlash(allowedsigners.RelPath))
	if _, err := allowedsigners.Ensure(signersPath, "human@example.com", allowedsigners.HumanNamespaces, human.PublicKey()); err != nil {
		t.Fatal(err)
	}
	gitSigner := ledger.NewSSHSignerNamespace(human, gitsign.Namespace)
	e := &prdEnv{
		dir: dir, repo: repo,
		signer: gitsign.Signer{
			Ident:     gitsign.Ident{Name: "Human", Email: "human@example.com"},
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(human.PublicKey()))),
		},
		sign: func(_ context.Context, payload []byte) (string, error) { return gitSigner.Sign(payload) },
	}
	e.commit(t, validPRD(t))
	e.s = connect(t, dir)
	return e
}

// commit writes content as PRD-001.md and commits everything under .arbiter.
func (e *prdEnv) commit(t *testing.T, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(e.dir, "prds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "prds", "PRD-001.md"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, e.repo, "add", ".arbiter/prds", ".arbiter/ledger")
	gitIn(t, e.repo, "commit", "-q", "--allow-empty", "-m", "PRD-001")
}

func (e *prdEnv) lock(amend bool) (*gitsign.Completed, error) {
	return e.s.LockPRD(context.Background(), gitsign.LockRequest{PRDID: "PRD-001", Amend: amend, Signer: e.signer}, e.sign)
}

func (e *prdEnv) mustLock(t *testing.T, amend bool) {
	t.Helper()
	if _, err := e.lock(amend); err != nil {
		t.Fatalf("lock (amend=%v): %v", amend, err)
	}
}

func (e *prdEnv) get(t *testing.T) PRDState {
	t.Helper()
	st, err := e.s.GetPRD(context.Background(), "PRD-001")
	if err != nil {
		t.Fatalf("GetPRD: %v", err)
	}
	return st
}

func (e *prdEnv) setStatus(t *testing.T, status prd.Status) {
	t.Helper()
	withDB(t, e.dir, func(raw *sql.DB) {
		mustExec(t, raw, `UPDATE prds SET status = ? WHERE id = 'PRD-001'`, string(status))
	})
}

func (e *prdEnv) tags(t *testing.T) string {
	t.Helper()
	return gitIn(t, e.repo, "tag", "-l")
}

func TestPRDLock_RecordsRow(t *testing.T) {
	e := newPRDEnv(t)
	content := validPRD(t)
	if st := e.get(t); st.Status != "" {
		t.Fatalf("status before lock = %q", st.Status)
	}
	e.mustLock(t, false)

	want, err := prd.SpecHash(content)
	if err != nil {
		t.Fatal(err)
	}
	st := e.get(t)
	if st.Status != prd.StatusLocked || st.LockTag != "arbiter/prd/PRD-001/v1" || st.SpecHash != want ||
		st.Title != "Token refresh" || st.TargetBranch != "feature/prd-001" || st.MaxBudgetUSD != 7.5 {
		t.Errorf("row = %+v (want spec_hash %s)", st, want)
	}
}

func TestPRDLock_Rejects(t *testing.T) {
	good := string(validPRD(t))
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"unparseable", "# PRD-001\n", "line 1"},
		{"id mismatch", strings.Replace(good, "id: PRD-001", "id: PRD-002", 1), "PRD-002"},
		{"stale spec_hash", strings.Replace(good, "title:", "spec_hash: "+strings.Repeat("a", 64)+"\ntitle:", 1), "spec_hash"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newPRDEnv(t)
			e.commit(t, []byte(tc.content))
			if _, err := e.lock(false); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("lock error = %v, want it to mention %q", err, tc.want)
			}
			if tags := e.tags(t); tags != "" {
				t.Errorf("tags = %q", tags)
			}
			if st := e.get(t); st.Status != "" {
				t.Errorf("row created: %+v", st)
			}
		})
	}
}

func TestPRDAmend(t *testing.T) {
	e := newPRDEnv(t)
	e.commit(t, withCriteria(t, validPRD(t), "1", "2"))
	e.mustLock(t, false)

	// An amendment while locked makes v2 and moves the row's lock tag.
	v2 := withCriteria(t, validPRD(t), "1", "3")
	e.commit(t, v2)
	e.mustLock(t, true)
	st := e.get(t)
	if st.Status != prd.StatusLocked || st.LockTag != "arbiter/prd/PRD-001/v2" {
		t.Fatalf("after amend: %+v", st)
	}
	if want, _ := prd.SpecHash(v2); st.SpecHash != want {
		t.Errorf("spec_hash = %s, want %s", st.SpecHash, want)
	}

	// AC-2 was retired by v2; bringing it back is refused.
	e.commit(t, withCriteria(t, validPRD(t), "1", "2", "3"))
	if _, err := e.lock(true); err == nil || !strings.Contains(err.Error(), "AC-2 was retired") {
		t.Fatalf("reusing a retired AC: err = %v", err)
	}
	if tags := e.tags(t); strings.Contains(tags, "v3") {
		t.Errorf("tags = %q", tags)
	}

	// Once execution has started, only a blocked_prd claim reopens the PRD.
	e.commit(t, withCriteria(t, validPRD(t), "1", "3", "4"))
	e.setStatus(t, prd.StatusExecuting)
	if _, err := e.lock(true); err == nil || !strings.Contains(err.Error(), "executing") {
		t.Fatalf("amend while executing: err = %v", err)
	}
	if st := e.get(t); st.Status != prd.StatusExecuting || st.LockTag != "arbiter/prd/PRD-001/v2" {
		t.Errorf("row changed by a refused amend: %+v", st)
	}

	e.setStatus(t, prd.StatusAmendmentNeeded)
	e.mustLock(t, true)
	if st := e.get(t); st.Status != prd.StatusLocked || st.LockTag != "arbiter/prd/PRD-001/v3" {
		t.Errorf("after amendment_needed: %+v", st)
	}
}

func TestPRDStore_MergeLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := newArbiterDir(t)
	withDB(t, dir, func(raw *sql.DB) {
		store := prdStore{db: raw}
		status := func() prd.Status {
			st, err := getPRD(ctx, raw, "PRD-001")
			if err != nil {
				t.Fatal(err)
			}
			return st.Status
		}

		if err := store.CheckMerge(ctx, "PRD-001"); err == nil || !strings.Contains(err.Error(), "not locked") {
			t.Errorf("CheckMerge without a row: %v", err)
		}
		if err := store.RecordMerge(ctx, "PRD-001"); err == nil {
			t.Error("RecordMerge without a row succeeded")
		}

		mustExec(t, raw, `INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
			VALUES ('PRD-001', 'T', 'p.md', 'h', 'executing', 'main')`)
		if err := store.CheckMerge(ctx, "PRD-001"); err == nil || !strings.Contains(err.Error(), "executing") {
			t.Errorf("CheckMerge while executing: %v", err)
		}
		if err := store.RecordMerge(ctx, "PRD-001"); err == nil {
			t.Error("RecordMerge while executing succeeded")
		}
		if got := status(); got != prd.StatusExecuting {
			t.Errorf("status = %s after refused RecordMerge", got)
		}

		mustExec(t, raw, `UPDATE prds SET status = 'completed' WHERE id = 'PRD-001'`)
		if err := store.CheckMerge(ctx, "PRD-001"); err != nil {
			t.Errorf("CheckMerge when completed: %v", err)
		}
		if err := store.RecordMerge(ctx, "PRD-001"); err != nil {
			t.Fatalf("RecordMerge: %v", err)
		}
		if got := status(); got != prd.StatusArchived {
			t.Errorf("status = %s, want archived", got)
		}
		if err := store.RecordMerge(ctx, "PRD-001"); err == nil {
			t.Error("second RecordMerge succeeded")
		}
	})
}

func TestPRDGet_UnknownAndBadID(t *testing.T) {
	ctx := context.Background()
	s := connect(t, newArbiterDir(t))
	st, err := s.GetPRD(ctx, "PRD-042")
	if err != nil {
		t.Fatalf("unknown id: %v", err)
	}
	if st.ID != "PRD-042" || st.Status != "" {
		t.Errorf("unknown id state = %+v", st)
	}
	var re *ipc.RemoteError
	if _, err := s.GetPRD(ctx, "nope"); !errors.As(err, &re) || re.Code != ipc.CodeBadParams {
		t.Errorf("bad id: err = %v", err)
	}
}

// If recording a lock in state.db failed after the tag was created, the
// signed tag is authoritative: lock refuses (the tag exists) and amend
// recreates the row.
func TestPRDAmend_RecreatesMissingRow(t *testing.T) {
	e := newPRDEnv(t)
	e.commit(t, withCriteria(t, validPRD(t), "1"))
	e.mustLock(t, false)
	withDB(t, e.dir, func(raw *sql.DB) {
		mustExec(t, raw, `DELETE FROM prds WHERE id = 'PRD-001'`)
	})

	if _, err := e.lock(false); err == nil || !strings.Contains(err.Error(), "amend") {
		t.Fatalf("relock with a missing row: err = %v", err)
	}
	e.mustLock(t, true)
	if st := e.get(t); st.Status != prd.StatusLocked || st.LockTag != "arbiter/prd/PRD-001/v2" {
		t.Errorf("after repair: %+v", st)
	}
}
