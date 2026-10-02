package auditlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

func newStore(t *testing.T) (*Store, ssh.PublicKey) {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return New(d.SQLDB(), ledger.NewSSHSigner(s)), s.PublicKey()
}

func appendSample(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	steps := []struct {
		chain, seat, action, task string
		payload                   map[string]any
	}{
		{"PRD-001", "human", "prd_lock", "", map[string]any{"tag": "arbiter/prd/PRD-001/v1", "spec_hash": "ab", "tag_object_sha": "cd"}},
		{"PRD-001", "core", "mint", "", map[string]any{"new_seat_id": "s1", "role": "ringleader", "parent_seat_id": nil, "credential_id": "c"}},
		{"PRD-001", "core", "exit", "TASK-101", map[string]any{"invocation_id": "i1", "exit_reason": "ok", "cost_usd": 1.5, "cost_estimated": false, "tokens": 42}},
		{ledger.GlobalChain, "core", "merge_commit", "", map[string]any{"sha": "abc"}},
	}
	for _, st := range steps {
		if _, err := s.Append(ctx, st.chain, st.seat, st.action, st.task, st.payload); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppendEntriesVerify(t *testing.T) {
	ctx := context.Background()
	s, pub := newStore(t)
	appendSample(t, s)

	entries, err := s.Entries(ctx, "PRD-001")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].TaskID != "" || entries[2].TaskID != "TASK-101" {
		t.Errorf("task ids = %q, %q", entries[0].TaskID, entries[2].TaskID)
	}
	seq, head, err := ledger.Verify(entries, "PRD-001", pub)
	if err != nil {
		t.Fatal(err)
	}
	hs, hh, err := s.Head(ctx, "PRD-001")
	if err != nil {
		t.Fatal(err)
	}
	if hs != seq || hh != head || seq != 3 {
		t.Errorf("Head = (%d, %s), Verify = (%d, %s)", hs, hh, seq, head)
	}

	global, err := s.Entries(ctx, ledger.GlobalChain)
	if err != nil {
		t.Fatal(err)
	}
	if len(global) != 1 {
		t.Fatalf("global has %d entries, want 1", len(global))
	}
	if _, _, err := ledger.Verify(global, ledger.GlobalChain, pub); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := ledger.WriteJSONL(&buf, entries); err != nil {
		t.Fatal(err)
	}
	if n, h, err := ledger.VerifyJSONL(&buf, "PRD-001", pub); err != nil || n != 3 || h != head {
		t.Fatalf("VerifyJSONL = (%d, %s, %v)", n, h, err)
	}
}

func TestHeadEmptyChain(t *testing.T) {
	s, _ := newStore(t)
	seq, hash, err := s.Head(context.Background(), "PRD-001")
	if err != nil || seq != 0 || hash != "" {
		t.Fatalf("Head = (%d, %q, %v), want (0, \"\", nil)", seq, hash, err)
	}
}

func TestAppendRejects(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t)
	appendSample(t, s)
	wantSeq, wantHash, _ := s.Head(ctx, "PRD-001")

	tests := []struct {
		name, chain, seat, action string
		payload                   map[string]any
	}{
		{"unknown action", "PRD-001", "core", "not_an_action", map[string]any{}},
		{"bad chain name", "PRD-1", "core", "merge_commit", map[string]any{"sha": "abc"}},
		{"missing seat", "PRD-001", "", "merge_commit", map[string]any{"sha": "abc"}},
		{"missing payload field", "PRD-001", "core", "merge_commit", map[string]any{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Append(ctx, tc.chain, tc.seat, tc.action, "", tc.payload); err == nil {
				t.Fatal("expected an error")
			}
			if seq, hash, _ := s.Head(ctx, "PRD-001"); seq != wantSeq || hash != wantHash {
				t.Errorf("head changed to (%d, %s)", seq, hash)
			}
			if seq, _, _ := s.Head(ctx, tc.chain); tc.chain == "PRD-1" && seq != 0 {
				t.Errorf("rejected chain has seq %d", seq)
			}
		})
	}
}

func TestConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	s, pub := newStore(t)
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Append(ctx, "PRD-001", "core", "merge_commit", "", map[string]any{"sha": "abc"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := s.Entries(ctx, "PRD-001")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("got %d entries, want %d", len(entries), n)
	}
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			t.Errorf("entry %d has seq %d", i, e.Seq)
		}
	}
	if _, _, err := ledger.Verify(entries, "PRD-001", pub); err != nil {
		t.Fatal(err)
	}
}

func TestFixedNow(t *testing.T) {
	s, _ := newStore(t)
	at := time.Date(2026, 3, 4, 5, 6, 7, 123456000, time.UTC)
	s.Now = func() time.Time { return at }
	e, err := s.Append(context.Background(), "global", "core", "merge_commit", "", map[string]any{"sha": "abc"})
	if err != nil {
		t.Fatal(err)
	}
	want := at.Format(ledger.TimeFormat)
	if e.CreatedAt != want {
		t.Errorf("returned created_at = %q, want %q", e.CreatedAt, want)
	}
	got, err := s.Entries(context.Background(), "global")
	if err != nil || len(got) != 1 || got[0].CreatedAt != want {
		t.Fatalf("stored created_at = %v (err %v), want %q", got, err, want)
	}
}
