package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/auditlog"
	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

const testSeat = "PRD-001/TASK-001/judge.1~abcd"

// fakeHandle is a supervisor.Handle for recorder tests.
type fakeHandle struct{}

func (fakeHandle) Pid() int                { return 4242 }
func (fakeHandle) ID() string              { return "job-7" }
func (fakeHandle) Exited() <-chan struct{} { return nil }
func (fakeHandle) Wait() error             { return nil }

// storeAppender adapts auditlog.Store to LedgerAppender (as core does).
type storeAppender struct{ s *auditlog.Store }

func (a storeAppender) Append(ctx context.Context, chain, seatID, action, taskID string, payload map[string]any) error {
	_, err := a.s.Append(ctx, chain, seatID, action, taskID, payload)
	return err
}

type failingAppender struct{}

func (failingAppender) Append(context.Context, string, string, string, string, map[string]any) error {
	return errors.New("ledger down")
}

// recorderDB returns a state.db with one minted judge seat and its ledger store.
func recorderDB(t *testing.T) (*sql.DB, *auditlog.Store) {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	raw := d.SQLDB()
	for _, q := range []string{
		`INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch) VALUES ('PRD-001', 'T', 'p.md', 'h', 'locked', 'main')`,
		`INSERT INTO tasks (id, prd_id, title, intent, status) VALUES ('TASK-001', 'PRD-001', 'T', 'i', 'ready')`,
		`INSERT INTO credentials (id, kind, harness, model, model_provenance, eligible_roles) VALUES ('cred:j', 'agent', 'claude-code', 'm', 'launched', '["judge"]')`,
		`INSERT INTO seats (id, role, task_id, prd_id, minted_by, credential_id, binding, status) VALUES ('` + testSeat + `', 'judge', 'TASK-001', 'PRD-001', 'core', 'cred:j', 'process', 'minted')`,
	} {
		if _, err := raw.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw, auditlog.New(raw, ledger.NewSSHSigner(signer))
}

func newSeatRecorder(raw *sql.DB, store *auditlog.Store) *SeatRecorder {
	return &SeatRecorder{
		DB: raw, Ledger: storeAppender{store}, PRDID: "PRD-001",
		SeatID: testSeat, TaskID: "TASK-001", Purpose: seat.PurposeClaimCheck,
	}
}

func TestSeatRecorderStartAndEnd(t *testing.T) {
	ctx := context.Background()
	raw, store := recorderDB(t)
	r := newSeatRecorder(raw, store)

	id, err := r.Start(ctx, fakeHandle{}, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	var handle, purpose, status string
	var pid int64
	if err := raw.QueryRowContext(ctx, `SELECT supervisor_handle, pid, purpose FROM invocations WHERE id = ? AND seat_id = ? AND task_id = 'TASK-001'`,
		id, testSeat).Scan(&handle, &pid, &purpose); err != nil {
		t.Fatalf("invocation row: %v", err)
	}
	if handle != "job-7" || pid != 4242 || purpose != "claim_check" {
		t.Errorf("row = %s %d %s", handle, pid, purpose)
	}
	if err := raw.QueryRowContext(ctx, `SELECT status FROM seats WHERE id = ?`, testSeat).Scan(&status); err != nil || status != "active" {
		t.Errorf("seat status %q, %v: want active after the first launch", status, err)
	}

	cost, apiStatus, text := 0.42, 529, "x"
	out := &Outcome{Kind: OutcomeError, Stream: &Stream{Result: &ResultEvent{
		IsError: true, Text: &text, TotalCostUSD: &cost, TerminalReason: "api_error", APIErrorStatus: &apiStatus}}}
	if err := r.End(ctx, id, seat.ExitCrash, out); err != nil {
		t.Fatal(err)
	}
	var reason, terminal string
	var gotCost float64
	var gotStatus int
	if err := raw.QueryRowContext(ctx, `SELECT exit_reason, cost_usd, terminal_reason, api_error_status FROM invocations WHERE id = ?`, id).
		Scan(&reason, &gotCost, &terminal, &gotStatus); err != nil {
		t.Fatal(err)
	}
	if reason != "crash" || gotCost != 0.42 || terminal != "api_error" || gotStatus != 529 {
		t.Errorf("ended row = %s %v %s %d", reason, gotCost, terminal, gotStatus)
	}

	entries, err := store.Entries(ctx, "PRD-001")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Action != "launch" || entries[1].Action != "exit" {
		t.Fatalf("ledger = %+v, want launch then exit", entries)
	}
	launch := entries[0]
	if launch.SeatID != testSeat || launch.TaskID != "TASK-001" ||
		launch.Payload["invocation_id"] != id || launch.Payload["prompt_hash"] != "abc123" || launch.Payload["purpose"] != "claim_check" {
		t.Errorf("launch entry = %+v", launch)
	}
	if exit := entries[1].Payload; exit["exit_reason"] != "crash" || fmt.Sprint(exit["cost_usd"]) != "0.42" || exit["cost_estimated"] != false {
		t.Errorf("exit payload = %v", exit)
	}
}

func TestSeatRecorderEndWithoutResult(t *testing.T) {
	ctx := context.Background()
	raw, store := recorderDB(t)
	r := newSeatRecorder(raw, store)
	id, err := r.Start(ctx, fakeHandle{}, "h")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.End(ctx, id, seat.ExitKilled, nil); err != nil {
		t.Fatal(err)
	}
	var cost sql.NullFloat64
	if err := raw.QueryRowContext(ctx, `SELECT cost_usd FROM invocations WHERE id = ?`, id).Scan(&cost); err != nil || cost.Valid {
		t.Errorf("cost_usd = %v, %v: want NULL", cost, err)
	}
	entries, _ := store.Entries(ctx, "PRD-001")
	if v, ok := entries[1].Payload["cost_usd"]; !ok || v != nil {
		t.Errorf("exit cost_usd = %v (present %v), want an explicit null", v, ok)
	}
}

func TestSeatRecorderSetSession(t *testing.T) {
	ctx := context.Background()
	raw, store := recorderDB(t)
	if err := newSeatRecorder(raw, store).SetSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if got, err := seat.HarnessSession(ctx, raw, testSeat); err != nil || got != sess {
		t.Errorf("HarnessSession = %q, %v", got, err)
	}
}

func TestSeatRecorderStartLedgerFailureEndsRow(t *testing.T) {
	ctx := context.Background()
	raw, store := recorderDB(t)
	r := newSeatRecorder(raw, store)
	r.Ledger = failingAppender{}
	if _, err := r.Start(ctx, fakeHandle{}, "h"); err == nil {
		t.Fatal("Start succeeded without its ledger entry")
	}
	var open int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM invocations WHERE ended_at IS NULL`).Scan(&open); err != nil || open != 0 {
		t.Errorf("%d invocation rows left open (%v): a failed Start must not leave a dangling row", open, err)
	}
}
