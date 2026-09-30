package core

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

func TestListSeats_TreeShape(t *testing.T) {
	dir := newArbiterDir(t)
	var rlID, workerID string
	withDB(t, dir, func(raw *sql.DB) {
		rlID, workerID = seedSeats(t, raw)
		startInvocation(t, raw, workerID)
	})

	s := connect(t, dir)
	var rows []SeatInfo
	if err := s.Call(context.Background(), MethodSeatsList, ListSeatsParams{}, &rows); err != nil {
		t.Fatalf("seats.list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	byID := map[string]SeatInfo{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	rl, w := byID[rlID], byID[workerID]
	if rl.ParentSeatID != "" || rl.TaskID != "" {
		t.Errorf("ringleader parent=%q task=%q, want both empty", rl.ParentSeatID, rl.TaskID)
	}
	if w.ParentSeatID != rlID || w.TaskID != "TASK-101" {
		t.Errorf("worker parent=%q task=%q, want %q / TASK-101", w.ParentSeatID, w.TaskID, rlID)
	}
	if w.Harness != "claude" || w.Model != "m" || w.InvocationCount != 1 {
		t.Errorf("worker harness=%q model=%q invocations=%d", w.Harness, w.Model, w.InvocationCount)
	}
}

func TestListSeats_PRDFilter(t *testing.T) {
	dir := newArbiterDir(t)
	withDB(t, dir, func(raw *sql.DB) {
		seedSeats(t, raw)
		mustExec(t, raw, `INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
			VALUES ('PRD-002', 'T', 'p.md', 'h', 'locked', 'main')`)
		if _, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
			Role: seat.RoleRingleader, PRDID: "PRD-002", CredentialID: "cred:rl", Binding: seat.BindingProcess,
		}); err != nil {
			t.Fatalf("mint PRD-002: %v", err)
		}
	})

	s := connect(t, dir)
	var rows []SeatInfo
	if err := s.Call(context.Background(), MethodSeatsList, ListSeatsParams{PRDID: "PRD-002"}, &rows); err != nil {
		t.Fatalf("seats.list: %v", err)
	}
	if len(rows) != 1 || rows[0].PRDID != "PRD-002" {
		t.Fatalf("got %+v, want exactly one PRD-002 seat", rows)
	}
}

func TestListSeats_EmptyIsEmptyList(t *testing.T) {
	s := connect(t, newArbiterDir(t))
	var rows []SeatInfo
	if err := s.Call(context.Background(), MethodSeatsList, nil, &rows); err != nil {
		t.Fatalf("seats.list: %v", err)
	}
	if rows == nil || len(rows) != 0 {
		t.Fatalf("rows = %#v, want empty non-nil slice", rows)
	}
}
