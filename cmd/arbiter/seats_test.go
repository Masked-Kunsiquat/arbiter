package main

import (
	"context"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

func TestLoadSeats_TreeShape(t *testing.T) {
	ctx := context.Background()
	adb, err := db.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer adb.Close()
	raw := adb.SQLDB()

	if _, err := raw.ExecContext(ctx, `
		INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES ('PRD-001', 'T', 'p.md', 'h', 'locked', 'main')`); err != nil {
		t.Fatalf("seed prd: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO tasks (id, prd_id, title, intent, status)
		VALUES ('TASK-101', 'PRD-001', 'T', 'intent', 'in_progress')`); err != nil {
		t.Fatalf("seed task: %v", err)
	}
	if err := seat.RegisterCredential(ctx, raw, seat.Credential{
		ID: "cred:rl", Kind: seat.KindAgent, EligibleRoles: []seat.Role{seat.RoleRingleader},
	}); err != nil {
		t.Fatalf("register cred: %v", err)
	}
	if err := seat.RegisterCredential(ctx, raw, seat.Credential{
		ID: "cred:w", Kind: seat.KindAgent, EligibleRoles: []seat.Role{seat.RoleWorker},
	}); err != nil {
		t.Fatalf("register cred: %v", err)
	}

	rlID, err := seat.MintSeat(ctx, raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role: seat.RoleRingleader, PRDID: "PRD-001", CredentialID: "cred:rl", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint ringleader: %v", err)
	}
	workerID, err := seat.MintSeat(ctx, raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-101",
		ParentSeatID: rlID, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint worker: %v", err)
	}

	rows, err := loadSeats(ctx, raw, "")
	if err != nil {
		t.Fatalf("loadSeats: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}

	var gotRL, gotWorker bool
	for _, r := range rows {
		switch r.id {
		case rlID:
			gotRL = true
			if r.parentID.Valid {
				t.Errorf("ringleader parent_seat_id should be NULL, got %q", r.parentID.String)
			}
		case workerID:
			gotWorker = true
			if !r.parentID.Valid || r.parentID.String != rlID {
				t.Errorf("worker parent_seat_id = %v, want %q", r.parentID, rlID)
			}
			if !r.taskID.Valid || r.taskID.String != "TASK-101" {
				t.Errorf("worker task_id = %v, want TASK-101", r.taskID)
			}
		}
	}
	if !gotRL || !gotWorker {
		t.Fatalf("expected both ringleader and worker rows, got rl=%v worker=%v", gotRL, gotWorker)
	}
}

func TestLoadSeats_PRDFilter(t *testing.T) {
	ctx := context.Background()
	adb, err := db.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer adb.Close()
	raw := adb.SQLDB()

	for _, id := range []string{"PRD-001", "PRD-002"} {
		if _, err := raw.ExecContext(ctx, `
			INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
			VALUES (?, 'T', 'p.md', 'h', 'locked', 'main')`, id); err != nil {
			t.Fatalf("seed prd %s: %v", id, err)
		}
	}
	if err := seat.RegisterCredential(ctx, raw, seat.Credential{
		ID: "cred:rl", Kind: seat.KindAgent, EligibleRoles: []seat.Role{seat.RoleRingleader},
	}); err != nil {
		t.Fatalf("register cred: %v", err)
	}
	for _, prd := range []string{"PRD-001", "PRD-002"} {
		if _, err := seat.MintSeat(ctx, raw, seat.Minter{IsHuman: true}, seat.MintRequest{
			Role: seat.RoleRingleader, PRDID: prd, CredentialID: "cred:rl", Binding: seat.BindingProcess,
		}); err != nil {
			t.Fatalf("mint for %s: %v", prd, err)
		}
	}

	rows, err := loadSeats(ctx, raw, "PRD-001")
	if err != nil {
		t.Fatalf("loadSeats: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].prdID != "PRD-001" {
		t.Errorf("prdID = %q, want PRD-001", rows[0].prdID)
	}
}
