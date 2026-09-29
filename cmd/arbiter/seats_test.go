package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"runtime"
	"strings"
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

// ─────────────────────────────────────────────────────────────────────────────
// parseSeatsArgs: flag/positional order independence and rejection of
// unconsumed arguments (CodeRabbit review on PR #42).
// ─────────────────────────────────────────────────────────────────────────────

func TestParseSeatsArgs_FlagBeforePositional(t *testing.T) {
	stats, prd, err := parseSeatsArgs([]string{"--stats", "PRD-001"})
	if err != nil {
		t.Fatalf("parseSeatsArgs: %v", err)
	}
	if !stats || prd != "PRD-001" {
		t.Errorf("got stats=%v prd=%q, want stats=true prd=PRD-001", stats, prd)
	}
}

func TestParseSeatsArgs_PositionalBeforeFlag(t *testing.T) {
	// This is the order the stdlib flag package alone gets wrong: Parse
	// stops at the first non-flag argument, so a trailing --stats would be
	// silently left in fs.Args() and never applied.
	stats, prd, err := parseSeatsArgs([]string{"PRD-001", "--stats"})
	if err != nil {
		t.Fatalf("parseSeatsArgs: %v", err)
	}
	if !stats || prd != "PRD-001" {
		t.Errorf("got stats=%v prd=%q, want stats=true prd=PRD-001", stats, prd)
	}
}

func TestParseSeatsArgs_NoArgs(t *testing.T) {
	stats, prd, err := parseSeatsArgs(nil)
	if err != nil {
		t.Fatalf("parseSeatsArgs: %v", err)
	}
	if stats || prd != "" {
		t.Errorf("got stats=%v prd=%q, want stats=false prd=\"\"", stats, prd)
	}
}

func TestParseSeatsArgs_RejectsUnknownFlag(t *testing.T) {
	if _, _, err := parseSeatsArgs([]string{"--stat"}); err == nil {
		t.Fatal("expected error for mistyped flag --stat, got nil")
	}
}

func TestParseSeatsArgs_RejectsExtraPositional(t *testing.T) {
	if _, _, err := parseSeatsArgs([]string{"PRD-001", "PRD-002"}); err == nil {
		t.Fatal("expected error for two positional arguments, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// findStateDB: a stat error other than ErrNotExist must surface, not be
// treated as "keep walking up" (CodeRabbit review on PR #42).
// ─────────────────────────────────────────────────────────────────────────────

func TestFindStateDB_SurfacesNonNotExistError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't block directory traversal for the owner on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: permission denial can't be simulated")
	}
	dir := t.TempDir()
	arbiterDir := dir + string(os.PathSeparator) + ".arbiter"
	if err := os.MkdirAll(arbiterDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Remove execute permission on .arbiter so stat-ing state.db inside it
	// fails with something other than ErrNotExist.
	if err := os.Chmod(arbiterDir, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(arbiterDir, 0o755) })

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { os.Chdir(oldWD) })

	_, err = findStateDB()
	if err == nil {
		t.Fatal("expected an error surfaced from a permission-denied stat, got nil")
	}
	if strings.Contains(err.Error(), "run 'arbiter init' first") {
		t.Errorf("expected the permission error to surface, got the not-found fallback: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// printTree: a row whose parent was excluded by a PRD filter still renders,
// as its own root, instead of vanishing (CodeRabbit review on PR #42).
// ─────────────────────────────────────────────────────────────────────────────

func TestPrintTree_OrphanedByFilterStillRenders(t *testing.T) {
	// Simulate what loadSeats(ctx, raw, "PRD-002") would return: a worker row
	// under TASK-201 whose parent (a PRD-001 ringleader) was excluded by the
	// filter and is therefore absent from this row set.
	rows := []seatRow{
		{
			id:           "PRD-002/TASK-201/worker.1~aaaa",
			role:         "worker",
			taskID:       sql.NullString{String: "TASK-201", Valid: true},
			prdID:        "PRD-002",
			parentID:     sql.NullString{String: "PRD-001/ringleader.1~zzzz", Valid: true},
			credentialID: "cred:w",
			status:       "active",
		},
	}

	out := captureStdout(t, func() { printTree(rows) })
	if !strings.Contains(out, "PRD-002/TASK-201/worker.1~aaaa") {
		t.Errorf("expected the orphaned row to render, got:\n%s", out)
	}
}

func TestPrintNode_IncludesSeatID(t *testing.T) {
	rows := []seatRow{
		{
			id:           "PRD-001/ringleader.1~aaaa",
			role:         "ringleader",
			prdID:        "PRD-001",
			credentialID: "cred:rl",
			status:       "active",
		},
	}
	out := captureStdout(t, func() { printTree(rows) })
	if !strings.Contains(out, "id=PRD-001/ringleader.1~aaaa") {
		t.Errorf("expected printed tree to include the seat id, got:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	return buf.String()
}
