package db_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/db"
)

// open returns a DB backed by a temp file that is automatically cleaned up.
func open(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	adb, err := db.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { adb.Close() })
	return adb
}

// ─────────────────────────────────────────────────────────────────────────────
// PRAGMAs
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_WALMode(t *testing.T) {
	adb := open(t)
	mode, err := adb.PragmaString(context.Background(), "journal_mode")
	if err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want \"wal\"", mode)
	}
}

func TestOpen_BusyTimeout(t *testing.T) {
	adb := open(t)
	v, err := adb.PragmaInt(context.Background(), "busy_timeout")
	if err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if v != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", v)
	}
}

func TestOpen_ForeignKeys(t *testing.T) {
	adb := open(t)
	v, err := adb.PragmaInt(context.Background(), "foreign_keys")
	if err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if v != 1 {
		t.Errorf("foreign_keys = %d, want 1", v)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema: all expected tables exist
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_AllTablesExist(t *testing.T) {
	adb := open(t)
	want := []string{
		"prds",
		"tasks",
		"task_edges",
		"task_symbol_deps",
		"reservations",
		"task_memories",
		"project_lessons",
		"lesson_injections",
		"lesson_outcomes",
		"disputes",
		"credentials",
		"seats",
		"invocations",
		"audit_log",
	}
	raw := adb.SQLDB()
	for _, tbl := range want {
		var name string
		err := raw.QueryRowContext(context.Background(),
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing: %v", tbl, err)
		}
	}
}

func TestOpen_FingerprintIndexExists(t *testing.T) {
	adb := open(t)
	var name string
	err := adb.SQLDB().QueryRowContext(context.Background(),
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_task_memories_fp'`,
	).Scan(&name)
	if err != nil {
		t.Errorf("index idx_task_memories_fp missing: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema: CHECK constraints enforce valid enum values
// ─────────────────────────────────────────────────────────────────────────────

// seed inserts a minimal prd and task into the DB; these are prerequisites for
// most constraint tests.
func seed(t *testing.T, raw *sql.DB) (prdID, taskID string) {
	t.Helper()
	prdID, taskID = "PRD-001", "TASK-001"
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES (?, 'Test PRD', '.arbiter/prds/PRD-001.md', 'abc', 'draft', 'main')`,
		prdID)
	if err != nil {
		t.Fatalf("seed prd: %v", err)
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO tasks (id, prd_id, title, intent, status)
		VALUES (?, ?, 'Test task', 'Do the thing', 'backlog')`,
		taskID, prdID)
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
	return
}

func TestPRD_StatusCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES ('PRD-BAD', 'x', 'x', 'x', 'invalid_status', 'main')`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid prd.status, got nil")
	}
}

func TestTask_StatusCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO tasks (id, prd_id, title, intent, status)
		VALUES ('TASK-BAD', 'PRD-001', 'x', 'x', 'flying')`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid task.status, got nil")
	}
}

func TestTaskEdge_SelfLoop(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(),
		`INSERT INTO task_edges (task_id, depends_on) VALUES ('TASK-001', 'TASK-001')`)
	if err == nil {
		t.Fatal("expected CHECK violation for self-loop, got nil")
	}
}

func TestTaskEdge_FKViolation(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(),
		`INSERT INTO task_edges (task_id, depends_on) VALUES ('TASK-001', 'TASK-NONEXISTENT')`)
	if err == nil {
		t.Fatal("expected FK violation inserting nonexistent depends_on, got nil")
	}
}

func TestCredential_KindCheck(t *testing.T) {
	adb := open(t)
	_, err := adb.SQLDB().ExecContext(context.Background(), `
		INSERT INTO credentials (id, kind, eligible_roles)
		VALUES ('cred:x', 'robot', '[]')`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid credential.kind, got nil")
	}
}

func TestSeat_RoleCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO credentials (id, kind, eligible_roles)
		VALUES ('cred:agent/m', 'agent', '["worker"]')`)
	if err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO seats (id, role, prd_id, minted_by, credential_id, binding, status)
		VALUES ('seat-1', 'overlord', 'PRD-001', 'human', 'cred:agent/m', 'process', 'minted')`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid seat.role, got nil")
	}
}

func TestInvocation_ExitReasonCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO credentials (id, kind, eligible_roles)
		VALUES ('cred:agent/w', 'agent', '["worker"]')`)
	if err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO seats (id, role, prd_id, minted_by, credential_id, binding, status)
		VALUES ('seat-w1', 'worker', 'PRD-001', 'human', 'cred:agent/w', 'process', 'active')`)
	if err != nil {
		t.Fatalf("insert seat: %v", err)
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO invocations (id, seat_id, purpose, exit_reason)
		VALUES ('inv-1', 'seat-w1', 'implement', 'vanished')`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid exit_reason, got nil")
	}
}

func TestTaskMemory_ObservationTypeCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO task_memories (id, task_id, attempt, content, observation_type)
		VALUES ('mem-1', 'TASK-001', 1, 'data', 'dream')`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid observation_type, got nil")
	}
}

func TestLessonInjection_TierCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO lesson_injections (id, lesson_id, lesson_tier, task_id, rank)
		VALUES ('inj-1', 'lesson-1', 'cosmic', 'TASK-001', 1)`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid lesson_tier, got nil")
	}
}

func TestLessonOutcome_AuthorRoleCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO lesson_outcomes
		  (id, lesson_id, lesson_tier, task_id, seat_id, author_role, outcome_type,
		   description, audit_chain, audit_seq)
		VALUES ('out-1','les-1','project','TASK-001','core','robot','catch','x','global',1)`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid author_role, got nil")
	}
}

func TestDispute_RulingCheck(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	seed(t, raw)
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO disputes (id, task_id, attack_test_id, worker_seat_id, worker_argument, ruling)
		VALUES ('dis-1', 'TASK-001', 'atk-1', 'seat-w1', 'arg', 'maybe')`)
	if err == nil {
		t.Fatal("expected CHECK violation for invalid ruling, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Open is idempotent: calling it twice on the same file works
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	adb1, err := db.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	adb1.Close()

	adb2, err := db.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	adb2.Close()
}

// ─────────────────────────────────────────────────────────────────────────────
// DFS cycle detection via AddTaskEdge
// ─────────────────────────────────────────────────────────────────────────────

// seedTasks creates n tasks (TASK-001 … TASK-00n) under PRD-001.
func seedTasks(t *testing.T, raw *sql.DB, n int) {
	t.Helper()
	_, err := raw.ExecContext(context.Background(), `
		INSERT OR IGNORE INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES ('PRD-001', 'P', 'p', 'h', 'draft', 'main')`)
	if err != nil {
		t.Fatalf("seed prd: %v", err)
	}
	for i := 1; i <= n; i++ {
		id := taskIDN(i)
		_, err := raw.ExecContext(context.Background(), `
			INSERT OR IGNORE INTO tasks (id, prd_id, title, intent, status)
			VALUES (?, 'PRD-001', 'T', 'T', 'backlog')`, id)
		if err != nil {
			t.Fatalf("seed task %d: %v", i, err)
		}
	}
}

func taskIDN(n int) string {
	return "TASK-" + strings.Repeat("0", max(0, 3-len(itoa(n)))) + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func TestAddTaskEdge_Simple(t *testing.T) {
	adb := open(t)
	seedTasks(t, adb.SQLDB(), 2)
	if err := adb.AddTaskEdge(context.Background(), "TASK-002", "TASK-001"); err != nil {
		t.Fatalf("AddTaskEdge(002→001): %v", err)
	}
}

func TestAddTaskEdge_DirectCycle(t *testing.T) {
	adb := open(t)
	seedTasks(t, adb.SQLDB(), 2)
	if err := adb.AddTaskEdge(context.Background(), "TASK-002", "TASK-001"); err != nil {
		t.Fatalf("setup edge 002→001: %v", err)
	}
	err := adb.AddTaskEdge(context.Background(), "TASK-001", "TASK-002")
	if !errors.Is(err, db.ErrCycle) {
		t.Fatalf("expected ErrCycle, got %v", err)
	}
}

func TestAddTaskEdge_IndirectCycle(t *testing.T) {
	// 1→2, 2→3, 3→1 should be rejected.
	adb := open(t)
	seedTasks(t, adb.SQLDB(), 3)
	must(t, adb.AddTaskEdge(context.Background(), "TASK-002", "TASK-001"))
	must(t, adb.AddTaskEdge(context.Background(), "TASK-003", "TASK-002"))
	err := adb.AddTaskEdge(context.Background(), "TASK-001", "TASK-003")
	if !errors.Is(err, db.ErrCycle) {
		t.Fatalf("expected ErrCycle for indirect cycle, got %v", err)
	}
}

func TestAddTaskEdge_Diamond_NoCycle(t *testing.T) {
	// Diamond: 4→2, 4→3, 2→1, 3→1 — valid DAG, no cycle.
	adb := open(t)
	seedTasks(t, adb.SQLDB(), 4)
	must(t, adb.AddTaskEdge(context.Background(), "TASK-002", "TASK-001"))
	must(t, adb.AddTaskEdge(context.Background(), "TASK-003", "TASK-001"))
	must(t, adb.AddTaskEdge(context.Background(), "TASK-004", "TASK-002"))
	must(t, adb.AddTaskEdge(context.Background(), "TASK-004", "TASK-003"))
}

func TestAddTaskEdge_SelfLoop_RejectsAtDB(t *testing.T) {
	// A self-loop is caught by the CHECK constraint before DFS is ever reached.
	adb := open(t)
	seedTasks(t, adb.SQLDB(), 1)
	err := adb.AddTaskEdge(context.Background(), "TASK-001", "TASK-001")
	if err == nil {
		t.Fatal("expected error for self-loop, got nil")
	}
}

func TestAddTaskEdge_LongChain_NoCycle(t *testing.T) {
	// 10→9→8→…→1, no cycle.
	const n = 10
	adb := open(t)
	seedTasks(t, adb.SQLDB(), n)
	for i := n; i > 1; i-- {
		must(t, adb.AddTaskEdge(context.Background(), taskIDN(i), taskIDN(i-1)))
	}
}

func TestAddTaskEdge_LongChainCycle(t *testing.T) {
	// 10→9→…→1, then 1→10 should be rejected.
	const n = 10
	adb := open(t)
	seedTasks(t, adb.SQLDB(), n)
	for i := n; i > 1; i-- {
		must(t, adb.AddTaskEdge(context.Background(), taskIDN(i), taskIDN(i-1)))
	}
	err := adb.AddTaskEdge(context.Background(), "TASK-001", taskIDN(n))
	if !errors.Is(err, db.ErrCycle) {
		t.Fatalf("expected ErrCycle for chain cycle, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FK cascade: deleting a task removes its edges
// ─────────────────────────────────────────────────────────────────────────────

func TestTaskEdge_CascadeDelete(t *testing.T) {
	adb := open(t)
	seedTasks(t, adb.SQLDB(), 2)
	must(t, adb.AddTaskEdge(context.Background(), "TASK-002", "TASK-001"))

	raw := adb.SQLDB()
	if _, err := raw.ExecContext(context.Background(),
		`DELETE FROM tasks WHERE id = 'TASK-001'`); err != nil {
		t.Fatalf("delete task: %v", err)
	}
	var count int
	if err := raw.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM task_edges`).Scan(&count); err != nil {
		t.Fatalf("count edges: %v", err)
	}
	if count != 0 {
		t.Errorf("task_edges count = %d after cascade delete, want 0", count)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// audit_log primary key is (chain, seq)
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditLog_PK(t *testing.T) {
	adb := open(t)
	raw := adb.SQLDB()
	ins := func(chain string, seq int) error {
		_, err := raw.ExecContext(context.Background(), `
			INSERT INTO audit_log
			  (v, chain, seq, seat_id, action, payload_json, created_at,
			   prev_hash, entry_hash, supervisor_signature)
			VALUES (1, ?, ?, 'human', 'prd_lock', '{}',
			        '2026-01-01T00:00:00.000000Z',
			        '`+strings.Repeat("0", 64)+`',
			        '`+strings.Repeat("a", 64)+`',
			        '---- BEGIN SSH SIGNATURE ----')`,
			chain, seq)
		return err
	}
	if err := ins("global", 1); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := ins("global", 1); err == nil {
		t.Fatal("expected PK violation on duplicate (chain,seq), got nil")
	}
	// Different chain is fine.
	if err := ins("PRD-001", 1); err != nil {
		t.Fatalf("insert PRD-001 seq 1: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
