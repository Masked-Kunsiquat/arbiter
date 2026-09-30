package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/core"
	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

// TestRunSeats_ThroughCore runs the command end to end in a scratch repo:
// it must reach the seats through the core (hosting one in-process, since
// none is running) and print the agent tree.
func TestRunSeats_ThroughCore(t *testing.T) {
	ctx := context.Background()
	// Short root rather than t.TempDir: the path embeds the test name and
	// can overflow the ~104-byte Unix socket path limit for core.sock.
	repo, err := os.MkdirTemp("", "arb") //nolint:usetesting // see above
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(repo) })
	arbiterDir := filepath.Join(repo, ".arbiter")
	if err = os.MkdirAll(arbiterDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	adb, err := db.Open(ctx, filepath.Join(arbiterDir, "state.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	raw := adb.SQLDB()
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES ('PRD-001', 'T', 'p.md', 'h', 'locked', 'main')`); err != nil {
		t.Fatalf("seed prd: %v", err)
	}
	if err := seat.RegisterCredential(ctx, raw, seat.Credential{
		ID: "cred:rl", Kind: seat.KindAgent, EligibleRoles: []seat.Role{seat.RoleRingleader},
	}); err != nil {
		t.Fatalf("register cred: %v", err)
	}
	rlID, err := seat.MintSeat(ctx, raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role: seat.RoleRingleader, PRDID: "PRD-001", CredentialID: "cred:rl", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint ringleader: %v", err)
	}
	_ = adb.Close()

	t.Chdir(repo)
	var runErr error
	out := captureStdout(t, func() { runErr = runSeats(ctx, []string{"PRD-001"}) })
	if runErr != nil {
		t.Fatalf("runSeats: %v", runErr)
	}
	if !strings.Contains(out, "id="+rlID) {
		t.Errorf("expected the ringleader in the tree, got:\n%s", out)
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

	t.Chdir(dir)

	_, err := findStateDB()
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
	// Simulate what seats.list with prd_id PRD-002 would return: a worker row
	// under TASK-201 whose parent (a PRD-001 ringleader) was excluded by the
	// filter and is therefore absent from this row set.
	rows := []core.SeatInfo{
		{
			ID:           "PRD-002/TASK-201/worker.1~aaaa",
			Role:         "worker",
			TaskID:       "TASK-201",
			PRDID:        "PRD-002",
			ParentSeatID: "PRD-001/ringleader.1~zzzz",
			CredentialID: "cred:w",
			Status:       "active",
		},
	}

	out := captureStdout(t, func() { printTree(rows) })
	if !strings.Contains(out, "PRD-002/TASK-201/worker.1~aaaa") {
		t.Errorf("expected the orphaned row to render, got:\n%s", out)
	}
}

func TestPrintNode_IncludesSeatID(t *testing.T) {
	rows := []core.SeatInfo{
		{
			ID:           "PRD-001/ringleader.1~aaaa",
			Role:         "ringleader",
			PRDID:        "PRD-001",
			CredentialID: "cred:rl",
			Status:       "active",
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
