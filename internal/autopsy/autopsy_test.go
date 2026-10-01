package autopsy_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/autopsy"
	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
	"github.com/Masked-Kunsiquat/arbiter/internal/worktree"
)

// ─────────────────────────────────────────────────────────────────────────────
// DB fixtures, following internal/seat/seat_test.go's shape.
// ─────────────────────────────────────────────────────────────────────────────

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	adb, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { adb.Close() })
	return adb.SQLDB()
}

func seedPRDAndTask(t *testing.T, raw *sql.DB, prdID, taskID, baseCommit string) {
	t.Helper()
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES (?, 'Test', 'p.md', 'h', 'locked', 'main')`, prdID)
	if err != nil {
		t.Fatalf("seed prd: %v", err)
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO tasks (id, prd_id, title, intent, status, base_commit)
		VALUES (?, ?, 'Task', 'intent', 'in_progress', ?)`, taskID, prdID, baseCommit)
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
}

func registerAgentCred(t *testing.T, raw *sql.DB, id string, roles ...seat.Role) {
	t.Helper()
	err := seat.RegisterCredential(context.Background(), raw, seat.Credential{
		ID:              id,
		Kind:            seat.KindAgent,
		Harness:         "claude-code",
		Model:           "claude-opus-5-5",
		ModelProvenance: seat.ProvenanceLaunched,
		EligibleRoles:   roles,
	})
	if err != nil {
		t.Fatalf("register credential: %v", err)
	}
}

// mintWorkerSeat mints a ringleader then a worker seat bound to taskID,
// activating the worker via its first invocation, and returns the worker
// seat id plus its invocation id.
func mintWorkerSeat(t *testing.T, raw *sql.DB, prdID, taskID string) (seatID, invocationID string) {
	t.Helper()
	workerID := mintWorkerSeatOnly(t, raw, prdID, taskID)
	invID := startInvocation(t, raw, workerID, taskID)
	return workerID, invID
}

// mintWorkerSeatOnly mints a ringleader then a worker seat bound to taskID,
// without starting an invocation (so a caller can start more than one, e.g.
// to simulate a retried autopsy against the same seat).
func mintWorkerSeatOnly(t *testing.T, raw *sql.DB, prdID, taskID string) (seatID string) {
	t.Helper()
	registerAgentCred(t, raw, "cred:rl-"+prdID, seat.RoleRingleader)
	rlID, err := seat.MintSeat(context.Background(), raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role: seat.RoleRingleader, PRDID: prdID, CredentialID: "cred:rl-" + prdID, Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint ringleader: %v", err)
	}

	registerAgentCred(t, raw, "cred:w-"+taskID, seat.RoleWorker)
	workerID, err := seat.MintSeat(context.Background(), raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: prdID, TaskID: taskID,
		ParentSeatID: rlID, CredentialID: "cred:w-" + taskID, Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint worker: %v", err)
	}
	return workerID
}

func startInvocation(t *testing.T, raw *sql.DB, seatID, taskID string) (invocationID string) {
	t.Helper()
	invID, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID:         seatID,
		TaskID:         taskID,
		Purpose:        seat.PurposeImplement,
		PID:            1234,
		LeaseExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("start invocation: %v", err)
	}
	return invID
}

// ─────────────────────────────────────────────────────────────────────────────
// Git fixtures.
// ─────────────────────────────────────────────────────────────────────────────

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
}

// initGitRepo initializes a temporary git repository with an initial commit,
// following internal/worktree/worktree_test.go's initGitRepo.
func initGitRepo(t *testing.T) (repoRoot, initialCommit string) {
	t.Helper()
	repoRoot = t.TempDir()

	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Arbiter Test",
			"GIT_AUTHOR_EMAIL=test@localhost",
			"GIT_COMMITTER_NAME=Arbiter Test",
			"GIT_COMMITTER_EMAIL=test@localhost",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s failed: %v: %s", strings.Join(args, " "), err, string(out))
		}
		return strings.TrimSpace(string(out))
	}

	runGit("init")
	runGit("config", "user.name", "Arbiter Test")
	runGit("config", "user.email", "test@localhost")
	runGit("config", "core.autocrlf", "false")

	trackedFile := filepath.Join(repoRoot, "tracked.txt")
	if err := os.WriteFile(trackedFile, []byte("initial content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "tracked.txt")
	runGit("commit", "-m", "initial commit")

	initialCommit = runGit("rev-parse", "HEAD")
	return repoRoot, initialCommit
}

// newSlot creates and ensures a warm worktree slot for repoRoot at
// initialCommit, using its own arbiterDir (so EmptyHooksDir has somewhere
// private to live) and returns the ready Slot.
func newSlot(t *testing.T, repoRoot, initialCommit string) *worktree.Slot {
	t.Helper()
	slot := worktree.NewSlot(repoRoot, worktree.DefaultSlotIndex)
	if err := slot.EnsureWorktree(context.Background(), initialCommit); err != nil {
		t.Fatalf("EnsureWorktree: %v", err)
	}
	return slot
}

func isClean(t *testing.T, git worktree.GitRunner, dir string) bool {
	t.Helper()
	out, err := git(context.Background(), dir, "status", "--porcelain")
	if err != nil {
		t.Fatalf("git status: %v", err)
	}
	return strings.TrimSpace(out) == ""
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner.Run
// ─────────────────────────────────────────────────────────────────────────────

func TestRun_EmptyDiffResets(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK-001", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-001")

	r := &autopsy.Runner{DB: raw, Git: slot.Git}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-001",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		Tail:         "no output",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Decision != autopsy.DecisionReset {
		t.Errorf("Decision = %q, want reset", res.Decision)
	}
	if res.CommitSHA != "" {
		t.Errorf("CommitSHA = %q, want empty on reset", res.CommitSHA)
	}

	var status, exitReason string
	var costEstimated int
	if err := raw.QueryRowContext(context.Background(),
		`SELECT exit_reason, cost_estimated FROM invocations WHERE id = ?`, invID,
	).Scan(&exitReason, &costEstimated); err != nil {
		t.Fatalf("query invocation: %v", err)
	}
	if exitReason != string(seat.ExitLeaseExpired) {
		t.Errorf("exit_reason = %q, want lease_expired", exitReason)
	}
	if costEstimated != 0 {
		t.Errorf("cost_estimated = %d, want 0 (no streamed cost)", costEstimated)
	}

	if err := raw.QueryRowContext(context.Background(),
		`SELECT status FROM seats WHERE id = ?`, seatID,
	).Scan(&status); err != nil {
		t.Fatalf("query seat: %v", err)
	}
	if status != string(seat.StatusExpired) {
		t.Errorf("seat status = %q, want expired", status)
	}

	var memCount int
	var observationType string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT COUNT(*), observation_type FROM task_memories WHERE id = ? GROUP BY observation_type`, res.MemoryID,
	).Scan(&memCount, &observationType); err != nil {
		t.Fatalf("query memory: %v", err)
	}
	if memCount != 1 || observationType != "autopsy" {
		t.Errorf("memory row = (%d, %q), want (1, autopsy)", memCount, observationType)
	}
}

func TestRun_NonEmptyDiffBuildPassesCheckpoints(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	if err := os.WriteFile(filepath.Join(slot.Path, "tracked.txt"), []byte("edited content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedPRDAndTask(t, raw, "PRD-001", "TASK-002", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-002")

	buildCalls := 0
	r := &autopsy.Runner{
		DB:  raw,
		Git: slot.Git,
		Build: func(_ context.Context, dir, command string) (string, error) {
			buildCalls++
			if dir != slot.Path {
				t.Errorf("build dir = %q, want %q", dir, slot.Path)
			}
			if command != "go build ./..." {
				t.Errorf("build command = %q, want go build ./...", command)
			}
			return "build ok", nil
		},
	}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-002",
		Attempt:      2,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		BuildCommand: "go build ./...",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if buildCalls != 1 {
		t.Fatalf("build calls = %d, want 1", buildCalls)
	}
	if res.Decision != autopsy.DecisionCheckpoint {
		t.Fatalf("Decision = %q, want checkpoint", res.Decision)
	}
	wantRef := "checkpoint/TASK-002/attempt-2"
	if res.CheckpointRef != wantRef {
		t.Errorf("CheckpointRef = %q, want %q", res.CheckpointRef, wantRef)
	}
	if res.CommitSHA == "" {
		t.Error("CommitSHA is empty, want a commit sha")
	}

	out, err := slot.Git(context.Background(), slot.Path, "rev-parse", wantRef)
	if err != nil {
		t.Fatalf("rev-parse %s: %v", wantRef, err)
	}
	if strings.TrimSpace(out) != res.CommitSHA {
		t.Errorf("branch %s points at %q, want %q", wantRef, strings.TrimSpace(out), res.CommitSHA)
	}

	if !isClean(t, slot.Git, slot.Path) {
		t.Error("worktree is not clean after checkpoint commit")
	}

	if gotParent := parentOf(t, slot.Git, slot.Path, res.CommitSHA); gotParent != base {
		t.Errorf("checkpoint parent = %q, want base commit %q", gotParent, base)
	}
}

// parentOf returns sha's sole parent commit.
func parentOf(t *testing.T, git worktree.GitRunner, dir, sha string) string {
	t.Helper()
	out, err := git(context.Background(), dir, "rev-parse", sha+"^")
	if err != nil {
		t.Fatalf("rev-parse %s^: %v", sha, err)
	}
	return strings.TrimSpace(out)
}

// TestRun_AgentCommittedItsOwnWork checkpoints correctly even though the
// agent committed on top of base itself and moved HEAD: the checkpoint must
// be built from the staged tree with base as its sole parent, not from
// whatever HEAD happens to be (coordinator review point 1).
func TestRun_AgentCommittedItsOwnWork(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	if err := os.WriteFile(filepath.Join(slot.Path, "tracked.txt"), []byte("edited by agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := slot.Git(context.Background(), slot.Path, "add", "-A"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if _, err := slot.Git(context.Background(), slot.Path,
		"-c", "user.name=Agent", "-c", "user.email=agent@localhost",
		"commit", "-m", "agent's own commit"); err != nil {
		t.Fatalf("git commit: %v", err)
	}
	// A further uncommitted edit on top, so the staged tree still differs
	// from the agent's own commit as well as from base.
	if err := os.WriteFile(filepath.Join(slot.Path, "tracked.txt"), []byte("edited again\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedPRDAndTask(t, raw, "PRD-001", "TASK-009", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-009")

	r := &autopsy.Runner{
		DB:  raw,
		Git: slot.Git,
		Build: func(context.Context, string, string) (string, error) {
			return "ok", nil
		},
	}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-009",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		BuildCommand: "go build ./...",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Decision != autopsy.DecisionCheckpoint {
		t.Fatalf("Decision = %q, want checkpoint", res.Decision)
	}
	if gotParent := parentOf(t, slot.Git, slot.Path, res.CommitSHA); gotParent != base {
		t.Errorf("checkpoint parent = %q, want base commit %q", gotParent, base)
	}
	if !isClean(t, slot.Git, slot.Path) {
		t.Error("worktree is not clean after checkpoint")
	}
	out, err := slot.Git(context.Background(), slot.Path, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	if strings.TrimSpace(out) != res.CommitSHA {
		t.Errorf("slot HEAD = %q, want checkpoint sha %q", strings.TrimSpace(out), res.CommitSHA)
	}
	if got, err := os.ReadFile(filepath.Join(slot.Path, "tracked.txt")); err != nil || string(got) != "edited again\n" {
		t.Errorf("tracked.txt = %q, %v, want the final uncommitted edit", got, err)
	}
}

// TestRun_RetryAfterCheckpointDoesNotFailOnGit exercises re-running the
// autopsy for the same seat after it already expired and already has a
// checkpoint, using a fresh invocation row (the supervisor may legitimately
// retry an autopsy). The seat transition must tolerate the already-expired
// seat, and the git steps must tolerate a slot that's already sitting at
// the previous checkpoint.
func TestRun_RetryAfterCheckpointDoesNotFailOnGit(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	if err := os.WriteFile(filepath.Join(slot.Path, "tracked.txt"), []byte("edit 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedPRDAndTask(t, raw, "PRD-001", "TASK-010", base)
	seatID := mintWorkerSeatOnly(t, raw, "PRD-001", "TASK-010")
	// Both invocation rows are started while the seat is still active/minted:
	// StartInvocation requires that, so the second ("retry") invocation has
	// to exist before the first autopsy expires the seat.
	invID1 := startInvocation(t, raw, seatID, "TASK-010")
	invID2 := startInvocation(t, raw, seatID, "TASK-010")

	r := &autopsy.Runner{
		DB:  raw,
		Git: slot.Git,
		Build: func(context.Context, string, string) (string, error) {
			return "ok", nil
		},
	}
	res1, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID1,
		SeatID:       seatID,
		TaskID:       "TASK-010",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		BuildCommand: "go build ./...",
	})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if res1.Decision != autopsy.DecisionCheckpoint {
		t.Fatalf("first Decision = %q, want checkpoint", res1.Decision)
	}

	// Retry: autopsy runs again for the seat's second invocation, which is
	// now already expired, with the slot already sitting exactly at the
	// checkpoint and nothing new to commit.
	res2, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID2,
		SeatID:       seatID,
		TaskID:       "TASK-010",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		BuildCommand: "go build ./...",
	})
	if err != nil {
		t.Fatalf("retried Run: %v", err)
	}
	if res2.Decision != autopsy.DecisionCheckpoint {
		t.Fatalf("retried Decision = %q, want checkpoint", res2.Decision)
	}

	var status string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT status FROM seats WHERE id = ?`, seatID,
	).Scan(&status); err != nil {
		t.Fatalf("query seat: %v", err)
	}
	if status != string(seat.StatusExpired) {
		t.Errorf("seat status = %q, want expired", status)
	}
}

// TestRun_CaptureFailureStillTransitionsSeatAndRecordsError exercises the
// containment fallback (coordinator review point 2): if staging the slot
// fails, Run must still transition the seat and still leave a memory row
// recording the error, and return a non-nil error.
func TestRun_CaptureFailureStillTransitionsSeatAndRecordsError(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK-011", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-011")

	failAdd := errors.New("simulated add failure")
	failingGit := func(ctx context.Context, dir string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "add" {
			return "", failAdd
		}
		return slot.Git(ctx, dir, args...)
	}

	r := &autopsy.Runner{DB: raw, Git: failingGit}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-011",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
	})
	if err == nil {
		t.Fatal("expected an error from the simulated add failure, got nil")
	}
	if !errors.Is(err, failAdd) {
		t.Errorf("Run error = %v, want it to wrap %v", err, failAdd)
	}
	if res == nil {
		t.Fatal("expected a non-nil Result even on failure")
	}
	if res.Decision != autopsy.DecisionReset {
		t.Errorf("Decision = %q, want reset (fallback)", res.Decision)
	}
	if res.MemoryID == "" {
		t.Fatal("expected a memory row to be recorded despite the failure")
	}

	var status, content string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT status FROM seats WHERE id = ?`, seatID,
	).Scan(&status); err != nil {
		t.Fatalf("query seat: %v", err)
	}
	if status != string(seat.StatusExpired) {
		t.Errorf("seat status = %q, want expired even after capture failure", status)
	}

	if err := raw.QueryRowContext(context.Background(),
		`SELECT content FROM task_memories WHERE id = ?`, res.MemoryID,
	).Scan(&content); err != nil {
		t.Fatalf("query memory content: %v", err)
	}
	var decoded struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(content), &decoded); err != nil {
		t.Fatalf("decode memory content: %v", err)
	}
	if decoded.Error == "" {
		t.Error("expected memory content.error to be populated")
	}
}

// TestRun_CleanRemovesUntrackedBuildArtifactButKeepsKeepList covers point 4:
// after the reset, git clean -fdx removes build debris but a configured
// keep-list directory (e.g. node_modules) survives.
func TestRun_CleanRemovesUntrackedBuildArtifactButKeepsKeepList(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	// A genuine (but ultimately failing-to-build) edit, plus untracked debris
	// the failed build left behind and a keep-list dependency dir.
	if err := os.WriteFile(filepath.Join(slot.Path, "tracked.txt"), []byte("edited content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot.Path, "build-debris.o"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	keepDir := filepath.Join(slot.Path, "node_modules")
	if err := os.MkdirAll(keepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keepFile := filepath.Join(keepDir, "dep.js")
	if err := os.WriteFile(keepFile, []byte("dep"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedPRDAndTask(t, raw, "PRD-001", "TASK-012", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-012")

	r := &autopsy.Runner{
		DB:  raw,
		Git: slot.Git,
		Build: func(context.Context, string, string) (string, error) {
			return "build failed", errors.New("exit status 1")
		},
	}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-012",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		BuildCommand: "go build ./...",
		KeepList:     []string{"node_modules"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Decision != autopsy.DecisionReset {
		t.Fatalf("Decision = %q, want reset", res.Decision)
	}

	if _, err := os.Stat(filepath.Join(slot.Path, "build-debris.o")); !os.IsNotExist(err) {
		t.Errorf("build-debris.o still exists after clean: %v", err)
	}
	if _, err := os.Stat(keepFile); err != nil {
		t.Errorf("keep-list file removed by clean: %v", err)
	}
}

func TestRun_NonEmptyDiffBuildFailsResets(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	if err := os.WriteFile(filepath.Join(slot.Path, "tracked.txt"), []byte("edited content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot.Path, "untracked.txt"), []byte("scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedPRDAndTask(t, raw, "PRD-001", "TASK-003", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-003")

	r := &autopsy.Runner{
		DB:  raw,
		Git: slot.Git,
		Build: func(context.Context, string, string) (string, error) {
			return "compile error: undefined foo", errors.New("exit status 1")
		},
	}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-003",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		BuildCommand: "go build ./...",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Decision != autopsy.DecisionReset {
		t.Fatalf("Decision = %q, want reset", res.Decision)
	}
	if res.BuildOutput != "compile error: undefined foo" {
		t.Errorf("BuildOutput = %q, want build failure output", res.BuildOutput)
	}

	if got, err := os.ReadFile(filepath.Join(slot.Path, "tracked.txt")); err != nil || string(got) != "initial content\n" {
		t.Errorf("tracked.txt = %q, %v, want original content restored", got, err)
	}
	if _, err := os.Stat(filepath.Join(slot.Path, "untracked.txt")); !os.IsNotExist(err) {
		t.Errorf("untracked.txt still exists after reset: %v", err)
	}

	var storedBuildOutput, content string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT content FROM task_memories WHERE id = ?`, res.MemoryID,
	).Scan(&content); err != nil {
		t.Fatalf("query memory content: %v", err)
	}
	var decoded struct {
		BuildOutput string `json:"build_output"`
	}
	if err := json.Unmarshal([]byte(content), &decoded); err != nil {
		t.Fatalf("decode memory content: %v", err)
	}
	storedBuildOutput = decoded.BuildOutput
	if storedBuildOutput != "compile error: undefined foo" {
		t.Errorf("stored build_output = %q, want build failure output", storedBuildOutput)
	}
}

func TestRun_CrashRevokesSeat(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK-004", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-004")

	r := &autopsy.Runner{DB: raw, Git: slot.Git}
	_, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-004",
		Attempt:      1,
		Cause:        autopsy.CauseCrash,
		BaseCommit:   base,
		SlotPath:     slot.Path,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var status, exitReason string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT status FROM seats WHERE id = ?`, seatID,
	).Scan(&status); err != nil {
		t.Fatalf("query seat: %v", err)
	}
	if status != string(seat.StatusRevoked) {
		t.Errorf("seat status = %q, want revoked", status)
	}
	if err := raw.QueryRowContext(context.Background(),
		`SELECT exit_reason FROM invocations WHERE id = ?`, invID,
	).Scan(&exitReason); err != nil {
		t.Fatalf("query invocation: %v", err)
	}
	if exitReason != string(seat.ExitCrash) {
		t.Errorf("exit_reason = %q, want crash", exitReason)
	}
}

func TestRun_StreamedCostRecordedAsEstimated(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK-005", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-005")

	cost := 0.42
	r := &autopsy.Runner{DB: raw, Git: slot.Git}
	_, err := r.Run(context.Background(), autopsy.Request{
		InvocationID:    invID,
		SeatID:          seatID,
		TaskID:          "TASK-005",
		Attempt:         1,
		Cause:           autopsy.CauseLeaseExpired,
		BaseCommit:      base,
		SlotPath:        slot.Path,
		StreamedCostUSD: &cost,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var gotCost float64
	var costEstimated int
	if err := raw.QueryRowContext(context.Background(),
		`SELECT cost_usd, cost_estimated FROM invocations WHERE id = ?`, invID,
	).Scan(&gotCost, &costEstimated); err != nil {
		t.Fatalf("query invocation: %v", err)
	}
	if gotCost != cost {
		t.Errorf("cost_usd = %v, want %v", gotCost, cost)
	}
	if costEstimated != 1 {
		t.Errorf("cost_estimated = %d, want 1", costEstimated)
	}
}

func TestRun_InvalidTaskIDRejected(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK/006", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK/006")

	r := &autopsy.Runner{DB: raw, Git: slot.Git}
	_, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK/006",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
	})
	if err == nil {
		t.Fatal("expected error for task id with unsafe ref characters, got nil")
	}
}

func TestRun_MissingFieldsRejected(t *testing.T) {
	raw := openDB(t)
	r := &autopsy.Runner{DB: raw, Git: func(context.Context, string, ...string) (string, error) { return "", nil }}
	_, err := r.Run(context.Background(), autopsy.Request{})
	if err == nil {
		t.Fatal("expected validation error for empty request, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RecordSummary / LatestSummary / WarningPrompt
// ─────────────────────────────────────────────────────────────────────────────

func TestRecordSummary_TruncatesAndCollapsesWhitespace(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK-007", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-007")

	r := &autopsy.Runner{DB: raw, Git: slot.Git}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-007",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	long := strings.Repeat("a ", 300) + "\nsecond line\tand a tab"
	if err := autopsy.RecordSummary(context.Background(), raw, res.MemoryID, long); err != nil {
		t.Fatalf("RecordSummary: %v", err)
	}

	var stored string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT root_cause_summary FROM task_memories WHERE id = ?`, res.MemoryID,
	).Scan(&stored); err != nil {
		t.Fatalf("query: %v", err)
	}
	if strings.Contains(stored, "\n") || strings.Contains(stored, "\t") {
		t.Errorf("stored summary contains raw whitespace: %q", stored)
	}
	if len([]rune(stored)) != 200 {
		t.Errorf("stored summary rune length = %d, want 200", len([]rune(stored)))
	}
}

func TestRecordSummary_UnknownMemory(t *testing.T) {
	raw := openDB(t)
	err := autopsy.RecordSummary(context.Background(), raw, "mem-nope", "summary")
	if err == nil {
		t.Fatal("expected error for unknown memory id, got nil")
	}
}

func TestLatestSummary(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK-008", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-008")

	if got, err := autopsy.LatestSummary(context.Background(), raw, "TASK-008"); err != nil || got != "" {
		t.Fatalf("LatestSummary before any memory = (%q, %v), want (\"\", nil)", got, err)
	}

	r := &autopsy.Runner{DB: raw, Git: slot.Git}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-008",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got, err := autopsy.LatestSummary(context.Background(), raw, "TASK-008"); err != nil || got != "" {
		t.Fatalf("LatestSummary before RecordSummary = (%q, %v), want (\"\", nil)", got, err)
	}

	if err := autopsy.RecordSummary(context.Background(), raw, res.MemoryID, "tried approach X, failed on Y"); err != nil {
		t.Fatalf("RecordSummary: %v", err)
	}

	got, err := autopsy.LatestSummary(context.Background(), raw, "TASK-008")
	if err != nil {
		t.Fatalf("LatestSummary: %v", err)
	}
	if got != "tried approach X, failed on Y" {
		t.Errorf("LatestSummary = %q, want %q", got, "tried approach X, failed on Y")
	}
}

// TestRun_TailCappedKeepingTheEnd covers point 5: a tail longer than 64 KiB
// is truncated with the marker at the start and the last lines (the ones
// that actually matter) preserved.
func TestRun_TailCappedKeepingTheEnd(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	seedPRDAndTask(t, raw, "PRD-001", "TASK-013", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-013")

	bigTail := strings.Repeat("x", 70*1024) + "FINAL-LINE-MARKER"

	r := &autopsy.Runner{DB: raw, Git: slot.Git}
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-013",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		Tail:         bigTail,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var content string
	if err := raw.QueryRowContext(context.Background(),
		`SELECT content FROM task_memories WHERE id = ?`, res.MemoryID,
	).Scan(&content); err != nil {
		t.Fatalf("query memory content: %v", err)
	}
	var decoded struct {
		Tail string `json:"tail"`
	}
	if err := json.Unmarshal([]byte(content), &decoded); err != nil {
		t.Fatalf("decode memory content: %v", err)
	}
	if len(decoded.Tail) > 64*1024+len("[truncated] ...\n") {
		t.Errorf("stored tail length = %d, want <= cap", len(decoded.Tail))
	}
	if !strings.HasSuffix(decoded.Tail, "FINAL-LINE-MARKER") {
		t.Error("stored tail should keep the end (the final line), got it trimmed off")
	}
	if !strings.HasPrefix(decoded.Tail, "[truncated] ...\n") {
		t.Errorf("stored tail should be marked truncated at the start, got prefix %q", decoded.Tail[:min(40, len(decoded.Tail))])
	}
}

// TestRun_BuildTimeoutKillsRunawayBuild covers point 3: the default build
// runner (Build left nil) must be bounded by BuildTimeout rather than
// hanging forever on a build command that never exits on its own.
func TestRun_BuildTimeoutKillsRunawayBuild(t *testing.T) {
	requireGit(t)
	raw := openDB(t)
	repoRoot, base := initGitRepo(t)
	slot := newSlot(t, repoRoot, base)

	if err := os.WriteFile(filepath.Join(slot.Path, "tracked.txt"), []byte("edited content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedPRDAndTask(t, raw, "PRD-001", "TASK-014", base)
	seatID, invID := mintWorkerSeat(t, raw, "PRD-001", "TASK-014")

	sleepCmd := "sleep 60"
	if runtime.GOOS == "windows" {
		sleepCmd = "ping -n 61 127.0.0.1 >NUL"
	}

	r := &autopsy.Runner{
		DB:           raw,
		Git:          slot.Git,
		BuildTimeout: 2 * time.Second,
	}

	start := time.Now()
	res, err := r.Run(context.Background(), autopsy.Request{
		InvocationID: invID,
		SeatID:       seatID,
		TaskID:       "TASK-014",
		Attempt:      1,
		Cause:        autopsy.CauseLeaseExpired,
		BaseCommit:   base,
		SlotPath:     slot.Path,
		BuildCommand: sleepCmd,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed > 30*time.Second {
		t.Errorf("Run took %v, want the build killed well within its 60s sleep", elapsed)
	}
	if res.Decision != autopsy.DecisionReset {
		t.Errorf("Decision = %q, want reset (the build never got to finish)", res.Decision)
	}
}

func TestWarningPrompt(t *testing.T) {
	if got := autopsy.WarningPrompt(""); got != "" {
		t.Errorf("WarningPrompt(\"\") = %q, want empty", got)
	}
	want := "WARNING: Previous attempt failed with tried X. Do NOT repeat that approach."
	if got := autopsy.WarningPrompt("tried X"); got != want {
		t.Errorf("WarningPrompt(%q) = %q, want %q", "tried X", got, want)
	}
}
