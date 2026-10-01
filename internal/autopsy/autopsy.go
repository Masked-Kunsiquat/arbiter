// Package autopsy implements the automated crash autopsy (spec §7
// "Automated Crash Autopsy"): when a worker's invocation ends without
// finishing (lease expiry or crash), it records the invocation's cost,
// decides whether the diff represents real progress, checkpoints or resets
// the worktree slot accordingly, and leaves a Tier-1 memory row so the next
// attempt (and, later, the Judge) can learn from it.
package autopsy

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisor"
	"github.com/Masked-Kunsiquat/arbiter/internal/worktree"
)

// Cause is why the invocation ended without finishing (spec §7 step 1).
type Cause string

const (
	// CauseLeaseExpired: the supervisor's lease ran out (seat -> expired,
	// exit_reason lease_expired, §8.B "Leases").
	CauseLeaseExpired Cause = "lease_expired"
	// CauseCrash: the harness process died or was killed (seat -> revoked,
	// exit_reason crash).
	CauseCrash Cause = "crash"
)

// maxContentFieldBytes caps the diff, tail, and build output fields stored
// in a memory row's content JSON (spec §7 step 2: the autopsy captures all
// three, but memory rows are meant to stay small enough to fit back into a
// prompt).
const maxContentFieldBytes = 64 * 1024

// defaultBuildTimeout bounds an unbounded or misbehaving build/type-check
// command so a single stuck build can't wedge the autopsy forever.
const defaultBuildTimeout = 10 * time.Minute

// taskRefPattern is the simpler alternative to shelling out to
// `git check-ref-format --branch`: a task id used in a checkpoint ref
// (checkpoint/<task>/attempt-N) must only contain characters that are safe
// in every git ref component.
var taskRefPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Request describes one invocation that ended without finishing.
type Request struct {
	InvocationID string
	SeatID       string
	TaskID       string
	Attempt      int // attempt number N: checkpoint/<task>/attempt-N, task_memories.attempt
	Cause        Cause
	BaseCommit   string // task's base_commit
	SlotPath     string // worktree slot directory
	BuildCommand string // config Test.Build; "" means no build check configured (treated as passing)
	Tail         string // last 50 lines of combined stdout/stderr (spec §7 step 2), already captured by the caller
	// StreamedCostUSD is the cost summed from streamed usage events (§5.8),
	// since a killed harness emits no final result event. nil if none seen.
	StreamedCostUSD *float64
	// KeepList is the per-ecosystem dependency keep-list (worktree.DefaultKeepList)
	// that must survive the post-decision git clean, same as worktree.Slot.Reset.
	KeepList []string
}

// Decision is the outcome of the deterministic progress check (spec §7 step 3).
type Decision string

const (
	DecisionCheckpoint Decision = "checkpoint"
	DecisionReset      Decision = "reset"
)

// Result is what the autopsy did to the slot and the memory it left behind.
type Result struct {
	Decision      Decision
	CheckpointRef string // "checkpoint/<task>/attempt-N" when Decision == checkpoint
	CommitSHA     string // checkpoint commit sha; "" on reset
	Diff          string // captured diff (vs BaseCommit, including untracked files)
	BuildOutput   string // build failure output when the build failed; "" otherwise
	MemoryID      string // task_memories row id
}

// Summarizer writes the Judge's one-line root-cause summary (an
// autopsy_summary invocation, §7 step 4). The real implementation lands
// with the Judge (§5.5); until then callers may pass nil.
type Summarizer interface {
	Summarize(ctx context.Context, res *Result, req Request) (string, error)
}

// Runner performs the autopsy steps against a database and a worktree slot.
type Runner struct {
	DB  *sql.DB
	Git worktree.GitRunner // from internal/worktree

	// Build runs the project's build/type-check command in dir. nil uses
	// defaultBuildRunner (a supervised process, falling back to a plain
	// shell command if the supervisor is unsupported on this platform).
	Build func(ctx context.Context, dir, command string) (output string, err error)

	// BuildTimeout bounds Build. 0 means defaultBuildTimeout (10 minutes).
	BuildTimeout time.Duration

	// Summarizer, if set, is asked for a root-cause summary after the seat
	// transition (§7 step 4) and the result is stored via RecordSummary.
	Summarizer Summarizer
}

// Run performs the crash autopsy for req: records the invocation's end,
// decides checkpoint vs. reset, writes the memory row, and transitions the
// seat (spec §7).
//
// If capturing the diff, running the build, or checkpointing fails, Run
// falls back to a best-effort reset to req.BaseCommit so the slot and seat
// are never left dirty or dangling: it still records a memory row (with the
// failure noted) and still transitions the seat, then returns every error
// that occurred joined together, alongside the non-nil Result describing
// what was actually recorded.
func (r *Runner) Run(ctx context.Context, req Request) (*Result, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}

	exitReason := seat.ExitLeaseExpired
	targetStatus := seat.StatusExpired
	if req.Cause == CauseCrash {
		exitReason = seat.ExitCrash
		targetStatus = seat.StatusRevoked
	}

	// Record the invocation's end first (spec §7 step 1), so cost from
	// streamed usage is captured even if the git steps below fail.
	if err := seat.EndInvocation(ctx, r.DB, seat.EndInvocationRequest{
		InvocationID:  req.InvocationID,
		ExitReason:    exitReason,
		CostUSD:       req.StreamedCostUSD,
		CostEstimated: req.StreamedCostUSD != nil,
	}); err != nil {
		return nil, fmt.Errorf("autopsy: recording invocation end: %w", err)
	}

	res, applyErr := r.evaluateAndApply(ctx, req)

	if seatErr := transitionSeat(ctx, r.DB, req.SeatID, targetStatus); seatErr != nil {
		return res, errors.Join(applyErr, seatErr)
	}
	if applyErr != nil {
		return res, applyErr
	}

	if r.Summarizer != nil {
		summary, err := r.Summarizer.Summarize(ctx, res, req)
		if err != nil {
			return res, fmt.Errorf("autopsy: summarizing: %w", err)
		}
		if err := RecordSummary(ctx, r.DB, res.MemoryID, summary); err != nil {
			return res, fmt.Errorf("autopsy: recording summary: %w", err)
		}
	}

	return res, nil
}

func validateRequest(req Request) error {
	if req.InvocationID == "" {
		return errors.New("autopsy: request requires an invocation_id")
	}
	if req.SeatID == "" {
		return errors.New("autopsy: request requires a seat_id")
	}
	if req.TaskID == "" {
		return errors.New("autopsy: request requires a task_id")
	}
	if req.BaseCommit == "" {
		return errors.New("autopsy: request requires a base_commit")
	}
	if req.SlotPath == "" {
		return errors.New("autopsy: request requires a slot_path")
	}
	if req.Cause != CauseLeaseExpired && req.Cause != CauseCrash {
		return fmt.Errorf("autopsy: invalid cause %q", req.Cause)
	}
	if req.Attempt < 1 {
		return fmt.Errorf("autopsy: invalid attempt %d, want >= 1", req.Attempt)
	}
	if !taskRefPattern.MatchString(req.TaskID) {
		return fmt.Errorf("autopsy: task id %q is not safe for a git ref", req.TaskID)
	}
	return nil
}

// evaluateAndApply captures the diff, evaluates progress deterministically
// (spec §7 step 3), checkpoints or resets the slot, cleans build/agent
// debris, and writes the memory row (step 2 onward; EndInvocation already
// ran in Run).
//
// On any failure in capture, build, or checkpoint, it falls back to a
// best-effort reset to req.BaseCommit so the slot is never left dirty, then
// still records the memory row (noting the failure) before returning. The
// returned *Result is non-nil whenever a memory row was written, even when
// err is also non-nil.
func (r *Runner) evaluateAndApply(ctx context.Context, req Request) (*Result, error) {
	res, applyErr := r.decide(ctx, req)
	if applyErr != nil {
		// Something in capture/build/checkpoint failed: fall back to a
		// best-effort reset so the slot isn't left in a half-committed or
		// dirty state. The reset failing too is folded into the joined error
		// below, not swallowed.
		if _, resetErr := r.Git(ctx, req.SlotPath, "reset", "--hard", req.BaseCommit); resetErr != nil {
			applyErr = errors.Join(applyErr, fmt.Errorf("autopsy: fallback reset to %s: %w", req.BaseCommit, resetErr))
		}
		if res == nil {
			res = &Result{}
		}
		res.Decision = DecisionReset
	}

	cleanTarget := req.BaseCommit
	if res.Decision == DecisionCheckpoint {
		cleanTarget = res.CommitSHA
	}
	if cleanErr := cleanSlot(ctx, r.Git, req.SlotPath, req.KeepList); cleanErr != nil {
		applyErr = errors.Join(applyErr, fmt.Errorf("autopsy: cleaning slot after reset to %s: %w", cleanTarget, cleanErr))
	}

	memoryID, memErr := r.recordMemory(ctx, req, res, applyErr)
	if memErr != nil {
		return res, errors.Join(applyErr, memErr)
	}
	res.MemoryID = memoryID

	return res, applyErr
}

// decide captures the diff, runs the build if needed, and either
// checkpoints or hard-resets the slot. It returns early (without resetting
// itself) on any git or build failure, leaving the fallback reset in
// evaluateAndApply to clean up.
func (r *Runner) decide(ctx context.Context, req Request) (*Result, error) {
	diff, treeIsBase, err := r.captureDiff(ctx, req.SlotPath, req.BaseCommit, req.KeepList)
	if err != nil {
		return nil, err
	}

	res := &Result{Diff: diff}

	if treeIsBase {
		res.Decision = DecisionReset
		if _, err := r.Git(ctx, req.SlotPath, "reset", "--hard", req.BaseCommit); err != nil {
			return res, fmt.Errorf("autopsy: resetting slot to %s: %w", req.BaseCommit, err)
		}
		return res, nil
	}

	buildPassed := true
	if req.BuildCommand != "" {
		output, err := r.runBuild(ctx, req.SlotPath, req.BuildCommand)
		res.BuildOutput = output
		buildPassed = err == nil
	}

	if !buildPassed {
		res.Decision = DecisionReset
		if _, err := r.Git(ctx, req.SlotPath, "reset", "--hard", req.BaseCommit); err != nil {
			return res, fmt.Errorf("autopsy: resetting slot to %s: %w", req.BaseCommit, err)
		}
		return res, nil
	}

	sha, ref, err := r.checkpoint(ctx, req)
	if err != nil {
		return res, err
	}
	res.Decision = DecisionCheckpoint
	res.CommitSHA = sha
	res.CheckpointRef = ref
	return res, nil
}

// captureDiff stages everything except the keep-list (including untracked
// files, spec §7 step 2: "git diff") and compares the resulting tree
// against baseCommit's tree, rather than relying on HEAD or the index: the
// agent may have committed, amended, or moved HEAD itself, or this call may
// be a retry, so neither HEAD nor "is the index empty" is trustworthy.
// treeIsBase reports whether the staged tree is identical to base's tree
// (an empty diff).
//
// Excluding the keep-list from `git add -A` is not just about keeping
// dependency dirs out of the diff/checkpoint: staging an untracked
// directory and then `git reset --hard`-ing to a commit that doesn't have
// it deletes it outright, before cleanSlot's `-e` ever gets a chance.
func (r *Runner) captureDiff(ctx context.Context, slotPath, baseCommit string, keepList []string) (diff string, treeIsBase bool, err error) {
	addArgs, err := addAllExceptKeepListArgs(keepList)
	if err != nil {
		return "", false, err
	}
	if _, err := r.Git(ctx, slotPath, addArgs...); err != nil {
		return "", false, fmt.Errorf("autopsy: staging slot changes: %w", err)
	}
	diff, err = r.Git(ctx, slotPath, "diff", "--cached", "--binary", "--no-ext-diff", baseCommit)
	if err != nil {
		return "", false, fmt.Errorf("autopsy: diffing against %s: %w", baseCommit, err)
	}

	treeOut, err := r.Git(ctx, slotPath, "write-tree")
	if err != nil {
		return "", false, fmt.Errorf("autopsy: writing staged tree: %w", err)
	}
	tree := strings.TrimSpace(treeOut)

	baseTreeOut, err := r.Git(ctx, slotPath, "rev-parse", baseCommit+"^{tree}")
	if err != nil {
		return "", false, fmt.Errorf("autopsy: resolving base tree for %s: %w", baseCommit, err)
	}
	baseTree := strings.TrimSpace(baseTreeOut)

	return diff, tree == baseTree, nil
}

// addAllExceptKeepListArgs builds the `git add -A` argv that stages
// everything except keepList's entries, validated the same way
// worktree.Slot.Reset validates its keep-list.
func addAllExceptKeepListArgs(keepList []string) ([]string, error) {
	args := []string{"add", "-A", "--"}
	pathspecs := []string{"."}
	for _, keep := range keepList {
		if keep == "" {
			continue
		}
		if !filepath.IsLocal(keep) || strings.HasPrefix(keep, "-") {
			return nil, fmt.Errorf("autopsy: keep path %q is not a local path", keep)
		}
		pathspecs = append(pathspecs, ":!"+filepath.ToSlash(filepath.Clean(keep)))
	}
	return append(args, pathspecs...), nil
}

// runBuild runs the configured build/type-check command, using the
// injected Build func if set or defaultBuildRunner otherwise, bounded by
// BuildTimeout (defaultBuildTimeout if unset).
func (r *Runner) runBuild(ctx context.Context, dir, command string) (string, error) {
	timeout := r.BuildTimeout
	if timeout <= 0 {
		timeout = defaultBuildTimeout
	}
	buildCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	build := r.Build
	if build == nil {
		build = defaultBuildRunner
	}
	return build(buildCtx, dir, command)
}

// defaultBuildRunner runs command inside a supervised container (spec §7:
// the build is as unbounded and agent-adjacent as the harness itself, so it
// gets the same containment) so a runaway build is fully killed on ctx's
// deadline, not just orphaned. Platforms without a supervisor implementation
// (supervisor.ErrUnsupported, currently macOS) fall back to a plain shell
// command with a bounded WaitDelay.
func defaultBuildRunner(ctx context.Context, dir, command string) (string, error) {
	sup, err := supervisor.New(supervisor.Options{})
	if err != nil {
		if errors.Is(err, supervisor.ErrUnsupported) {
			return execBuildRunner(ctx, dir, command)
		}
		return "", fmt.Errorf("autopsy: starting build supervisor: %w", err)
	}

	shellPath, shellArgs := shellCommand(command)
	var output strings.Builder
	h, err := sup.Spawn(supervisor.Cmd{
		Path:   shellPath,
		Args:   shellArgs,
		Dir:    dir,
		Env:    os.Environ(),
		Stdout: &output,
		Stderr: &output,
	})
	if err != nil {
		return "", fmt.Errorf("autopsy: spawning build: %w", err)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- h.Wait() }()

	select {
	case <-ctx.Done():
		_ = sup.Terminate(h, 5*time.Second)
		<-waitErr
		return output.String(), fmt.Errorf("autopsy: build timed out: %w", ctx.Err())
	case err := <-waitErr:
		return output.String(), err
	}
}

// execBuildRunner is the plain os/exec fallback for platforms without a
// supervisor implementation. WaitDelay and Cancel bound how long it waits
// for the command to die once ctx is done, instead of leaking a process
// that ignores its context cancellation signal.
func execBuildRunner(ctx context.Context, dir, command string) (string, error) {
	shellPath, shellArgs := shellCommand(command)
	cmd := exec.CommandContext(ctx, shellPath, shellArgs...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// shellCommand returns the platform shell invocation for command, matching
// worktree.DefaultCommandRunner's choice of shell.
func shellCommand(command string) (path string, args []string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", []string{"/c", command}
	}
	return "sh", []string{"-c", command}
}

// checkpoint builds the checkpoint commit from the already-staged tree and
// moves checkpoint/<task>/attempt-N to it (spec §7 step 3). It deliberately
// does not depend on HEAD or an existing commit in the slot: `git
// commit-tree` takes the tree written by captureDiff and req.BaseCommit as
// the sole parent directly, so a self-committing agent, a moved HEAD, or a
// retried autopsy can't change what gets checkpointed or who its parent is.
func (r *Runner) checkpoint(ctx context.Context, req Request) (sha, ref string, err error) {
	treeOut, err := r.Git(ctx, req.SlotPath, "write-tree")
	if err != nil {
		return "", "", fmt.Errorf("autopsy: writing checkpoint tree: %w", err)
	}
	tree := strings.TrimSpace(treeOut)

	msg := fmt.Sprintf("checkpoint: %s attempt %d (%s)", req.TaskID, req.Attempt, req.Cause)
	shaOut, err := r.Git(ctx, req.SlotPath,
		"-c", "user.name=Arbiter",
		"-c", "user.email=arbiter@localhost",
		"-c", "commit.gpgsign=false",
		"commit-tree", tree, "-p", req.BaseCommit, "-m", msg,
	)
	if err != nil {
		return "", "", fmt.Errorf("autopsy: creating checkpoint commit: %w", err)
	}
	sha = strings.TrimSpace(shaOut)

	ref = fmt.Sprintf("checkpoint/%s/attempt-%d", req.TaskID, req.Attempt)
	if _, err := r.Git(ctx, req.SlotPath, "branch", "-f", ref, sha); err != nil {
		return "", "", fmt.Errorf("autopsy: moving %s to %s: %w", ref, sha, err)
	}
	if _, err := r.Git(ctx, req.SlotPath, "reset", "--hard", sha); err != nil {
		return "", "", fmt.Errorf("autopsy: moving slot to checkpoint %s: %w", sha, err)
	}
	return sha, ref, nil
}

// cleanSlot removes build and agent debris left behind by either decision
// (spec §7: the slot is warm and reused by the next attempt), preserving
// the per-ecosystem keep-list the same way worktree.Slot.Reset does.
func cleanSlot(ctx context.Context, git worktree.GitRunner, slotPath string, keepList []string) error {
	cleanArgs := []string{"clean", "-fdx"}
	for _, keep := range keepList {
		if keep == "" {
			continue
		}
		if !filepath.IsLocal(keep) || strings.HasPrefix(keep, "-") {
			return fmt.Errorf("autopsy: keep path %q is not a local path", keep)
		}
		cleanArgs = append(cleanArgs, "-e", filepath.Clean(keep))
	}
	if _, err := git(ctx, slotPath, cleanArgs...); err != nil {
		return fmt.Errorf("autopsy: clean slot with keep-list %v: %w", keepList, err)
	}
	return nil
}

// memoryContent is the JSON shape stored in task_memories.content for an
// autopsy observation.
type memoryContent struct {
	Cause         string `json:"cause"`
	InvocationID  string `json:"invocation_id"`
	SeatID        string `json:"seat_id"`
	Decision      string `json:"decision"`
	CheckpointRef string `json:"checkpoint_ref,omitempty"`
	Tail          string `json:"tail"`
	Diff          string `json:"diff"`
	BuildOutput   string `json:"build_output,omitempty"`
	// Error records a capture/build/checkpoint/clean failure that forced the
	// fallback reset path, so the next attempt's prompt (and, later, the
	// Judge) can see that this autopsy didn't run cleanly.
	Error string `json:"error,omitempty"`
}

// recordMemory inserts the Tier-1 task_memories row for this autopsy (spec
// §7 step 2 and the memory schema, internal/db/schema.sql). applyErr, if
// non-nil, is recorded in the content JSON's "error" field; recordMemory
// always runs regardless of applyErr, so a failed autopsy still leaves a
// row behind.
func (r *Runner) recordMemory(ctx context.Context, req Request, res *Result, applyErr error) (string, error) {
	id, err := randomMemoryID()
	if err != nil {
		return "", err
	}

	var errText string
	if applyErr != nil {
		errText = applyErr.Error()
	}

	content, err := json.Marshal(memoryContent{
		Cause:         string(req.Cause),
		InvocationID:  req.InvocationID,
		SeatID:        req.SeatID,
		Decision:      string(res.Decision),
		CheckpointRef: res.CheckpointRef,
		Tail:          truncateKeepEnd(req.Tail),
		Diff:          truncateKeepStart(res.Diff),
		BuildOutput:   truncateKeepEnd(res.BuildOutput),
		Error:         errText,
	})
	if err != nil {
		return "", fmt.Errorf("autopsy: encoding memory content: %w", err)
	}

	var commitSHA any
	if res.CommitSHA != "" {
		commitSHA = res.CommitSHA
	}

	// fingerprint and root_cause_summary are left unset (NULL): the trace
	// fingerprint lands in v0.2 (§6.D), and root_cause_summary is filled in
	// later by RecordSummary once the Judge has written its summary (§7 step 4).
	if _, err := r.DB.ExecContext(ctx, `
		INSERT INTO task_memories (id, task_id, attempt, commit_sha, observation_type, content)
		VALUES (?, ?, ?, ?, 'autopsy', ?)`,
		id, req.TaskID, req.Attempt, commitSHA, string(content),
	); err != nil {
		return "", fmt.Errorf("autopsy: inserting memory row: %w", err)
	}
	return id, nil
}

// truncateKeepStart caps s to maxContentFieldBytes, keeping the beginning
// and marking the cut at the end, without splitting a UTF-8 rune: the start
// of a diff carries the file headers that matter most for orientation.
func truncateKeepStart(s string) string {
	if len(s) <= maxContentFieldBytes {
		return s
	}
	cut := runeSafeIndex(s, maxContentFieldBytes)
	return s[:cut] + "\n... [truncated]"
}

// truncateKeepEnd caps s to maxContentFieldBytes, keeping the end and
// marking the cut at the start, without splitting a UTF-8 rune: for tail
// and build output, the last lines (the actual error) matter most.
func truncateKeepEnd(s string) string {
	if len(s) <= maxContentFieldBytes {
		return s
	}
	start := len(s) - maxContentFieldBytes
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return "[truncated] ...\n" + s[start:]
}

// runeSafeIndex returns the largest index <= n that does not split a UTF-8
// rune in s.
func runeSafeIndex(s string, n int) int {
	if n >= len(s) {
		return len(s)
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}

// transitionSeat moves seatID to targetStatus, tolerating a seat that is
// already there: a retried autopsy (e.g. after a crash mid-Run) must not
// fail just because a previous attempt already made the transition.
func transitionSeat(ctx context.Context, db *sql.DB, seatID string, targetStatus seat.Status) error {
	var current seat.Status
	err := db.QueryRowContext(ctx, `SELECT status FROM seats WHERE id = ?`, seatID).Scan(&current)
	if err != nil {
		return fmt.Errorf("autopsy: loading seat %s status: %w", seatID, err)
	}
	if current == targetStatus {
		return nil
	}
	if err := seat.Transition(ctx, db, seatID, targetStatus); err != nil {
		return fmt.Errorf("autopsy: transitioning seat %s to %s: %w", seatID, targetStatus, err)
	}
	return nil
}

func randomMemoryID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("autopsy: generating memory id: %w", err)
	}
	return "mem-" + hex.EncodeToString(b), nil
}

// RecordSummary stores summary as the memory's root_cause_summary (spec §7
// step 4). summary is trimmed to a single line and truncated to 200
// characters without splitting a trailing partial rune.
func RecordSummary(ctx context.Context, db *sql.DB, memoryID, summary string) error {
	if memoryID == "" {
		return errors.New("autopsy: RecordSummary requires a memory_id")
	}
	clean := oneLine(summary)
	res, err := db.ExecContext(ctx, `UPDATE task_memories SET root_cause_summary = ? WHERE id = ?`, clean, memoryID)
	if err != nil {
		return fmt.Errorf("autopsy: recording summary for %s: %w", memoryID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("autopsy: recording summary for %s: %w", memoryID, err)
	}
	if n == 0 {
		return fmt.Errorf("autopsy: memory %s not found", memoryID)
	}
	return nil
}

// oneLine collapses summary to a single line and truncates it to 200
// characters, never splitting a trailing multi-byte rune.
func oneLine(summary string) string {
	fields := strings.Fields(summary)
	s := strings.Join(fields, " ")
	const maxRunes = 200
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes])
}

// LatestSummary returns the newest non-empty autopsy root_cause_summary for
// taskID ("", nil if none exists yet).
func LatestSummary(ctx context.Context, db *sql.DB, taskID string) (string, error) {
	var summary string
	err := db.QueryRowContext(ctx, `
		SELECT root_cause_summary FROM task_memories
		WHERE task_id = ? AND observation_type = 'autopsy'
		  AND root_cause_summary IS NOT NULL AND root_cause_summary != ''
		ORDER BY created_at DESC, id DESC
		LIMIT 1`, taskID,
	).Scan(&summary)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("autopsy: loading latest summary for %s: %w", taskID, err)
	}
	return summary, nil
}

// WarningPrompt returns the §7 step 5 prompt line warning the next attempt
// about the previous one's failure. "" for an empty summary.
func WarningPrompt(summary string) string {
	if summary == "" {
		return ""
	}
	return "WARNING: Previous attempt failed with " + summary + ". Do NOT repeat that approach."
}
