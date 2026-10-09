package seat

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Purpose matches the invocations.purpose values from §4 (not a CHECK
// constraint in the schema, but pinned by the catalog in §8.E and §9.A).
type Purpose string

const (
	PurposePlan           Purpose = "plan"
	PurposeSpec           Purpose = "spec"
	PurposeImplement      Purpose = "implement"
	PurposeFix            Purpose = "fix"
	PurposeAttack         Purpose = "attack"
	PurposeAttackMaint    Purpose = "attack_maintenance"
	PurposeClaimCheck     Purpose = "claim_check"
	PurposeDisputeRuling  Purpose = "dispute_ruling"
	PurposeVerdict        Purpose = "verdict"
	PurposeAutopsySummary Purpose = "autopsy_summary"
)

// ExitReason matches the invocations.exit_reason CHECK constraint.
type ExitReason string

const (
	ExitOK            ExitReason = "ok"
	ExitInvalidOutput ExitReason = "invalid_output"
	ExitCrash         ExitReason = "crash"
	ExitLeaseExpired  ExitReason = "lease_expired"
	ExitKilled        ExitReason = "killed"
	// ExitBudgetExhausted: the harness stopped at --max-budget-usd (§5.8);
	// the task goes to awaiting_human, not the autopsy.
	ExitBudgetExhausted ExitReason = "budget_exhausted"
)

// StartInvocationRequest describes a new process launch under an existing
// seat. The seat must already be 'minted' or 'active'; StartInvocation moves
// it to 'active' if this is its first invocation.
type StartInvocationRequest struct {
	SeatID           string
	TaskID           string // empty when not task-bound (e.g. a plan invocation)
	Purpose          Purpose
	SupervisorHandle string // PGID (POSIX) or Job Object name (Windows)
	PID              int64
	LeaseExpiresAt   time.Time
}

// StartInvocation inserts an invocations row and activates the seat if this
// is its first invocation (seat status minted -> active).
func StartInvocation(ctx context.Context, db *sql.DB, req StartInvocationRequest) (string, error) {
	if req.SeatID == "" {
		return "", errors.New("seat: invocation requires a seat_id")
	}
	if req.Purpose == "" {
		return "", errors.New("seat: invocation requires a purpose")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("seat: StartInvocation: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on any non-commit path

	var status Status
	if err := tx.QueryRowContext(ctx, `SELECT status FROM seats WHERE id = ?`, req.SeatID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("seat: %s not found", req.SeatID)
		}
		return "", fmt.Errorf("seat: loading seat %s: %w", req.SeatID, err)
	}
	if status != StatusMinted && status != StatusActive {
		return "", fmt.Errorf("seat: %s: cannot start an invocation from status %s", req.SeatID, status)
	}
	if status == StatusMinted {
		if _, err := tx.ExecContext(ctx, `UPDATE seats SET status = ? WHERE id = ?`, string(StatusActive), req.SeatID); err != nil {
			return "", fmt.Errorf("seat: activating %s: %w", req.SeatID, err)
		}
	}

	id, err := randomInvocationID()
	if err != nil {
		return "", err
	}
	var taskID any
	if req.TaskID != "" {
		taskID = req.TaskID
	}
	var leaseExpiresAt any
	if !req.LeaseExpiresAt.IsZero() {
		leaseExpiresAt = req.LeaseExpiresAt.UTC()
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO invocations (id, seat_id, task_id, purpose, supervisor_handle, pid, lease_expires_at)
		VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?)`,
		id, req.SeatID, taskID, string(req.Purpose), req.SupervisorHandle, req.PID, leaseExpiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("seat: starting invocation for seat %s: %w", req.SeatID, err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("seat: StartInvocation: commit: %w", err)
	}
	return id, nil
}

// RenewLease stores a renewed lease expiry for an open invocation (§7: the
// supervisor renews leases while the process is live). A zero expiresAt
// stores NULL: the lease is frozen while paused. Renewing an ended
// invocation is an error.
func RenewLease(ctx context.Context, db *sql.DB, invocationID string, expiresAt time.Time) error {
	var at any
	if !expiresAt.IsZero() {
		at = expiresAt.UTC()
	}
	res, err := db.ExecContext(ctx, `
		UPDATE invocations SET lease_expires_at = ?
		WHERE id = ? AND ended_at IS NULL`,
		at, invocationID,
	)
	if err != nil {
		return fmt.Errorf("seat: renewing lease for %s: %w", invocationID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("seat: renewing lease for %s: %w", invocationID, err)
	}
	if n == 0 {
		return fmt.Errorf("seat: invocation %s not found or already ended", invocationID)
	}
	return nil
}

// EndInvocationRequest records how an invocation finished.
type EndInvocationRequest struct {
	InvocationID  string
	ExitReason    ExitReason
	CostUSD       *float64 // nil if none arrived (killed), per spec §4
	CostEstimated bool     // true when CostUSD was summed from streamed usage instead (§5.8)
	// TerminalReason and APIErrorStatus come from the harness's result
	// event (§9.A); "" and nil (stored NULL) when none arrived.
	TerminalReason string
	APIErrorStatus *int
}

// EndInvocation records the exit reason and cost for an invocation. It does
// not transition the seat: a crash or lease expiry needs a fresh seat (§8.B
// rule 1), which is the caller's decision, not this function's.
func EndInvocation(ctx context.Context, db *sql.DB, req EndInvocationRequest) error {
	if req.InvocationID == "" {
		return errors.New("seat: EndInvocation requires an invocation_id")
	}
	switch req.ExitReason {
	case ExitOK, ExitInvalidOutput, ExitCrash, ExitLeaseExpired, ExitKilled, ExitBudgetExhausted:
	default:
		return fmt.Errorf("seat: invalid exit_reason %q", req.ExitReason)
	}
	var cost, apiStatus any
	if req.CostUSD != nil {
		cost = *req.CostUSD
	}
	if req.APIErrorStatus != nil {
		apiStatus = *req.APIErrorStatus
	}
	res, err := db.ExecContext(ctx, `
		UPDATE invocations
		SET exit_reason = ?, cost_usd = ?, cost_estimated = ?,
		    terminal_reason = NULLIF(?, ''), api_error_status = ?, ended_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		string(req.ExitReason), cost, req.CostEstimated, req.TerminalReason, apiStatus, req.InvocationID,
	)
	if err != nil {
		return fmt.Errorf("seat: ending invocation %s: %w", req.InvocationID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("seat: ending invocation %s: %w", req.InvocationID, err)
	}
	if n == 0 {
		return fmt.Errorf("seat: invocation %s not found", req.InvocationID)
	}
	return nil
}

func randomInvocationID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("seat: generating invocation id: %w", err)
	}
	return "inv-" + hex.EncodeToString(b), nil
}

// SetHarnessSession stores the harness conversation id reported by the
// seat's first invocation (seats.harness_session_id, §9.A), so later
// invocations resume it. The id stays the same across --resume, so storing
// the same value again is a no-op; a different value is an error, since it
// means a resume silently started a new conversation.
func SetHarnessSession(ctx context.Context, db *sql.DB, seatID, sessionID string) error {
	if sessionID == "" {
		return errors.New("seat: SetHarnessSession requires a session id")
	}
	res, err := db.ExecContext(ctx, `
		UPDATE seats SET harness_session_id = ?
		WHERE id = ? AND (harness_session_id IS NULL OR harness_session_id = ?)`,
		sessionID, seatID, sessionID,
	)
	if err != nil {
		return fmt.Errorf("seat: setting harness session for %s: %w", seatID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("seat: setting harness session for %s: %w", seatID, err)
	}
	if n == 0 {
		current, err := HarnessSession(ctx, db, seatID)
		if err != nil {
			return err
		}
		return fmt.Errorf("seat: %s already has harness session %s, got %s", seatID, current, sessionID)
	}
	return nil
}

// HarnessSession returns the seat's harness conversation id, "" if none yet.
func HarnessSession(ctx context.Context, db *sql.DB, seatID string) (string, error) {
	var id sql.NullString
	err := db.QueryRowContext(ctx, `SELECT harness_session_id FROM seats WHERE id = ?`, seatID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("seat: %s not found", seatID)
	}
	if err != nil {
		return "", fmt.Errorf("seat: loading harness session for %s: %w", seatID, err)
	}
	return id.String, nil
}
