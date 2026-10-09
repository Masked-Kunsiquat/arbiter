package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisor"
)

// LedgerAppender appends one entry to a ledger chain (auditlog.Store, via
// the core's adapter).
type LedgerAppender interface {
	Append(ctx context.Context, chain, seatID, action, taskID string, payload map[string]any) error
}

// SeatRecorder is the state.db Recorder for one seat's invocations: the
// invocations row (§4), the ledger launch and exit entries on the PRD's
// chain (§8.E), and seats.harness_session_id.
type SeatRecorder struct {
	DB     *sql.DB
	Ledger LedgerAppender // nil writes no ledger entries
	PRDID  string         // the ledger chain

	SeatID  string
	TaskID  string // "" when not task-bound (plan)
	Purpose seat.Purpose

	// InjectedLessonIDs go in the launch entry (v0.2 lesson injection);
	// empty in v0.1.
	InjectedLessonIDs []string
}

// Start inserts the invocations row and appends the launch entry. If the
// entry can't be written, the row is ended (killed) before returning, so a
// failed Start leaves nothing open.
func (r *SeatRecorder) Start(ctx context.Context, h supervisor.Handle, promptHash string) (string, error) {
	id, err := seat.StartInvocation(ctx, r.DB, seat.StartInvocationRequest{
		SeatID:           r.SeatID,
		TaskID:           r.TaskID,
		Purpose:          r.Purpose,
		SupervisorHandle: h.ID(),
		PID:              int64(h.Pid()),
	})
	if err != nil {
		return "", err
	}
	lessons := r.InjectedLessonIDs
	if lessons == nil {
		lessons = []string{}
	}
	err = r.appendEntry(ctx, "launch", map[string]any{
		"invocation_id":       id,
		"seat_id":             r.SeatID,
		"purpose":             string(r.Purpose),
		"prompt_hash":         promptHash,
		"injected_lesson_ids": lessons,
	})
	if err != nil {
		endErr := seat.EndInvocation(ctx, r.DB, seat.EndInvocationRequest{InvocationID: id, ExitReason: seat.ExitKilled})
		return "", errors.Join(err, endErr)
	}
	return id, nil
}

// SetSession stores the seat's harness session id (seat.SetHarnessSession).
func (r *SeatRecorder) SetSession(ctx context.Context, sessionID string) error {
	return seat.SetHarnessSession(ctx, r.DB, r.SeatID, sessionID)
}

// End records the exit on the row and appends the exit entry. out may be
// nil (nothing was read); its result event, if any, supplies the cost,
// terminal_reason and api_error_status.
func (r *SeatRecorder) End(ctx context.Context, invocationID string, reason seat.ExitReason, out *Outcome) error {
	req := seat.EndInvocationRequest{InvocationID: invocationID, ExitReason: reason}
	if out != nil && out.Stream != nil && out.Stream.Result != nil {
		res := out.Stream.Result
		req.CostUSD, req.TerminalReason, req.APIErrorStatus = res.TotalCostUSD, res.TerminalReason, res.APIErrorStatus
	}
	if err := seat.EndInvocation(ctx, r.DB, req); err != nil {
		return err
	}
	var cost any // null when unknown (§8.E)
	if req.CostUSD != nil {
		cost = *req.CostUSD
	}
	return r.appendEntry(ctx, "exit", map[string]any{
		"invocation_id":  invocationID,
		"exit_reason":    string(reason),
		"cost_usd":       cost,
		"cost_estimated": req.CostEstimated,
	})
}

func (r *SeatRecorder) appendEntry(ctx context.Context, action string, payload map[string]any) error {
	if r.Ledger == nil {
		return nil
	}
	if err := r.Ledger.Append(ctx, r.PRDID, r.SeatID, action, r.TaskID, payload); err != nil {
		return fmt.Errorf("agent: ledger %s entry: %w", action, err)
	}
	return nil
}
