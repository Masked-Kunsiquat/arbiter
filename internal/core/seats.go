package core

import (
	"context"
	"database/sql"
	"fmt"
)

// SeatInfo is one seat joined with its credential, as served by
// MethodSeatsList for `arbiter seats` (spec §9.B). Optional columns that
// are NULL in the database are empty strings here.
type SeatInfo struct {
	ID              string  `json:"id"`
	Role            string  `json:"role"`
	TaskID          string  `json:"task_id,omitempty"`
	PRDID           string  `json:"prd_id"`
	ParentSeatID    string  `json:"parent_seat_id,omitempty"`
	CredentialID    string  `json:"credential_id"`
	Status          string  `json:"status"`
	Harness         string  `json:"harness,omitempty"`
	Model           string  `json:"model,omitempty"`
	InvocationCount int     `json:"invocation_count"`
	TotalCostUSD    float64 `json:"total_cost_usd"`
}

// listSeats returns every seat (or only prdFilter's, if non-empty) ordered
// by PRD then seat id.
func listSeats(ctx context.Context, raw *sql.DB, prdFilter string) ([]SeatInfo, error) {
	query := `
		SELECT s.id, s.role, s.task_id, s.prd_id, s.parent_seat_id, s.credential_id, s.status,
		       c.harness, c.model,
		       (SELECT COUNT(*) FROM invocations i WHERE i.seat_id = s.id),
		       (SELECT COALESCE(SUM(i.cost_usd), 0) FROM invocations i WHERE i.seat_id = s.id)
		FROM seats s
		LEFT JOIN credentials c ON c.id = s.credential_id`
	args := []any{}
	if prdFilter != "" {
		query += " WHERE s.prd_id = ?"
		args = append(args, prdFilter)
	}
	query += " ORDER BY s.prd_id, s.id"

	sqlRows, err := raw.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying seats: %w", err)
	}
	defer sqlRows.Close()

	seats := []SeatInfo{}
	for sqlRows.Next() {
		var (
			s                               SeatInfo
			taskID, parentID, harness, model sql.NullString
		)
		if err := sqlRows.Scan(&s.ID, &s.Role, &taskID, &s.PRDID, &parentID, &s.CredentialID,
			&s.Status, &harness, &model, &s.InvocationCount, &s.TotalCostUSD); err != nil {
			return nil, fmt.Errorf("scanning seat row: %w", err)
		}
		s.TaskID, s.ParentSeatID, s.Harness, s.Model = taskID.String, parentID.String, harness.String, model.String
		seats = append(seats, s)
	}
	if err := sqlRows.Err(); err != nil {
		return nil, fmt.Errorf("reading seats: %w", err)
	}
	return seats, nil
}
