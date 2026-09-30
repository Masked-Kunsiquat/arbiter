package core

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Masked-Kunsiquat/arbiter/internal/db"
)

// recoverInvocations marks every invocation still open at startup as
// killed and returns their ids (spec §10.B: "On the next start the core
// marks open invocations killed and runs autopsies on them").
//
// Only the lock holder calls this, so an open invocation here can only
// belong to a previous host that died without ending it: the OS already
// released that host's lock and its Job Object / process group took the
// agents down with it. cost_usd stays NULL, as for any killed invocation
// (§4). The seat is not transitioned; a crash needs a fresh seat (§8.B
// rule 1), which is the Runner's decision when it runs the autopsy.
func recoverInvocations(ctx context.Context, d *db.DB) ([]string, error) {
	tx, err := d.SQLDB().BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("core: recovery: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ids, err := openInvocationIDs(ctx, tx)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE invocations
		SET exit_reason = 'killed', ended_at = CURRENT_TIMESTAMP
		WHERE ended_at IS NULL`); err != nil {
		return nil, fmt.Errorf("core: recovery: marking invocations killed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("core: recovery: commit: %w", err)
	}
	return ids, nil
}

func openInvocationIDs(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM invocations WHERE ended_at IS NULL ORDER BY started_at, id`)
	if err != nil {
		return nil, fmt.Errorf("core: recovery: listing open invocations: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("core: recovery: scanning invocation id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("core: recovery: listing open invocations: %w", err)
	}
	return ids, nil
}
