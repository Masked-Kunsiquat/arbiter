// Package auditlog persists ledger chains in state.db's audit_log table (spec §8.B, §4.A).
// There is one chain per PRD plus "global". Entries are hashed and supervisor-signed at write
// time by ledger.NewEntry, so a row is never stored unsigned.
package auditlog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// Store appends to and reads ledger chains in the audit_log table.
type Store struct {
	db     *sql.DB
	signer ledger.Signer
	Now    func() time.Time // nil means time.Now
	mu     sync.Mutex       // serializes Append: read head, sign, insert
}

// New returns a Store over an open state.db.
func New(db *sql.DB, signer ledger.Signer) *Store {
	return &Store{db: db, signer: signer}
}

// Append builds, signs and inserts the next entry of chain in one transaction.
func (s *Store) Append(ctx context.Context, chain, seatID, action, taskID string, payload map[string]any) (ledger.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ledger.Entry{}, fmt.Errorf("auditlog: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	seq, hash := int64(0), ledger.ZeroHash
	err = tx.QueryRowContext(ctx,
		`SELECT seq, entry_hash FROM audit_log WHERE chain = ? ORDER BY seq DESC LIMIT 1`, chain).Scan(&seq, &hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ledger.Entry{}, fmt.Errorf("auditlog: read head of %s: %w", chain, err)
	}

	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	e, err := ledger.NewEntry(chain, seq, hash, seatID, action, taskID, payload, now(), s.signer)
	if err != nil {
		return ledger.Entry{}, fmt.Errorf("auditlog: %w", err)
	}
	pj, err := e.PayloadJSON()
	if err != nil {
		return ledger.Entry{}, fmt.Errorf("auditlog: %s: %w", action, err)
	}
	var task any
	if e.TaskID != "" {
		task = e.TaskID
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_log (v, chain, seq, task_id, seat_id, action, payload_json, created_at, prev_hash, entry_hash, supervisor_signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.V, e.Chain, e.Seq, task, e.SeatID, e.Action, string(pj), e.CreatedAt, e.PrevHash, e.EntryHash, e.Signature)
	if err != nil {
		return ledger.Entry{}, fmt.Errorf("auditlog: insert %s seq %d: %w", chain, e.Seq, err)
	}
	if err := tx.Commit(); err != nil {
		return ledger.Entry{}, fmt.Errorf("auditlog: commit: %w", err)
	}
	return e, nil
}

// Head returns the last seq and entry_hash of chain. An empty chain is (0, "", nil); this is
// the contract of gitsign.LedgerHeads.
func (s *Store) Head(ctx context.Context, chain string) (seq int64, entryHash string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT seq, entry_hash FROM audit_log WHERE chain = ? ORDER BY seq DESC LIMIT 1`, chain).Scan(&seq, &entryHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("auditlog: read head of %s: %w", chain, err)
	}
	return seq, entryHash, nil
}

// Entries returns every entry of chain in seq order.
func (s *Store) Entries(ctx context.Context, chain string) ([]ledger.Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT v, chain, seq, task_id, seat_id, action, payload_json, created_at, prev_hash, entry_hash, supervisor_signature
		 FROM audit_log WHERE chain = ? ORDER BY seq`, chain)
	if err != nil {
		return nil, fmt.Errorf("auditlog: query %s: %w", chain, err)
	}
	defer func() { _ = rows.Close() }()

	var out []ledger.Entry
	for rows.Next() {
		var (
			e    ledger.Entry
			task sql.NullString
			pj   string
		)
		if err := rows.Scan(&e.V, &e.Chain, &e.Seq, &task, &e.SeatID, &e.Action, &pj, &e.CreatedAt, &e.PrevHash, &e.EntryHash, &e.Signature); err != nil {
			return nil, fmt.Errorf("auditlog: scan %s: %w", chain, err)
		}
		e.TaskID = task.String
		if e.Payload, err = ledger.DecodePayload([]byte(pj)); err != nil {
			return nil, fmt.Errorf("auditlog: %s seq %d: %w", chain, e.Seq, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auditlog: read %s: %w", chain, err)
	}
	return out, nil
}
