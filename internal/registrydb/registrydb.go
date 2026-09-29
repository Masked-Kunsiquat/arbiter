// Package registrydb manages Arbiter's machine-global SQLite registry
// (spec §4.B).
//
// # File location
//
//	~/.config/arbiter/global_registry.db  (shared across the machine, one
//	instance regardless of how many repos use Arbiter)
//
// # Invariants
//
//   - WAL journal mode
//   - PRAGMA busy_timeout = 5000
//   - PRAGMA foreign_keys = ON
//   - All DDL is applied from the embedded schema on every Open; IF NOT EXISTS
//     guards make this idempotent.
//   - Agents never write to this database (spec §6.E): only the core, at
//     Gate 3 (human-signed promotion), and the human CLI write here. This
//     package exposes no agent-facing invocation path — callers are core/CLI
//     code only, and that boundary must be enforced by who calls Open, not by
//     anything in this package.
package registrydb

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	// Register the pure-Go SQLite driver under the name "sqlite".
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

// DB wraps *sql.DB with Arbiter-specific helpers.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) a global_registry.db at the given path, applies all
// PRAGMAs and the schema, and returns a ready-to-use DB.
//
// The caller must call Close when done.
func Open(ctx context.Context, path string) (*DB, error) {
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("registrydb: open %q: %w", path, err)
	}

	// SQLite is single-writer; one connection is both sufficient and correct.
	// WAL mode allows one writer + multiple concurrent readers, so we allow a
	// small pool so read-only callers (tests, etc.) can hold idle connections.
	raw.SetMaxOpenConns(1)
	raw.SetMaxIdleConns(1)

	rdb := &DB{db: raw}
	if err := rdb.init(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return rdb, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// SQLDB returns the underlying *sql.DB for callers that need direct access
// (e.g. sqlx.NewDb in tests).
func (d *DB) SQLDB() *sql.DB { return d.db }

// init applies mandatory PRAGMAs and the idempotent schema DDL.
func (d *DB) init(ctx context.Context) error {
	pragmas := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
	}
	for _, p := range pragmas {
		if _, err := d.db.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("registrydb: %s: %w", p, err)
		}
	}

	ddl, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("registrydb: reading embedded schema: %w", err)
	}
	if _, err := d.db.ExecContext(ctx, string(ddl)); err != nil {
		return fmt.Errorf("registrydb: applying schema: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience: verify PRAGMAs are live on an already-open connection
// ─────────────────────────────────────────────────────────────────────────────

// PragmaString queries a PRAGMA and returns its string value.
func (d *DB) PragmaString(ctx context.Context, name string) (string, error) {
	var val string
	//nolint:gosec // name comes from internal callers only, never user input
	err := d.db.QueryRowContext(ctx, "PRAGMA "+name).Scan(&val)
	if err != nil {
		return "", fmt.Errorf("registrydb: PRAGMA %s: %w", name, err)
	}
	return val, nil
}

// PragmaInt queries a PRAGMA and returns its integer value.
func (d *DB) PragmaInt(ctx context.Context, name string) (int64, error) {
	var val int64
	//nolint:gosec // name comes from internal callers only, never user input
	err := d.db.QueryRowContext(ctx, "PRAGMA "+name).Scan(&val)
	if err != nil {
		return 0, fmt.Errorf("registrydb: PRAGMA %s: %w", name, err)
	}
	return val, nil
}
