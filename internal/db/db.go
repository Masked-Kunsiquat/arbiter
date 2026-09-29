// Package db manages Arbiter's embedded SQLite database (spec §4.A).
//
// # File location
//
//	.arbiter/state.db  (repository-level, one per repo)
//
// # Invariants
//
//   - WAL journal mode
//   - PRAGMA busy_timeout = 5000
//   - PRAGMA foreign_keys = ON
//   - All DDL is applied from the embedded schema on every Open; IF NOT EXISTS
//     guards make this idempotent.
//   - task_edges inserts run a DFS cycle-check inside the same transaction; a
//     cycle causes the transaction to be rolled back and an error returned.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
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

// Open opens (or creates) a state.db at the given path, applies all PRAGMAs
// and the schema, and returns a ready-to-use DB.
//
// The caller must call Close when done.
func Open(ctx context.Context, path string) (*DB, error) {
	// modernc/sqlite DSN: plain file path works; ?_busy_timeout etc. can also
	// be set via PRAGMA after open, which we prefer for clarity.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("db: open %q: %w", path, err)
	}

	// SQLite is single-writer; one connection is both sufficient and correct.
	// WAL mode allows one writer + multiple concurrent readers, so we allow a
	// small pool so read-only callers (tests, etc.) can hold idle connections.
	raw.SetMaxOpenConns(1)
	raw.SetMaxIdleConns(1)

	adb := &DB{db: raw}
	if err := adb.init(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return adb, nil
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
			return fmt.Errorf("db: %s: %w", p, err)
		}
	}

	ddl, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("db: reading embedded schema: %w", err)
	}
	if _, err := d.db.ExecContext(ctx, string(ddl)); err != nil {
		return fmt.Errorf("db: applying schema: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// task_edges: cycle-checked insert
// ─────────────────────────────────────────────────────────────────────────────

// ErrCycle is returned when inserting a task_edge would create a cycle in the
// task DAG.
var ErrCycle = errors.New("db: task_edges: cycle detected")

// AddTaskEdge inserts the edge (taskID → dependsOn) inside a transaction and
// runs a DFS reachability check from dependsOn back to taskID. If a path
// exists the transaction is rolled back and ErrCycle is returned.
//
// The check is O(V+E) over the sub-graph reachable from dependsOn; for the
// small DAGs typical of a single PRD this is negligible.
func (d *DB) AddTaskEdge(ctx context.Context, taskID, dependsOn string) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: AddTaskEdge: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on any non-commit path

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO task_edges (task_id, depends_on) VALUES (?, ?)`,
		taskID, dependsOn,
	); err != nil {
		return fmt.Errorf("db: AddTaskEdge: insert: %w", err)
	}

	// DFS: can we reach taskID starting from dependsOn?
	// If yes, adding this edge would create a cycle.
	cycle, err := dfsCycleCheck(ctx, tx, dependsOn, taskID)
	if err != nil {
		return fmt.Errorf("db: AddTaskEdge: cycle check: %w", err)
	}
	if cycle {
		return ErrCycle
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: AddTaskEdge: commit: %w", err)
	}
	return nil
}

// dfsCycleCheck returns true if target is reachable from start following
// task_edges (start → depends_on direction) within the transaction tx.
// It reads from the already-modified snapshot so the newly inserted edge is
// included in the search.
func dfsCycleCheck(ctx context.Context, tx *sql.Tx, start, target string) (bool, error) {
	visited := make(map[string]bool)
	stack := []string{start}

	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if node == target {
			return true, nil
		}
		if visited[node] {
			continue
		}
		visited[node] = true

		rows, err := tx.QueryContext(ctx,
			`SELECT depends_on FROM task_edges WHERE task_id = ?`, node,
		)
		if err != nil {
			return false, fmt.Errorf("querying edges from %q: %w", node, err)
		}
		var next []string
		for rows.Next() {
			var dep string
			if err := rows.Scan(&dep); err != nil {
				rows.Close()
				return false, fmt.Errorf("scanning edge: %w", err)
			}
			next = append(next, dep)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return false, fmt.Errorf("iterating edges from %q: %w", node, err)
		}
		stack = append(stack, next...)
	}
	return false, nil
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
		return "", fmt.Errorf("db: PRAGMA %s: %w", name, err)
	}
	return val, nil
}

// PragmaInt queries a PRAGMA and returns its integer value.
func (d *DB) PragmaInt(ctx context.Context, name string) (int64, error) {
	var val int64
	//nolint:gosec // name comes from internal callers only, never user input
	err := d.db.QueryRowContext(ctx, "PRAGMA "+name).Scan(&val)
	if err != nil {
		return 0, fmt.Errorf("db: PRAGMA %s: %w", name, err)
	}
	return val, nil
}
