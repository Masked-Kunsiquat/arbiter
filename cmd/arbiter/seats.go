package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masked-Kunsiquat/arbiter/internal/db"
)

// seatRow is one seats table row, joined with its credential for display.
type seatRow struct {
	id           string
	role         string
	taskID       sql.NullString
	prdID        string
	parentID     sql.NullString
	credentialID string
	status       string
	harness      sql.NullString
	model        sql.NullString

	invocationCount int
	totalCostUSD    float64
}

// runSeats implements `arbiter seats [<prd-id>] [--stats]` (spec §9.B).
//
// v0.1 scaffold note: this opens .arbiter/state.db directly. Spec §10.B says
// the CLI should instead talk to a running core over its IPC pipe/socket and
// never open state.db itself; that core process doesn't exist yet (issue
// #15). This direct-read path is a stopgap to unblock the command, not the
// final architecture.
func runSeats(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("seats", flag.ContinueOnError)
	stats := fs.Bool("stats", false, "add dismissed-attack and upheld-claim rates per credential")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var prdFilter string
	if fs.NArg() > 0 {
		prdFilter = fs.Arg(0)
	}

	dbPath, err := findStateDB()
	if err != nil {
		return err
	}
	adb, err := db.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", dbPath, err)
	}
	defer adb.Close()

	rows, err := loadSeats(ctx, adb.SQLDB(), prdFilter)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("no seats found")
		return nil
	}

	printTree(rows)
	if *stats {
		fmt.Println()
		fmt.Println("--stats: dismissed-attack and upheld-claim rates are not available yet (require issues #10, #11).")
	}
	return nil
}

// findStateDB locates .arbiter/state.db by walking up from the current
// directory, the way git locates .git.
func findStateDB() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for {
		candidate := filepath.Join(dir, ".arbiter", "state.db")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no .arbiter/state.db found (run 'arbiter init' first)")
		}
		dir = parent
	}
}

func loadSeats(ctx context.Context, raw *sql.DB, prdFilter string) ([]seatRow, error) {
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

	var rows []seatRow
	for sqlRows.Next() {
		var r seatRow
		if err := sqlRows.Scan(&r.id, &r.role, &r.taskID, &r.prdID, &r.parentID, &r.credentialID,
			&r.status, &r.harness, &r.model, &r.invocationCount, &r.totalCostUSD); err != nil {
			return nil, fmt.Errorf("scanning seat row: %w", err)
		}
		rows = append(rows, r)
	}
	if err := sqlRows.Err(); err != nil {
		return nil, fmt.Errorf("reading seats: %w", err)
	}
	return rows, nil
}

// printTree renders seats as an indented tree by parent_seat_id, grouped and
// sorted by PRD, mirroring the shape in spec §5.0.
func printTree(rows []seatRow) {
	byParent := map[string][]seatRow{}
	var roots []seatRow
	byID := map[string]seatRow{}
	for _, r := range rows {
		byID[r.id] = r
		if r.parentID.Valid && r.parentID.String != "" {
			byParent[r.parentID.String] = append(byParent[r.parentID.String], r)
		} else {
			roots = append(roots, r)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].id < roots[j].id })

	var currentPRD string
	for _, root := range roots {
		if root.prdID != currentPRD {
			if currentPRD != "" {
				fmt.Println()
			}
			fmt.Printf("%s\n", root.prdID)
			currentPRD = root.prdID
		}
		printNode(root, byParent, 0)
	}
}

func printNode(r seatRow, byParent map[string][]seatRow, depth int) {
	indent := strings.Repeat("  ", depth)
	label := r.role
	if r.taskID.Valid {
		label = r.taskID.String + "/" + r.role
	}
	cred := r.credentialID
	if r.harness.Valid && r.model.Valid {
		cred = fmt.Sprintf("%s (%s/%s)", r.credentialID, r.harness.String, r.model.String)
	}
	fmt.Printf("%s└── %s [%s]  %s  invocations=%d cost=$%.2f\n",
		indent, label, r.status, cred, r.invocationCount, r.totalCostUSD)

	children := byParent[r.id]
	sort.Slice(children, func(i, j int) bool { return children[i].id < children[j].id })
	for _, c := range children {
		printNode(c, byParent, depth+1)
	}
}
