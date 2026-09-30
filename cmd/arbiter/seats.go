package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masked-Kunsiquat/arbiter/internal/core"
)

// runSeats implements `arbiter seats [<prd-id>] [--stats]` (spec §9.B).
// Like every command, it asks the core rather than reading state.db: it
// connects to the running core, or hosts one in-process for the duration
// of the command if none is running (§10.B).
func runSeats(ctx context.Context, args []string) error {
	stats, prdFilter, err := parseSeatsArgs(args)
	if err != nil {
		return err
	}

	sess, err := connectCore(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()

	var rows []core.SeatInfo
	if err := sess.Call(ctx, core.MethodSeatsList, core.ListSeatsParams{PRDID: prdFilter}, &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("no seats found")
		return nil
	}

	printTree(rows)
	if stats {
		fmt.Println()
		fmt.Println("--stats: dismissed-attack and upheld-claim rates are not available yet (require issues #10, #11).")
	}
	return nil
}

// parseSeatsArgs accepts the optional PRD id and --stats in either order
// (flag.FlagSet.Parse alone stops at the first non-flag argument, so
// "arbiter seats PRD-001 --stats" would otherwise leave --stats unconsumed
// and silently ignored). Any argument that isn't consumed as either the
// single positional PRD id or a recognized flag is an error, including a
// mistyped flag like "--stat".
func parseSeatsArgs(args []string) (stats bool, prdFilter string, err error) {
	var positional []string
	for _, arg := range args {
		switch arg {
		case "--stats", "-stats":
			stats = true
		default:
			if strings.HasPrefix(arg, "-") {
				return false, "", fmt.Errorf("unknown flag %q", arg)
			}
			positional = append(positional, arg)
		}
	}
	switch len(positional) {
	case 0:
	case 1:
		prdFilter = positional[0]
	default:
		return false, "", fmt.Errorf("unexpected arguments: %v", positional[1:])
	}
	return stats, prdFilter, nil
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
		_, err := os.Stat(candidate)
		switch {
		case err == nil:
			return candidate, nil
		case errors.Is(err, fs.ErrNotExist):
			// keep walking up
		default:
			return "", fmt.Errorf("checking %s: %w", candidate, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no .arbiter/state.db found (run 'arbiter init' first)")
		}
		dir = parent
	}
}

// printTree renders seats as an indented tree by parent_seat_id, grouped and
// sorted by PRD, mirroring the shape in spec §5.0.
//
// byID is built in its own pass before any row is classified as a root or a
// child, so a --prd-id filter that excludes a parent seat doesn't silently
// drop its children: a row whose parent isn't in the filtered set (because
// the filter excluded it, not because it's truly a ringleader) still
// renders, just as its own root, instead of vanishing.
func printTree(rows []core.SeatInfo) {
	byID := map[string]core.SeatInfo{}
	for _, r := range rows {
		byID[r.ID] = r
	}

	byParent := map[string][]core.SeatInfo{}
	var roots []core.SeatInfo
	for _, r := range rows {
		if r.ParentSeatID != "" {
			if _, ok := byID[r.ParentSeatID]; ok {
				byParent[r.ParentSeatID] = append(byParent[r.ParentSeatID], r)
				continue
			}
		}
		roots = append(roots, r)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].ID < roots[j].ID })

	var currentPRD string
	for _, root := range roots {
		if root.PRDID != currentPRD {
			if currentPRD != "" {
				fmt.Println()
			}
			fmt.Printf("%s\n", root.PRDID)
			currentPRD = root.PRDID
		}
		printNode(root, byParent, 0)
	}
}

func printNode(r core.SeatInfo, byParent map[string][]core.SeatInfo, depth int) {
	indent := strings.Repeat("  ", depth)
	label := r.Role
	if r.TaskID != "" {
		label = r.TaskID + "/" + r.Role
	}
	cred := r.CredentialID
	if r.Harness != "" && r.Model != "" {
		cred = fmt.Sprintf("%s (%s/%s)", r.CredentialID, r.Harness, r.Model)
	}
	fmt.Printf("%s└── %s [%s]  id=%s  %s  invocations=%d cost=$%.2f\n",
		indent, label, r.Status, r.ID, cred, r.InvocationCount, r.TotalCostUSD)

	children := byParent[r.ID]
	sort.Slice(children, func(i, j int) bool { return children[i].ID < children[j].ID })
	for _, c := range children {
		printNode(c, byParent, depth+1)
	}
}
