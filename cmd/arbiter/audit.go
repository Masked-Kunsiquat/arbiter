package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Masked-Kunsiquat/arbiter/internal/audit"
)

// runAudit implements `arbiter audit verify [<commit>]` (§8.D). It reads git only and never
// connects to the core or opens state.db (§10.A).
func runAudit(ctx context.Context, args []string) error {
	rev, err := parseAuditArgs(args)
	if err != nil {
		return err
	}
	// git finds the repository from the working directory, linked worktrees included.
	report, err := audit.Verify(ctx, ".", rev)
	if err != nil {
		return err
	}
	failed := 0
	for _, group := range [][]audit.Result{report.Commits, report.Ledgers} {
		for _, r := range group {
			if r.Err != nil {
				failed++
				fmt.Printf("FAIL %s: %v\n", r.Subject, r.Err)
			} else {
				fmt.Printf("ok   %s\n", r.Subject)
			}
		}
	}
	total := len(report.Commits) + len(report.Ledgers)
	fmt.Printf("%d checked, %d failed\n", total, failed)
	if !report.OK() {
		return errors.New("audit verify: verification failed")
	}
	return nil
}

// parseAuditArgs returns the revision to audit (HEAD by default).
func parseAuditArgs(args []string) (rev string, err error) {
	if len(args) == 0 || args[0] != "verify" {
		return "", errors.New("usage: arbiter audit verify [<commit>]")
	}
	rest := args[1:]
	switch {
	case len(rest) == 0:
		return "HEAD", nil
	case len(rest) == 1 && !strings.HasPrefix(rest[0], "-"):
		return rest[0], nil
	default:
		return "", errors.New("usage: arbiter audit verify [<commit>]")
	}
}
