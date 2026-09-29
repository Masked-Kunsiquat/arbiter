// Command arbiter is Arbiter's CLI (spec §9.B "CLI Command Suite").
//
// This is a v0.1 bootstrap scaffold: only enough of the command tree exists
// to unblock work that depends on a CLI entrypoint (e.g. `arbiter seats`,
// issue #5). `arbiter init`, PRD lifecycle commands, and the core/Runner
// process (issue #1, #15) are not implemented yet.
package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "arbiter:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	switch args[0] {
	case "seats":
		return runSeats(ctx, args[1:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (see 'arbiter help')", args[0])
	}
}

func printUsage() {
	fmt.Println(`arbiter — local-first execution arbiter (v0.1 scaffold)

Usage:
  arbiter seats [<prd-id>] [--stats]   Print the agent tree

Only a subset of the full CLI command suite (spec §9.B) exists so far.`)
}
