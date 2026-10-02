// Command arbiter is Arbiter's CLI (spec §9.B "CLI Command Suite").
//
// This is a v0.1 bootstrap scaffold: only enough of the command tree exists
// to unblock work that depends on a CLI entrypoint (e.g. `arbiter seats`,
// issue #5; `arbiter init`, issue #1). PRD lifecycle commands and the
// Runner are not implemented yet; the process supervisor it will use is
// internal/supervisor (issue #15).
//
// Commands reach state through the core, never by opening state.db
// themselves: connectCore attaches to the core already running for the
// repo, or hosts one in-process for the duration of the command (§10.B).
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
	"github.com/Masked-Kunsiquat/arbiter/internal/core"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisor"
)

func main() {
	// Hidden helper commands the process supervisor re-executes this binary
	// for (_ctrlbreak, _pgshim; spec §7). Checked before anything else.
	if code, ok := supervisor.RunHelper(os.Args[1:]); ok {
		os.Exit(code)
	}
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
	case "init":
		return runInit(ctx, args[1:])
	case "seats":
		if err := loadAndValidateConfig(); err != nil {
			return err
		}
		return runSeats(ctx, args[1:])
	case "audit":
		return runAudit(ctx, args[1:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (see 'arbiter help')", args[0])
	}
}

func loadAndValidateConfig() error {
	dbPath, err := findStateDB()
	if err != nil {
		return err
	}
	arbiterDir := filepath.Dir(dbPath)
	cfgPath := config.Path(arbiterDir)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := config.Validate(cfg, ""); err != nil {
		return fmt.Errorf("startup config validation failed:\n%w", err)
	}
	return nil
}

// connectCore connects to the core for the enclosing repo (found by
// walking up to .arbiter/state.db), hosting it in-process if no other
// arbiter process is. The caller must Close the session.
func connectCore(ctx context.Context) (*core.Session, error) {
	dbPath, err := findStateDB()
	if err != nil {
		return nil, err
	}
	return core.Connect(ctx, filepath.Dir(dbPath))
}

func printUsage() {
	fmt.Println(`arbiter — local-first execution arbiter (v0.1 scaffold)

Usage:
  arbiter init [--force]               Detect ecosystem, scaffold .arbiter/, write config.toml
  arbiter seats [<prd-id>] [--stats]   Print the agent tree
  arbiter audit verify [<commit>]      Verify commit signatures and the committed ledger (git only)

Only a subset of the full CLI command suite (spec §9.B) exists so far.`)
}
