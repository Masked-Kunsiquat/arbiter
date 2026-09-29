package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
	"github.com/Masked-Kunsiquat/arbiter/internal/stack"
)

// runInit implements `arbiter init` (spec §9.B, §9.C, §13): detect the
// repo's ecosystem, scaffold .arbiter/{worktrees,prds,ledger}/, write a
// default config.toml, add the *.jsonl .gitattributes entry, then validate
// the result so a broken install fails loudly at the point of creation
// rather than on first use.
func runInit(ctx context.Context, args []string) error {
	force, err := parseInitArgs(args)
	if err != nil {
		return err
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	ecosystems, err := stack.Detect(repoRoot)
	if err != nil {
		return fmt.Errorf("detecting ecosystem: %w", err)
	}
	if len(ecosystems) == 0 {
		return fmt.Errorf("arbiter init: no known ecosystem detected in %s (no go.mod, package.json, pyproject.toml, requirements.txt, or setup.py)", repoRoot)
	}
	if len(ecosystems) > 1 {
		names := make([]string, len(ecosystems))
		for i, e := range ecosystems {
			names[i] = e.Name
		}
		fmt.Printf("arbiter init: multiple ecosystems detected (%s); using %s. Edit .arbiter/config.toml to adjust.\n",
			strings.Join(names, ", "), ecosystems[0].Name)
	}
	primary := ecosystems[0]

	arbiterDir, err := config.Scaffold(repoRoot)
	if err != nil {
		return err
	}

	cfg := config.FromEcosystem(primary)
	cfgPath := config.ConfigPath(arbiterDir)

	if err := config.Validate(cfg, primary.Name); err != nil {
		return fmt.Errorf("arbiter init: config validation failed before writing:\n%w", err)
	}

	if err := config.Write(cfg, cfgPath, force); err != nil {
		return err
	}

	if err := config.EnsureGitattributes(repoRoot); err != nil {
		return err
	}

	fmt.Printf("arbiter init: detected %s, wrote %s\n", primary.Name, cfgPath)
	return nil
}

func parseInitArgs(args []string) (force bool, err error) {
	for _, a := range args {
		switch a {
		case "--force", "-force":
			force = true
		default:
			return false, fmt.Errorf("unknown flag %q", a)
		}
	}
	return force, nil
}
