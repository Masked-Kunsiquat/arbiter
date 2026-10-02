package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/humansig"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisorkey"
)

// ensureAllowedSigners adds the supervisor key's line (namespaces
// "git,arbiter-ledger") and, when git is set up for SSH signing, the human's
// line (namespace "git") to .arbiter/ledger/allowed_signers (§8.C, §8.D).
// The file is committed with the ledger; `arbiter audit verify` and the
// core's signature checks take verifying keys only from it.
//
// A missing or unusable human signing setup is a warning, not an error: init
// should work before the human has configured signing, and the core names
// the fix when a lock or final merge needs it.
func ensureAllowedSigners(ctx context.Context, repoRoot, arbiterDir string) error {
	path := filepath.Join(arbiterDir, filepath.FromSlash(allowedsigners.RelPath))

	cfgDir, err := supervisorkey.DefaultConfigDir()
	if err != nil {
		return err
	}
	sup, err := supervisorkey.LoadOrGenerate(cfgDir)
	if err != nil {
		return err
	}
	host, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("arbiter init: hostname for the supervisor key's principal: %w", err)
	}
	if added, err := allowedsigners.Ensure(path, allowedsigners.SupervisorPrincipal(host), allowedsigners.SupervisorNamespaces, sup.PublicKey()); err != nil {
		return err
	} else if added {
		fmt.Printf("arbiter init: added the supervisor key (arbiter@%s) to %s\n", host, path)
	}

	if err := ensureHumanSigner(ctx, repoRoot, path); err != nil {
		fmt.Printf("arbiter init: warning: your signing key is not in %s yet: %v\n", path, err)
	}
	return nil
}

func ensureHumanSigner(ctx context.Context, repoRoot, path string) error {
	cfg, err := humansig.LoadConfig(ctx, repoRoot)
	if err != nil {
		return err
	}
	signer, err := humansig.NewSigner(cfg)
	if err != nil {
		return err
	}
	pub, err := signer.PublicKey(ctx)
	if err != nil {
		return err
	}
	added, err := allowedsigners.Ensure(path, cfg.Email, allowedsigners.HumanNamespaces, pub)
	if err != nil {
		return err
	}
	if added {
		fmt.Printf("arbiter init: added your signing key (%s) to %s\n", cfg.Email, path)
	}
	return nil
}
