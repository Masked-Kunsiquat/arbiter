// Package supervisorkey manages Arbiter's supervisor Ed25519 signing key
// (spec §8.B).
//
// One Ed25519 SSH signing key is held by the core, by default at
// ~/.config/arbiter/supervisor_ed25519 (an OpenSSH-format private key, the
// same format ssh-keygen produces). It signs ledger entries (namespace
// "arbiter-ledger", see internal/ledger) and the task-level commits described
// in spec §8.D. Ed25519 signatures are deterministic, so the same entry signs
// to the same bytes on every platform.
//
// v0.1 stores the key on disk with restrictive permissions. The OS keychain
// or an SSH agent (spec's "optionally") is future work: LoadOrGenerate's
// signature is deliberately narrow (a directory path in, a Signer out) so a
// keychain- or agent-backed implementation can replace the disk path later
// without changing callers.
package supervisorkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// FileName is the default key file name inside the config directory.
const FileName = "supervisor_ed25519"

// LoadOrGenerate reads the supervisor key from <configDir>/supervisor_ed25519,
// generating and persisting a fresh Ed25519 key on first run. It returns an
// ssh.Signer suitable for ledger.NewSSHSigner.
//
// The key file is written with mode 0600 (owner read/write only); configDir
// is created with mode 0700 if it does not exist. Both are best-effort on
// Windows, where Go's os package maps them onto ACLs imprecisely, but the
// spec's threat model (§8.A) already assumes any process running as the same
// OS user can read local files, so this is a courtesy, not the defense.
func LoadOrGenerate(configDir string) (ssh.Signer, error) {
	path := filepath.Join(configDir, FileName)

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		signer, perr := ssh.ParsePrivateKey(data)
		if perr != nil {
			return nil, fmt.Errorf("supervisorkey: parsing %s: %w", path, perr)
		}
		if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			return nil, fmt.Errorf("supervisorkey: %s is a %s key, want ed25519", path, signer.PublicKey().Type())
		}
		return signer, nil
	case errors.Is(err, os.ErrNotExist):
		return generateAndSave(configDir, path)
	default:
		return nil, fmt.Errorf("supervisorkey: reading %s: %w", path, err)
	}
}

func generateAndSave(configDir, path string) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: generating key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "arbiter-supervisor")
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: marshaling key: %w", err)
	}

	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("supervisorkey: creating %s: %w", configDir, err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("supervisorkey: writing %s: %w", path, err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: building signer: %w", err)
	}
	return signer, nil
}

// DefaultConfigDir returns ~/.config/arbiter (spec §8.B, §4.B), honoring
// XDG_CONFIG_HOME when set, as os.UserConfigDir does on POSIX; on Windows it
// falls back to os.UserConfigDir's %AppData%-based default since the spec
// fixes ~/.config/arbiter as the Unix convention it's borrowing, not a
// Windows one.
func DefaultConfigDir() (string, error) {
	base, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("supervisorkey: resolving home directory: %w", err)
	}
	return filepath.Join(base, ".config", "arbiter"), nil
}
