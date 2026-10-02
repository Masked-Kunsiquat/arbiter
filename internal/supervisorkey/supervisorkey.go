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
	"runtime"

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

	info, err := os.Stat(path)
	switch {
	case err == nil:
		if err := checkPermissions(info); err != nil {
			return nil, err
		}
		return loadKey(path)
	case errors.Is(err, os.ErrNotExist):
		return generateAndSave(configDir, path)
	default:
		return nil, fmt.Errorf("supervisorkey: stat %s: %w", path, err)
	}
}

// checkPermissions rejects a key file that grants group or other access.
// This is a courtesy on top of the threat model in §8.A (any process running
// as the same OS user can already read local files regardless), but it
// catches an accidentally-loosened umask or a key copied in from elsewhere
// with the wrong mode.
func checkPermissions(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		// POSIX mode bits aren't meaningful on Windows; ACLs would be the
		// real check, and the threat model here is already best-effort on
		// this platform (see the package doc comment).
		return nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("supervisorkey: key file has group/other permissions %o, want 0600 or stricter", perm)
	}
	return nil
}

func loadKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: reading %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: parsing %s: %w", path, err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("supervisorkey: %s is a %s key, want ed25519", path, signer.PublicKey().Type())
	}
	return signer, nil
}

// generateAndSave creates a fresh key and publishes it to path without ever
// replacing a file that's already there: it writes to a temp file in the
// same directory, then links the temp file onto path (os.Link fails if path
// already exists, and never leaves a partial file at path either way). If
// another process wins the race and publishes first, this loads and returns
// that file's key instead of the one just generated here.
func generateAndSave(configDir, path string) (ssh.Signer, error) {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("supervisorkey: creating %s: %w", configDir, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: generating key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "arbiter-supervisor")
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: marshaling key: %w", err)
	}

	tmp, err := os.CreateTemp(configDir, ".supervisor_ed25519.tmp-*")
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: creating temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the link below succeeds and nothing references tmpPath's name anymore

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("supervisorkey: setting permissions on %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(pem.EncodeToMemory(block)); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("supervisorkey: writing %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("supervisorkey: closing %s: %w", tmpPath, err)
	}

	if err := os.Link(tmpPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("supervisorkey: publishing %s: %w", path, err)
		}
		// Someone else published first; use their key, not ours.
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, fmt.Errorf("supervisorkey: %s appeared but could not be read: %w", path, statErr)
		}
		if err := checkPermissions(info); err != nil {
			return nil, err
		}
		return loadKey(path)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("supervisorkey: building signer: %w", err)
	}
	return signer, nil
}

// DefaultConfigDir returns ~/.config/arbiter (spec §8.B, §4.B) under
// os.UserHomeDir ($HOME, or %USERPROFILE% on Windows) on every platform. It
// does not consult XDG_CONFIG_HOME or %AppData%: the spec fixes the path.
func DefaultConfigDir() (string, error) {
	base, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("supervisorkey: resolving home directory: %w", err)
	}
	return filepath.Join(base, ".config", "arbiter"), nil
}
