package supervisorkey_test

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/supervisorkey"
)

func TestLoadOrGenerate_GeneratesOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")

	signer, err := supervisorkey.LoadOrGenerate(configDir)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %q, want %q", signer.PublicKey().Type(), ssh.KeyAlgoED25519)
	}

	keyPath := filepath.Join(configDir, supervisorkey.FileName)
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file at %s: %v", keyPath, err)
	}
}

func TestLoadOrGenerate_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")

	signer1, err := supervisorkey.LoadOrGenerate(configDir)
	if err != nil {
		t.Fatalf("first LoadOrGenerate: %v", err)
	}
	signer2, err := supervisorkey.LoadOrGenerate(configDir)
	if err != nil {
		t.Fatalf("second LoadOrGenerate: %v", err)
	}

	if !bytes.Equal(signer1.PublicKey().Marshal(), signer2.PublicKey().Marshal()) {
		t.Error("expected the same key to be reloaded, got a different public key")
	}
}

func TestLoadOrGenerate_SignsDeterministically(t *testing.T) {
	// Ed25519 signatures are deterministic (spec §8.B): the same entry
	// signs to the same bytes on every platform.
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")

	signer, err := supervisorkey.LoadOrGenerate(configDir)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	msg := []byte("test message")
	sig1, err := signer.Sign(nil, msg)
	if err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	sig2, err := signer.Sign(nil, msg)
	if err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	if !bytes.Equal(sig1.Blob, sig2.Blob) {
		t.Error("expected deterministic Ed25519 signatures, got different bytes")
	}
}

func TestLoadOrGenerate_RejectsNonEd25519Key(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Write garbage (not even a valid PEM) to the key file path.
	keyPath := filepath.Join(configDir, supervisorkey.FileName)
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := supervisorkey.LoadOrGenerate(configDir); err == nil {
		t.Fatal("expected error loading invalid key file, got nil")
	}
}

func TestLoadOrGenerate_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")

	if _, err := supervisorkey.LoadOrGenerate(configDir); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	info, err := os.Stat(filepath.Join(configDir, supervisorkey.FileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 0600", perm)
	}
}

func TestDefaultConfigDir(t *testing.T) {
	dir, err := supervisorkey.DefaultConfigDir()
	if err != nil {
		t.Fatalf("DefaultConfigDir: %v", err)
	}
	if filepath.Base(dir) != "arbiter" {
		t.Errorf("DefaultConfigDir = %q, want a path ending in .config/arbiter", dir)
	}
}

// sanity: ed25519 keys are 32-byte public keys, so signatures should be
// verifiable via the standard library too (belt-and-suspenders on top of the
// ssh.Signer contract itself).
func TestLoadOrGenerate_PublicKeySize(t *testing.T) {
	dir := t.TempDir()
	signer, err := supervisorkey.LoadOrGenerate(filepath.Join(dir, "arbiter"))
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	cryptoPub, ok := signer.PublicKey().(ssh.CryptoPublicKey)
	if !ok {
		t.Fatal("public key does not implement ssh.CryptoPublicKey")
	}
	edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key is not ed25519.PublicKey")
	}
	if len(edPub) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(edPub), ed25519.PublicKeySize)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixes from CodeRabbit review on PR #42: permission check on load, atomic
// publish on generate.
// ─────────────────────────────────────────────────────────────────────────────

func TestLoadOrGenerate_RejectsLooseExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")

	// Generate a real key first, then loosen its permissions to simulate an
	// accidentally-widened umask or a key copied in from elsewhere.
	if _, err := supervisorkey.LoadOrGenerate(configDir); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	keyPath := filepath.Join(configDir, supervisorkey.FileName)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := supervisorkey.LoadOrGenerate(configDir); err == nil {
		t.Fatal("expected error loading a key file with group/other permissions, got nil")
	}
}

func TestLoadOrGenerate_ConcurrentGenerate_SameKeyWins(t *testing.T) {
	// Two "processes" racing LoadOrGenerate on a fresh config dir must agree
	// on one key, never each publish their own and silently diverge.
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")

	type result struct {
		pub []byte
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			signer, err := supervisorkey.LoadOrGenerate(configDir)
			if err != nil {
				results <- result{nil, err}
				return
			}
			results <- result{signer.PublicKey().Marshal(), nil}
		}()
	}

	r1, r2 := <-results, <-results
	if r1.err != nil {
		t.Fatalf("goroutine 1: %v", r1.err)
	}
	if r2.err != nil {
		t.Fatalf("goroutine 2: %v", r2.err)
	}
	if !bytes.Equal(r1.pub, r2.pub) {
		t.Error("expected both concurrent callers to agree on the same published key")
	}
}

func TestLoadOrGenerate_NoTempFilesLeftBehind(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "arbiter")

	if _, err := supervisorkey.LoadOrGenerate(configDir); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != supervisorkey.FileName {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("configDir contents = %v, want only %q", names, supervisorkey.FileName)
	}
}
