package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/gitsign"
	"github.com/Masked-Kunsiquat/arbiter/internal/gittest"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
	"github.com/Masked-Kunsiquat/arbiter/internal/prd"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// The signing round trip crosses the IPC boundary: the payload bytes the
// core prepares must reach the signer unchanged, and the signature must come
// back to the core, which verifies it and writes the tag.
func TestSession_LockPRDOverIPC(t *testing.T) {
	gittest.Isolate(t)

	dir := newArbiterDir(t)
	repo := filepath.Dir(dir)
	gitIn(t, repo, "init", "-q", "-b", "main")
	gitIn(t, repo, "config", "user.name", "Human")
	gitIn(t, repo, "config", "user.email", "human@example.com")

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	sshSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	signersPath := filepath.Join(dir, filepath.FromSlash(allowedsigners.RelPath))
	if _, err := allowedsigners.Ensure(signersPath, "human@example.com", allowedsigners.HumanNamespaces, sshSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "prds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prds", "PRD-001.md"), validPRD(t), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "add", ".arbiter/prds", ".arbiter/ledger")
	gitIn(t, repo, "commit", "-q", "-m", "PRD-001")

	s := connect(t, dir)
	req := gitsign.LockRequest{
		PRDID: "PRD-001",
		Signer: gitsign.Signer{
			Ident:     gitsign.Ident{Name: "Human", Email: "human@example.com"},
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey()))),
		},
	}
	gitSigner := ledger.NewSSHSignerNamespace(sshSigner, gitsign.Namespace)
	var signed []byte
	done, err := s.LockPRD(context.Background(), req, func(_ context.Context, payload []byte) (string, error) {
		signed = payload
		return gitSigner.Sign(payload)
	})
	if err != nil {
		t.Fatalf("LockPRD: %v", err)
	}
	if done.Ref != "refs/tags/arbiter/prd/PRD-001/v1" {
		t.Errorf("ref = %s", done.Ref)
	}
	// The tag object is exactly the signed payload plus the signature.
	obj := gitIn(t, repo, "cat-file", "tag", done.ObjectSHA)
	if !strings.HasPrefix(obj+"\n", string(signed)) {
		t.Errorf("tag object does not start with the signed payload:\n%s\n--- payload ---\n%s", obj, signed)
	}

	// The lock is recorded in state.db with the hash of what was tagged.
	wantHash, err := prd.SpecHash(validPRD(t))
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.GetPRD(context.Background(), "PRD-001")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != prd.StatusLocked || st.LockTag != "arbiter/prd/PRD-001/v1" || st.SpecHash != wantHash {
		t.Errorf("prd row = %+v, want locked, tag v1, spec_hash %s", st, wantHash)
	}

	// A signer error aborts without creating anything.
	req.Amend = true
	if _, err := s.LockPRD(context.Background(), req, func(context.Context, []byte) (string, error) {
		return "", errors.New("touch timed out")
	}); err == nil || !strings.Contains(err.Error(), "touch timed out") {
		t.Errorf("signer error = %v", err)
	}
	if tags := gitIn(t, repo, "tag", "-l"); tags != "arbiter/prd/PRD-001/v1" {
		t.Errorf("tags = %q", tags)
	}
}
