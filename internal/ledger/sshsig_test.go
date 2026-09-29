package ledger

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHSigRejects(t *testing.T) {
	s := testSigner(t, 1)
	msg := []byte(strings.Repeat("a", 64))
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySSHSig(s.PublicKey(), Namespace, msg, sig); err != nil {
		t.Fatalf("good signature rejected: %v", err)
	}
	if err := VerifySSHSig(s.PublicKey(), "git", msg, sig); err == nil {
		t.Error("accepted under the git namespace")
	}
	if err := VerifySSHSig(testSigner(t, 2).PublicKey(), Namespace, msg, sig); err == nil {
		t.Error("accepted for a different key")
	}
	if err := VerifySSHSig(s.PublicKey(), Namespace, []byte(strings.Repeat("b", 64)), sig); err == nil {
		t.Error("accepted for a different message")
	}
}

// Our signatures verify with OpenSSH, so a ledger can be checked without Arbiter installed.
func TestSSHSigInteropVerifyWithSSHKeygen(t *testing.T) {
	keygen := sshKeygen(t)
	s := testSigner(t, 1)
	dir := t.TempDir()
	msg := strings.Repeat("c", 64)
	sig, err := s.Sign([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	signers := filepath.Join(dir, "allowed_signers")
	line := `arbiter@test namespaces="` + Namespace + `" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + "\n"
	write(t, signers, line)
	write(t, filepath.Join(dir, "sig"), sig+"\n")

	cmd := exec.Command(keygen, "-Y", "verify", "-f", signers, "-I", "arbiter@test", "-n", Namespace, "-s", filepath.Join(dir, "sig"))
	cmd.Stdin = strings.NewReader(msg)
	out, err := cmd.CombinedOutput()
	t.Logf("ssh-keygen -Y verify: %s", strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("ssh-keygen rejected our signature: %v", err)
	}
}

// And OpenSSH's signatures verify with ours.
func TestSSHSigInteropSignWithSSHKeygen(t *testing.T) {
	keygen := sshKeygen(t)
	s := testSigner(t, 1)
	dir := t.TempDir()
	block, err := ssh.MarshalPrivateKey(ed25519Key(1), "arbiter-test")
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	msg := strings.Repeat("d", 64)
	write(t, filepath.Join(dir, "msg"), msg)
	cmd := exec.Command(keygen, "-Y", "sign", "-f", key, "-n", Namespace, filepath.Join(dir, "msg"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen -Y sign failed (key file permissions on this OS?): %v: %s", err, out)
	}
	sig, err := os.ReadFile(filepath.Join(dir, "msg.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySSHSig(s.PublicKey(), Namespace, []byte(msg), string(sig)); err != nil {
		t.Fatalf("ssh-keygen signature rejected: %v", err)
	}
	// Ed25519 is deterministic: OpenSSH and Go produce the same signature bytes.
	ours, _ := s.Sign([]byte(msg))
	if strings.TrimSpace(string(sig)) != ours {
		t.Errorf("signature bytes differ from ssh-keygen's\n ssh-keygen: %s\n ours:       %s", sig, ours)
	}
}

func sshKeygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	return p
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
