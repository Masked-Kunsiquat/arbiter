package allowedsigners

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func ed25519Key(n byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32))
}

func testKey(t *testing.T, n byte) ssh.PublicKey {
	t.Helper()
	pub, err := ssh.NewPublicKey(ed25519Key(n).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func keyText(t *testing.T, n byte) string {
	t.Helper()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(testKey(t, n))))
}

func mustParse(t *testing.T, s string) *File {
	t.Helper()
	f, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParse(t *testing.T) {
	k1, k2 := keyText(t, 1), keyText(t, 2)
	src := "# a comment\r\n\r\n" +
		`arbiter@host namespaces="git,arbiter-ledger" ` + k1 + "\r\n" +
		"  # indented comment\n" +
		"alice@example.com " + k2 + " laptop key\n"
	f := mustParse(t, src)
	if len(f.Lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(f.Lines))
	}
	sup := f.Lines[0]
	if strings.Join(sup.Namespaces, "|") != "git|arbiter-ledger" {
		t.Errorf("namespaces = %q", sup.Namespaces)
	}
	if sup.LineNo != 3 || sup.Principals[0] != "arbiter@host" {
		t.Errorf("supervisor line = %+v", sup)
	}
	hum := f.Lines[1]
	if hum.Namespaces != nil || hum.LineNo != 5 {
		t.Errorf("human line = %+v", hum)
	}
	if !bytes.Equal(hum.Key.Marshal(), testKey(t, 2).Marshal()) {
		t.Error("human key mismatch")
	}
}

func TestParseOptions(t *testing.T) {
	k := keyText(t, 1)
	f := mustParse(t, `a cert-authority,NAMESPACES="git",valid-after="20240102" `+k+"\n")
	l := f.Lines[0]
	want := time.Date(2024, 1, 2, 0, 0, 0, 0, time.Local)
	if !l.CertAuthority || !l.ValidAfter.Equal(want) || len(l.Namespaces) != 1 {
		t.Errorf("line = %+v", l)
	}
	f = mustParse(t, `a valid-before="202401020304Z" `+k+"\n")
	if want := time.Date(2024, 1, 2, 3, 4, 0, 0, time.UTC); !f.Lines[0].ValidBefore.Equal(want) {
		t.Errorf("valid-before = %v", f.Lines[0].ValidBefore)
	}
}

func TestParseErrors(t *testing.T) {
	k := keyText(t, 1)
	tests := []struct{ name, src, want string }{
		{"unknown option", "# c\na bogus-opt " + k + "\n", "line 2"},
		{"malformed key", "a ssh-ed25519 AAAAnotakey\n", "line 1"},
		{"no key", "a\n", "line 1"},
		{"bad time", `a valid-after="2024" ` + k + "\n", "valid-after"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.src))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	k1, k2, k3 := keyText(t, 1), keyText(t, 2), keyText(t, 3)
	src := `arbiter@host namespaces="git,arbiter-ledger" ` + k1 + "\n" +
		`alice@example.com ` + k2 + "\n" +
		`*@example.com,!bob@example.com namespaces="git" ` + k3 + "\n"
	f := mustParse(t, src)
	at := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		principal string
		ns        string
		key       byte
		wantErr   string // empty = success
	}{
		{"ok supervisor", "arbiter@host", "arbiter-ledger", 1, ""},
		{"wrong namespace", "arbiter@host", "other", 1, "namespace"},
		{"no namespaces means any", "alice@example.com", "whatever", 2, ""},
		{"wrong principal", "mallory@host", "git", 1, "principal"},
		{"negated principal", "bob@example.com", "git", 3, "principal"},
		{"wildcard principal", "carol@example.com", "git", 3, ""},
		{"wildcard wrong ns", "carol@example.com", "arbiter-ledger", 3, "namespace"},
		{"different key", "arbiter@host", "git", 9, "no line"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := f.Authorize(tc.principal, tc.ns, testKey(t, tc.key), at)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestAuthorizeCertAuthorityIgnored(t *testing.T) {
	f := mustParse(t, "a cert-authority "+keyText(t, 1)+"\n")
	err := f.Authorize("a", "git", testKey(t, 1), time.Now())
	if err == nil || !strings.Contains(err.Error(), "no line") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthorizeValidity(t *testing.T) {
	k := keyText(t, 1)
	f := mustParse(t, `a valid-after="20240101Z",valid-before="20240201Z" `+k+"\n")
	key := testKey(t, 1)
	tests := []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"before window", time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC), false},
		{"window start", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"inside", time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC), true},
		{"window end exclusive", time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := f.Authorize("a", "git", key, tc.at)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestAuthorizeAnyLineSucceeds(t *testing.T) {
	k := keyText(t, 1)
	f := mustParse(t, `a namespaces="x" `+k+"\n"+`a namespaces="git" `+k+"\n")
	if err := f.Authorize("a", "git", testKey(t, 1), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestWildcard(t *testing.T) {
	tests := []struct {
		pat, s string
		want   bool
	}{
		{"*", "", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*@x.com", "a/b[c]@x.com", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b", "abX", false},
		{"[a]", "a", false},
	}
	for _, tc := range tests {
		if got := wildcard(tc.pat, tc.s); got != tc.want {
			t.Errorf("wildcard(%q,%q) = %v", tc.pat, tc.s, got)
		}
	}
}

func TestFormatLineRoundTrip(t *testing.T) {
	key := testKey(t, 4)
	for _, ns := range [][]string{SupervisorNamespaces, HumanNamespaces, nil} {
		line := FormatLine(SupervisorPrincipal("h"), ns, key)
		if strings.Contains(line, "\n") {
			t.Fatal("newline in line")
		}
		f := mustParse(t, line+"\n")
		l := f.Lines[0]
		if l.Principals[0] != "arbiter@h" || !sameSet(l.Namespaces, ns) || len(l.Namespaces) != len(ns) {
			t.Errorf("round trip %q -> %+v", line, l)
		}
		if !bytes.Equal(l.Key.Marshal(), key.Marshal()) {
			t.Error("key mismatch")
		}
	}
}

func TestEnsure(t *testing.T) {
	key := testKey(t, 1)
	path := filepath.Join(t.TempDir(), "ledger", "allowed_signers")

	added, err := Ensure(path, "alice", HumanNamespaces, key)
	if err != nil || !added {
		t.Fatalf("first Ensure = %v, %v", added, err)
	}
	before, _ := os.ReadFile(path)
	if !bytes.HasSuffix(before, []byte("\n")) || bytes.Contains(before, []byte("\r")) {
		t.Errorf("bad file: %q", before)
	}
	added, err = Ensure(path, "alice", HumanNamespaces, key)
	if err != nil || added {
		t.Fatalf("second Ensure = %v, %v", added, err)
	}
	if _, err := Ensure(path, "alice", SupervisorNamespaces, key); err == nil {
		t.Fatal("conflicting namespaces: want error")
	}
	if _, err := Ensure(path, "bob", HumanNamespaces, key); err == nil {
		t.Fatal("conflicting principal: want error")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Errorf("file changed: %q -> %q", before, after)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Authorize("alice", "git", key, time.Now()); err != nil {
		t.Error(err)
	}
}

func TestEnsureAppendsNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed_signers")
	existing := "# header"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if added, err := Ensure(path, "a", HumanNamespaces, testKey(t, 2)); err != nil || !added {
		t.Fatalf("Ensure = %v, %v", added, err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "# header\na namespaces=") {
		t.Errorf("data = %q", data)
	}
}

func TestLoadMissing(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "nope"))
	if err != nil || f == nil || len(f.Lines) != 0 {
		t.Fatalf("Load = %v, %v", f, err)
	}
}

func TestInteropSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	dir := t.TempDir()
	priv := ed25519Key(1)
	block, err := ssh.MarshalPrivateKey(priv, "arbiter-test")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	msg := "hello allowed_signers"
	msgFile := filepath.Join(dir, "msg")
	if err := os.WriteFile(msgFile, []byte(msg), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(keygen, "-Y", "sign", "-f", keyFile, "-n", "git", msgFile).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen -Y sign failed (key file permissions on this OS?): %v: %s", err, out)
	}
	signers := filepath.Join(dir, "allowed_signers")
	line := FormatLine("alice@example.com", HumanNamespaces, testKey(t, 1)) + "\n"
	if err := os.WriteFile(signers, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	verify := func(ns string) error {
		cmd := exec.Command(keygen, "-Y", "verify", "-f", signers, "-I", "alice@example.com", "-n", ns, "-s", msgFile+".sig")
		cmd.Stdin = strings.NewReader(msg)
		out, err := cmd.CombinedOutput()
		t.Logf("verify -n %s: %s", ns, strings.TrimSpace(string(out)))
		return err
	}
	if err := verify("git"); err != nil {
		t.Fatalf("ssh-keygen rejected namespace git: %v", err)
	}
	if err := verify("arbiter-other"); err == nil {
		t.Fatal("ssh-keygen accepted a namespace outside the line's namespaces")
	}
}
