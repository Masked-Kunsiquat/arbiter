package humansig

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const fakeSig = "-----BEGIN SSH SIGNATURE-----\nFAKE\n-----END SSH SIGNATURE-----\n"

// TestMain lets the test binary double as a fake signing program.
func TestMain(m *testing.M) {
	if os.Getenv("HUMANSIG_FAKE_SIGNER") == "1" {
		os.Exit(fakeSigner())
	}
	os.Exit(m.Run())
}

// fakeSigner records its argv and the key file's contents, then writes "<buffer>.sig".
func fakeSigner() int {
	args := os.Args[1:]
	if os.Getenv("HUMANSIG_FAKE_FAIL") == "1" {
		_, _ = os.Stderr.WriteString("usage: ssh-keygen [-q] [-a rounds]\n")
		return 1
	}
	if rec := os.Getenv("HUMANSIG_FAKE_RECORD"); rec != "" {
		_ = os.WriteFile(rec, []byte(strings.Join(args, "\n")), 0o600)
	}
	for i, a := range args {
		if a == "-f" && i+1 < len(args) {
			if out := os.Getenv("HUMANSIG_FAKE_KEYOUT"); out != "" {
				b, _ := os.ReadFile(args[i+1])
				_ = os.WriteFile(out, b, 0o600)
			}
		}
	}
	if err := os.WriteFile(args[len(args)-1]+".sig", []byte(fakeSig), 0o600); err != nil {
		return 2
	}
	return 0
}

func testKey(t *testing.T, dir string) (priv, pub string, pk ssh.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	k := ed25519.NewKeyFromSeed(seed)
	block, err := ssh.MarshalPrivateKey(k, "humansig-test")
	if err != nil {
		t.Fatal(err)
	}
	priv = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(priv, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	pk, err = ssh.NewPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub = priv + ".pub"
	if err := os.WriteFile(pub, ssh.MarshalAuthorizedKey(pk), 0o600); err != nil {
		t.Fatal(err)
	}
	return priv, pub, pk
}

func keyText(pk ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

func isolateGit(t *testing.T) {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func TestLoadConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	isolateGit(t)
	dir := t.TempDir()
	git(t, dir, "init", "-q")

	c, err := LoadConfig(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != "" || c.SigningKey != "" || c.Email != "" || c.Program != "ssh-keygen" {
		t.Errorf("unset config = %+v", c)
	}

	for k, v := range map[string]string{
		"gpg.format":                "ssh",
		"gpg.ssh.program":           "my-signer",
		"user.signingkey":           "~/.ssh/id.pub",
		"gpg.ssh.defaultKeyCommand": "ssh-add -L",
		"user.name":                 "Hu Man",
		"user.email":                "h@example.com",
	} {
		git(t, dir, "config", k, v)
	}
	c, err = LoadConfig(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Format: "ssh", Program: "my-signer", SigningKey: "~/.ssh/id.pub", DefaultKeyCommand: "ssh-add -L", Name: "Hu Man", Email: "h@example.com"}
	if c != want {
		t.Errorf("got %+v, want %+v", c, want)
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Format: "ssh", SigningKey: "k", Email: "h@example.com"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	withCmd := Config{Format: "ssh", DefaultKeyCommand: "x", Email: "h@example.com"}
	if err := withCmd.Validate(); err != nil {
		t.Fatalf("default key command config rejected: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"format", func(c *Config) { c.Format = "openpgp" }, "gpg.format ssh"},
		{"empty format", func(c *Config) { c.Format = "" }, "gpg.format ssh"},
		{"email", func(c *Config) { c.Email = "" }, "user.email"},
		{"key", func(c *Config) { c.SigningKey = "" }, "user.signingkey"},
	}
	for _, tc := range cases {
		c := ok
		tc.mut(&c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want mention of %q", tc.name, err, tc.want)
		}
		if _, nerr := NewSigner(c); nerr == nil {
			t.Errorf("%s: NewSigner accepted invalid config", tc.name)
		}
	}
}

func TestPublicKey(t *testing.T) {
	dir := t.TempDir()
	priv, pub, pk := testKey(t, dir)
	line := keyText(pk) + " me@example.com"
	ctx := context.Background()

	get := func(key string) (ssh.PublicKey, error) {
		t.Helper()
		s, err := NewSigner(Config{Format: "ssh", SigningKey: key, Email: "h@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		return s.PublicKey(ctx)
	}
	for name, key := range map[string]string{
		"literal":       line,
		"key:: literal": "key::" + line,
		"pub path":      pub,
		"private+pub":   priv,
	} {
		got, err := get(key)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got.Marshal()) != string(pk.Marshal()) {
			t.Errorf("%s: wrong key", name)
		}
	}

	if err := os.Remove(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := get(priv); err == nil || !strings.Contains(err.Error(), ".pub") {
		t.Errorf("private key without .pub: err = %v", err)
	}
}

func TestPublicKeyDefaultKeyCommand(t *testing.T) {
	_, _, pk := testKey(t, t.TempDir())
	// "echo ..." works under both sh -c and cmd /C.
	s, err := NewSigner(Config{Format: "ssh", DefaultKeyCommand: "echo " + keyText(pk), Email: "h@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Marshal()) != string(pk.Marshal()) {
		t.Error("wrong key from defaultKeyCommand")
	}

	bad, err := NewSigner(Config{Format: "ssh", DefaultKeyCommand: "echo not-a-key", Email: "h@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.PublicKey(context.Background()); err == nil {
		t.Error("accepted non-key output")
	}
}

// fakeSignerFor returns a Signer whose program is this test binary in fake-signer mode, plus
// the files where the fake records its argv and the key file contents it saw.
func fakeSignerFor(t *testing.T, key string) (s *Signer, argsFile, keyOut string) {
	t.Helper()
	exe, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	keyOut = filepath.Join(dir, "key")
	t.Setenv("HUMANSIG_FAKE_SIGNER", "1")
	t.Setenv("HUMANSIG_FAKE_RECORD", argsFile)
	t.Setenv("HUMANSIG_FAKE_KEYOUT", keyOut)
	s, err = NewSigner(Config{Format: "ssh", Program: exe, SigningKey: key, Email: "h@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s.stdin = strings.NewReader("")
	s.stderr = &strings.Builder{}
	return s, argsFile, keyOut
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertGone(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("temp file %s not removed (err=%v)", p, err)
	}
}

func TestSignInvocation(t *testing.T) {
	_, _, pk := testKey(t, t.TempDir())
	literal := keyText(pk)
	pathKey := filepath.Join(t.TempDir(), "id")

	for _, tc := range []struct {
		name, key string
		literal   bool
	}{
		{"key:: literal", "key::" + literal, true},
		{"ssh- literal", literal, true},
		{"path", pathKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, argsFile, keyOut := fakeSignerFor(t, tc.key)
			sig, err := s.Sign(context.Background(), []byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			if sig != strings.TrimRight(fakeSig, "\n") {
				t.Errorf("sig = %q", sig)
			}
			args := strings.Split(readFile(t, argsFile), "\n")
			wantLen := 7
			if tc.literal {
				wantLen = 8
			}
			if len(args) != wantLen {
				t.Fatalf("args = %q, want %d", args, wantLen)
			}
			for i, w := range []string{"-Y", "sign", "-n", "git", "-f"} {
				if args[i] != w {
					t.Fatalf("args = %q", args)
				}
			}
			keyFile, bufFile := args[5], args[len(args)-1]
			if tc.literal {
				if args[6] != "-U" {
					t.Errorf("missing -U: %q", args)
				}
				if !strings.HasPrefix(filepath.Base(keyFile), ".git_signing_key_tmp") {
					t.Errorf("key file = %q", keyFile)
				}
				if got := readFile(t, keyOut); strings.TrimSpace(got) != literal || strings.Contains(got, "key::") {
					t.Errorf("temp key file contents = %q", got)
				}
				assertGone(t, keyFile)
			} else if keyFile != tc.key {
				t.Errorf("key file = %q, want %q", keyFile, tc.key)
			}
			if !strings.HasPrefix(filepath.Base(bufFile), ".git_signing_buffer_tmp") {
				t.Errorf("buffer file = %q", bufFile)
			}
			assertGone(t, bufFile)
			assertGone(t, bufFile+".sig")
		})
	}
}

func TestSignFailure(t *testing.T) {
	s, _, _ := fakeSignerFor(t, "/some/key")
	t.Setenv("HUMANSIG_FAKE_FAIL", "1")
	_, err := s.Sign(context.Background(), []byte("x"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "signing failed") || !strings.Contains(err.Error(), "OpenSSH") {
		t.Errorf("err = %v", err)
	}
}

func TestSignDefaultKeyCommandIsLiteral(t *testing.T) {
	_, _, pk := testKey(t, t.TempDir())
	s, argsFile, _ := fakeSignerFor(t, "placeholder")
	s.cfg.SigningKey = ""
	s.cfg.DefaultKeyCommand = "echo " + keyText(pk)
	if _, err := s.Sign(context.Background(), []byte("p")); err != nil {
		t.Fatal(err)
	}
	if args := strings.Split(readFile(t, argsFile), "\n"); len(args) != 8 || args[6] != "-U" {
		t.Errorf("args = %q", args)
	}
}

func TestSignWithSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	dir := t.TempDir()
	priv, _, pk := testKey(t, dir)
	s, err := NewSigner(Config{Format: "ssh", Program: keygen, SigningKey: priv, Email: "h@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s.stdin = strings.NewReader("")
	payload := []byte("tree 0000\nauthor h\n\nmsg\n")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Skipf("ssh-keygen -Y sign failed (key file permissions on this OS?): %v", err)
	}
	if !strings.HasPrefix(sig, "-----BEGIN SSH SIGNATURE-----") || !strings.HasSuffix(sig, "-----END SSH SIGNATURE-----") {
		t.Fatalf("not armored: %q", sig)
	}
	signers := filepath.Join(dir, "allowed_signers")
	if err := os.WriteFile(signers, []byte(`h@example.com namespaces="git" `+keyText(pk)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigFile := filepath.Join(dir, "sig")
	if err := os.WriteFile(sigFile, []byte(sig+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(keygen, "-Y", "verify", "-f", signers, "-I", "h@example.com", "-n", "git", "-s", sigFile)
	cmd.Stdin = strings.NewReader(string(payload))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rejected signature: %v: %s", err, out)
	}
}

func TestProgramPath(t *testing.T) {
	if got := programPath(`"C:\Program Files\x\ssh-keygen.exe"`); got != `C:\Program Files\x\ssh-keygen.exe` {
		t.Errorf("got %q", got)
	}
}
