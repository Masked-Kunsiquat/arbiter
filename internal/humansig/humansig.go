// Package humansig is the CLI-side human signer (spec §8.C): signing is always client-side.
// The core never holds the key; it prepares the object, this package signs it locally by
// invoking the configured SSH signing program exactly as git's sign_buffer_ssh does, so
// ssh-agent, YubiKeys and 1Password's SSH agent all work unchanged.
package humansig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
)

// namespace is the SSH signature namespace git uses for commit and tag signatures.
const namespace = "git"

// Config is the human's git signing setup, read from git config in the repo.
type Config struct {
	Format            string // gpg.format; must be "ssh"
	Program           string // gpg.ssh.program; default "ssh-keygen"
	SigningKey        string // user.signingkey, raw
	DefaultKeyCommand string // gpg.ssh.defaultKeyCommand
	Name, Email       string // user.name, user.email
}

// LoadConfig reads the signing-related git config in repoDir. A missing key yields "".
func LoadConfig(ctx context.Context, repoDir string) (Config, error) {
	var c Config
	fields := []struct {
		key string
		dst *string
	}{
		{"gpg.format", &c.Format},
		{"gpg.ssh.program", &c.Program},
		{"user.signingkey", &c.SigningKey},
		{"gpg.ssh.defaultKeyCommand", &c.DefaultKeyCommand},
		{"user.name", &c.Name},
		{"user.email", &c.Email},
	}
	for _, f := range fields {
		v, err := gitConfigGet(ctx, repoDir, f.key)
		if err != nil {
			return Config{}, err
		}
		*f.dst = v
	}
	if c.Program == "" {
		c.Program = "ssh-keygen"
	}
	return c, nil
}

func gitConfigGet(ctx context.Context, dir, key string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-c", "core.fsmonitor=false", "config", "--get", key)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return "", nil // key not set
		}
		return "", fmt.Errorf("humansig: git config --get %s: %w: %s", key, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// Validate returns an actionable error when signing can't work.
func (c Config) Validate() error {
	if c.Format != "ssh" {
		return errors.New("arbiter: human signatures use git's SSH signing; run: git config gpg.format ssh")
	}
	if c.Email == "" {
		return errors.New("arbiter: no signer identity; run: git config user.email <you@example.com>")
	}
	if c.SigningKey == "" && c.DefaultKeyCommand == "" {
		return errors.New("arbiter: no signing key; run: git config user.signingkey <path-to-public-key>")
	}
	return nil
}

// Signer signs payloads in namespace "git" with the human's key.
type Signer struct {
	cfg    Config
	stdin  io.Reader
	stderr io.Writer
}

// NewSigner validates cfg and returns a Signer.
func NewSigner(cfg Config) (*Signer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Signer{cfg: cfg, stdin: os.Stdin, stderr: os.Stderr}, nil
}

// isLiteral mirrors git's is_literal_ssh_key, plus the other literal OpenSSH key types.
func isLiteral(s string) bool {
	for _, p := range []string{"key::", "ssh-", "sk-ssh-", "ecdsa-sha2-", "sk-ecdsa-"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// keyRef is the resolved signing key: literal key text, or a file path.
type keyRef struct {
	literal bool
	value   string
}

func (s *Signer) resolveKey(ctx context.Context) (keyRef, error) {
	if s.cfg.SigningKey == "" {
		line, err := s.defaultKey(ctx)
		if err != nil {
			return keyRef{}, err
		}
		return keyRef{literal: true, value: line}, nil
	}
	if isLiteral(s.cfg.SigningKey) {
		return keyRef{literal: true, value: strings.TrimPrefix(s.cfg.SigningKey, "key::")}, nil
	}
	p, err := expandHome(s.cfg.SigningKey)
	if err != nil {
		return keyRef{}, err
	}
	return keyRef{value: p}, nil
}

// defaultKey runs gpg.ssh.defaultKeyCommand and returns its first non-empty line (a literal key).
// Like git, it splits the command on whitespace and runs it without a shell.
func (s *Signer) defaultKey(ctx context.Context) (string, error) {
	argv := strings.Fields(s.cfg.DefaultKeyCommand)
	if len(argv) == 0 {
		return "", errors.New("humansig: gpg.ssh.defaultKeyCommand is empty")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = s.stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("humansig: gpg.ssh.defaultKeyCommand %q: %w", s.cfg.DefaultKeyCommand, err)
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "key::") && !strings.HasPrefix(line, "ssh-") {
			return "", fmt.Errorf("humansig: gpg.ssh.defaultKeyCommand %q printed %q, which is not a public key", s.cfg.DefaultKeyCommand, line)
		}
		return strings.TrimPrefix(line, "key::"), nil
	}
	return "", fmt.Errorf("humansig: gpg.ssh.defaultKeyCommand %q printed no key", s.cfg.DefaultKeyCommand)
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("humansig: expand %q: %w", p, err)
		}
		return filepath.Join(home, p[1:]), nil
	}
	return p, nil
}

// PublicKey resolves the signing public key so the core can check allowed_signers before prompting.
func (s *Signer) PublicKey(ctx context.Context) (ssh.PublicKey, error) {
	ref, err := s.resolveKey(ctx)
	if err != nil {
		return nil, err
	}
	if ref.literal {
		return parsePub([]byte(ref.value), "user.signingkey")
	}
	if b, err := os.ReadFile(ref.value + ".pub"); err == nil {
		return parsePub(b, ref.value+".pub")
	}
	b, err := os.ReadFile(ref.value)
	if err != nil {
		return nil, fmt.Errorf("humansig: read signing key: %w", err)
	}
	k, err := parsePub(b, ref.value)
	if err != nil {
		return nil, fmt.Errorf("%w (if this is a private key, point user.signingkey at the .pub file or a literal public key)", err)
	}
	return k, nil
}

func parsePub(b []byte, what string) (ssh.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, fmt.Errorf("humansig: parse public key from %s: %w", what, err)
	}
	return k, nil
}

// Sign returns the armored SSH signature over payload in namespace "git", as ssh-keygen -Y sign
// writes it (trailing newline trimmed). It invokes the program exactly as git's sign_buffer_ssh.
func (s *Signer) Sign(ctx context.Context, payload []byte) (string, error) {
	ref, err := s.resolveKey(ctx)
	if err != nil {
		return "", err
	}
	keyFile := ref.value
	if ref.literal {
		f, err := os.CreateTemp("", ".git_signing_key_tmp*")
		if err != nil {
			return "", fmt.Errorf("humansig: create temp key file: %w", err)
		}
		keyFile = f.Name()
		defer os.Remove(keyFile)
		_, werr := f.WriteString(ref.value + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", fmt.Errorf("humansig: write temp key file: %w", werr)
		}
	}

	buf, err := os.CreateTemp("", ".git_signing_buffer_tmp*")
	if err != nil {
		return "", fmt.Errorf("humansig: create temp buffer file: %w", err)
	}
	bufName := buf.Name()
	defer os.Remove(bufName)
	defer os.Remove(bufName + ".sig")
	_, werr := buf.Write(payload)
	if cerr := buf.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", fmt.Errorf("humansig: write temp buffer file: %w", werr)
	}

	args := []string{"-Y", "sign", "-n", namespace, "-f", keyFile}
	if ref.literal {
		args = append(args, "-U")
	}
	args = append(args, bufName)

	cmd := exec.CommandContext(ctx, programPath(s.cfg.Program), args...)
	cmd.Stdin = s.stdin
	var captured bytes.Buffer
	cmd.Stderr = io.MultiWriter(s.stderr, &captured)
	if err := cmd.Run(); err != nil {
		msg := fmt.Sprintf("humansig: signing failed: %s: %v", s.cfg.Program, err)
		if strings.Contains(captured.String(), "usage:") {
			msg += " (your OpenSSH is too old to support -Y sign; OpenSSH 8.2 or newer is required)"
		}
		return "", errors.New(msg)
	}

	sig, err := os.ReadFile(bufName + ".sig")
	if err != nil {
		return "", fmt.Errorf("humansig: signing failed: %s wrote no signature: %w", s.cfg.Program, err)
	}
	return strings.TrimRight(string(sig), "\r\n"), nil
}

// programPath strips quotes from a quoted program path and, on Windows, resolves a bare name.
func programPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 && (p[0] == '"' && p[len(p)-1] == '"' || p[0] == '\'' && p[len(p)-1] == '\'') {
		p = p[1 : len(p)-1]
	}
	if runtime.GOOS == "windows" && !strings.ContainsAny(p, `/\`) {
		if lp, err := exec.LookPath(p); err == nil {
			return lp
		}
	}
	return p
}
