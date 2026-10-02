// Package allowedsigners parses, queries, and appends to an OpenSSH
// allowed_signers file (see ssh-keygen(1), ALLOWED SIGNERS).
//
// Arbiter commits this file at .arbiter/ledger/allowed_signers (spec §8.D). It
// ships with the ledger because it is also the ledger's test oracle:
// `ssh-keygen -Y verify` can check any ledger signature against it. The
// supervisor key's line is restricted to the namespaces "git,arbiter-ledger";
// human keys get "git". Verifying keys always come from this file, never from
// the signed object.
package allowedsigners

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// RelPath is where the file lives relative to the .arbiter directory.
const RelPath = "ledger/allowed_signers"

// SupervisorNamespaces and HumanNamespaces are the namespace sets Arbiter writes.
var (
	SupervisorNamespaces = []string{"git", LedgerNamespace}
	HumanNamespaces      = []string{"git"}
)

// SupervisorPrincipal returns the principal Arbiter uses for its own key.
func SupervisorPrincipal(host string) string { return "arbiter@" + host }

// Line is one parsed allowed_signers entry.
type Line struct {
	Principals    []string  // comma-separated patterns from column 1
	Namespaces    []string  // from namespaces="a,b"; nil means any namespace
	CertAuthority bool      // cert-authority option (ignored by Authorize)
	ValidAfter    time.Time // zero if absent
	ValidBefore   time.Time // zero if absent
	Key           ssh.PublicKey
	LineNo        int
}

// File is a parsed allowed_signers file.
type File struct{ Lines []Line }

// Parse reads an allowed_signers file. Unknown options and malformed keys are
// errors (fail closed).
func Parse(r io.Reader) (*File, error) {
	f := &File{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	n := 0
	for sc.Scan() {
		n++
		text := strings.TrimSpace(sc.Text()) // also drops a trailing \r
		if text == "" || text[0] == '#' {
			continue
		}
		l, err := parseLine(text)
		if err != nil {
			return nil, fmt.Errorf("allowedsigners: line %d: %w", n, err)
		}
		l.LineNo = n
		f.Lines = append(f.Lines, l)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("allowedsigners: read: %w", err)
	}
	return f, nil
}

// Load parses the file at path. A missing file yields an empty File.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("allowedsigners: read %s: %w", path, err)
	}
	f, err := Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

func parseLine(text string) (Line, error) {
	var l Line
	var princ, rest string
	if text[0] == '"' {
		end := strings.IndexByte(text[1:], '"')
		if end < 0 {
			return l, errors.New("unterminated quote in principals")
		}
		princ, rest = text[1:1+end], text[end+2:]
	} else {
		i := strings.IndexAny(text, " \t")
		if i < 0 {
			return l, errors.New("missing key")
		}
		princ, rest = text[:i], text[i:]
	}
	if princ == "" {
		return l, errors.New("empty principals")
	}
	l.Principals = strings.Split(princ, ",")

	key, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(rest)))
	if err != nil {
		return l, fmt.Errorf("parse key: %w", err)
	}
	l.Key = key
	for _, o := range opts {
		if err := applyOption(&l, o); err != nil {
			return l, err
		}
	}
	return l, nil
}

func applyOption(l *Line, opt string) error {
	name, val, hasVal := strings.Cut(opt, "=")
	if hasVal {
		val = strings.TrimSuffix(strings.TrimPrefix(val, `"`), `"`)
	}
	switch strings.ToLower(name) {
	case "cert-authority":
		l.CertAuthority = true
	case "namespaces":
		if !hasVal || val == "" {
			return errors.New("namespaces option needs a value")
		}
		l.Namespaces = strings.Split(val, ",")
	case "valid-after", "valid-before":
		t, err := parseTime(val)
		if err != nil {
			return fmt.Errorf("%s: %w", strings.ToLower(name), err)
		}
		if strings.EqualFold(name, "valid-after") {
			l.ValidAfter = t
		} else {
			l.ValidBefore = t
		}
	default:
		return fmt.Errorf("unknown option %q", name)
	}
	return nil
}

// parseTime parses YYYYMMDD[HHMM[SS]][Z]; without Z the time is local.
func parseTime(s string) (time.Time, error) {
	loc := time.Local
	if t, ok := strings.CutSuffix(s, "Z"); ok {
		s, loc = t, time.UTC
	}
	var layout string
	switch len(s) {
	case 8:
		layout = "20060102"
	case 12:
		layout = "200601021504"
	case 14:
		layout = "20060102150405"
	default:
		return time.Time{}, fmt.Errorf("invalid time %q", s)
	}
	t, err := time.ParseInLocation(layout, s, loc)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time %q: %w", s, err)
	}
	return t, nil
}

// wildcard matches s against an ssh-style pattern with '*' and '?'.
func wildcard(pat, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pat) && (pat[px] == '?' || pat[px] == s[sx]):
			px++
			sx++
		case px < len(pat) && pat[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pat) && pat[px] == '*' {
		px++
	}
	return px == len(pat)
}

// matchList reports whether s matches the pattern list: any matching negated
// ("!pat") pattern vetoes, otherwise any positive match succeeds.
func matchList(pats []string, s string) bool {
	matched := false
	for _, p := range pats {
		if neg, ok := strings.CutPrefix(p, "!"); ok {
			if wildcard(neg, s) {
				return false
			}
			continue
		}
		if wildcard(p, s) {
			matched = true
		}
	}
	return matched
}

// Authorize reports whether key may sign for principal in namespace at time at.
// It returns nil on success, otherwise an error explaining the most specific
// reason no line authorized the signature.
func (f *File) Authorize(principal, namespace string, key ssh.PublicKey, at time.Time) error {
	kb := key.Marshal()
	var best error
	rank := -1
	fail := func(r int, err error) {
		if r > rank {
			rank, best = r, err
		}
	}
	for _, l := range f.Lines {
		if l.CertAuthority || !bytes.Equal(l.Key.Marshal(), kb) {
			continue
		}
		if !matchList(l.Principals, principal) {
			fail(1, fmt.Errorf("allowedsigners: key present (line %d) but principal %q not matched", l.LineNo, principal))
			continue
		}
		if l.Namespaces != nil && !matchList(l.Namespaces, namespace) {
			fail(2, fmt.Errorf("allowedsigners: namespace %q not allowed for key (line %d)", namespace, l.LineNo))
			continue
		}
		if !l.ValidAfter.IsZero() && at.Before(l.ValidAfter) {
			fail(3, fmt.Errorf("allowedsigners: key not yet valid (line %d, valid-after %s)", l.LineNo, l.ValidAfter.Format(time.RFC3339)))
			continue
		}
		if !l.ValidBefore.IsZero() && !at.Before(l.ValidBefore) {
			fail(3, fmt.Errorf("allowedsigners: key expired (line %d, valid-before %s)", l.LineNo, l.ValidBefore.Format(time.RFC3339)))
			continue
		}
		return nil
	}
	if best == nil {
		return fmt.Errorf("allowedsigners: no line for key %s", ssh.FingerprintSHA256(key))
	}
	return best
}

// FormatLine renders `<principal> namespaces="<ns,...>" <keytype> <base64>`
// with no comment and no trailing newline. Empty namespaces omit the option.
func FormatLine(principal string, namespaces []string, key ssh.PublicKey) string {
	var b strings.Builder
	b.WriteString(principal)
	if len(namespaces) > 0 {
		b.WriteString(` namespaces="` + strings.Join(namespaces, ",") + `"`)
	}
	b.WriteString(" " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	return b.String()
}

// Ensure makes sure path contains a line authorizing key for principal with
// exactly these namespaces. An equivalent existing line is a no-op (false). A
// line with the same key that differs in principal, namespaces, or carries a
// validity window is an error: trust is never silently rewritten. Otherwise
// the line is appended (LF endings), creating the file and parent dirs.
func Ensure(path, principal string, namespaces []string, key ssh.PublicKey) (added bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("allowedsigners: read %s: %w", path, err)
	}
	f, err := Parse(bytes.NewReader(data))
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	kb := key.Marshal()
	for _, l := range f.Lines {
		if l.CertAuthority || !bytes.Equal(l.Key.Marshal(), kb) {
			continue
		}
		if containsString(l.Principals, principal) && sameSet(l.Namespaces, namespaces) &&
			l.ValidAfter.IsZero() && l.ValidBefore.IsZero() {
			return false, nil
		}
		return false, fmt.Errorf("allowedsigners: %s line %d already has this key with different principals, namespaces, or validity; refusing to rewrite trust", path, l.LineNo)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("allowedsigners: create dir: %w", err)
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return false, fmt.Errorf("allowedsigners: open %s: %w", path, err)
	}
	line := FormatLine(principal, namespaces, key) + "\n"
	if len(data) > 0 && data[len(data)-1] != '\n' {
		line = "\n" + line
	}
	if _, err := out.WriteString(line); err != nil {
		_ = out.Close()
		return false, fmt.Errorf("allowedsigners: write %s: %w", path, err)
	}
	if err := out.Close(); err != nil {
		return false, fmt.Errorf("allowedsigners: close %s: %w", path, err)
	}
	return true, nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	for _, x := range a {
		if !containsString(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !containsString(a, x) {
			return false
		}
	}
	return true
}

// LedgerNamespace is the namespace only the supervisor key may sign in.
const LedgerNamespace = "arbiter-ledger"

// IsSupervisorKey reports whether any line marks key as Arbiter's own: a line
// allowing the arbiter-ledger namespace, or one with an arbiter@<host>
// principal. Human-signature checks (§8.C) reject such keys, so the core,
// which holds the supervisor key, can't stand in for the human.
func (f *File) IsSupervisorKey(key ssh.PublicKey) bool {
	kb := key.Marshal()
	for _, l := range f.Lines {
		if !bytes.Equal(l.Key.Marshal(), kb) {
			continue
		}
		if slices.Contains(l.Namespaces, LedgerNamespace) {
			return true
		}
		for _, p := range l.Principals {
			if strings.HasPrefix(p, "arbiter@") {
				return true
			}
		}
	}
	return false
}
