package prd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// arbiterKeyRe matches the frontmatter keys Arbiter writes and that
// spec_hash therefore excludes (§2.C).
var arbiterKeyRe = regexp.MustCompile(`^(status|spec_hash|created_by)[ \t]*:`)

// stripBOM removes a leading UTF-8 byte-order mark.
func stripBOM(s string) string { return strings.TrimPrefix(s, "\ufeff") }

// normalize strips a BOM and converts CRLF and lone CR to LF (§2.C).
func normalize(src []byte) string {
	s := stripBOM(string(src))
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// findClose returns the index of the closing "---" fence of the frontmatter in
// lines (line 0 must be the opening fence), or a message describing why not.
func findClose(lines []string) (int, string) {
	if len(lines) == 0 || lines[0] != "---" {
		return 0, "missing frontmatter: first line must be ---"
	}
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			return i, ""
		}
	}
	return 0, "unterminated frontmatter: no closing ---"
}

// isContinuation reports whether a frontmatter line continues the previous
// key's value (starts with a space or tab).
func isContinuation(line string) bool {
	return line != "" && (line[0] == ' ' || line[0] == '\t')
}

// Canonical returns the bytes spec_hash is computed over: the file with a BOM
// removed, line endings normalized to LF, and the status, spec_hash and
// created_by frontmatter entries (with continuation lines) removed (§2.C). The
// PRD need not otherwise be valid, but the frontmatter fences must exist.
func Canonical(src []byte) ([]byte, error) {
	lines := strings.Split(normalize(src), "\n")
	closeIdx, msg := findClose(lines)
	if msg != "" {
		return nil, errors.New("prd: " + msg)
	}
	out := make([]string, 0, len(lines))
	out = append(out, lines[0])
	for i := 1; i < closeIdx; i++ {
		if arbiterKeyRe.MatchString(lines[i]) {
			for i+1 < closeIdx && isContinuation(lines[i+1]) {
				i++
			}
			continue
		}
		out = append(out, lines[i])
	}
	out = append(out, lines[closeIdx:]...)
	return []byte(strings.Join(out, "\n")), nil
}

// SpecHash returns the lowercase hex SHA-256 of Canonical(src) (§2.C).
func SpecHash(src []byte) (string, error) {
	c, err := Canonical(src)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// Hasher computes spec_hash for locking: unlike the package-level SpecHash it
// requires the PRD to parse cleanly first, so an invalid PRD can't be locked.
type Hasher struct{}

// SpecHash parses src strictly (returning any *ParseError) and then hashes it.
func (Hasher) SpecHash(src []byte) (string, error) {
	if _, err := Parse(src); err != nil {
		return "", err
	}
	return SpecHash(src)
}

// ArbiterFields are the frontmatter fields Arbiter writes on the author's
// behalf. Empty fields are left untouched.
type ArbiterFields struct {
	Status    Status
	SpecHash  string
	CreatedBy string
}

// rawLine is a line with its original terminator ("\n", "\r\n", "\r" or "").
type rawLine struct{ text, eol string }

func splitRawLines(s string) []rawLine {
	var out []rawLine
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			out = append(out, rawLine{s[start:i], "\n"})
			start = i + 1
		case '\r':
			eol := "\r"
			if i+1 < len(s) && s[i+1] == '\n' {
				eol = "\r\n"
				i++
			}
			out = append(out, rawLine{s[start : i+1-len(eol)], eol})
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, rawLine{s[start:], ""})
	}
	return out
}

// yamlScalar renders s as a single-line YAML scalar, quoted only when needed.
func yamlScalar(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n") {
		return "", errors.New("prd: frontmatter value must be a single line")
	}
	b, err := yaml.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("prd: encode yaml scalar: %w", err)
	}
	return strings.TrimSuffix(string(b), "\n"), nil
}

// SetArbiterFields writes the non-empty fields of f into src's frontmatter,
// replacing any existing entries for those keys and leaving every other byte
// (including line endings) unchanged. New lines go in the order status,
// created_by, spec_hash directly after the title entry, or before the closing
// fence if there is no title. The result has the same spec_hash as src (§2.C).
func SetArbiterFields(src []byte, f ArbiterFields) ([]byte, error) {
	s := string(src)
	bom := ""
	if strings.HasPrefix(s, "\ufeff") {
		bom, s = "\ufeff", s[len("\ufeff"):]
	}
	lines := splitRawLines(s)
	texts := make([]string, len(lines))
	for i, l := range lines {
		texts[i] = l.text
	}
	closeIdx, msg := findClose(texts)
	if msg != "" {
		return nil, errors.New("prd: " + msg)
	}

	type kv struct{ key, val string }
	var set []kv
	for _, p := range []kv{{"status", string(f.Status)}, {"created_by", f.CreatedBy}, {"spec_hash", f.SpecHash}} {
		if p.val == "" {
			continue
		}
		v, err := yamlScalar(p.val)
		if err != nil {
			return nil, err
		}
		set = append(set, kv{p.key, v})
	}

	remove := map[string]*regexp.Regexp{}
	for _, p := range set {
		remove[p.key] = regexp.MustCompile(`^` + regexp.QuoteMeta(p.key) + `[ \t]*:`)
	}
	fm := make([]rawLine, 0, closeIdx)
	for i := 1; i < closeIdx; i++ {
		drop := false
		for _, re := range remove {
			if re.MatchString(lines[i].text) {
				drop = true
				break
			}
		}
		if drop {
			for i+1 < closeIdx && isContinuation(lines[i+1].text) {
				i++
			}
			continue
		}
		fm = append(fm, lines[i])
	}

	// Insertion point: after the title entry and its continuation lines.
	at := len(fm)
	titleRe := regexp.MustCompile(`^title[ \t]*:`)
	for i, l := range fm {
		if titleRe.MatchString(l.text) {
			at = i + 1
			for at < len(fm) && isContinuation(fm[at].text) {
				at++
			}
			break
		}
	}

	eol := "\n"
	if len(lines) > 0 && lines[0].eol != "" {
		eol = lines[0].eol
	}
	var b strings.Builder
	b.WriteString(bom)
	write := func(l rawLine) { b.WriteString(l.text + l.eol) }
	write(lines[0])
	for _, l := range fm[:at] {
		write(l)
	}
	for _, p := range set {
		b.WriteString(p.key + ": " + p.val + eol)
	}
	for _, l := range fm[at:] {
		write(l)
	}
	for _, l := range lines[closeIdx:] {
		write(l)
	}
	return []byte(b.String()), nil
}
