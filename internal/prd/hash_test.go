package prd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalKnownVector(t *testing.T) {
	src := "\ufeff---\r\nid: PRD-001\r\nstatus: locked\r\nspec_hash: abc\r\n  cont\r\n\tcont2\r\ntitle: T\r\ncreated_by : me\r\n---\r\n\r\nbody  \r\n"
	want := "---\nid: PRD-001\ntitle: T\n---\n\nbody  \n"
	got, err := Canonical([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("Canonical = %q, want %q", got, want)
	}
	sum := sha256.Sum256([]byte(want))
	h, err := SpecHash([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if h != hex.EncodeToString(sum[:]) {
		t.Errorf("SpecHash = %s", h)
	}
}

func TestCanonicalKeepsBodyKeys(t *testing.T) {
	// status: in the body and similarly named frontmatter keys are not removed.
	src := "---\nid: PRD-001\nstatus_note: x\n---\nstatus: locked\n"
	got, err := Canonical([]byte(src))
	if err != nil || string(got) != src {
		t.Errorf("Canonical = %q, %v", got, err)
	}
}

func TestCanonicalNeedsFences(t *testing.T) {
	for _, src := range []string{"", "id: x\n", "---\nid: x\n"} {
		if _, err := Canonical([]byte(src)); err == nil {
			t.Errorf("Canonical(%q) succeeded", src)
		}
		if _, err := SpecHash([]byte(src)); err == nil {
			t.Errorf("SpecHash(%q) succeeded", src)
		}
	}
}

func mustHash(t *testing.T, src string) string {
	t.Helper()
	h, err := SpecHash([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSpecHashInvariance(t *testing.T) {
	base := mustHash(t, specExample)
	same := map[string]string{
		"crlf":           strings.ReplaceAll(specExample, "\n", "\r\n"),
		"bom":            "\ufeff" + specExample,
		"status changed": strings.Replace(specExample, "status: locked", "status: executing", 1),
		"hash changed":   strings.Replace(specExample, testHash, strings.Repeat("a", 64), 1),
		"created_by":     strings.Replace(specExample, "created_by: human:Masked-Kunsiquat\n", "", 1),
		"all removed":    strings.Replace(strings.Replace(strings.Replace(specExample, "status: locked\n", "", 1), "created_by: human:Masked-Kunsiquat\n", "", 1), "spec_hash: "+testHash+"\n", "", 1),
	}
	for name, v := range same {
		if got := mustHash(t, v); got != base {
			t.Errorf("%s: hash changed", name)
		}
	}
	differ := map[string]string{
		"title":    strings.Replace(specExample, "Rotation", "Rotations", 1),
		"budget":   strings.Replace(specExample, "5.00", "6.00", 1),
		"trailing": specExample + " ",
		"no final": strings.TrimSuffix(specExample, "\n"),
		"body":     strings.Replace(specExample, "AC-1", "AC-9", 1),
	}
	for name, v := range differ {
		if got := mustHash(t, v); got == base {
			t.Errorf("%s: hash did not change", name)
		}
	}
	if len(base) != 64 || strings.ToLower(base) != base {
		t.Errorf("hash = %q", base)
	}
}

func TestHasherStrict(t *testing.T) {
	var h interface {
		SpecHash([]byte) (string, error)
	} = Hasher{}
	got, err := h.SpecHash([]byte(specExample))
	if err != nil || got != mustHash(t, specExample) {
		t.Errorf("got %q, %v", got, err)
	}
	bad := strings.Replace(specExample, "- [ ] AC-3", "AC-3", 1)
	_, err = h.SpecHash([]byte(bad))
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Errorf("err = %v, want *ParseError", err)
	}
}

func TestSetArbiterFields(t *testing.T) {
	newHash := strings.Repeat("ab", 32)
	f := ArbiterFields{Status: StatusLocked, SpecHash: newHash, CreatedBy: "human:me"}
	author := minimal(okIntent, okInv, okBound, okAC)

	tests := []struct {
		name string
		src  string
		want string // expected frontmatter prefix; "" skips the exact check
	}{
		{
			"after title", author,
			"---\nid: PRD-001\ntitle: T\nstatus: locked\ncreated_by: human:me\nspec_hash: " + newHash + "\ntarget_branch: feat/x\n---\n",
		},
		{
			"replaces existing with continuations",
			strings.Replace(author, "title: T\n", "title: T\nstatus: draft\nspec_hash: old\n  more\ncreated_by: x\n", 1),
			"---\nid: PRD-001\ntitle: T\nstatus: locked\ncreated_by: human:me\nspec_hash: " + newHash + "\ntarget_branch: feat/x\n---\n",
		},
		{
			"after folded title",
			strings.Replace(author, "title: T\n", "title: >-\n  long\n  title\n", 1),
			"---\nid: PRD-001\ntitle: >-\n  long\n  title\nstatus: locked\ncreated_by: human:me\nspec_hash: " + newHash + "\ntarget_branch: feat/x\n---\n",
		},
		{
			"no title",
			strings.Replace(author, "title: T\n", "", 1),
			"---\nid: PRD-001\ntarget_branch: feat/x\nstatus: locked\ncreated_by: human:me\nspec_hash: " + newHash + "\n---\n",
		},
		{"crlf", strings.ReplaceAll(author, "\n", "\r\n"), ""},
		{"bom", "\ufeff" + author, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := SetArbiterFields([]byte(tc.src), f)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && !strings.HasPrefix(string(out), tc.want) {
				t.Errorf("got\n%q\nwant prefix\n%q", out, tc.want)
			}
			if mustHash(t, string(out)) != mustHash(t, tc.src) {
				t.Error("spec_hash changed")
			}
			if !strings.Contains(tc.src, "title:") || tc.name == "after folded title" {
				return // not a complete PRD (or multi-line, which Parse rejects): nothing to parse
			}
			p, err := Parse(out)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.Status != StatusLocked || p.SpecHash != newHash || p.CreatedBy != "human:me" {
				t.Errorf("parsed %+v", p)
			}
			// Body is untouched.
			body := func(s string) string { return s[strings.LastIndex(s, "---")+3:] }
			if body(string(out)) != body(tc.src) {
				t.Error("body changed")
			}
		})
	}
}

func TestSetArbiterFieldsLineEndingsAndPartial(t *testing.T) {
	src := "---\r\nid: PRD-001\r\ntitle: T\r\nstatus: draft\r\ntarget_branch: b\n---\nbody\n"
	out, err := SetArbiterFields([]byte(src), ArbiterFields{CreatedBy: "me"})
	if err != nil {
		t.Fatal(err)
	}
	// Only non-empty fields change; status is kept; inserted line uses CRLF;
	// other lines (including the mixed LF ones) are byte-for-byte unchanged.
	want := "---\r\nid: PRD-001\r\ntitle: T\r\ncreated_by: me\r\nstatus: draft\r\ntarget_branch: b\n---\nbody\n"
	if string(out) != want {
		t.Errorf("got %q\nwant %q", out, want)
	}
}

func TestSetArbiterFieldsQuoting(t *testing.T) {
	out, err := SetArbiterFields([]byte("---\ntitle: T\n---\n"), ArbiterFields{CreatedBy: "a: b #c"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "---\ntitle: T\ncreated_by: 'a: b #c'\n---\n" {
		t.Errorf("got %q", out)
	}
}

func TestSetArbiterFieldsErrors(t *testing.T) {
	if _, err := SetArbiterFields([]byte("no frontmatter\n"), ArbiterFields{Status: StatusDraft}); err == nil {
		t.Error("expected error without frontmatter")
	}
	if _, err := SetArbiterFields([]byte("---\n---\n"), ArbiterFields{CreatedBy: "a\nb"}); err == nil {
		t.Error("expected error for multi-line value")
	}
}
