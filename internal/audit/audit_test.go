package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/gitsign"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

const humanEmail = "human@example.com"

func newSigner(t *testing.T, seed byte) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func git(t *testing.T, dir string, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo is a temp git repo whose commits the tests assemble by hand.
type repo struct {
	dir  string
	last string // sha of the current tip
	sup  ssh.Signer
}

func newRepo(t *testing.T, sup ssh.Signer) *repo {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	dir := t.TempDir()
	git(t, dir, "", "init", "-q", "-b", "main")
	git(t, dir, "", "config", "user.name", "Human")
	git(t, dir, "", "config", "user.email", humanEmail)
	return &repo{dir: dir, sup: sup}
}

func (r *repo) write(t *testing.T, rel, content string) {
	t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// commit writes a commit with the files currently in the worktree. A nil signer leaves it
// unsigned.
func (r *repo) commit(t *testing.T, msg string, signer ssh.Signer) string {
	t.Helper()
	git(t, r.dir, "", "add", "-A")
	tree := git(t, r.dir, "", "write-tree")
	var parents []string
	if r.last != "" {
		parents = []string{r.last}
	}
	id := gitsign.Ident{Name: "Human", Email: humanEmail}
	payload := gitsign.CommitPayload(tree, parents, id, id, time.Now(), msg)
	obj := payload
	if signer != nil {
		sig, err := ledger.NewSSHSignerNamespace(signer, gitsign.Namespace).Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		if obj, err = gitsign.AttachCommitSig(payload, sig, "gpgsig"); err != nil {
			t.Fatal(err)
		}
	}
	sha := git(t, r.dir, string(obj), "hash-object", "-t", "commit", "-w", "--stdin")
	git(t, r.dir, "", "update-ref", "refs/heads/main", sha)
	r.last = sha
	return sha
}

func signersFile(sup, human ssh.Signer) string {
	return allowedsigners.FormatLine("arbiter@test", allowedsigners.SupervisorNamespaces, sup.PublicKey()) + "\n" +
		allowedsigners.FormatLine(humanEmail, allowedsigners.HumanNamespaces, human.PublicKey()) + "\n"
}

// buildChain returns a chain of n valid entries signed by signer.
func buildChain(t *testing.T, signer ssh.Signer, n int) []ledger.Entry {
	t.Helper()
	c, err := ledger.NewChain("PRD-001", ledger.NewSSHSigner(signer))
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		if _, err := c.Append("PRD-001/ringleader", "merge_commit", "", map[string]any{"sha": "abc123"}); err != nil {
			t.Fatal(err)
		}
	}
	return c.Entries()
}

func jsonl(t *testing.T, entries []ledger.Entry) string {
	t.Helper()
	var b bytes.Buffer
	if err := ledger.WriteJSONL(&b, entries); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func pinFor(entries []ledger.Entry) gitsign.LedgerPin {
	e := entries[len(entries)-1]
	return gitsign.LedgerPin{Path: ".arbiter/ledger/PRD-001.jsonl", Seq: e.Seq, Hash: e.EntryHash}
}

func msgFor(pin gitsign.LedgerPin) string {
	return "task merge\n\nArbiter-PRD: PRD-001@v1 (tag arbiter/prd/PRD-001/v1)\nArbiter-Ledger: " + pin.String() + "\n"
}

func verify(t *testing.T, r *repo) *Report {
	t.Helper()
	rep, err := Verify(context.Background(), r.dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func wantFail(t *testing.T, rep *Report, in []Result, substr string) {
	t.Helper()
	if rep.OK() {
		t.Fatal("report OK, want failure")
	}
	for _, res := range in {
		if res.Err != nil && strings.Contains(res.Err.Error(), substr) {
			return
		}
	}
	t.Fatalf("no failure containing %q: commits=%v ledgers=%v", substr, rep.Commits, rep.Ledgers)
}

func TestVerifyValid(t *testing.T) {
	sup, human := newSigner(t, 1), newSigner(t, 2)
	r := newRepo(t, sup)
	chain := buildChain(t, sup, 3)

	r.write(t, ".arbiter/ledger/allowed_signers", signersFile(sup, human))
	r.write(t, ".arbiter/ledger/PRD-001.jsonl", jsonl(t, chain[:2]))
	r.commit(t, msgFor(pinFor(chain[:2])), sup)
	r.write(t, ".arbiter/ledger/PRD-001.jsonl", jsonl(t, chain))
	r.commit(t, msgFor(pinFor(chain)), sup)
	// A human-signed commit carrying a pin (the final merge shape) is also fine.
	r.write(t, "README.md", "x\n")
	r.commit(t, msgFor(pinFor(chain)), human)

	rep := verify(t, r)
	if !rep.OK() || len(rep.Commits) != 3 || len(rep.Ledgers) != 1 {
		t.Fatalf("commits=%v ledgers=%v", rep.Commits, rep.Ledgers)
	}
}

func TestVerifyFailures(t *testing.T) {
	sup, human, rogue := newSigner(t, 1), newSigner(t, 2), newSigner(t, 3)
	chain := buildChain(t, sup, 3)
	good := jsonl(t, chain)

	tests := []struct {
		name   string
		setup  func(t *testing.T, r *repo)
		in     func(*Report) []Result
		substr string
	}{
		{
			name: "truncated ledger",
			setup: func(t *testing.T, r *repo) {
				t.Helper()
				r.write(t, ".arbiter/ledger/PRD-001.jsonl", jsonl(t, chain[:2]))
				r.commit(t, msgFor(pinFor(chain)), sup)
			},
			in:     func(rep *Report) []Result { return rep.Commits },
			substr: "pinned head",
		},
		{
			name: "edited entry",
			setup: func(t *testing.T, r *repo) {
				t.Helper()
				edited := strings.Replace(good, `"sha":"abc123"`, `"sha":"abc124"`, 1)
				if edited == good {
					t.Fatal("edit did not apply")
				}
				r.write(t, ".arbiter/ledger/PRD-001.jsonl", edited)
				r.commit(t, msgFor(pinFor(chain)), sup)
			},
			in:     func(rep *Report) []Result { return append(rep.Commits, rep.Ledgers...) },
			substr: "entry_hash mismatch",
		},
		{
			name: "unsigned commit",
			setup: func(t *testing.T, r *repo) {
				t.Helper()
				r.write(t, ".arbiter/ledger/PRD-001.jsonl", good)
				r.commit(t, msgFor(pinFor(chain)), nil)
			},
			in:     func(rep *Report) []Result { return rep.Commits },
			substr: "not signed",
		},
		{
			name: "ledger signed by unknown key",
			setup: func(t *testing.T, r *repo) {
				t.Helper()
				rogueChain := buildChain(t, rogue, 3)
				r.write(t, ".arbiter/ledger/PRD-001.jsonl", jsonl(t, rogueChain))
				r.commit(t, msgFor(pinFor(rogueChain)), sup)
			},
			in:     func(rep *Report) []Result { return append(rep.Commits, rep.Ledgers...) },
			substr: "no line for key",
		},
		{
			name: "commit signed by unknown key",
			setup: func(t *testing.T, r *repo) {
				t.Helper()
				r.write(t, ".arbiter/ledger/PRD-001.jsonl", good)
				r.commit(t, msgFor(pinFor(chain)), rogue)
			},
			in:     func(rep *Report) []Result { return rep.Commits },
			substr: "no line for key",
		},
		{
			name: "pinned ledger missing",
			setup: func(t *testing.T, r *repo) {
				t.Helper()
				r.write(t, "README.md", "x\n")
				r.commit(t, msgFor(pinFor(chain)), sup)
			},
			in:     func(rep *Report) []Result { return rep.Commits },
			substr: "PRD-001.jsonl",
		},
		{
			name: "tampered message",
			setup: func(t *testing.T, r *repo) {
				t.Helper()
				r.write(t, ".arbiter/ledger/PRD-001.jsonl", good)
				sha := r.commit(t, msgFor(pinFor(chain)), sup)
				raw := git(t, r.dir, "", "cat-file", "commit", sha)
				forged := strings.Replace(raw, "task merge", "task mergf", 1)
				forgedSha := git(t, r.dir, forged+"\n", "hash-object", "-t", "commit", "-w", "--stdin")
				git(t, r.dir, "", "update-ref", "refs/heads/main", forgedSha)
			},
			in:     func(rep *Report) []Result { return rep.Commits },
			substr: "signature",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRepo(t, sup)
			r.write(t, ".arbiter/ledger/allowed_signers", signersFile(sup, human))
			tc.setup(t, r)
			rep := verify(t, r)
			wantFail(t, rep, tc.in(rep), tc.substr)
		})
	}
}

func TestVerifySetupErrors(t *testing.T) {
	sup := newSigner(t, 1)
	r := newRepo(t, sup)
	r.write(t, "README.md", "x\n")
	r.commit(t, "no signers\n", nil)
	if _, err := Verify(context.Background(), r.dir, "main"); err == nil {
		t.Fatal("missing allowed_signers accepted")
	}
	if _, err := Verify(context.Background(), r.dir, "nope"); err == nil {
		t.Fatal("unknown rev accepted")
	}
}

func TestParseCommitRoundTrip(t *testing.T) {
	sup := newSigner(t, 1)
	id := gitsign.Ident{Name: "Human", Email: humanEmail}
	when := time.Unix(1700000000, 0).UTC()
	payload := gitsign.CommitPayload(strings.Repeat("a", 40), []string{strings.Repeat("b", 40)}, id, id, when, "subject\n\nbody line\n")
	sig, err := ledger.NewSSHSignerNamespace(sup, gitsign.Namespace).Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"gpgsig", "gpgsig-sha256"} {
		raw, err := gitsign.AttachCommitSig(payload, sig, header)
		if err != nil {
			t.Fatal(err)
		}
		c, err := parseCommit(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c.payload, payload) {
			t.Errorf("%s: payload mismatch:\n%q\n%q", header, c.payload, payload)
		}
		if c.sig != strings.TrimRight(sig, "\r\n") {
			t.Errorf("%s: signature mismatch", header)
		}
		if c.email != humanEmail || c.committed != when.Unix() || c.subject != "subject" {
			t.Errorf("%s: parsed %+v", header, c)
		}
	}
	c, err := parseCommit(payload)
	if err != nil || c.sig != "" {
		t.Fatalf("unsigned: %+v, %v", c, err)
	}
}
