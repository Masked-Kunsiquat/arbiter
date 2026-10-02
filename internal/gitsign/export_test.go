package gitsign

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// fakeStore is a live ledger held in memory: LedgerHeads and LedgerEntries.
type fakeStore struct{ chain *ledger.Chain }

func (f fakeStore) Head(context.Context, string) (int64, string, error) {
	seq, hash := f.chain.Head()
	if seq == 0 {
		hash = ""
	}
	return seq, hash, nil
}

func (f fakeStore) Entries(context.Context, string) ([]ledger.Entry, error) {
	return f.chain.Entries(), nil
}

func appendN(t *testing.T, chain *ledger.Chain, n int) {
	t.Helper()
	for range n {
		seq, _ := chain.Head()
		payload := map[string]any{"from": "a", "to": "b", "reason": strconv.FormatInt(seq+1, 10)}
		if _, err := chain.Append("core", "task_state", "TASK-1", payload); err != nil {
			t.Fatal(err)
		}
	}
}

// newLedgerChain is a PRD-001 chain signed (namespace arbiter-ledger) by k.
func newLedgerChain(t *testing.T, k testKey) *ledger.Chain {
	t.Helper()
	s, err := ssh.NewSignerFromKey(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ledger.NewChain("PRD-001", ledger.NewSSHSigner(s))
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// commitExport commits chain's current entries to the feature branch, as a
// task commit would.
func commitExport(t *testing.T, repo string, chain *ledger.Chain) {
	t.Helper()
	var buf strings.Builder
	if err := chain.WriteJSONL(&buf); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "checkout", "-q", "feature")
	writeFile(t, filepath.Join(repo, ".arbiter", "ledger", "PRD-001.jsonl"), buf.String())
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "task commit")
	run(t, repo, "checkout", "-q", "main")
}

// exportSetup returns a repo with a feature branch and the supervisor key in
// allowed_signers, and a Service whose live PRD-001 chain is returned.
func exportSetup(t *testing.T) (*Service, string, testKey, *ledger.Chain) {
	t.Helper()
	human, sup := newTestKey(t, 1), newTestKey(t, 5)
	svc, repo := newRepo(t, human)
	addSupervisor(t, svc, repo, sup)
	addFeature(t, repo)
	chain := newLedgerChain(t, sup)
	svc.Heads, svc.Entries, svc.Supervisor = fakeStore{chain}, fakeStore{chain}, sup.signer
	svc.SupervisorIdent = Ident{Name: "Arbiter", Email: "arbiter@host"}
	return svc, repo, human, chain
}

func TestExportBeforeMerge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		committed int // entries already exported on the feature branch
		live      int // entries in the live chain
		exports   bool
	}{
		{"lagging export is brought up to date", 2, 4, true},
		{"never exported", 0, 1, true},
		{"current export is left alone", 3, 3, false},
		{"empty live chain", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, human, chain := exportSetup(t)
			appendN(t, chain, tc.committed)
			if tc.committed > 0 {
				commitExport(t, repo, chain)
			}
			appendN(t, chain, tc.live-tc.committed)
			before := strings.TrimSpace(run(t, repo, "rev-parse", "feature"))

			msg := mergeAndRead(t, svc, repo, human, mergeReq(human))

			after := strings.TrimSpace(run(t, repo, "rev-parse", "feature"))
			if exported := after != before; exported != tc.exports {
				t.Fatalf("exported = %v, want %v", exported, tc.exports)
			}
			if run(t, repo, "status", "--porcelain") != "" {
				t.Error("export touched the working tree or index")
			}
			seq, hash := chain.Head()
			if seq == 0 {
				if strings.Contains(msg, "Arbiter-Ledger") {
					t.Errorf("merge message pins an empty chain:\n%s", msg)
				}
				return
			}
			pin := "Arbiter-Ledger: .arbiter/ledger/PRD-001.jsonl#seq=" + strconv.FormatInt(seq, 10) + " sha256:" + hash
			if !strings.Contains(msg, pin) {
				t.Errorf("merge message =\n%s\nwant it to contain %s", msg, pin)
			}
			if !tc.exports {
				return
			}
			if parent := strings.TrimSpace(run(t, repo, "rev-parse", "feature^")); parent != before {
				t.Errorf("export commit's parent = %s, want the old feature tip %s", parent, before)
			}
			exportMsg := run(t, repo, "log", "-1", "--format=%an <%ae>|%cn <%ce>|%B", "feature")
			if !strings.HasPrefix(exportMsg, "Arbiter <arbiter@host>|Human <"+humanEmail+">|") || !strings.Contains(exportMsg, pin) {
				t.Errorf("export commit = %q", exportMsg)
			}
			var want strings.Builder
			if err := chain.WriteJSONL(&want); err != nil {
				t.Fatal(err)
			}
			// run trims output, so compare without the final LF.
			if got := run(t, repo, "show", "feature:.arbiter/ledger/PRD-001.jsonl"); got != strings.TrimSpace(want.String()) {
				t.Errorf("exported file differs from the live chain:\n%s\nwant\n%s", got, want.String())
			}
			if size := run(t, repo, "cat-file", "-s", "feature:.arbiter/ledger/PRD-001.jsonl"); size != strconv.Itoa(want.Len()) {
				t.Errorf("exported file is %s bytes, want %d (canonical, LF-terminated)", size, want.Len())
			}
			verifySupervisorCommit(t, svc, repo, "feature")
		})
	}
}

// verifySupervisorCommit checks the export commit with git itself, against
// allowed_signers, as GitHub would.
func verifySupervisorCommit(t *testing.T, svc *Service, repo, rev string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Log("ssh-keygen not on PATH; skipping the git verify step only")
		return
	}
	cmd := exec.Command("git", "-c", "gpg.ssh.allowedSignersFile="+filepath.ToSlash(svc.AllowedSignersPath()), "verify-commit", "-v", rev)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `Good "git" signature for arbiter@host`) {
		t.Fatalf("git verify-commit %s: %v\n%s", rev, err, out)
	}
}

func TestExportRejects(t *testing.T) {
	ctx := context.Background()

	t.Run("committed export ahead of live chain", func(t *testing.T) {
		svc, repo, human, chain := exportSetup(t)
		appendN(t, chain, 3)
		commitExport(t, repo, chain)
		short := newLedgerChain(t, newTestKey(t, 5))
		appendN(t, short, 2)
		svc.Heads, svc.Entries = fakeStore{short}, fakeStore{short}
		if _, err := svc.PrepareMerge(ctx, mergeReq(human)); err == nil || !strings.Contains(err.Error(), "ahead of the live chain") {
			t.Errorf("err = %v, want an ahead-of-live refusal", err)
		}
	})

	t.Run("source is not a branch", func(t *testing.T) {
		svc, repo, human, chain := exportSetup(t)
		appendN(t, chain, 1)
		req := mergeReq(human)
		req.Source = strings.TrimSpace(run(t, repo, "rev-parse", "feature"))
		if _, err := svc.PrepareMerge(ctx, req); err == nil || !strings.Contains(err.Error(), "to be a branch") {
			t.Errorf("err = %v, want a not-a-branch refusal", err)
		}
	})

	t.Run("live chain signed by another key", func(t *testing.T) {
		svc, _, human, _ := exportSetup(t)
		other := newLedgerChain(t, newTestKey(t, 9))
		appendN(t, other, 2)
		svc.Heads, svc.Entries = fakeStore{other}, fakeStore{other}
		if _, err := svc.PrepareMerge(ctx, mergeReq(human)); err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Errorf("err = %v, want a verification refusal", err)
		}
	})
}
