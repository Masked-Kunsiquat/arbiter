package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/audit"
	"github.com/Masked-Kunsiquat/arbiter/internal/gitsign"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisorkey"
)

// The ledger end to end through a real core: the lock is recorded in
// audit_log, the final merge first exports the chain to the feature branch in
// a supervisor-signed commit and pins its head, and `arbiter audit verify`
// accepts the result (§8.B, §8.D).
func TestSession_LedgerEndToEnd(t *testing.T) {
	ctx := context.Background()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	dir := newArbiterDir(t)
	repo := filepath.Dir(dir)
	gitIn(t, repo, "init", "-q", "-b", "main")
	gitIn(t, repo, "config", "user.name", "Human")
	gitIn(t, repo, "config", "user.email", "human@example.com")

	human, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	// TestMain points HOME at a temporary directory, so this is the key the
	// core loads.
	cfgDir, err := supervisorkey.DefaultConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	sup, err := supervisorkey.LoadOrGenerate(cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	signersPath := filepath.Join(dir, filepath.FromSlash(allowedsigners.RelPath))
	if _, err := allowedsigners.Ensure(signersPath, allowedsigners.SupervisorPrincipal("host"), allowedsigners.SupervisorNamespaces, sup.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := allowedsigners.Ensure(signersPath, "human@example.com", allowedsigners.HumanNamespaces, human.PublicKey()); err != nil {
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

	signer := gitsign.Signer{
		Ident:     gitsign.Ident{Name: "Human", Email: "human@example.com"},
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(human.PublicKey()))),
	}
	gitSigner := ledger.NewSSHSignerNamespace(human, gitsign.Namespace)
	sign := func(_ context.Context, payload []byte) (string, error) { return gitSigner.Sign(payload) }

	s := connect(t, dir)
	lock, err := s.LockPRD(ctx, gitsign.LockRequest{PRDID: "PRD-001", Signer: signer}, sign)
	if err != nil {
		t.Fatalf("LockPRD: %v", err)
	}

	// Feature work on a branch; main moves too, so the merge has two parents.
	gitIn(t, repo, "checkout", "-q", "-b", "feature")
	if err := os.WriteFile(filepath.Join(repo, "feature.txt"), []byte("feature\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "add", "feature.txt")
	gitIn(t, repo, "commit", "-q", "-m", "feature work")
	gitIn(t, repo, "checkout", "-q", "main")
	if err := os.WriteFile(filepath.Join(repo, "main.txt"), []byte("main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "add", "main.txt")
	gitIn(t, repo, "commit", "-q", "-m", "main work")

	// The final merge waits for a completed PRD. Task completion (#14) isn't
	// built yet, so mark it directly.
	withDB(t, dir, func(raw *sql.DB) {
		mustExec(t, raw, `UPDATE prds SET status = 'completed' WHERE id = 'PRD-001'`)
	})

	if _, err := s.MergeFinal(ctx, gitsign.MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: signer}, sign); err != nil {
		t.Fatalf("MergeFinal: %v", err)
	}

	// The exported chain is the single prd_lock entry, and the merge pins it.
	entries, err := ledger.ReadJSONL(strings.NewReader(gitIn(t, repo, "show", "main:.arbiter/ledger/PRD-001.jsonl") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "prd_lock" || entries[0].SeatID != gitsign.HumanSeat || entries[0].Payload["tag_object_sha"] != lock.ObjectSHA {
		t.Fatalf("exported ledger = %+v", entries)
	}
	if msg := gitIn(t, repo, "log", "-1", "--format=%B", "main"); !strings.Contains(msg, "Arbiter-Ledger: .arbiter/ledger/PRD-001.jsonl#seq=1 sha256:"+entries[0].EntryHash) {
		t.Errorf("merge message does not pin the exported head:\n%s", msg)
	}

	report, err := audit.Verify(ctx, repo, "main")
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() || len(report.Commits) != 2 || len(report.Ledgers) != 1 {
		t.Errorf("audit verify: %+v", report)
	}
}
