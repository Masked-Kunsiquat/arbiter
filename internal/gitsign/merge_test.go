package gitsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// commitLedger writes a PRD-001 chain of n entries to the feature branch, as
// the core's export would, and returns its head.
func commitLedger(t *testing.T, repo string, n int) (int64, string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ledger.NewChain("PRD-001", ledger.NewSSHSigner(s))
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := chain.Append("core", "task_state", "TASK-1", map[string]any{"from": "a", "to": "b", "reason": strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := chain.WriteJSONL(&buf); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "checkout", "-q", "feature")
	writeFile(t, filepath.Join(repo, ".arbiter", "ledger", "PRD-001.jsonl"), buf.String())
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "export ledger")
	run(t, repo, "checkout", "-q", "main")
	return chain.Head()
}

type fakeHeads struct {
	seq  int64
	hash string
}

func (f fakeHeads) Head(context.Context, string) (int64, string, error) { return f.seq, f.hash, nil }

func mergeReq(key testKey) MergeRequest {
	return MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()}
}

// mergeAndRead runs a full merge and returns the merged commit's message.
func mergeAndRead(t *testing.T, svc *Service, repo string, key testKey, req MergeRequest) string {
	t.Helper()
	ctx := context.Background()
	prep, err := svc.PrepareMerge(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckMerge(ctx, svc.ArbiterDir, req, prep); err != nil {
		t.Fatalf("client rejected an honest merge: %v", err)
	}
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err != nil {
		t.Fatal(err)
	}
	verifyWithGit(t, svc, repo, "verify-commit", "main")
	return run(t, repo, "log", "-1", "--format=%B", "main")
}

func TestMergeTrailers(t *testing.T) {
	key := newTestKey(t, 1)

	t.Run("no ledger yet", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		addFeature(t, repo)
		run(t, repo, "tag", "arbiter/prd/PRD-001/v2")
		req := mergeReq(key)
		req.Message = "Ship PRD-001\n\nBody text."
		got := mergeAndRead(t, svc, repo, key, req)
		want := "Ship PRD-001\n\nBody text.\n\nArbiter-PRD: PRD-001@v2 (tag arbiter/prd/PRD-001/v2)"
		if got != want {
			t.Errorf("message =\n%s\nwant\n%s", got, want)
		}
	})

	t.Run("ledger head pinned", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		addFeature(t, repo)
		seq, hash := commitLedger(t, repo, 3)
		svc.Heads = fakeHeads{seq, hash}
		got := mergeAndRead(t, svc, repo, key, mergeReq(key))
		want := "Arbiter-Ledger: .arbiter/ledger/PRD-001.jsonl#seq=3 sha256:" + hash
		if !strings.HasSuffix(got, want) || !strings.Contains(got, "Arbiter-PRD: PRD-001@v1 ") {
			t.Errorf("message =\n%s\nwant it to end with\n%s", got, want)
		}
	})
}

func TestMergeTrailerRejects(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)

	t.Run("never locked", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		addFeature(t, repo)
		run(t, repo, "tag", "-d", "arbiter/prd/PRD-001/v1")
		if _, err := svc.PrepareMerge(ctx, mergeReq(key)); err == nil || !strings.Contains(err.Error(), "no lock tag") {
			t.Errorf("err = %v, want a no-lock-tag refusal", err)
		}
	})

	t.Run("user-supplied trailer", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		addFeature(t, repo)
		req := mergeReq(key)
		req.Message = "Ship it\n\nArbiter-Ledger: forged"
		if _, err := svc.PrepareMerge(ctx, req); err == nil {
			t.Error("accepted a message with an Arbiter- trailer")
		}
	})

	t.Run("export lags live chain", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		addFeature(t, repo)
		_, hash := commitLedger(t, repo, 2)
		svc.Heads = fakeHeads{5, hash}
		if _, err := svc.PrepareMerge(ctx, mergeReq(key)); err == nil || !strings.Contains(err.Error(), "export it") {
			t.Errorf("err = %v, want a stale-export refusal", err)
		}
	})

	t.Run("export missing but live chain has entries", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		addFeature(t, repo)
		svc.Heads = fakeHeads{1, strings.Repeat("a", 64)}
		if _, err := svc.PrepareMerge(ctx, mergeReq(key)); err == nil {
			t.Error("merged without pinning a non-empty live chain")
		}
	})
}
