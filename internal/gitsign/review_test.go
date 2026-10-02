package gitsign

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// addSupervisor commits a supervisor line for key, as arbiter init writes it.
func addSupervisor(t *testing.T, svc *Service, repo string, key testKey) {
	t.Helper()
	if _, err := allowedsigners.Ensure(svc.AllowedSignersPath(), allowedsigners.SupervisorPrincipal("host"), allowedsigners.SupervisorNamespaces, key.pub); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "supervisor key")
}

// The core holds the supervisor key; it must not be able to sign as the human.
func TestSupervisorKeyIsNotHuman(t *testing.T) {
	ctx := context.Background()
	human, sup := newTestKey(t, 1), newTestKey(t, 9)
	svc, repo := newRepo(t, human)
	addSupervisor(t, svc, repo, sup)

	asSup := sup.signerInfo()
	asSup.Email = "arbiter@host"
	if _, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: asSup}); err == nil {
		t.Error("PrepareLock accepted the supervisor key as signer")
	}

	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: human.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: sup.sign(t, prep.Payload)}); err == nil {
		t.Error("Complete accepted a supervisor-key signature")
	}
}

// Trust comes from the committed allowed_signers, not working-tree edits.
func TestUncommittedSignerLineIgnored(t *testing.T) {
	ctx := context.Background()
	human, other := newTestKey(t, 1), newTestKey(t, 3)
	svc, _ := newRepo(t, human)
	if _, err := allowedsigners.Ensure(svc.AllowedSignersPath(), "other@example.com", allowedsigners.HumanNamespaces, other.pub); err != nil {
		t.Fatal(err)
	}
	req := LockRequest{PRDID: "PRD-001", Signer: other.signerInfo()}
	req.Signer.Email = "other@example.com"
	if _, err := svc.PrepareLock(ctx, req); err == nil {
		t.Error("accepted a key that is only in the working-tree allowed_signers")
	}
}

// Whitespace around the client's armor is normalized before it is written, so
// git still recognizes the signature.
func TestSignatureReArmored(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	messy := "\r\n  " + strings.ReplaceAll(key.sign(t, prep.Payload), "\n", "\r\n") + "\r\n\r\n"
	done, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: messy})
	if err != nil {
		t.Fatal(err)
	}
	obj := run(t, repo, "cat-file", "tag", done.ObjectSHA)
	if strings.Contains(obj, "\r") || !strings.Contains(obj, "\n-----BEGIN SSH SIGNATURE-----\n") {
		t.Errorf("signature not canonical in tag object:\n%q", obj)
	}
	verifyWithGit(t, svc, repo, "verify-tag", "arbiter/prd/PRD-001/v1")
}

func TestMergeLinkedWorktree(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	addFeature(t, repo)
	run(t, repo, "checkout", "-q", "--detach")
	wt := filepath.Join(t.TempDir(), "main wt") // a space, to exercise path parsing
	run(t, repo, "worktree", "add", "-q", wt, "main")

	prep, err := svc.PrepareMerge(ctx, MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	done, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)})
	if err != nil {
		t.Fatal(err)
	}
	if got := run(t, wt, "rev-parse", "HEAD"); got != done.ObjectSHA {
		t.Errorf("linked worktree HEAD = %s, want %s", got, done.ObjectSHA)
	}
	if _, err := os.Stat(filepath.Join(wt, "feature.txt")); err != nil {
		t.Errorf("linked worktree not fast-forwarded: %v", err)
	}
}

func TestMergeDirtyWorktreeNamesCommit(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	addFeature(t, repo)
	// An untracked file the merge would overwrite blocks the fast-forward.
	writeFile(t, filepath.Join(repo, "feature.txt"), "local\n")

	prep, err := svc.PrepareMerge(ctx, MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)})
	if err == nil {
		t.Fatal("fast-forward over a conflicting local file succeeded")
	}
	if !strings.Contains(err.Error(), "git merge --ff-only ") {
		t.Errorf("error does not tell the user how to finish: %v", err)
	}
}

// The client refuses to sign anything but what it asked for.
func TestClientChecks(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	addFeature(t, repo)
	lockReq := LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()}
	mergeReq := MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()}

	lock, err := svc.PrepareLock(ctx, lockReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckLock(ctx, svc.ArbiterDir, lockReq, lock); err != nil {
		t.Fatalf("honest lock rejected: %v", err)
	}
	merge, err := svc.PrepareMerge(ctx, mergeReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckMerge(ctx, svc.ArbiterDir, mergeReq, merge); err != nil {
		t.Fatalf("honest merge rejected: %v", err)
	}

	feature := run(t, repo, "rev-parse", "feature")
	main := run(t, repo, "rev-parse", "main")
	tamper := func(p *Prepared, from, to string) *Prepared {
		t.Helper()
		if !strings.Contains(string(p.Payload), from) {
			t.Fatalf("payload lacks %q", from)
		}
		return &Prepared{RequestID: p.RequestID, Ref: p.Ref, Payload: []byte(strings.Replace(string(p.Payload), from, to, 1))}
	}
	evil := map[string]error{
		"lock other commit":  CheckLock(ctx, svc.ArbiterDir, lockReq, tamper(lock, "object "+main, "object "+feature)),
		"lock other tag":     CheckLock(ctx, svc.ArbiterDir, lockReq, tamper(lock, "PRD-001/v1", "PRD-001/v7")),
		"lock other tagger":  CheckLock(ctx, svc.ArbiterDir, lockReq, tamper(lock, "<human@example.com>", "<evil@example.com>")),
		"lock extra header":  CheckLock(ctx, svc.ArbiterDir, lockReq, tamper(lock, "type commit\n", "type commit\nextra x\n")),
		"lock other ref":     CheckLock(ctx, svc.ArbiterDir, lockReq, &Prepared{Payload: lock.Payload, Ref: "refs/tags/x"}),
		"merge other parent": CheckMerge(ctx, svc.ArbiterDir, mergeReq, tamper(merge, "parent "+feature, "parent "+main)),
		"merge other tree":   CheckMerge(ctx, svc.ArbiterDir, mergeReq, tamper(merge, "tree ", "tree 0")),
		"merge other ref":    CheckMerge(ctx, svc.ArbiterDir, mergeReq, &Prepared{Payload: merge.Payload, Ref: "refs/heads/feature"}),
		"merge extra header": CheckMerge(ctx, svc.ArbiterDir, mergeReq, tamper(merge, "\n\n", "\nencoding x\n\n")),
		"merge other author": CheckMerge(ctx, svc.ArbiterDir, mergeReq, tamper(merge, "author Human", "author Evil")),
	}
	for name, err := range evil {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// OpenSSH refuses SHA-1 RSA SSHSIGs; so does Arbiter.
func TestSHA1RSASignatureRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sha1Only, err := ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ledger.NewSSHSignerNamespace(sha1Only, Namespace).Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.ParseSSHSig(sig); err == nil {
		t.Error("ssh-rsa (SHA-1) SSHSIG accepted")
	}
}

// Stray tags with non-canonical version suffixes don't move the next version.
func TestLatestLockVersionCanonicalOnly(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	for _, v := range []string{"+9", "09", "x"} {
		run(t, repo, "tag", "arbiter/prd/PRD-001/v"+v)
	}
	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err != nil {
		t.Fatalf("lock refused despite only non-canonical tags: %v", err)
	}
	if prep.Ref != "refs/tags/arbiter/prd/PRD-001/v1" {
		t.Errorf("ref = %s, want v1", prep.Ref)
	}
}
