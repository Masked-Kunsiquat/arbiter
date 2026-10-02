package gitsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

const humanEmail = "human@example.com"

// testKey is a deterministic Ed25519 key signing in namespace "git", standing
// in for the human's key on the CLI side.
type testKey struct {
	signer *ledger.SSHSigner
	pub    ssh.PublicKey
	priv   ed25519.PrivateKey
}

func newTestKey(t *testing.T, seed byte) testKey {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{signer: ledger.NewSSHSignerNamespace(s, Namespace), pub: s.PublicKey(), priv: priv}
}

func (k testKey) signerInfo() Signer {
	return Signer{
		Ident:     Ident{Name: "Human", Email: humanEmail},
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.pub))),
	}
}

func (k testKey) sign(t *testing.T, payload []byte) string {
	t.Helper()
	sig, err := k.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// isolateGit keeps the developer's global and system git config (signing
// programs, hooks, default branch) out of the test.
func isolateGit(t *testing.T) {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newRepo makes a repo on main with a committed PRD-001 and allowed_signers
// listing key for humanEmail.
func newRepo(t *testing.T, key testKey) (*Service, string) {
	t.Helper()
	isolateGit(t)
	repo := t.TempDir()
	run(t, repo, "init", "-q", "-b", "main")
	run(t, repo, "config", "user.name", "Human")
	run(t, repo, "config", "user.email", humanEmail)
	run(t, repo, "config", "commit.gpgsign", "false")
	writeFile(t, filepath.Join(repo, ".arbiter", "prds", "PRD-001.md"), "---\nid: PRD-001\n---\n# PRD\n")
	svc := NewService(filepath.Join(repo, ".arbiter"))
	if _, err := allowedsigners.Ensure(svc.AllowedSignersPath(), humanEmail, allowedsigners.HumanNamespaces, key.pub); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "add PRD-001 and allowed_signers")
	return svc, repo
}

type fakeLedger struct{ entries []map[string]any }

func (f *fakeLedger) Append(_ context.Context, chain, seatID, action, taskID string, payload map[string]any) error {
	f.entries = append(f.entries, map[string]any{
		"chain": chain, "seat": seatID, "action": action, "task": taskID, "payload": payload,
	})
	return nil
}

type fakeHasher struct{}

func (fakeHasher) SpecHash(prd []byte) (string, error) {
	return "fake:" + strconv.Itoa(len(prd)), nil
}

// verifyWithGit checks the object with git's own verifier (which runs
// ssh-keygen -Y verify against allowed_signers), the same check GitHub and
// `arbiter audit verify` rely on.
func verifyWithGit(t *testing.T, svc *Service, repo, verb, name string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Log("ssh-keygen not on PATH; skipping the git verify step only")
		return
	}
	cmd := exec.Command("git", "-c", "gpg.ssh.allowedSignersFile="+filepath.ToSlash(svc.AllowedSignersPath()), verb, "-v", name)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s %s: %v\n%s", verb, name, err, out)
	}
	if !strings.Contains(string(out), `Good "git" signature for `+humanEmail) {
		t.Errorf("git %s output lacks a good signature line:\n%s", verb, out)
	}
}

func TestLockRoundTrip(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	led := &fakeLedger{}
	svc.Ledger, svc.SpecHash = led, fakeHasher{}

	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	if prep.Ref != "refs/tags/arbiter/prd/PRD-001/v1" {
		t.Errorf("ref = %s", prep.Ref)
	}
	done, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)})
	if err != nil {
		t.Fatal(err)
	}
	if got := run(t, repo, "rev-parse", "refs/tags/arbiter/prd/PRD-001/v1"); got != done.ObjectSHA {
		t.Errorf("tag points at %s, Complete returned %s", got, done.ObjectSHA)
	}
	if got, want := run(t, repo, "rev-parse", "arbiter/prd/PRD-001/v1^{commit}"), run(t, repo, "rev-parse", "HEAD"); got != want {
		t.Errorf("tag peels to %s, want HEAD %s", got, want)
	}
	verifyWithGit(t, svc, repo, "verify-tag", "arbiter/prd/PRD-001/v1")

	if len(led.entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(led.entries))
	}
	e := led.entries[0]
	p := e["payload"].(map[string]any)
	if e["chain"] != "PRD-001" || e["seat"] != HumanSeat || e["action"] != "prd_lock" ||
		p["tag"] != "arbiter/prd/PRD-001/v1" || p["tag_object_sha"] != done.ObjectSHA || p["spec_hash"] == nil {
		t.Errorf("ledger entry = %v", e)
	}

	// A second lock is refused; an amendment makes v2.
	if _, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()}); err == nil {
		t.Error("second lock of the same PRD was accepted")
	}
	prep, err = svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Amend: true, Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	if prep.Ref != "refs/tags/arbiter/prd/PRD-001/v2" {
		t.Errorf("amend ref = %s", prep.Ref)
	}
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err != nil {
		t.Fatal(err)
	}
	verifyWithGit(t, svc, repo, "verify-tag", "arbiter/prd/PRD-001/v2")
}

func TestLockWithoutLedgerOrHasher(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, _ := newRepo(t, key)
	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err != nil {
		t.Fatal(err)
	}
}

func TestLockPrepareRejects(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, _ := newRepo(t, key)
	stranger := newTestKey(t, 2)

	wrongEmail := key.signerInfo()
	wrongEmail.Email = "other@example.com"
	noName := key.signerInfo()
	noName.Name = ""

	for name, req := range map[string]LockRequest{
		"bad PRD id":          {PRDID: "PRD-1", Signer: key.signerInfo()},
		"PRD not committed":   {PRDID: "PRD-002", Signer: key.signerInfo()},
		"amend before lock":   {PRDID: "PRD-001", Amend: true, Signer: key.signerInfo()},
		"key not allowed":     {PRDID: "PRD-001", Signer: stranger.signerInfo()},
		"principal mismatch":  {PRDID: "PRD-001", Signer: wrongEmail},
		"missing name":        {PRDID: "PRD-001", Signer: noName},
		"bad commit":          {PRDID: "PRD-001", Commit: "no-such-rev", Signer: key.signerInfo()},
		"option-looking rev":  {PRDID: "PRD-001", Commit: "--all", Signer: key.signerInfo()},
		"unparseable pub key": {PRDID: "PRD-001", Signer: Signer{Ident: key.signerInfo().Ident, PublicKey: "nope"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.PrepareLock(ctx, req); err == nil {
				t.Error("accepted")
			} else {
				t.Log(err)
			}
		})
	}
}

func TestCompleteRejects(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	stranger := newTestKey(t, 2)

	t.Run("signature by another key", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: stranger.sign(t, prep.Payload)}); err == nil {
			t.Fatal("accepted a signature from a key not in allowed_signers")
		}
		if out := run(t, repo, "tag", "-l"); out != "" {
			t.Errorf("tag created despite bad signature: %s", out)
		}
		// Single use: the request is gone even though it failed.
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err == nil {
			t.Error("request reusable after a failed Complete")
		}
	})

	t.Run("signature over other bytes", func(t *testing.T) {
		svc, _ := newRepo(t, key)
		prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, append(prep.Payload, 'x'))}); err == nil {
			t.Fatal("accepted a signature over different bytes")
		}
	})

	t.Run("ledger namespace", func(t *testing.T) {
		svc, _ := newRepo(t, key)
		prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
		if err != nil {
			t.Fatal(err)
		}
		s, _ := ssh.NewSignerFromKey(key.priv)
		sig, err := ledger.NewSSHSigner(s).Sign(prep.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: sig}); err == nil {
			t.Fatal("accepted an arbiter-ledger signature as a git signature")
		}
	})

	t.Run("used twice", func(t *testing.T) {
		svc, _ := newRepo(t, key)
		prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
		if err != nil {
			t.Fatal(err)
		}
		sig := key.sign(t, prep.Payload)
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: sig}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: sig}); err == nil {
			t.Fatal("request completed twice")
		}
	})

	t.Run("expired", func(t *testing.T) {
		svc, _ := newRepo(t, key)
		now := time.Now()
		svc.Now = func() time.Time { return now }
		prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(PendingTTL + time.Second)
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err == nil {
			t.Fatal("expired request accepted")
		}
	})

	t.Run("racing locks", func(t *testing.T) {
		svc, _ := newRepo(t, key)
		a, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
		if err != nil {
			t.Fatal(err)
		}
		b, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: a.RequestID, Signature: key.sign(t, a.Payload)}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Complete(ctx, CompleteRequest{RequestID: b.RequestID, Signature: key.sign(t, b.Payload)}); err == nil {
			t.Fatal("second v1 lock overwrote the first")
		}
	})
}

// addFeature marks PRD-001 locked at v1, commits a file on a new branch
// "feature" and returns to main. (A lightweight tag is enough: merges only
// look up the latest lock version.)
func addFeature(t *testing.T, repo string) {
	t.Helper()
	run(t, repo, "tag", "arbiter/prd/PRD-001/v1")
	run(t, repo, "checkout", "-q", "-b", "feature")
	writeFile(t, filepath.Join(repo, "feature.txt"), "feature\n")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "feature work")
	run(t, repo, "checkout", "-q", "main")
	// main moves too, so the merge is a real two-parent merge, not a fast-forward.
	writeFile(t, filepath.Join(repo, "main.txt"), "main\n")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-q", "-m", "main work")
}

func TestMergeRoundTrip(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)

	for _, checkedOut := range []bool{true, false} {
		name := "target checked out"
		if !checkedOut {
			name = "target not checked out"
		}
		t.Run(name, func(t *testing.T) {
			svc, repo := newRepo(t, key)
			addFeature(t, repo)
			oldMain := run(t, repo, "rev-parse", "main")
			feature := run(t, repo, "rev-parse", "feature")
			if !checkedOut {
				run(t, repo, "checkout", "-q", "--detach")
			}

			prep, err := svc.PrepareMerge(ctx, MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()})
			if err != nil {
				t.Fatal(err)
			}
			done, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)})
			if err != nil {
				t.Fatal(err)
			}
			if got := run(t, repo, "rev-parse", "main"); got != done.ObjectSHA {
				t.Errorf("main = %s, want %s", got, done.ObjectSHA)
			}
			if got := run(t, repo, "rev-parse", "main^1", "main^2"); got != oldMain+"\n"+feature {
				t.Errorf("parents = %q", got)
			}
			if checkedOut {
				if _, err := os.Stat(filepath.Join(repo, "feature.txt")); err != nil {
					t.Errorf("worktree not fast-forwarded: %v", err)
				}
				if st := run(t, repo, "status", "--porcelain"); st != "" {
					t.Errorf("worktree dirty after merge:\n%s", st)
				}
			}
			verifyWithGit(t, svc, repo, "verify-commit", "main")
		})
	}
}

func TestMergeRejects(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)

	t.Run("already merged", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		run(t, repo, "branch", "feature")
		if _, err := svc.PrepareMerge(ctx, MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()}); err == nil {
			t.Fatal("accepted a no-op merge")
		}
	})

	t.Run("conflict", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		run(t, repo, "checkout", "-q", "-b", "feature")
		writeFile(t, filepath.Join(repo, "x.txt"), "feature\n")
		run(t, repo, "add", ".")
		run(t, repo, "commit", "-q", "-m", "f")
		run(t, repo, "checkout", "-q", "main")
		writeFile(t, filepath.Join(repo, "x.txt"), "main\n")
		run(t, repo, "add", ".")
		run(t, repo, "commit", "-q", "-m", "m")
		if _, err := svc.PrepareMerge(ctx, MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()}); err == nil {
			t.Fatal("accepted a conflicting merge")
		}
	})

	t.Run("bad target", func(t *testing.T) {
		svc, repo := newRepo(t, key)
		addFeature(t, repo)
		for _, target := range []string{"nope", "main..x", ""} {
			if _, err := svc.PrepareMerge(ctx, MergeRequest{PRDID: "PRD-001", Source: "feature", Target: target, Signer: key.signerInfo()}); err == nil {
				t.Errorf("target %q accepted", target)
			}
		}
	})

	for _, checkedOut := range []bool{true, false} {
		t.Run("target moved, checked out="+map[bool]string{true: "yes", false: "no"}[checkedOut], func(t *testing.T) {
			svc, repo := newRepo(t, key)
			addFeature(t, repo)
			prep, err := svc.PrepareMerge(ctx, MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()})
			if err != nil {
				t.Fatal(err)
			}
			run(t, repo, "commit", "-q", "--allow-empty", "-m", "main moved")
			moved := run(t, repo, "rev-parse", "main")
			if !checkedOut {
				run(t, repo, "checkout", "-q", "--detach")
			}
			if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err == nil {
				t.Fatal("merge applied over a moved target")
			}
			if got := run(t, repo, "rev-parse", "main"); got != moved {
				t.Errorf("main = %s, want it left at %s", got, moved)
			}
		})
	}
}

func TestAttachCommitSig(t *testing.T) {
	payload := []byte("tree t\nauthor a\ncommitter c\n\nmsg\n")
	got, err := AttachCommitSig(payload, "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n", "gpgsig")
	if err != nil {
		t.Fatal(err)
	}
	want := "tree t\nauthor a\ncommitter c\ngpgsig -----BEGIN SSH SIGNATURE-----\n AAAA\n -----END SSH SIGNATURE-----\n\nmsg\n"
	if string(got) != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}

// fakePRDs records what the service hands the PRD store and can fail a check.
type fakePRDs struct {
	lockN      []int
	lockPrior  [][][]byte
	lockErr    error
	recorded   []string // tag + " " + spec hash
	recordedPR [][]byte
	recordErr  error
	mergeErr   error
	merges     []string
	merged     []string
}

func (f *fakePRDs) CheckLock(_ context.Context, _ string, n int, _ []byte, prior [][]byte) error {
	f.lockN = append(f.lockN, n)
	f.lockPrior = append(f.lockPrior, prior)
	return f.lockErr
}

func (f *fakePRDs) RecordLock(_ context.Context, _, tag string, prd []byte, specHash string) error {
	f.recorded = append(f.recorded, tag+" "+specHash)
	f.recordedPR = append(f.recordedPR, prd)
	return f.recordErr
}

func (f *fakePRDs) CheckMerge(_ context.Context, prdID string) error {
	f.merges = append(f.merges, prdID)
	return f.mergeErr
}

func (f *fakePRDs) RecordMerge(_ context.Context, prdID string) error {
	f.merged = append(f.merged, prdID)
	return nil
}

func TestPRDStoreLockHooks(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	prds := &fakePRDs{}
	svc.PRDs, svc.SpecHash = prds, fakeHasher{}

	v1 := "---\nid: PRD-001\n---\n# PRD\n"
	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	if len(prds.recorded) != 0 {
		t.Errorf("RecordLock ran before Complete: %v", prds.recorded)
	}
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err != nil {
		t.Fatal(err)
	}
	// Checked at prepare and again just before the tag is created.
	if len(prds.lockN) != 2 || prds.lockN[0] != 1 || prds.lockN[1] != 1 || len(prds.lockPrior[0]) != 0 || len(prds.lockPrior[1]) != 0 {
		t.Errorf("first lock: n=%v prior=%q", prds.lockN, prds.lockPrior)
	}
	wantHash, _ := fakeHasher{}.SpecHash([]byte(v1))
	if len(prds.recorded) != 1 || prds.recorded[0] != "arbiter/prd/PRD-001/v1 "+wantHash || string(prds.recordedPR[0]) != v1 {
		t.Errorf("RecordLock = %q", prds.recorded)
	}

	// The amendment sees v1's content as prior, not the new file.
	v2 := v1 + "more\n"
	writeFile(t, filepath.Join(repo, ".arbiter", "prds", "PRD-001.md"), v2)
	run(t, repo, "commit", "-q", "-am", "amend PRD-001")
	prep, err = svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Amend: true, Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	if len(prds.lockN) != 3 || prds.lockN[2] != 2 || len(prds.lockPrior[2]) != 1 || string(prds.lockPrior[2][0]) != v1 {
		t.Errorf("amend: n=%v prior=%q", prds.lockN, prds.lockPrior)
	}
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err != nil {
		t.Fatal(err)
	}
	if len(prds.recorded) != 2 || !strings.HasPrefix(prds.recorded[1], "arbiter/prd/PRD-001/v2 ") || string(prds.recordedPR[1]) != v2 {
		t.Errorf("RecordLock after amend = %q", prds.recorded)
	}
}

// A state change while the human signs (the re-check in Complete fails)
// must not leave a signed tag behind.
func TestPRDStoreRecheckAtComplete(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	prds := &fakePRDs{}
	svc.PRDs = prds
	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	prds.lockErr = errors.New("PRD-001 is executing")
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err == nil || !strings.Contains(err.Error(), "executing") {
		t.Fatalf("Complete = %v", err)
	}
	if tags := run(t, repo, "tag", "-l"); tags != "" {
		t.Errorf("tags = %q", tags)
	}
	if len(prds.recorded) != 0 {
		t.Errorf("RecordLock = %q", prds.recorded)
	}
}

// A failed state.db record must not also lose the prd_lock ledger entry.
func TestPRDStoreRecordErrorStillLedgers(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, _ := newRepo(t, key)
	led := &fakeLedger{}
	svc.Ledger, svc.PRDs = led, &fakePRDs{recordErr: errors.New("database is locked")}
	prep, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err != nil {
		t.Fatal(err)
	}
	done, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)})
	if err == nil || !strings.Contains(err.Error(), "database is locked") || done == nil {
		t.Fatalf("Complete = %v, %v", done, err)
	}
	if len(led.entries) != 1 {
		t.Errorf("ledger entries = %d, want 1", len(led.entries))
	}
}

func TestPRDStoreCheckLockErrorAborts(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	svc.PRDs = &fakePRDs{lockErr: errors.New("PRD-001 is not lockable")}

	_, err := svc.PrepareLock(ctx, LockRequest{PRDID: "PRD-001", Signer: key.signerInfo()})
	if err == nil || !strings.Contains(err.Error(), "not lockable") {
		t.Fatalf("PrepareLock = %v", err)
	}
	if len(svc.pending) != 0 {
		t.Errorf("pending = %d, want 0", len(svc.pending))
	}
	if tags := run(t, repo, "tag", "-l"); tags != "" {
		t.Errorf("tags = %q", tags)
	}
}

func TestPRDStoreMergeHooks(t *testing.T) {
	ctx := context.Background()
	key := newTestKey(t, 1)
	svc, repo := newRepo(t, key)
	addFeature(t, repo)
	prds := &fakePRDs{mergeErr: errors.New("PRD-001 is executing")}
	svc.PRDs = prds
	req := MergeRequest{PRDID: "PRD-001", Source: "feature", Target: "main", Signer: key.signerInfo()}

	oldMain := run(t, repo, "rev-parse", "main")
	if _, err := svc.PrepareMerge(ctx, req); err == nil || !strings.Contains(err.Error(), "is executing") {
		t.Fatalf("PrepareMerge = %v", err)
	}
	if len(svc.pending) != 0 || len(prds.merged) != 0 {
		t.Errorf("pending = %d, merged = %v", len(svc.pending), prds.merged)
	}

	prds.mergeErr = nil
	prep, err := svc.PrepareMerge(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(prds.merged) != 0 {
		t.Errorf("RecordMerge ran before Complete: %v", prds.merged)
	}
	if _, err := svc.Complete(ctx, CompleteRequest{RequestID: prep.RequestID, Signature: key.sign(t, prep.Payload)}); err != nil {
		t.Fatal(err)
	}
	if len(prds.merged) != 1 || prds.merged[0] != "PRD-001" {
		t.Errorf("RecordMerge calls = %v", prds.merged)
	}
	if run(t, repo, "rev-parse", "main") == oldMain {
		t.Error("main did not move")
	}
}
