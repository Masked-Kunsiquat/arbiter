package gitsign

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Masked-Kunsiquat/arbiter/internal/allowedsigners"
	"github.com/Masked-Kunsiquat/arbiter/internal/worktree"
)

// PendingTTL bounds how long a prepared object waits for its signature. It
// covers a hardware-key touch or a password-manager prompt, not a lunch break.
const PendingTTL = 10 * time.Minute

// HumanSeat is the ledger seat_id for human actions (§4.A audit_log).
const HumanSeat = "human"

var prdIDRe = regexp.MustCompile(`^PRD-\d{3,}$`)

// LedgerAppender appends an entry to a ledger chain (§8.B, §8.E). The real
// implementation, which persists audit_log rows and signs them with the
// supervisor key, lands with the ledger (issue #19); until then a nil
// LedgerAppender records nothing.
type LedgerAppender interface {
	Append(ctx context.Context, chain, seatID, action, taskID string, payload map[string]any) error
}

// SpecHasher computes a PRD's spec_hash from its file content (§2.C). The
// real implementation lands with the PRD parser (issue #2); until then a nil
// SpecHasher leaves spec_hash null in the prd_lock entry.
type SpecHasher interface {
	SpecHash(prd []byte) (string, error)
}

// Signer is who will sign: the human's git identity and the public key their
// git signing setup resolves to, so Prepare can check allowed_signers before
// asking them to touch a key.
type Signer struct {
	Ident
	PublicKey string `json:"public_key"` // authorized_keys format
}

// LockRequest asks for a PRD lock tag arbiter/prd/<id>/v<n> (§2.A, §8.C).
type LockRequest struct {
	PRDID  string `json:"prd_id"`
	Commit string `json:"commit,omitempty"` // the commit holding the PRD; "" means HEAD
	Amend  bool   `json:"amend,omitempty"`  // true for v<n+1> of an already-locked PRD
	Signer Signer `json:"signer"`
}

// MergeRequest asks for the final, human-signed feature → main merge commit.
type MergeRequest struct {
	PRDID   string `json:"prd_id"`
	Source  string `json:"source"` // the feature branch (or any commit-ish)
	Target  string `json:"target"` // branch name, e.g. "main"
	Message string `json:"message,omitempty"`
	Signer  Signer `json:"signer"`
}

// Prepared is an object waiting for its signature.
type Prepared struct {
	RequestID string `json:"request_id"`
	Payload   []byte `json:"payload"` // the exact bytes to sign, namespace "git"
	Ref       string `json:"ref"`     // the ref Complete will create or move
}

// CompleteRequest returns the signature for a Prepared object.
type CompleteRequest struct {
	RequestID string `json:"request_id"`
	Signature string `json:"signature"` // armored SSHSIG
}

// Completed is the outcome of a successful Complete.
type Completed struct {
	Ref       string `json:"ref"`
	ObjectSHA string `json:"object_sha"`
}

type pendingKind int

const (
	kindLock pendingKind = iota + 1
	kindMerge
)

type pending struct {
	kind      pendingKind
	payload   []byte
	ref       string
	oldOID    string // kindMerge: the target head the merge was built on
	target    string // kindMerge: branch name
	principal string
	created   time.Time
	signersAt string // the commit whose allowed_signers authorizes this object

	// kindLock ledger fields
	prdID, tag string
	specHash   any // string, or nil when no SpecHasher is set
}

// Service prepares and completes human-signed objects for one repository.
type Service struct {
	RepoDir    string // the repository's top-level directory
	ArbiterDir string // its .arbiter directory

	Ledger   LedgerAppender   // may be nil (see LedgerAppender)
	Heads    LedgerHeads      // may be nil (see LedgerHeads)
	SpecHash SpecHasher       // may be nil (see SpecHasher)
	Now      func() time.Time // nil means time.Now

	mu      sync.Mutex
	pending map[string]*pending
}

// NewService returns a Service for the repository whose .arbiter directory
// is arbiterDir.
func NewService(arbiterDir string) *Service {
	return &Service{RepoDir: filepath.Dir(arbiterDir), ArbiterDir: arbiterDir}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// AllowedSignersPath is the allowed_signers file in the working tree (§8.D).
func (s *Service) AllowedSignersPath() string {
	return filepath.Join(s.ArbiterDir, filepath.FromSlash(allowedsigners.RelPath))
}

// signersAt reads allowed_signers as committed at commit. Signatures are
// checked against the committed file, the one `arbiter audit verify` uses
// later, never an uncommitted edit in the working tree.
func (s *Service) signersAt(ctx context.Context, commit string) (*allowedsigners.File, error) {
	path := ".arbiter/" + allowedsigners.RelPath
	out, err := s.git(ctx, s.RepoDir, nil, "cat-file", "blob", commit+":"+path)
	if err != nil {
		return nil, fmt.Errorf("gitsign: %s is not committed at %s; run arbiter init and commit it: %w", path, short(commit), err)
	}
	f, err := allowedsigners.Parse(strings.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("gitsign: %s at %s: %w", path, short(commit), err)
	}
	return f, nil
}

// checkSigner fails early, before any prompt, when the human's key isn't in
// allowed_signers (as committed at commit) for their email.
func (s *Service) checkSigner(ctx context.Context, sg Signer, commit string, at time.Time) error {
	if err := sg.validate(); err != nil {
		return err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sg.PublicKey))
	if err != nil {
		return fmt.Errorf("gitsign: signer public key: %w", err)
	}
	signers, err := s.signersAt(ctx, commit)
	if err != nil {
		return err
	}
	if signers.IsSupervisorKey(key) {
		return errors.New("gitsign: that is Arbiter's supervisor key; set user.signingkey to your own key")
	}
	if err := signers.Authorize(sg.Email, Namespace, key, at); err != nil {
		return fmt.Errorf("gitsign: %w; add your key to .arbiter/%s and commit it (arbiter init does this from user.signingkey)", err, allowedsigners.RelPath)
	}
	return nil
}

// PrepareLock builds the tag object for PRD lock tag arbiter/prd/<id>/v<n>.
func (s *Service) PrepareLock(ctx context.Context, req LockRequest) (*Prepared, error) {
	if !prdIDRe.MatchString(req.PRDID) {
		return nil, fmt.Errorf("gitsign: bad PRD id %q", req.PRDID)
	}
	now := s.now()
	rev := req.Commit
	if rev == "" {
		rev = "HEAD"
	}
	commit, err := s.revParse(ctx, rev+"^{commit}")
	if err != nil {
		return nil, err
	}
	if err := s.checkSigner(ctx, req.Signer, commit, now); err != nil {
		return nil, err
	}
	prdPath := ".arbiter/prds/" + req.PRDID + ".md"
	prd, err := s.git(ctx, s.RepoDir, nil, "cat-file", "blob", commit+":"+prdPath)
	if err != nil {
		return nil, fmt.Errorf("gitsign: %s is not committed at %s: %w", prdPath, short(commit), err)
	}

	latest, err := s.latestLockVersion(ctx, req.PRDID)
	if err != nil {
		return nil, err
	}
	switch {
	case !req.Amend && latest > 0:
		return nil, fmt.Errorf("gitsign: %s is already locked at v%d; amend it instead", req.PRDID, latest)
	case req.Amend && latest == 0:
		return nil, fmt.Errorf("gitsign: %s is not locked yet; lock it before amending", req.PRDID)
	}
	version := latest + 1
	tag := fmt.Sprintf("arbiter/prd/%s/v%d", req.PRDID, version)

	var specHash any
	if s.SpecHash != nil {
		h, err := s.SpecHash.SpecHash([]byte(prd))
		if err != nil {
			return nil, fmt.Errorf("gitsign: spec_hash of %s: %w", prdPath, err)
		}
		specHash = h
	}

	verb := "Lock"
	if req.Amend {
		verb = "Amend"
	}
	payload := TagPayload(commit, "commit", tag, req.Signer.Ident, now, fmt.Sprintf("%s %s v%d", verb, req.PRDID, version))
	return s.store(&pending{
		kind: kindLock, payload: payload, ref: "refs/tags/" + tag, principal: req.Signer.Email, created: now,
		signersAt: commit, prdID: req.PRDID, tag: tag, specHash: specHash,
	})
}

// latestLockVersion returns the highest n among arbiter/prd/<id>/v<n>, 0 if none.
func (s *Service) latestLockVersion(ctx context.Context, prdID string) (int, error) {
	out, err := s.git(ctx, s.RepoDir, nil, "for-each-ref", "--format=%(refname)", "refs/tags/arbiter/prd/"+prdID+"/")
	if err != nil {
		return 0, err
	}
	latest := 0
	prefix := "refs/tags/arbiter/prd/" + prdID + "/v"
	for line := range strings.Lines(out) {
		// Only canonical suffixes count: v+9 or v09 would otherwise parse.
		suffix := strings.TrimPrefix(strings.TrimSpace(line), prefix)
		n, err := strconv.Atoi(suffix)
		if err == nil && strconv.Itoa(n) == suffix && n > latest {
			latest = n
		}
	}
	return latest, nil
}

// PrepareMerge builds the two-parent merge commit of Source into Target.
// The merged tree comes from `git merge-tree --write-tree`; a conflicting
// merge is refused (the integration pass resolves conflicts first).
func (s *Service) PrepareMerge(ctx context.Context, req MergeRequest) (*Prepared, error) {
	if !prdIDRe.MatchString(req.PRDID) {
		return nil, fmt.Errorf("gitsign: bad PRD id %q", req.PRDID)
	}
	if req.Source == "" || req.Target == "" {
		return nil, errors.New("gitsign: merge needs a source and a target branch")
	}
	now := s.now()
	targetRef := "refs/heads/" + req.Target
	if _, err := s.git(ctx, s.RepoDir, nil, "check-ref-format", targetRef); err != nil {
		return nil, fmt.Errorf("gitsign: bad target branch %q", req.Target)
	}
	target, err := s.revParse(ctx, targetRef+"^{commit}")
	if err != nil {
		return nil, err
	}
	source, err := s.revParse(ctx, req.Source+"^{commit}")
	if err != nil {
		return nil, err
	}
	if err := s.checkSigner(ctx, req.Signer, target, now); err != nil {
		return nil, err
	}
	if _, err := s.git(ctx, s.RepoDir, nil, "merge-base", "--is-ancestor", source, target); err == nil {
		return nil, fmt.Errorf("gitsign: %s is already merged into %s", req.Source, req.Target)
	}
	tree, err := s.mergeTree(ctx, target, source)
	if err != nil {
		return nil, fmt.Errorf("gitsign: merging %s into %s: %w", req.Source, req.Target, err)
	}

	msg, head, err := s.mergeMessage(ctx, req, source)
	if err != nil {
		return nil, err
	}
	if err := s.checkExportCurrent(ctx, req.PRDID, head); err != nil {
		return nil, err
	}
	payload := CommitPayload(tree, []string{target, source}, req.Signer.Ident, req.Signer.Ident, now, msg)
	return s.store(&pending{
		kind: kindMerge, payload: payload, ref: targetRef, oldOID: target, target: req.Target,
		principal: req.Signer.Email, created: now, signersAt: target,
	})
}

// mergeTree writes the merged tree of target and source and returns its id.
// Exit status 1 from `git merge-tree --write-tree` means conflicts; anything
// else usually means git is older than 2.38, which added --write-tree.
func (s *Service) mergeTree(ctx context.Context, target, source string) (string, error) {
	out, err := s.git(ctx, s.RepoDir, nil, "merge-tree", "--write-tree", "--no-messages", target, source)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return "", errors.New("the merge has conflicts; resolve them on the feature branch first")
		}
		return "", fmt.Errorf("git merge-tree --write-tree failed (it needs git 2.38 or newer): %w", err)
	}
	return strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]), nil
}

func (s *Service) store(p *pending) (*Prepared, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("gitsign: request id: %w", err)
	}
	id := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = make(map[string]*pending)
	}
	for k, old := range s.pending {
		if p.created.Sub(old.created) > PendingTTL {
			delete(s.pending, k)
		}
	}
	s.pending[id] = p
	return &Prepared{RequestID: id, Payload: bytes.Clone(p.payload), Ref: p.ref}, nil
}

// take removes and returns a pending request. Requests are single-use: a bad
// signature means preparing again.
func (s *Service) take(id string, now time.Time) (*pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	delete(s.pending, id)
	if !ok {
		return nil, fmt.Errorf("gitsign: no pending signing request %q (it may have been used or the core restarted)", id)
	}
	if now.Sub(p.created) > PendingTTL {
		return nil, fmt.Errorf("gitsign: signing request %q expired after %v", id, PendingTTL)
	}
	return p, nil
}

// Complete verifies the signature for a prepared object, writes the signed
// object, and creates (lock tag) or advances (merge target) its ref.
func (s *Service) Complete(ctx context.Context, req CompleteRequest) (*Completed, error) {
	now := s.now()
	p, err := s.take(req.RequestID, now)
	if err != nil {
		return nil, err
	}
	signers, err := s.signersAt(ctx, p.signersAt)
	if err != nil {
		return nil, err
	}
	sig, err := Verify(signers, p.principal, p.payload, req.Signature, p.created)
	if err != nil {
		return nil, err
	}
	// Attach canonical armor, not the client's text: stray whitespace would
	// verify here but make git and GitHub see the object as unsigned.
	switch p.kind {
	case kindLock:
		return s.completeLock(ctx, p, sig.Armor())
	case kindMerge:
		return s.completeMerge(ctx, p, sig.Armor())
	default:
		return nil, fmt.Errorf("gitsign: unknown request kind %d", p.kind)
	}
}

func (s *Service) completeLock(ctx context.Context, p *pending, sig string) (*Completed, error) {
	sha, err := s.writeObject(ctx, "tag", AttachTagSig(p.payload, sig))
	if err != nil {
		return nil, err
	}
	// "create" fails if the tag already exists, so two racing locks can't both win.
	if _, err := s.git(ctx, s.RepoDir, []byte("create "+p.ref+" "+sha+"\n"), "update-ref", "--stdin"); err != nil {
		return nil, fmt.Errorf("gitsign: creating %s: %w", p.ref, err)
	}
	done := &Completed{Ref: p.ref, ObjectSHA: sha}
	if s.Ledger != nil {
		payload := map[string]any{"tag": p.tag, "spec_hash": p.specHash, "tag_object_sha": sha}
		if err := s.Ledger.Append(ctx, p.prdID, HumanSeat, "prd_lock", "", payload); err != nil {
			return done, fmt.Errorf("gitsign: %s created, but recording prd_lock in the ledger failed: %w", p.ref, err)
		}
	}
	return done, nil
}

func (s *Service) completeMerge(ctx context.Context, p *pending, sig string) (*Completed, error) {
	format, err := s.git(ctx, s.RepoDir, nil, "rev-parse", "--show-object-format")
	if err != nil {
		return nil, err
	}
	header := "gpgsig"
	if strings.TrimSpace(format) == "sha256" {
		header = "gpgsig-sha256"
	}
	obj, err := AttachCommitSig(p.payload, sig, header)
	if err != nil {
		return nil, err
	}
	sha, err := s.writeObject(ctx, "commit", obj)
	if err != nil {
		return nil, err
	}
	if err := s.advanceBranch(ctx, p.target, p.oldOID, sha); err != nil {
		return nil, err
	}
	return &Completed{Ref: p.ref, ObjectSHA: sha}, nil
}

// advanceBranch moves branch from oldOID to newOID. If the branch is checked
// out in a worktree, that worktree is fast-forwarded with `git merge
// --ff-only` so its index and files follow; a bare update-ref would leave it
// looking like it had reverted the merge. Otherwise the ref is updated with
// oldOID as the expected value, so a branch that moved since Prepare is
// never overwritten.
func (s *Service) advanceBranch(ctx context.Context, branch, oldOID, newOID string) error {
	ref := "refs/heads/" + branch
	wt, err := s.worktreeFor(ctx, ref)
	if err != nil {
		return err
	}
	if wt == "" {
		if _, err := s.git(ctx, s.RepoDir, nil, "update-ref", ref, newOID, oldOID); err != nil {
			return fmt.Errorf("gitsign: advancing %s (did it move since the merge was prepared?): %w", branch, err)
		}
		return nil
	}
	head, err := s.git(ctx, wt, nil, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(head) != oldOID {
		return fmt.Errorf("gitsign: %s moved since the merge was prepared (now %s); prepare it again", branch, short(strings.TrimSpace(head)))
	}
	if _, err := s.git(ctx, wt, nil, "merge", "--ff-only", "--quiet", newOID); err != nil {
		return fmt.Errorf("gitsign: fast-forwarding %s in %s (signed commit %s is written; commit or stash local changes and run `git merge --ff-only %s` there): %w",
			branch, wt, short(newOID), newOID, err)
	}
	return nil
}

// worktreeFor returns the worktree that has ref checked out, or "" if none
// does, or if the one that does is prunable (its directory is gone).
func (s *Service) worktreeFor(ctx context.Context, ref string) (string, error) {
	out, err := s.git(ctx, s.RepoDir, nil, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return "", err
	}
	// Attribute fields are NUL-terminated; an empty field ends a worktree.
	var path string
	var match, prunable bool
	for field := range strings.SplitSeq(out, "\x00") {
		switch {
		case field == "":
			if match && !prunable {
				if _, err := os.Stat(path); err == nil {
					return path, nil
				}
			}
			path, match, prunable = "", false, false
		case strings.HasPrefix(field, "worktree "):
			path = strings.TrimPrefix(field, "worktree ")
		case field == "branch "+ref:
			match = true
		case field == "prunable" || strings.HasPrefix(field, "prunable "):
			prunable = true
		}
	}
	return "", nil
}

func (s *Service) writeObject(ctx context.Context, typ string, obj []byte) (string, error) {
	out, err := s.git(ctx, s.RepoDir, obj, "hash-object", "-t", typ, "-w", "--stdin")
	if err != nil {
		return "", fmt.Errorf("gitsign: writing signed %s: %w", typ, err)
	}
	return strings.TrimSpace(out), nil
}

func (s *Service) revParse(ctx context.Context, rev string) (string, error) {
	out, err := s.git(ctx, s.RepoDir, nil, "rev-parse", "--verify", "--quiet", "--end-of-options", rev)
	if err != nil {
		return "", fmt.Errorf("gitsign: %q does not name a commit", strings.TrimSuffix(rev, "^{commit}"))
	}
	return strings.TrimSpace(out), nil
}

// git runs git in dir with Arbiter's mandatory overrides (§5.3: no hooks, no
// fsmonitor), feeding stdin when non-nil. It returns stdout; stderr goes into
// the error.
func (s *Service) git(ctx context.Context, dir string, stdin []byte, args ...string) (string, error) {
	emptyHooks, err := worktree.EmptyHooksDir(s.ArbiterDir)
	if err != nil {
		return "", err
	}
	full := append([]string{"-c", "core.hooksPath=" + filepath.ToSlash(emptyHooks), "-c", "core.fsmonitor=false"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()+" "+stdout.String()))
	}
	return stdout.String(), nil
}

func short(sha string) string { return sha[:min(12, len(sha))] }
