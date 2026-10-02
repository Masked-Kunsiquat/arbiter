package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/prd"
)

func TestParsePRDArgs(t *testing.T) {
	tests := []struct {
		args    []string
		want    prdArgs
		wantErr bool
	}{
		{[]string{"init", "My feature"}, prdArgs{Sub: "init", Title: "My feature"}, false},
		{[]string{"init", "T", "--branch", "feat/x"}, prdArgs{Sub: "init", Title: "T", Branch: "feat/x"}, false},
		{[]string{"init", "--branch=feat/x", "T"}, prdArgs{Sub: "init", Title: "T", Branch: "feat/x"}, false},
		{[]string{"init"}, prdArgs{}, true},
		{[]string{"init", "  "}, prdArgs{}, true},
		{[]string{"init", "T", "--branch"}, prdArgs{}, true},
		{[]string{"init", "T", "U"}, prdArgs{}, true},
		{[]string{"init", "T", "--into", "main"}, prdArgs{}, true},
		{[]string{"lock", "PRD-004"}, prdArgs{Sub: "lock", ID: "PRD-004"}, false},
		{[]string{"amend", "PRD-1000"}, prdArgs{Sub: "amend", ID: "PRD-1000"}, false},
		{[]string{"lock", "PRD-4"}, prdArgs{}, true},
		{[]string{"lock", "prd-004"}, prdArgs{}, true},
		{[]string{"lock"}, prdArgs{}, true},
		{[]string{"lock", "PRD-004", "PRD-005"}, prdArgs{}, true},
		{[]string{"lock", "PRD-004", "--branch", "x"}, prdArgs{}, true},
		{[]string{"review", "PRD-004"}, prdArgs{Sub: "review", ID: "PRD-004", Into: "main"}, false},
		{[]string{"review", "--into", "develop", "PRD-004"}, prdArgs{Sub: "review", ID: "PRD-004", Into: "develop"}, false},
		{[]string{"review", "PRD-004", "--into="}, prdArgs{}, true},
		{nil, prdArgs{}, true},
		{[]string{"bogus"}, prdArgs{}, true},
	}
	for _, tc := range tests {
		got, err := parsePRDArgs(tc.args)
		if (err != nil) != tc.wantErr || (err == nil && got != tc.want) {
			t.Errorf("parsePRDArgs(%q) = %+v, %v", tc.args, got, err)
		}
	}
}

func TestNextPRDID(t *testing.T) {
	tests := []struct {
		names []string
		want  string
	}{
		{nil, "PRD-001"},
		{[]string{"PRD-001.md"}, "PRD-002"},
		{[]string{"PRD-001.md", "PRD-007.md", "PRD-003.md"}, "PRD-008"},
		{[]string{"notes.md", "PRD-010.txt", "PRD-.md", "prd-020.md"}, "PRD-001"},
		{[]string{"PRD-999.md"}, "PRD-1000"},
	}
	for _, tc := range tests {
		if got := nextPRDID(tc.names); got != tc.want {
			t.Errorf("nextPRDID(%v) = %s, want %s", tc.names, got, tc.want)
		}
	}
}

func TestFormatLineErrors(t *testing.T) {
	const path = ".arbiter/prds/PRD-004.md"
	err := &prd.ParseError{Errs: []prd.LineError{{Line: 0, Msg: "no acceptance criteria"}, {Line: 9, Msg: "late"}, {Line: 3, Msg: "early"}}}
	want := []string{path + ":3: early", path + ":9: late", path + ": no acceptance criteria"}
	if got := formatLineErrors(path, err); !reflect.DeepEqual(got, want) {
		t.Errorf("formatLineErrors = %q, want %q", got, want)
	}
	if got := formatLineErrors(path, errors.New("boom")); !reflect.DeepEqual(got, []string{path + ": boom"}) {
		t.Errorf("non-parse error = %q", got)
	}
}

// gitRepo makes a temp git repo with an .arbiter/state.db marker (enough for
// findStateDB), isolates git config, and chdirs into it.
func gitRepo(t *testing.T) string {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	repo := t.TempDir()
	gitT(t, repo, "init", "-q", "-b", "main")
	gitT(t, repo, "config", "user.name", "Human")
	gitT(t, repo, "config", "user.email", "human@example.com")
	gitT(t, repo, "config", "commit.gpgsign", "false")
	if err := os.MkdirAll(filepath.Join(repo, ".arbiter"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".arbiter", "state.db"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	return repo
}

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestPRDInit(t *testing.T) {
	repo := gitRepo(t)
	ctx := context.Background()
	if err := runPRD(ctx, []string{"init", "First"}); err != nil {
		t.Fatal(err)
	}
	if err := runPRD(ctx, []string{"init", "Second", "--branch", "feat/second"}); err != nil {
		t.Fatal(err)
	}

	first, err := os.ReadFile(filepath.Join(repo, ".arbiter", "prds", "PRD-001.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"id: PRD-001", "title: First", "target_branch: feature/prd-001", "created_by: human:Human"} {
		if !strings.Contains(string(first), want) {
			t.Errorf("PRD-001.md lacks %q:\n%s", want, first)
		}
	}
	second, err := os.ReadFile(filepath.Join(repo, ".arbiter", "prds", "PRD-002.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(second), "target_branch: feat/second") {
		t.Errorf("PRD-002.md:\n%s", second)
	}
	// The unedited template must not lock.
	if _, err := prd.Parse(first); err == nil {
		t.Error("the untouched template parses")
	}
}

// An invalid PRD fails with every problem line-numbered on stderr, before
// anything is committed or the core is contacted.
func TestPRDLockInvalidMakesNoCommit(t *testing.T) {
	repo := gitRepo(t)
	ctx := context.Background()
	if err := runPRD(ctx, []string{"init", "Draft"}); err != nil {
		t.Fatal(err)
	}
	gitT(t, repo, "add", ".")
	gitT(t, repo, "commit", "-q", "-m", "base")
	head := gitT(t, repo, "rev-parse", "HEAD")

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	lockErr := runPRD(ctx, []string{"lock", "PRD-001"})
	os.Stderr = old
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}

	if lockErr == nil || !strings.Contains(lockErr.Error(), "does not parse") {
		t.Fatalf("lock error = %v", lockErr)
	}
	if !strings.Contains(buf.String(), ".arbiter/prds/PRD-001.md:") {
		t.Errorf("stderr lacks path:line errors:\n%s", buf.String())
	}
	if got := gitT(t, repo, "rev-parse", "HEAD"); got != head {
		t.Errorf("HEAD moved from %s to %s", head, got)
	}
	if st := gitT(t, repo, "status", "--porcelain"); st != "" {
		t.Errorf("worktree changed:\n%s", st)
	}
	if tags := gitT(t, repo, "tag", "-l"); tags != "" {
		t.Errorf("tags = %q", tags)
	}
}

// lockTestPRD is a valid PRD with the given acceptance criteria lines.
func lockTestPRD(criteria ...string) string {
	return "---\nid: PRD-001\ntitle: T\ntarget_branch: feat/x\n---\n## Intent\nDo it.\n## Invariants\n- [INVARIANT-1] Be safe.\n" +
		"## File Boundaries\n- `src/**`\n## Acceptance Criteria\n" + strings.Join(criteria, "\n") + "\n"
}

// commitLockTestPRD commits content as the PRD file and, if tag is set, points
// a lightweight lock tag at the commit.
func commitLockTestPRD(t *testing.T, repo, content, tag string) {
	t.Helper()
	path := filepath.Join(repo, ".arbiter", "prds", "PRD-001.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, repo, "add", ".")
	gitT(t, repo, "commit", "-q", "-m", "prd")
	if tag != "" {
		gitT(t, repo, "tag", tag)
	}
}

// Every check that can fail runs before the lock writes or commits anything.
func TestPRDLockPlanChecksBeforeWriting(t *testing.T) {
	repo := gitRepo(t)
	ctx := context.Background()
	const ac1, ac2 = "- [ ] AC-1: One.", "- [ ] AC-2: Two."
	commitLockTestPRD(t, repo, lockTestPRD(ac1, ac2), "arbiter/prd/PRD-001/v1")
	commitLockTestPRD(t, repo, lockTestPRD(ac1), "arbiter/prd/PRD-001/v2")
	// The working copy reuses AC-2, which v2 retired.
	reuse := lockTestPRD(ac1, ac2, "- [ ] AC-3: Three.")
	commitLockTestPRD(t, repo, reuse, "")
	head := gitT(t, repo, "rev-parse", "HEAD")

	plan := func(sub string, status prd.Status, content string) ([]byte, string, error) {
		t.Helper()
		p, err := prd.Parse([]byte(content))
		if err != nil {
			t.Fatal(err)
		}
		var errOut bytes.Buffer
		out, err := prdLockPlan(ctx, repo, prdArgs{Sub: sub, ID: "PRD-001"}, []byte(content), p, status, &errOut)
		return out, errOut.String(), err
	}

	if _, stderr, err := plan("amend", prd.StatusLocked, reuse); err == nil || !strings.Contains(stderr, "retired") {
		t.Errorf("amend reusing a retired ID: err = %v, stderr = %q", err, stderr)
	}
	if _, _, err := plan("lock", prd.StatusDraft, reuse); err == nil || !strings.Contains(err.Error(), "already locked; use prd amend") {
		t.Errorf("lock of a locked PRD: err = %v", err)
	}
	if _, _, err := plan("amend", prd.StatusArchived, lockTestPRD(ac1)); err == nil || !strings.Contains(err.Error(), "cannot move to locked") {
		t.Errorf("amend of an archived PRD: err = %v", err)
	}
	if got := gitT(t, repo, "rev-parse", "HEAD"); got != head {
		t.Errorf("HEAD moved from %s to %s", head, got)
	}
	if st := gitT(t, repo, "status", "--porcelain"); st != "" {
		t.Errorf("worktree changed:\n%s", st)
	}

	// A clean amendment (new ID above the highest, empty status) passes and
	// yields a file that parses with the same spec_hash.
	good := lockTestPRD(ac1, "- [ ] AC-3: Three.")
	out, _, err := plan("amend", "", good)
	if err != nil {
		t.Fatalf("clean amend: %v", err)
	}
	if p, err := prd.Parse(out); err != nil || p.Status != prd.StatusLocked {
		t.Errorf("planned file: %+v, %v", p, err)
	}
}

// A first lock of a draft PRD passes the plan.
func TestPRDLockPlanFirstLock(t *testing.T) {
	repo := gitRepo(t)
	good := lockTestPRD("- [ ] AC-1: One.")
	commitLockTestPRD(t, repo, good, "")
	p, err := prd.Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	out, err := prdLockPlan(context.Background(), repo, prdArgs{Sub: "lock", ID: "PRD-001"}, []byte(good), p, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "status: locked") {
		t.Errorf("planned file lacks status: locked:\n%s", out)
	}
}
