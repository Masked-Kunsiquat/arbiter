package worktree_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
	"github.com/Masked-Kunsiquat/arbiter/internal/worktree"
)

// initGitRepo initializes a temporary git repository with an initial commit.
func initGitRepo(t *testing.T) (repoRoot, initialCommit string) {
	t.Helper()
	repoRoot = t.TempDir()

	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Arbiter Test",
			"GIT_AUTHOR_EMAIL=test@localhost",
			"GIT_COMMITTER_NAME=Arbiter Test",
			"GIT_COMMITTER_EMAIL=test@localhost",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s failed: %v: %s", strings.Join(args, " "), err, string(out))
		}
		return strings.TrimSpace(string(out))
	}

	runGit("init")
	runGit("config", "user.name", "Arbiter Test")
	runGit("config", "user.email", "test@localhost")
	runGit("config", "core.autocrlf", "false")

	trackedFile := filepath.Join(repoRoot, "tracked.txt")
	if err := os.WriteFile(trackedFile, []byte("initial content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "tracked.txt")
	runGit("commit", "-m", "initial commit")

	initialCommit = runGit("rev-parse", "HEAD")
	return repoRoot, initialCommit
}

func TestDefaultKeepList(t *testing.T) {
	cases := []struct {
		eco  string
		want []string
	}{
		{"go", nil},
		{"node", []string{"node_modules"}},
		{"python", []string{".venv"}},
		{"rust", []string{"target"}},
		{"unknown", nil},
	}

	for _, tc := range cases {
		got := worktree.DefaultKeepList(tc.eco)
		if !slices.Equal(got, tc.want) {
			t.Errorf("DefaultKeepList(%q) = %v, want %v", tc.eco, got, tc.want)
		}
	}
}

func TestSlotPathAndNaming(t *testing.T) {
	arbiterDir := filepath.Join(string(filepath.Separator), "repo", ".arbiter")

	if got := worktree.SlotName(0); got != "slot-0" {
		t.Errorf("SlotName(0) = %q, want slot-0", got)
	}
	if got := worktree.SlotName(1); got != "slot-1" {
		t.Errorf("SlotName(1) = %q, want slot-1", got)
	}

	wantSlot0 := filepath.Join(arbiterDir, "worktrees", "slot-0")
	if got := worktree.SlotDir(arbiterDir, 0); got != wantSlot0 {
		t.Errorf("SlotDir(0) = %q, want %q", got, wantSlot0)
	}

	wantMeta0 := filepath.Join(arbiterDir, "worktrees", "slot-0.meta.json")
	if got := worktree.MetadataPath(arbiterDir, 0); got != wantMeta0 {
		t.Errorf("MetadataPath(0) = %q, want %q", got, wantMeta0)
	}
}

func TestEnsureWorktreeAndReset(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, worktree.DefaultSlotIndex)

	// 1. Ensure worktree creates slot-0
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatalf("EnsureWorktree: %v", err)
	}

	// Verify .git file exists in slot worktree
	slotGit := filepath.Join(slot.Path, ".git")
	if _, err := os.Stat(slotGit); err != nil {
		t.Fatalf("slot .git file missing: %v", err)
	}

	// Calling EnsureWorktree again should be idempotent
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatalf("EnsureWorktree idempotent call: %v", err)
	}

	// 2. Simulate agent edits in slot:
	// a) Modify tracked file
	trackedSlot := filepath.Join(slot.Path, "tracked.txt")
	if err := os.WriteFile(trackedSlot, []byte("tampered content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// b) Add untracked file
	untrackedSlot := filepath.Join(slot.Path, "temp.txt")
	if err := os.WriteFile(untrackedSlot, []byte("delete me\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// c) Add keep-list directory
	nodeModules := filepath.Join(slot.Path, "node_modules", "mypkg")
	if err := os.MkdirAll(nodeModules, 0o755); err != nil {
		t.Fatal(err)
	}
	depFile := filepath.Join(nodeModules, "index.js")
	if err := os.WriteFile(depFile, []byte("console.log('dep');\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Reset slot with keep-list = ["node_modules"]
	if err := slot.Reset(ctx, initialCommit, []string{"node_modules"}); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	// Verify tracked file was restored to initial commit
	trackedData, err := os.ReadFile(trackedSlot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(trackedData)) != "initial content" {
		t.Errorf("tracked.txt = %q, want 'initial content'", string(trackedData))
	}

	// Verify untracked file was deleted
	if _, err := os.Stat(untrackedSlot); !os.IsNotExist(err) {
		t.Errorf("temp.txt should be removed, got err: %v", err)
	}

	// Verify keep-list directory survived
	depData, err := os.ReadFile(depFile)
	if err != nil {
		t.Fatalf("keep-list file index.js missing after reset: %v", err)
	}
	if string(depData) != "console.log('dep');\n" {
		t.Errorf("keep-list content corrupted: %q", string(depData))
	}
}

func TestComputeLockfileHash(t *testing.T) {
	dir := t.TempDir()

	// Empty lockfiles list
	emptyHash, err := worktree.ComputeLockfileHash(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(emptyHash) != 64 {
		t.Errorf("emptyHash length = %d, want 64", len(emptyHash))
	}

	// Non-existent lockfile returns deterministic hash for absent record (differing from empty list)
	nonExistentHash, err := worktree.ComputeLockfileHash(dir, []string{"nonexistent.lock"})
	if err != nil {
		t.Fatal(err)
	}
	if len(nonExistentHash) != 64 {
		t.Errorf("nonExistentHash length = %d, want 64", len(nonExistentHash))
	}
	if nonExistentHash == emptyHash {
		t.Errorf("nonExistentHash should differ from emptyHash (absent record tracked deterministically)")
	}
	nonExistentHash2, _ := worktree.ComputeLockfileHash(dir, []string{"nonexistent.lock"})
	if nonExistentHash2 != nonExistentHash {
		t.Errorf("nonExistentHash should be deterministic: %s vs %s", nonExistentHash2, nonExistentHash)
	}
	otherAbsentHash, _ := worktree.ComputeLockfileHash(dir, []string{"other.lock"})
	if otherAbsentHash == nonExistentHash {
		t.Errorf("different absent lockfiles should produce different hashes")
	}

	// Create go.sum
	goSum := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(goSum, []byte("pkg v1.0.0 h1:abc=\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	hash1, err := worktree.ComputeLockfileHash(dir, []string{"go.sum"})
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == emptyHash {
		t.Errorf("hash1 should differ from empty hash")
	}

	// Modify go.sum
	if err := os.WriteFile(goSum, []byte("pkg v1.0.1 h1:xyz=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash2, err := worktree.ComputeLockfileHash(dir, []string{"go.sum"})
	if err != nil {
		t.Fatal(err)
	}
	if hash2 == hash1 {
		t.Errorf("hash2 should differ from hash1 after content change")
	}

	// Order independence
	pkgLock := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(pkgLock, []byte(`{"name":"test"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hashOrder1, _ := worktree.ComputeLockfileHash(dir, []string{"go.sum", "package-lock.json"})
	hashOrder2, _ := worktree.ComputeLockfileHash(dir, []string{"package-lock.json", "go.sum"})
	if hashOrder1 != hashOrder2 {
		t.Errorf("lockfile hashing must be order-independent: %s vs %s", hashOrder1, hashOrder2)
	}
}

func TestSlotMetadataPersistence(t *testing.T) {
	repoRoot := t.TempDir()
	slot := worktree.NewSlot(repoRoot, 0)

	// Loading before saving returns default empty metadata
	meta, err := slot.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if meta.LastInstallHash != "" {
		t.Errorf("LastInstallHash = %q, want empty", meta.LastInstallHash)
	}

	// Save install hash
	wantHash := "abcdef1234567890"
	if err := slot.SetLastInstallHash(wantHash); err != nil {
		t.Fatal(err)
	}

	gotHash, err := slot.LastInstallHash()
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != wantHash {
		t.Errorf("LastInstallHash = %q, want %q", gotHash, wantHash)
	}

	// Verify metadata file is outside slot.Path
	metaFile := worktree.MetadataPath(slot.ArbiterDir, 0)
	if _, err := os.Stat(metaFile); err != nil {
		t.Errorf("metaFile stat: %v", err)
	}
	slotDirWithSep := slot.Path + string(filepath.Separator)
	if metaFile == slot.Path || strings.HasPrefix(metaFile, slotDirWithSep) {
		t.Errorf("metaFile %s must live outside slot worktree %s", metaFile, slot.Path)
	}
}

func TestReinstallDeps_LockfileHash(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	// Write package-lock.json
	lockPath := filepath.Join(slot.Path, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(`{"version": 1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var installCalls []string
	slot.Cmd = func(_ context.Context, dir, command string, env []string) error {
		installCalls = append(installCalls, command)
		return nil
	}

	depsCfg := &config.Deps{
		Install:   "npm ci",
		Lockfiles: []string{"package-lock.json"},
		Keep:      []string{"node_modules"},
	}

	// 1. First run: last install hash is empty -> must install
	reinstalled, err := slot.ReinstallDeps(ctx, depsCfg, false, false)
	if err != nil {
		t.Fatalf("first ReinstallDeps: %v", err)
	}
	if !reinstalled {
		t.Errorf("first run: want reinstalled = true")
	}
	if len(installCalls) != 1 || installCalls[0] != "npm ci" {
		t.Errorf("installCalls = %v, want ['npm ci']", installCalls)
	}

	// 2. Second run: lockfile hash matches -> must NOT install
	installCalls = nil
	reinstalled, err = slot.ReinstallDeps(ctx, depsCfg, false, false)
	if err != nil {
		t.Fatalf("second ReinstallDeps: %v", err)
	}
	if reinstalled {
		t.Errorf("second run with identical lockfile: want reinstalled = false")
	}
	if len(installCalls) != 0 {
		t.Errorf("installCalls = %v, want empty", installCalls)
	}

	// 3. Lockfile modified -> must install
	if err := os.WriteFile(lockPath, []byte(`{"version": 2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	installCalls = nil
	reinstalled, err = slot.ReinstallDeps(ctx, depsCfg, false, false)
	if err != nil {
		t.Fatalf("third ReinstallDeps: %v", err)
	}
	if !reinstalled {
		t.Errorf("modified lockfile: want reinstalled = true")
	}
	if len(installCalls) != 1 {
		t.Errorf("installCalls = %v, want 1 call", installCalls)
	}

	// 4. Force reinstall even with unchanged lockfile
	installCalls = nil
	reinstalled, err = slot.ReinstallDeps(ctx, depsCfg, true, false)
	if err != nil {
		t.Fatalf("forced ReinstallDeps: %v", err)
	}
	if !reinstalled {
		t.Errorf("forced run: want reinstalled = true")
	}
	if len(installCalls) != 1 {
		t.Errorf("installCalls = %v, want 1 call", installCalls)
	}
}

func TestReinstallDeps_UnseenChanges(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(slot.Path, "requirements.txt")
	if err := os.WriteFile(lockPath, []byte("pytest==8.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	installed := false
	slot.Cmd = func(_ context.Context, dir, command string, env []string) error {
		installed = true
		return nil
	}

	depsCfg := &config.Deps{
		Install:   "pip install -r requirements.txt",
		Lockfiles: []string{"requirements.txt"},
		Keep:      []string{".venv"},
	}

	// First run sets the initial hash
	if _, err := slot.ReinstallDeps(ctx, depsCfg, false, false); err != nil {
		t.Fatal(err)
	}

	// Simulate an agent tampering with .venv
	venvDir := filepath.Join(slot.Path, ".venv", "lib")
	if err := os.MkdirAll(venvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(venvDir, "tampered.py")
	if err := os.WriteFile(tampered, []byte("# evil edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Reinstall with unseenChanges = true
	installed = false
	reinstalled, err := slot.ReinstallDeps(ctx, depsCfg, false, true)
	if err != nil {
		t.Fatalf("ReinstallDeps with unseenChanges: %v", err)
	}
	if !reinstalled || !installed {
		t.Errorf("unseenChanges must trigger reinstallation")
	}

	// Verify keep-list directory was wiped before install
	if _, err := os.Stat(tampered); !os.IsNotExist(err) {
		t.Errorf("tampered file %s should have been erased", tampered)
	}
}

func TestReinstallDeps_NonLocalKeepRejected(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(slot.Path, "requirements.txt")
	if err := os.WriteFile(lockPath, []byte("pytest==8.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	slot.Cmd = func(_ context.Context, dir, command string, env []string) error {
		return nil
	}

	depsCfg := &config.Deps{
		Install:   "pip install -r requirements.txt",
		Lockfiles: []string{"requirements.txt"},
		Keep:      []string{"../escaping"},
	}

	// First run sets the initial hash
	if _, err := slot.ReinstallDeps(ctx, depsCfg, false, false); err != nil {
		t.Fatal(err)
	}

	// Reinstall with unseenChanges = true and non-local keep entry
	if _, err := slot.ReinstallDeps(ctx, depsCfg, false, true); err == nil {
		t.Fatal("expected error for non-local keep path, got nil")
	}
}

func TestUnseenState_KeepListChanges(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	keepDir := filepath.Join(slot.Path, "node_modules", "pkg")
	if err := os.MkdirAll(keepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fileA := filepath.Join(keepDir, "a.js")
	if err := os.WriteFile(fileA, []byte("console.log('a');\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	keepList := []string{"node_modules"}
	lockfiles := []string{"package-lock.json"}

	// Take snapshot
	snap, err := slot.TakeSnapshot(keepList, lockfiles)
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	// 1. Untouched -> no changes
	rep, err := slot.CheckUnseenState(keepList, lockfiles, snap)
	if err != nil {
		t.Fatalf("CheckUnseenState: %v", err)
	}
	if rep.KeepListChanged {
		t.Errorf("want KeepListChanged = false")
	}

	// 2. Added file in keep dir
	fileB := filepath.Join(keepDir, "b.js")
	if err := os.WriteFile(fileB, []byte("console.log('b');\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = slot.CheckUnseenState(keepList, lockfiles, snap)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.KeepListChanged {
		t.Errorf("added file in keep dir: want KeepListChanged = true")
	}
	_ = os.Remove(fileB)

	// 3. Modified file in keep dir
	if err := os.WriteFile(fileA, []byte("console.log('modified');\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = slot.CheckUnseenState(keepList, lockfiles, snap)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.KeepListChanged {
		t.Errorf("modified file in keep dir: want KeepListChanged = true")
	}

	// 4. Deleted file in keep dir
	_ = os.Remove(fileA)
	rep, err = slot.CheckUnseenState(keepList, lockfiles, snap)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.KeepListChanged {
		t.Errorf("deleted file in keep dir: want KeepListChanged = true")
	}
}

func TestUnseenState_GitConfigAndHooksTampering(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	gitConfig := filepath.Join(repoRoot, ".git", "config")
	origConfigData, err := os.ReadFile(gitConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Create an existing benign hook
	hooksDir := filepath.Join(repoRoot, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	benignHook := filepath.Join(hooksDir, "post-commit")
	if err := os.WriteFile(benignHook, []byte("#!/bin/sh\necho benign\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	snap, err := slot.TakeSnapshot(nil, nil)
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	// 1. Tamper with .git/config
	if err := os.WriteFile(gitConfig, []byte(string(origConfigData)+"\n[evil]\nhack = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Plant malicious hook
	maliciousHook := filepath.Join(hooksDir, "pre-push")
	if err := os.WriteFile(maliciousHook, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// 3. Modify benign hook
	if err := os.WriteFile(benignHook, []byte("#!/bin/sh\necho tampered\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Run CheckUnseenState
	rep, err := slot.CheckUnseenState(nil, nil, snap)
	if err != nil {
		t.Fatalf("CheckUnseenState: %v", err)
	}

	if !rep.Violation {
		t.Errorf("tampering with git state must report Violation = true")
	}
	if !rep.GitConfigChanged {
		t.Errorf("GitConfigChanged must be true")
	}
	if !rep.GitHooksChanged {
		t.Errorf("GitHooksChanged must be true")
	}

	// Verify .git/config was restored
	currConfig, err := os.ReadFile(gitConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(currConfig) != string(origConfigData) {
		t.Errorf("git config was not restored to original content")
	}

	// Verify malicious hook was deleted
	if _, err := os.Stat(maliciousHook); !os.IsNotExist(err) {
		t.Errorf("planted hook %s should have been removed", maliciousHook)
	}

	// Verify benign hook was restored
	currBenign, err := os.ReadFile(benignHook)
	if err != nil {
		t.Fatal(err)
	}
	if string(currBenign) != "#!/bin/sh\necho benign\n" {
		t.Errorf("benign hook content was not restored")
	}
}

func TestSharedCacheEnv(t *testing.T) {
	arbiterDir := filepath.Join(string(filepath.Separator), "repo", ".arbiter")

	cfg0 := worktree.DefaultCacheConfig(arbiterDir, 0)
	cfg1 := worktree.DefaultCacheConfig(arbiterDir, 1)

	// Shared caches must be identical
	if cfg0.GoCacheDir != cfg1.GoCacheDir {
		t.Errorf("GoCacheDir mismatch: %s vs %s", cfg0.GoCacheDir, cfg1.GoCacheDir)
	}
	if cfg0.SccacheDir != cfg1.SccacheDir {
		t.Errorf("SccacheDir mismatch: %s vs %s", cfg0.SccacheDir, cfg1.SccacheDir)
	}
	if cfg0.PnpmStoreDir != cfg1.PnpmStoreDir {
		t.Errorf("PnpmStoreDir mismatch: %s vs %s", cfg0.PnpmStoreDir, cfg1.PnpmStoreDir)
	}

	// CARGO_TARGET_DIR must be per-slot
	if cfg0.CargoTargetDir == cfg1.CargoTargetDir {
		t.Errorf("CARGO_TARGET_DIR must differ per slot: %s vs %s", cfg0.CargoTargetDir, cfg1.CargoTargetDir)
	}
	if !strings.Contains(cfg0.CargoTargetDir, "slot-0") {
		t.Errorf("cfg0.CargoTargetDir %q should contain slot-0", cfg0.CargoTargetDir)
	}
	if !strings.Contains(cfg1.CargoTargetDir, "slot-1") {
		t.Errorf("cfg1.CargoTargetDir %q should contain slot-1", cfg1.CargoTargetDir)
	}

	// Test Env variables
	env0 := cfg0.Env()
	hasKey := func(env []string, prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}

	if !hasKey(env0, "GOCACHE=") {
		t.Errorf("missing GOCACHE in env")
	}
	if !hasKey(env0, "SCCACHE_DIR=") {
		t.Errorf("missing SCCACHE_DIR in env")
	}
	if !hasKey(env0, "PNPM_STORE_DIR=") {
		t.Errorf("missing PNPM_STORE_DIR in env")
	}
	if !hasKey(env0, "CARGO_TARGET_DIR=") {
		t.Errorf("missing CARGO_TARGET_DIR in env")
	}

	// Test EnsureDirs creates directories on disk
	tempDir := t.TempDir()
	tempCache := worktree.DefaultCacheConfig(tempDir, 0)
	if err := tempCache.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if _, err := os.Stat(tempCache.GoCacheDir); err != nil {
		t.Errorf("stat GoCacheDir: %v", err)
	}
	if _, err := os.Stat(tempCache.CargoTargetDir); err != nil {
		t.Errorf("stat CargoTargetDir: %v", err)
	}
}

func TestWorktreePool(t *testing.T) {
	repoRoot := t.TempDir()
	pool := worktree.NewPool(repoRoot)

	s0 := pool.DefaultSlot()
	if s0.Index != 0 {
		t.Errorf("DefaultSlot Index = %d, want 0", s0.Index)
	}

	s0Again := pool.Slot(0)
	if s0 != s0Again {
		t.Errorf("Slot(0) must return the cached instance")
	}

	s1 := pool.Slot(1)
	if s1.Index != 1 {
		t.Errorf("Slot(1) Index = %d, want 1", s1.Index)
	}
}

func TestUnseenState_SpoofedSizeAndModTime(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	keepDir := filepath.Join(slot.Path, "node_modules", "pkg")
	if err := os.MkdirAll(keepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fileA := filepath.Join(keepDir, "index.js")
	originalContent := []byte("console.log('original');\n")
	if err := os.WriteFile(fileA, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	keepList := []string{"node_modules"}
	snap, err := slot.TakeSnapshot(keepList, nil)
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	fi, err := os.Stat(fileA)
	if err != nil {
		t.Fatal(err)
	}
	origModTime := fi.ModTime()

	// Adversary pads content so size is identical and restores mtime via os.Chtimes
	spoofedContent := []byte("console.log('tampered');\n") // exactly 25 bytes, same as original
	if len(spoofedContent) != len(originalContent) {
		t.Fatalf("test setup error: len %d != %d", len(spoofedContent), len(originalContent))
	}
	if err := os.WriteFile(fileA, spoofedContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fileA, origModTime, origModTime); err != nil {
		t.Fatal(err)
	}

	// Verify that CheckUnseenState detects change via checksum
	rep, err := slot.CheckUnseenState(keepList, nil, snap)
	if err != nil {
		t.Fatalf("CheckUnseenState: %v", err)
	}
	if !rep.KeepListChanged {
		t.Errorf("expected KeepListChanged = true for spoofed size/mtime dependency file, got false")
	}
}

func TestUnseenState_WorktreeGitPointerAndConfigTampering(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	snap, err := slot.TakeSnapshot(nil, nil)
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	// 1. Worker replaces slot-0/.git with a directory containing malicious config
	slotGitPath := filepath.Join(slot.Path, ".git")
	_ = os.Remove(slotGitPath)
	if err := os.Mkdir(slotGitPath, 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := slot.CheckUnseenState(nil, nil, snap)
	if err != nil {
		t.Fatalf("CheckUnseenState: %v", err)
	}
	if !rep.Violation || !rep.GitConfigChanged {
		t.Errorf("replacing .git pointer with directory: want Violation=true, GitConfigChanged=true; got Violation=%v, GitConfigChanged=%v", rep.Violation, rep.GitConfigChanged)
	}

	// Verify .git was restored to a file
	fi, err := os.Lstat(slotGitPath)
	if err != nil || fi.IsDir() {
		t.Errorf("expected slot .git to be restored to pointer file, got isDir=%v, err=%v", fi != nil && fi.IsDir(), err)
	}

	// 2. Worker plants config.worktree in worktree admin dir
	adminDir := filepath.Join(repoRoot, ".git", "worktrees", "slot-0")
	cfgWorktree := filepath.Join(adminDir, "config.worktree")
	if err := os.WriteFile(cfgWorktree, []byte("[core]\nhooksPath = /evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err = slot.CheckUnseenState(nil, nil, snap)
	if err != nil {
		t.Fatalf("CheckUnseenState: %v", err)
	}
	if !rep.Violation || !rep.GitConfigChanged {
		t.Errorf("planting config.worktree: want Violation=true, GitConfigChanged=true; got Violation=%v, GitConfigChanged=%v", rep.Violation, rep.GitConfigChanged)
	}
	if _, err := os.Stat(cfgWorktree); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected planted config.worktree to be removed, but file still exists")
	}
}

func TestUnseenState_CargoTargetDirTrackingAndWipe(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	cache := slot.CacheConfig()
	targetArtifactDir := filepath.Join(cache.CargoTargetDir, "debug")
	if err := os.MkdirAll(targetArtifactDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(targetArtifactDir, "libapp.rlib")
	if err := os.WriteFile(artifact, []byte("clean artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	depsCfg := &config.Deps{
		Install:   "echo building",
		Lockfiles: []string{"Cargo.lock"},
		Keep:      []string{"target"},
	}
	cargoLock := filepath.Join(slot.Path, "Cargo.lock")
	if err := os.WriteFile(cargoLock, []byte("[lock]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	slot.Cmd = func(_ context.Context, dir, command string, env []string) error {
		return nil
	}

	// Install once to set initial hash
	if _, err := slot.ReinstallDeps(ctx, depsCfg, false, false); err != nil {
		t.Fatal(err)
	}

	// Snapshot with target in keepList
	snap, err := slot.TakeSnapshot(depsCfg.Keep, depsCfg.Lockfiles)
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	// Worker poisons the build artifact in CARGO_TARGET_DIR
	if err := os.WriteFile(artifact, []byte("poisoned artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// CheckUnseenState must catch changes in CargoTargetDir
	rep, err := slot.CheckUnseenState(depsCfg.Keep, depsCfg.Lockfiles, snap)
	if err != nil {
		t.Fatalf("CheckUnseenState: %v", err)
	}
	if !rep.KeepListChanged {
		t.Errorf("modifying CargoTargetDir artifact: want KeepListChanged = true, got false")
	}

	// Reinstall with unseenChanges = true must wipe CargoTargetDir
	if _, err := slot.ReinstallDeps(ctx, depsCfg, false, true); err != nil {
		t.Fatalf("ReinstallDeps with unseenChanges: %v", err)
	}
	if _, err := os.Stat(artifact); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected tainted artifact in CargoTargetDir to be removed, but still exists")
	}

	// Reset with keepList omitting target must wipe CargoTargetDir
	if err := os.MkdirAll(targetArtifactDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("stale artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := slot.Reset(ctx, initialCommit, nil); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, err := os.Stat(artifact); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected CargoTargetDir to be wiped on Reset when target is not kept")
	}
}

func TestDefaultGitRunner_CoreHooksPathOverride(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	emptyHooks := worktree.EmptyHooksDir(slot.Path)
	if emptyHooks == "" {
		t.Fatal("EmptyHooksDir returned empty string")
	}
	fi, err := os.Stat(emptyHooks)
	if err != nil || !fi.IsDir() {
		t.Fatalf("EmptyHooksDir %s does not exist or is not a directory: %v", emptyHooks, err)
	}

	out, err := slot.Git(ctx, slot.Path, "status")
	if err != nil {
		t.Fatalf("slot.Git status with empty hooksPath failed: %v, out: %s", err, out)
	}
}

func TestScanKeepFiles_ValidationAndSymlinks(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	badKeepLists := [][]string{
		{"../escaping"},
		{"-flag"},
		{"nested/../../escaping"},
	}
	for _, bad := range badKeepLists {
		if _, err := slot.TakeSnapshot(bad, nil); err == nil {
			t.Errorf("TakeSnapshot with %v: want error, got nil", bad)
		}
		if err := slot.Reset(ctx, initialCommit, bad); err == nil {
			t.Errorf("Reset with %v: want error, got nil", bad)
		}
	}
}

func TestCheckAndRestoreHooks_Hardened(t *testing.T) {
	repoRoot, initialCommit := initGitRepo(t)
	ctx := context.Background()

	slot := worktree.NewSlot(repoRoot, 0)
	if err := slot.EnsureWorktree(ctx, initialCommit); err != nil {
		t.Fatal(err)
	}

	hooksDir := filepath.Join(repoRoot, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	snap, err := slot.TakeSnapshot(nil, nil)
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	// Adversary replaces hook with a directory of the same name
	_ = os.Remove(hookPath)
	if err := os.Mkdir(hookPath, 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := slot.CheckUnseenState(nil, nil, snap)
	if err != nil {
		t.Fatalf("CheckUnseenState: %v", err)
	}
	if !rep.Violation || !rep.GitHooksChanged {
		t.Errorf("replacing hook with directory: want Violation=true, GitHooksChanged=true")
	}

	// Verify hook was restored to a file
	fi, err := os.Stat(hookPath)
	if err != nil || fi.IsDir() {
		t.Fatalf("expected hook to be restored to file, got isDir=%v, err=%v", fi != nil && fi.IsDir(), err)
	}
}
