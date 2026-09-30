package worktree

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
)

// DefaultSlotIndex is 0 for single-lane mode (spec §7: "Single-lane uses one
// persistent worktree (.arbiter/worktrees/slot-0)").
const DefaultSlotIndex = 0

// DefaultSlotName is the directory name for the default single-lane slot.
const DefaultSlotName = "slot-0"

// SlotName returns the directory basename for slot index (e.g. "slot-0").
func SlotName(index int) string {
	return fmt.Sprintf("slot-%d", index)
}

// SlotDir returns the absolute path for slot index within arbiterDir.
func SlotDir(arbiterDir string, index int) string {
	return filepath.Join(arbiterDir, "worktrees", SlotName(index))
}

// DefaultKeepList returns the default keep-list for a given ecosystem (spec §7).
// Dependency directories survive git clean -fdx between tasks so dependencies
// do not need to be reinstalled on every run:
//   - Go: none
//   - Node: node_modules
//   - Python: .venv
//   - Rust: target
func DefaultKeepList(ecosystem string) []string {
	switch strings.ToLower(ecosystem) {
	case "node":
		return []string{"node_modules"}
	case "python":
		return []string{".venv"}
	case "rust":
		return []string{"target"}
	case "go":
		fallthrough
	default:
		return nil
	}
}

// GitRunner executes a git command in dir with the provided arguments.
type GitRunner func(ctx context.Context, dir string, args ...string) (string, error)

// CommandRunner executes a shell command in dir with the provided environment.
type CommandRunner func(ctx context.Context, dir string, command string, env []string) error

// EmptyHooksDir returns an absolute path to a guaranteed-empty hooks directory
// to ensure git never executes user or repository hooks during Arbiter operations
// (spec §5.3: "-c core.hooksPath=<empty arbiter dir> -c core.fsmonitor=false").
func EmptyHooksDir(baseDir string) string {
	var targetDir string
	if baseDir != "" {
		current := filepath.Clean(baseDir)
		for range 5 {
			cand := filepath.Join(current, ".arbiter")
			if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
				targetDir = filepath.Join(cand, "empty-hooks")
				break
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	if targetDir == "" {
		targetDir = filepath.Join(os.TempDir(), "arbiter-empty-hooks")
	}
	_ = os.MkdirAll(targetDir, 0o755)
	return targetDir
}

// DefaultGitRunner executes git with Arbiter's mandatory security overrides
// (spec §5.3: "Separately, every git command Arbiter runs itself passes
// -c core.hooksPath=<empty arbiter dir> -c core.fsmonitor=false").
func DefaultGitRunner(ctx context.Context, dir string, args ...string) (string, error) {
	emptyHooks := EmptyHooksDir(dir)
	fullArgs := append([]string{
		"-c", "core.hooksPath=" + filepath.ToSlash(emptyHooks),
		"-c", "core.fsmonitor=false",
	}, args...)
	cmd := exec.CommandContext(ctx, "git", fullArgs...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// DefaultCommandRunner executes command in dir using the platform shell
// (cmd.exe on Windows, sh on POSIX).
func DefaultCommandRunner(ctx context.Context, dir string, command string, env []string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running command %q: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Slot represents one warm worktree slot.
type Slot struct {
	Index      int
	RepoRoot   string
	ArbiterDir string
	Path       string
	Git        GitRunner
	Cmd        CommandRunner
}

// NewSlot creates a new Slot handle for slotIndex under repoRoot.
func NewSlot(repoRoot string, index int) *Slot {
	arbiterDir := filepath.Join(repoRoot, ".arbiter")
	return &Slot{
		Index:      index,
		RepoRoot:   repoRoot,
		ArbiterDir: arbiterDir,
		Path:       SlotDir(arbiterDir, index),
		Git:        DefaultGitRunner,
		Cmd:        DefaultCommandRunner,
	}
}

// EnsureWorktree verifies that the slot exists as a valid git worktree,
// creating it if necessary (spec §7).
func (s *Slot) EnsureWorktree(ctx context.Context, baseCommit string) error {
	if baseCommit == "" {
		baseCommit = "HEAD"
	}

	gitFile := filepath.Join(s.Path, ".git")
	if _, err := os.Stat(gitFile); err == nil {
		// Worktree already exists on disk
		return nil
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(s.Path)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("worktree: creating worktrees parent dir: %w", err)
	}

	// Prune any stale worktree registrations in git before adding
	_, _ = s.Git(ctx, s.RepoRoot, "worktree", "prune")

	// Add the worktree in detached HEAD state
	_, err := s.Git(ctx, s.RepoRoot, "worktree", "add", "--detach", s.Path, baseCommit)
	if err != nil {
		return fmt.Errorf("worktree: adding worktree for %s: %w", s.Path, err)
	}

	return nil
}

// Reset resets the slot between tasks (spec §7: "Between tasks, the slot is
// reset with git checkout --detach <base> && git clean -fdx -e node_modules -e target -e .venv ...
// (per-ecosystem keep-list), so dependency directories survive").
func (s *Slot) Reset(ctx context.Context, baseCommit string, keepList []string) error {
	if baseCommit == "" {
		baseCommit = "HEAD"
	}

	// Force checkout to discard any uncommitted tracked modifications from prior runs
	if _, err := s.Git(ctx, s.Path, "checkout", "--force", "--detach", baseCommit); err != nil {
		return fmt.Errorf("worktree: checkout base commit %s in slot: %w", baseCommit, err)
	}

	// Build git clean arguments
	cleanArgs := []string{"clean", "-fdx"}
	for _, keep := range keepList {
		if keep == "" {
			continue
		}
		if !filepath.IsLocal(keep) || strings.HasPrefix(keep, "-") {
			return fmt.Errorf("worktree: keep path %q is not a local path", keep)
		}
		cleanArgs = append(cleanArgs, "-e", filepath.Clean(keep))
	}

	if _, err := s.Git(ctx, s.Path, cleanArgs...); err != nil {
		return fmt.Errorf("worktree: clean slot with keep-list %v: %w", keepList, err)
	}

	// If target is not kept, wipe per-slot CargoTargetDir to prevent artifact leakage
	if !slices.Contains(keepList, "target") {
		if ct := s.CacheConfig().CargoTargetDir; ct != "" {
			_ = os.RemoveAll(ct)
		}
	}

	// Update base commit in metadata
	meta, err := s.Metadata()
	if err == nil {
		meta.LastBaseCommit = baseCommit
		_ = s.SaveMetadata(meta)
	}

	return nil
}

// Metadata loads the slot's persisted state.
func (s *Slot) Metadata() (*SlotMetadata, error) {
	return LoadMetadata(s.ArbiterDir, s.Index)
}

// SaveMetadata saves the slot's persisted state.
func (s *Slot) SaveMetadata(meta *SlotMetadata) error {
	meta.SlotIndex = s.Index
	return SaveMetadata(s.ArbiterDir, meta)
}

// LastInstallHash returns the recorded lockfile hash from the slot's last install.
func (s *Slot) LastInstallHash() (string, error) {
	meta, err := s.Metadata()
	if err != nil {
		return "", err
	}
	return meta.LastInstallHash, nil
}

// SetLastInstallHash updates and persists the slot's last install hash.
func (s *Slot) SetLastInstallHash(hash string) error {
	meta, err := s.Metadata()
	if err != nil {
		return err
	}
	meta.LastInstallHash = hash
	meta.LastInstalledAt = time.Now().UTC()
	return s.SaveMetadata(meta)
}

// ComputeLockfileHash computes the hash for the slot's lockfiles.
func (s *Slot) ComputeLockfileHash(lockfiles []string) (string, error) {
	return ComputeLockfileHash(s.Path, lockfiles)
}

func wipeTaintedKeepDirs(slotPath string, keepList []string, cargoTargetDir string) error {
	for _, keep := range keepList {
		if keep == "" {
			continue
		}
		if !filepath.IsLocal(keep) || strings.HasPrefix(keep, "-") {
			return fmt.Errorf("worktree: keep path %q is not a local path", keep)
		}
		targetDir := filepath.Join(slotPath, filepath.Clean(keep))
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("worktree: removing tainted keep dir %s: %w", targetDir, err)
		}
	}
	if slices.Contains(keepList, "target") && cargoTargetDir != "" {
		if err := os.RemoveAll(cargoTargetDir); err != nil {
			return fmt.Errorf("worktree: removing tainted cargo target dir %s: %w", cargoTargetDir, err)
		}
	}
	return nil
}

// ReinstallDeps installs dependencies in the slot if needed (spec §7:
// "Dependencies reinstall only when the lockfile hash differs from the slot's
// last install, or when the unseen-state check (§5.3) finds the keep-list dirs
// changed during an agent run").
//
// When unseenChanges is true, keep-list directories are wiped before installation
// to prevent tainted or patched dependencies from leaking into future test runs.
func (s *Slot) ReinstallDeps(ctx context.Context, depsCfg *config.Deps, force bool, unseenChanges bool) (bool, error) {
	if depsCfg == nil {
		return false, nil
	}

	currHash, err := s.ComputeLockfileHash(depsCfg.Lockfiles)
	if err != nil {
		return false, fmt.Errorf("worktree: computing lockfile hash: %w", err)
	}

	meta, err := s.Metadata()
	if err != nil {
		return false, fmt.Errorf("worktree: reading slot metadata: %w", err)
	}

	if !ShouldReinstall(currHash, meta.LastInstallHash, unseenChanges, force) {
		return false, nil
	}

	// If keep-list directories were altered during an agent run, wipe them
	// before reinstalling from the lockfile (spec §5.3).
	if unseenChanges {
		if err := wipeTaintedKeepDirs(s.Path, depsCfg.Keep, s.CacheConfig().CargoTargetDir); err != nil {
			return false, err
		}
	}

	// Run dependency install command if configured
	if depsCfg.Install != "" {
		cache := s.CacheConfig()
		if err := cache.EnsureDirs(); err != nil {
			return false, err
		}
		env := s.Env(os.Environ())
		if err := s.Cmd(ctx, s.Path, depsCfg.Install, env); err != nil {
			return false, fmt.Errorf("worktree: running dependency install (%s): %w", depsCfg.Install, err)
		}
	}

	// Update recorded lockfile hash on successful install
	meta.LastInstallHash = currHash
	meta.LastInstalledAt = time.Now().UTC()
	if err := s.SaveMetadata(meta); err != nil {
		return true, fmt.Errorf("worktree: updating install hash: %w", err)
	}

	return true, nil
}

// TakeSnapshot records the unseen-state snapshot for this slot (spec §5.3).
func (s *Slot) TakeSnapshot(keepList, lockfiles []string) (*Snapshot, error) {
	var extraDirs []string
	if slices.Contains(keepList, "target") {
		if ct := s.CacheConfig().CargoTargetDir; ct != "" {
			extraDirs = append(extraDirs, ct)
		}
	}
	return TakeSnapshot(s.Path, s.RepoRoot, keepList, lockfiles, extraDirs...)
}

// CheckUnseenState verifies and restores unseen state against snap (spec §5.3).
func (s *Slot) CheckUnseenState(keepList, lockfiles []string, snap *Snapshot) (*UnseenReport, error) {
	var extraDirs []string
	if slices.Contains(keepList, "target") {
		if ct := s.CacheConfig().CargoTargetDir; ct != "" {
			extraDirs = append(extraDirs, ct)
		}
	}
	return CheckUnseenState(s.Path, s.RepoRoot, keepList, lockfiles, snap, extraDirs...)
}

// CacheConfig returns the shared and per-slot cache configuration for this slot.
func (s *Slot) CacheConfig() CacheConfig {
	return DefaultCacheConfig(s.ArbiterDir, s.Index)
}

// Env overlays the slot's shared caches and per-slot CARGO_TARGET_DIR onto baseEnv.
func (s *Slot) Env(baseEnv []string) []string {
	return ApplyEnv(baseEnv, s.CacheConfig().Env())
}

// Pool manages a collection of warm worktree slots (spec §7, §12).
type Pool struct {
	RepoRoot   string
	ArbiterDir string
	slots      map[int]*Slot
	mu         sync.Mutex
}

// NewPool initializes a worktree Pool for repoRoot.
func NewPool(repoRoot string) *Pool {
	arbiterDir := filepath.Join(repoRoot, ".arbiter")
	return &Pool{
		RepoRoot:   repoRoot,
		ArbiterDir: arbiterDir,
		slots:      make(map[int]*Slot),
	}
}

// Slot returns the Slot for index, allocating it if needed.
func (p *Pool) Slot(index int) *Slot {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.slots[index]; ok {
		return s
	}
	s := NewSlot(p.RepoRoot, index)
	p.slots[index] = s
	return s
}

// DefaultSlot returns slot-0 for single-lane operations.
func (p *Pool) DefaultSlot() *Slot {
	return p.Slot(DefaultSlotIndex)
}
