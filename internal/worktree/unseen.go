package worktree

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// FileMeta holds size and modification time for an untracked/ignored file
// (spec §5.3: "size and mtime for every file under the keep-list dirs").
type FileMeta struct {
	RelPath string
	Size    int64
	ModTime time.Time
}

// GitFileBackup holds a byte snapshot of a sensitive git file (.git/config or
// a hook script) so it can be verified and restored if an agent tampers with it.
type GitFileBackup struct {
	RelPath string
	Content []byte
	Mode    os.FileMode
}

// Snapshot records the state of lockfiles, keep-list directories, .git/config,
// and .git/hooks/ before an agent is launched (spec §5.3: "Before any agent
// launch, the Runner records a snapshot...").
type Snapshot struct {
	LockfileHash string
	KeepFiles    map[string]FileMeta
	GitConfig    *GitFileBackup
	GitHooks     map[string]*GitFileBackup
}

// UnseenReport details any changes found by CheckUnseenState compared to a prior snapshot.
type UnseenReport struct {
	LockfileHashChanged bool
	CurrentLockfileHash string
	KeepListChanged     bool
	ChangedKeepPaths    []string
	GitConfigChanged    bool
	GitHooksChanged     bool
	RestoredPaths       []string
	Violation           bool
}

// ShouldReinstall returns whether dependencies must be reinstalled based on
// this report and the slot's recorded install hash.
func (r *UnseenReport) ShouldReinstall(lastInstallHash string) bool {
	return ShouldReinstall(r.CurrentLockfileHash, lastInstallHash, r.KeepListChanged, false)
}

func resolveGitDir(repoRoot string) string {
	gitPath := filepath.Join(repoRoot, ".git")
	fi, err := os.Stat(gitPath)
	if err != nil || fi.IsDir() {
		return gitPath
	}
	data, err := os.ReadFile(gitPath)
	if err != nil {
		return gitPath
	}
	content := strings.TrimSpace(string(data))
	if !strings.HasPrefix(content, "gitdir:") {
		return gitPath
	}
	target := strings.TrimSpace(strings.TrimPrefix(content, "gitdir:"))
	if !filepath.IsAbs(target) {
		target = filepath.Join(repoRoot, target)
	}
	commondirFile := filepath.Join(target, "commondir")
	cdData, err := os.ReadFile(commondirFile)
	if err != nil {
		return filepath.Clean(target)
	}
	cdTarget := strings.TrimSpace(string(cdData))
	if !filepath.IsAbs(cdTarget) {
		cdTarget = filepath.Join(target, cdTarget)
	}
	return filepath.Clean(cdTarget)
}

func scanKeepFiles(slotDir string, keepList []string) (map[string]FileMeta, error) {
	keepFiles := make(map[string]FileMeta)
	for _, keep := range keepList {
		keepClean := filepath.Clean(keep)
		keepDir := filepath.Join(slotDir, keepClean)
		fi, err := os.Stat(keepDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("worktree: stat keep dir %s: %w", keepDir, err)
		}
		if !fi.IsDir() {
			rel, _ := filepath.Rel(slotDir, keepDir)
			keepFiles[filepath.ToSlash(rel)] = FileMeta{
				RelPath: filepath.ToSlash(rel),
				Size:    fi.Size(),
				ModTime: fi.ModTime(),
			}
			continue
		}

		err = filepath.WalkDir(keepDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(slotDir, path)
			if err != nil {
				return err
			}
			normalized := filepath.ToSlash(rel)
			keepFiles[normalized] = FileMeta{
				RelPath: normalized,
				Size:    info.Size(),
				ModTime: info.ModTime(),
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("worktree: scanning keep dir %s: %w", keepDir, err)
		}
	}
	return keepFiles, nil
}

func snapshotGitHooks(hooksDir string) map[string]*GitFileBackup {
	gitHooks := make(map[string]*GitFileBackup)
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		return gitHooks
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		hp := filepath.Join(hooksDir, e.Name())
		data, err := os.ReadFile(hp)
		if err != nil {
			continue
		}
		mode := os.FileMode(0o755)
		if info, err := e.Info(); err == nil {
			mode = info.Mode()
		}
		gitHooks[e.Name()] = &GitFileBackup{
			RelPath: e.Name(),
			Content: data,
			Mode:    mode,
		}
	}
	return gitHooks
}

// TakeSnapshot records a snapshot of slotDir and the repo's shared git configuration
// before an agent run starts.
func TakeSnapshot(slotDir, repoRoot string, keepList, lockfiles []string) (*Snapshot, error) {
	lockHash, err := ComputeLockfileHash(slotDir, lockfiles)
	if err != nil {
		return nil, fmt.Errorf("worktree: snapshot lockfile hash: %w", err)
	}

	keepFiles, err := scanKeepFiles(slotDir, keepList)
	if err != nil {
		return nil, err
	}

	gitDir := resolveGitDir(repoRoot)

	// Snapshot .git/config
	var gitConfigBackup *GitFileBackup
	configPath := filepath.Join(gitDir, "config")
	if cfgData, err := os.ReadFile(configPath); err == nil {
		fi, _ := os.Stat(configPath)
		mode := os.FileMode(0o644)
		if fi != nil {
			mode = fi.Mode()
		}
		gitConfigBackup = &GitFileBackup{
			RelPath: "config",
			Content: cfgData,
			Mode:    mode,
		}
	}

	// Snapshot .git/hooks/
	gitHooks := snapshotGitHooks(filepath.Join(gitDir, "hooks"))

	return &Snapshot{
		LockfileHash: lockHash,
		KeepFiles:    keepFiles,
		GitConfig:    gitConfigBackup,
		GitHooks:     gitHooks,
	}, nil
}

func diffKeepFiles(snapFiles, currFiles map[string]FileMeta, report *UnseenReport) {
	changedPathsMap := make(map[string]bool)
	for path, curr := range currFiles {
		old, found := snapFiles[path]
		if !found || curr.Size != old.Size || !curr.ModTime.Equal(old.ModTime) {
			report.KeepListChanged = true
			changedPathsMap[path] = true
		}
	}
	for path := range snapFiles {
		if _, found := currFiles[path]; !found {
			report.KeepListChanged = true
			changedPathsMap[path] = true
		}
	}
	for path := range changedPathsMap {
		report.ChangedKeepPaths = append(report.ChangedKeepPaths, path)
	}
	slices.Sort(report.ChangedKeepPaths)
}

func checkAndRestoreHooks(hooksDir string, snapHooks map[string]*GitFileBackup, report *UnseenReport) {
	currHooks := make(map[string]bool)
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		entries = nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		currHooks[name] = true
		hp := filepath.Join(hooksDir, name)

		old, existed := snapHooks[name]
		if !existed {
			// Newly planted hook
			report.GitHooksChanged = true
			report.Violation = true
			if rmErr := os.Remove(hp); rmErr == nil {
				report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
			}
			continue
		}

		// Existed, check content
		currData, err := os.ReadFile(hp)
		if err != nil || !bytes.Equal(currData, old.Content) {
			report.GitHooksChanged = true
			report.Violation = true
			if werr := os.WriteFile(hp, old.Content, old.Mode); werr == nil {
				report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
			}
		}
	}

	// Check for hooks that were deleted
	for name, old := range snapHooks {
		if currHooks[name] {
			continue
		}
		report.GitHooksChanged = true
		report.Violation = true
		hp := filepath.Join(hooksDir, name)
		if werr := os.WriteFile(hp, old.Content, old.Mode); werr == nil {
			report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
		}
	}
}

// CheckUnseenState compares the current state of slotDir and the shared git
// configuration against snap (spec §5.3). If any git config or hook files were
// modified, added, or deleted, they are automatically restored and a violation
// is reported.
func CheckUnseenState(slotDir, repoRoot string, keepList, lockfiles []string, snap *Snapshot) (*UnseenReport, error) {
	if snap == nil {
		return nil, errors.New("worktree: nil snapshot passed to CheckUnseenState")
	}

	report := &UnseenReport{}

	// 1. Check lockfile hash
	currLockHash, err := ComputeLockfileHash(slotDir, lockfiles)
	if err != nil {
		return nil, fmt.Errorf("worktree: checking lockfile hash: %w", err)
	}
	report.CurrentLockfileHash = currLockHash
	if currLockHash != snap.LockfileHash {
		report.LockfileHashChanged = true
	}

	// 2. Check keep-list directories
	currKeepFiles, err := scanKeepFiles(slotDir, keepList)
	if err != nil {
		return nil, err
	}
	diffKeepFiles(snap.KeepFiles, currKeepFiles, report)

	// 3. Check and restore .git/config
	gitDir := resolveGitDir(repoRoot)
	configPath := filepath.Join(gitDir, "config")
	if snap.GitConfig != nil {
		currData, err := os.ReadFile(configPath)
		if err != nil || !bytes.Equal(currData, snap.GitConfig.Content) {
			report.GitConfigChanged = true
			report.Violation = true
			if rerr := os.WriteFile(configPath, snap.GitConfig.Content, snap.GitConfig.Mode); rerr == nil {
				report.RestoredPaths = append(report.RestoredPaths, ".git/config")
			}
		}
	}

	// 4. Check and restore .git/hooks/
	checkAndRestoreHooks(filepath.Join(gitDir, "hooks"), snap.GitHooks, report)
	slices.Sort(report.RestoredPaths)

	return report, nil
}
