package worktree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// FileMeta holds size, modification time, checksum, and symlink info for an untracked/ignored file
// (spec §5.3: "size and mtime for every file under the keep-list dirs").
type FileMeta struct {
	RelPath    string
	Size       int64
	ModTime    time.Time
	Checksum   [32]byte
	IsSymlink  bool
	LinkTarget string
}

// GitFileBackup holds a byte snapshot of a sensitive git file (.git/config or
// a hook script) so it can be verified and restored if an agent tampers with it.
type GitFileBackup struct {
	RelPath string
	Content []byte
	Mode    os.FileMode
	// Opaque marks an entry that existed but couldn't be backed up (a
	// directory or an unreadable file). It is left in place while unchanged
	// (see keepOpaqueHook), and never restored as a file.
	Opaque bool
	// Size and ModTime are recorded for opaque regular files, whose content
	// can't be compared.
	Size    int64
	ModTime time.Time
}

// Snapshot records the state of lockfiles, keep-list directories, .git/config,
// and .git/hooks/ before an agent is launched (spec §5.3: "Before any agent
// launch, the Runner records a snapshot...").
type Snapshot struct {
	LockfileHash       string
	KeepFiles          map[string]FileMeta
	GitConfig          *GitFileBackup
	GitHooks           map[string]*GitFileBackup
	WorktreeGitPointer *GitFileBackup
	WorktreeConfig     *GitFileBackup
	WorktreeCommondir  *GitFileBackup
	WorktreeGitdir     *GitFileBackup
	WorktreeHooks      map[string]*GitFileBackup
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

func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return [32]byte{}, err
	}
	var res [32]byte
	copy(res[:], hasher.Sum(nil))
	return res, nil
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

func resolveWorktreeAdminDir(slotDir string) string {
	gitPath := filepath.Join(slotDir, ".git")
	fi, err := os.Lstat(gitPath)
	if err != nil || fi.IsDir() {
		return ""
	}
	data, err := os.ReadFile(gitPath)
	if err != nil {
		return ""
	}
	content := strings.TrimSpace(string(data))
	if !strings.HasPrefix(content, "gitdir:") {
		return ""
	}
	target := strings.TrimSpace(strings.TrimPrefix(content, "gitdir:"))
	if !filepath.IsAbs(target) {
		target = filepath.Join(slotDir, target)
	}
	return filepath.Clean(target)
}

func scanSingleKeepEntry(slotDir, keep string, keepFiles map[string]FileMeta) error {
	if keep == "" {
		return nil
	}
	if !filepath.IsLocal(keep) || strings.HasPrefix(keep, "-") {
		return fmt.Errorf("worktree: keep path %q is not a local path", keep)
	}
	keepClean := filepath.Clean(keep)
	keepDir := filepath.Join(slotDir, keepClean)
	fi, err := os.Lstat(keepDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("worktree: stat keep dir %s: %w", keepDir, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, _ := os.Readlink(keepDir)
		rel, _ := filepath.Rel(slotDir, keepDir)
		norm := filepath.ToSlash(rel)
		keepFiles[norm] = FileMeta{
			RelPath:    norm,
			Size:       fi.Size(),
			ModTime:    fi.ModTime(),
			IsSymlink:  true,
			LinkTarget: target,
		}
		return nil
	}
	if !fi.IsDir() {
		h, err := hashFile(keepDir)
		if err != nil {
			return fmt.Errorf("worktree: hashing %s: %w", keepDir, err)
		}
		rel, _ := filepath.Rel(slotDir, keepDir)
		norm := filepath.ToSlash(rel)
		keepFiles[norm] = FileMeta{
			RelPath:  norm,
			Size:     fi.Size(),
			ModTime:  fi.ModTime(),
			Checksum: h,
		}
		return nil
	}
	return walkKeepDir(slotDir, keepDir, keepFiles)
}

func walkKeepDir(slotDir, keepDir string, keepFiles map[string]FileMeta) error {
	return filepath.WalkDir(keepDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(slotDir, path)
		if err != nil {
			return err
		}
		norm := filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(path)
			info, _ := d.Info()
			var sz int64
			var mt time.Time
			if info != nil {
				sz = info.Size()
				mt = info.ModTime()
			}
			keepFiles[norm] = FileMeta{
				RelPath:    norm,
				Size:       sz,
				ModTime:    mt,
				IsSymlink:  true,
				LinkTarget: target,
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h, err := hashFile(path)
		if err != nil {
			return err
		}
		keepFiles[norm] = FileMeta{
			RelPath:  norm,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Checksum: h,
		}
		return nil
	})
}

func scanExtraDir(extra string, keepFiles map[string]FileMeta) error {
	fi, err := os.Lstat(extra)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("worktree: stat extra dir %s: %w", extra, err)
	}
	prefix := "extra:" + filepath.Base(extra)
	if !fi.IsDir() {
		h, err := hashFile(extra)
		if err != nil {
			return fmt.Errorf("worktree: hashing %s: %w", extra, err)
		}
		keepFiles[prefix] = FileMeta{
			RelPath:  prefix,
			Size:     fi.Size(),
			ModTime:  fi.ModTime(),
			Checksum: h,
		}
		return nil
	}
	return filepath.WalkDir(extra, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(extra, path)
		if err != nil {
			return err
		}
		key := prefix + "/" + filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(path)
			info, _ := d.Info()
			var sz int64
			var mt time.Time
			if info != nil {
				sz = info.Size()
				mt = info.ModTime()
			}
			keepFiles[key] = FileMeta{
				RelPath:    key,
				Size:       sz,
				ModTime:    mt,
				IsSymlink:  true,
				LinkTarget: target,
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h, err := hashFile(path)
		if err != nil {
			return err
		}
		keepFiles[key] = FileMeta{
			RelPath:  key,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Checksum: h,
		}
		return nil
	})
}

func scanKeepFiles(slotDir string, keepList []string, extraDirs ...string) (map[string]FileMeta, error) {
	keepFiles := make(map[string]FileMeta)
	for _, keep := range keepList {
		if err := scanSingleKeepEntry(slotDir, keep, keepFiles); err != nil {
			return nil, err
		}
	}
	for _, extra := range extraDirs {
		if extra == "" {
			continue
		}
		if err := scanExtraDir(extra, keepFiles); err != nil {
			return nil, err
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
		info, err := e.Info()
		if err != nil {
			continue // removed since ReadDir
		}
		backup := &GitFileBackup{RelPath: e.Name(), Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime()}
		// Record entries that can't be backed up too, so the check doesn't
		// take them for planted hooks and delete them.
		if data, err := os.ReadFile(filepath.Join(hooksDir, e.Name())); err == nil && !e.IsDir() {
			backup.Content = data
		} else {
			backup.Opaque = true
		}
		gitHooks[e.Name()] = backup
	}
	return gitHooks
}

func snapshotWorktreeGit(slotDir string, snap *Snapshot) {
	slotGitPath := filepath.Join(slotDir, ".git")
	fi, err := os.Lstat(slotGitPath)
	if err == nil && !fi.IsDir() {
		if data, rerr := os.ReadFile(slotGitPath); rerr == nil {
			snap.WorktreeGitPointer = &GitFileBackup{
				RelPath: ".git",
				Content: data,
				Mode:    fi.Mode(),
			}
		}
	}

	adminDir := resolveWorktreeAdminDir(slotDir)
	if adminDir == "" {
		return
	}

	wtCfgPath := filepath.Join(adminDir, "config.worktree")
	if data, err := os.ReadFile(wtCfgPath); err == nil {
		fi, _ := os.Stat(wtCfgPath)
		mode := os.FileMode(0o644)
		if fi != nil {
			mode = fi.Mode()
		}
		snap.WorktreeConfig = &GitFileBackup{
			RelPath: "config.worktree",
			Content: data,
			Mode:    mode,
		}
	}

	cdPath := filepath.Join(adminDir, "commondir")
	if data, err := os.ReadFile(cdPath); err == nil {
		snap.WorktreeCommondir = &GitFileBackup{RelPath: "commondir", Content: data, Mode: 0o644}
	}

	gdPath := filepath.Join(adminDir, "gitdir")
	if data, err := os.ReadFile(gdPath); err == nil {
		snap.WorktreeGitdir = &GitFileBackup{RelPath: "gitdir", Content: data, Mode: 0o644}
	}

	snap.WorktreeHooks = snapshotGitHooks(filepath.Join(adminDir, "hooks"))
}

// TakeSnapshot records a snapshot of slotDir and the repo's shared git configuration
// before an agent run starts.
func TakeSnapshot(slotDir, repoRoot string, keepList, lockfiles []string, extraDirs ...string) (*Snapshot, error) {
	lockHash, err := ComputeLockfileHash(slotDir, lockfiles)
	if err != nil {
		return nil, fmt.Errorf("worktree: snapshot lockfile hash: %w", err)
	}

	keepFiles, err := scanKeepFiles(slotDir, keepList, extraDirs...)
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

	snap := &Snapshot{
		LockfileHash: lockHash,
		KeepFiles:    keepFiles,
		GitConfig:    gitConfigBackup,
		GitHooks:     gitHooks,
	}

	snapshotWorktreeGit(slotDir, snap)
	return snap, nil
}

func diffKeepFiles(snapFiles, currFiles map[string]FileMeta, report *UnseenReport) {
	changedPathsMap := make(map[string]bool)
	for path, curr := range currFiles {
		old, found := snapFiles[path]
		if !found || curr.Size != old.Size || !curr.ModTime.Equal(old.ModTime) ||
			curr.Checksum != old.Checksum || curr.IsSymlink != old.IsSymlink ||
			curr.LinkTarget != old.LinkTarget {
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

func checkAndRestoreHooks(hooksDir string, snapHooks map[string]*GitFileBackup, report *UnseenReport) error {
	currHooks := make(map[string]bool)
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			entries = nil
		} else {
			return fmt.Errorf("worktree: reading hooks dir %s: %w", hooksDir, err)
		}
	}

	for _, e := range entries {
		name := e.Name()
		currHooks[name] = true
		hp := filepath.Join(hooksDir, name)

		old, existed := snapHooks[name]
		if !existed {
			// Newly planted hook or directory
			report.GitHooksChanged = true
			report.Violation = true
			if err := os.RemoveAll(hp); err != nil {
				return fmt.Errorf("worktree: removing planted hook %s: %w", hp, err)
			}
			report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
			continue
		}

		if old.Opaque {
			if keepOpaqueHook(e, old) {
				continue
			}
			// Something else took the place of an entry we couldn't back
			// up: it can't be restored, so only remove what was planted.
			report.GitHooksChanged = true
			report.Violation = true
			if err := os.RemoveAll(hp); err != nil {
				return fmt.Errorf("worktree: removing hook replacing %s: %w", hp, err)
			}
			report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
			continue
		}

		if e.IsDir() {
			report.GitHooksChanged = true
			report.Violation = true
			if err := restoreFile(hp, old.Content, old.Mode); err != nil {
				return fmt.Errorf("worktree: restoring hook %s: %w", hp, err)
			}
			report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
			continue
		}

		currData, rerr := os.ReadFile(hp)
		info, ierr := e.Info()
		modeChanged := ierr == nil && (info.Mode() != old.Mode)

		if rerr != nil || !bytes.Equal(currData, old.Content) || modeChanged {
			report.GitHooksChanged = true
			report.Violation = true
			if err := restoreFile(hp, old.Content, old.Mode); err != nil {
				return fmt.Errorf("worktree: restoring hook %s: %w", hp, err)
			}
			report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
		}
	}

	for name, old := range snapHooks {
		if currHooks[name] || old.Opaque {
			continue
		}
		report.GitHooksChanged = true
		report.Violation = true
		hp := filepath.Join(hooksDir, name)
		if err := restoreFile(hp, old.Content, old.Mode); err != nil {
			return fmt.Errorf("worktree: restoring deleted hook %s: %w", hp, err)
		}
		report.RestoredPaths = append(report.RestoredPaths, filepath.ToSlash(filepath.Join(".git/hooks", name)))
	}
	return nil
}

// keepOpaqueHook reports whether e, at the name of an entry the snapshot
// couldn't back up, can be left in place: it is still a real directory, or
// still a regular file with the same mode, size and mtime. A symlink or a
// changed entry could now point git at a runnable hook, so it is not kept.
func keepOpaqueHook(e fs.DirEntry, old *GitFileBackup) bool {
	info, err := e.Info()
	if err != nil || info.Mode().Type() != old.Mode.Type() {
		return false
	}
	if info.IsDir() {
		return true
	}
	return info.Mode().IsRegular() && info.Mode() == old.Mode &&
		info.Size() == old.Size && info.ModTime().Equal(old.ModTime)
}

func checkAndRestoreWorktreeConfig(adminDir string, backup *GitFileBackup, report *UnseenReport) error {
	wtCfgPath := filepath.Join(adminDir, "config.worktree")
	if backup == nil {
		if _, err := os.Lstat(wtCfgPath); err == nil {
			report.GitConfigChanged = true
			report.Violation = true
			if err := os.RemoveAll(wtCfgPath); err != nil {
				return fmt.Errorf("worktree: removing planted config.worktree: %w", err)
			}
			report.RestoredPaths = append(report.RestoredPaths, "config.worktree")
		}
		return nil
	}

	currData, err := os.ReadFile(wtCfgPath)
	fi, _ := os.Lstat(wtCfgPath)
	modeChanged := fi != nil && fi.Mode() != backup.Mode
	if err != nil || !bytes.Equal(currData, backup.Content) || modeChanged {
		report.GitConfigChanged = true
		report.Violation = true
		if err := restoreFile(wtCfgPath, backup.Content, backup.Mode); err != nil {
			return fmt.Errorf("worktree: restoring config.worktree: %w", err)
		}
		report.RestoredPaths = append(report.RestoredPaths, "config.worktree")
	}
	return nil
}

// restoreFile writes a backup to path as a regular file. Anything else at
// path (a symlink, a directory) is removed first, so the write can't follow
// a planted link out of the git dir.
func restoreFile(path string, content []byte, mode fs.FileMode) error {
	if _, err := os.Lstat(path); err == nil && !isRegularFile(path) {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		return err
	}
	_ = os.Chmod(path, mode)
	return nil
}

// isRegularFile reports whether path itself (not a symlink's target) is a
// regular file.
func isRegularFile(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

// checkAndRestoreAdminFile restores backup (one of the worktree admin dir's
// pointer files, e.g. commondir) if it was changed, replaced or removed.
func checkAndRestoreAdminFile(adminDir string, backup *GitFileBackup, report *UnseenReport) error {
	if backup == nil {
		return nil
	}
	p := filepath.Join(adminDir, backup.RelPath)
	currData, err := os.ReadFile(p)
	if err == nil && isRegularFile(p) && bytes.Equal(currData, backup.Content) {
		return nil
	}
	report.GitConfigChanged = true
	report.Violation = true
	if err := restoreFile(p, backup.Content, backup.Mode); err != nil {
		return fmt.Errorf("worktree: restoring %s: %w", backup.RelPath, err)
	}
	report.RestoredPaths = append(report.RestoredPaths, backup.RelPath)
	return nil
}

func checkAndRestoreWorktreeGit(slotDir string, snap *Snapshot, report *UnseenReport) error {
	if snap.WorktreeGitPointer != nil {
		slotGitPath := filepath.Join(slotDir, ".git")
		fi, lerr := os.Lstat(slotGitPath)
		currData, rerr := os.ReadFile(slotGitPath)
		if lerr != nil || rerr != nil || fi.IsDir() || !bytes.Equal(currData, snap.WorktreeGitPointer.Content) {
			report.GitConfigChanged = true
			report.Violation = true
			_ = os.RemoveAll(slotGitPath)
			if werr := os.WriteFile(slotGitPath, snap.WorktreeGitPointer.Content, snap.WorktreeGitPointer.Mode); werr != nil {
				return fmt.Errorf("worktree: restoring slot .git pointer: %w", werr)
			}
			report.RestoredPaths = append(report.RestoredPaths, ".git")
		}
	}

	adminDir := resolveWorktreeAdminDir(slotDir)
	if adminDir == "" {
		return nil
	}

	if err := checkAndRestoreWorktreeConfig(adminDir, snap.WorktreeConfig, report); err != nil {
		return err
	}

	for _, backup := range []*GitFileBackup{snap.WorktreeCommondir, snap.WorktreeGitdir} {
		if err := checkAndRestoreAdminFile(adminDir, backup, report); err != nil {
			return err
		}
	}

	if snap.WorktreeHooks != nil {
		if err := checkAndRestoreHooks(filepath.Join(adminDir, "hooks"), snap.WorktreeHooks, report); err != nil {
			return err
		}
	}
	return nil
}

// CheckUnseenState compares the current state of slotDir and the shared git
// configuration against snap (spec §5.3). If any git config or hook files were
// modified, added, or deleted, they are automatically restored and a violation
// is reported.
func CheckUnseenState(slotDir, repoRoot string, keepList, lockfiles []string, snap *Snapshot, extraDirs ...string) (*UnseenReport, error) {
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

	// 2. Check keep-list directories and extraDirs
	currKeepFiles, err := scanKeepFiles(slotDir, keepList, extraDirs...)
	if err != nil {
		return nil, err
	}
	diffKeepFiles(snap.KeepFiles, currKeepFiles, report)

	// 3. Check and restore .git/config
	gitDir := resolveGitDir(repoRoot)
	configPath := filepath.Join(gitDir, "config")
	if snap.GitConfig != nil {
		currData, err := os.ReadFile(configPath)
		fi, _ := os.Lstat(configPath)
		modeChanged := fi != nil && fi.Mode() != snap.GitConfig.Mode
		if err != nil || !bytes.Equal(currData, snap.GitConfig.Content) || modeChanged {
			report.GitConfigChanged = true
			report.Violation = true
			if rerr := restoreFile(configPath, snap.GitConfig.Content, snap.GitConfig.Mode); rerr != nil {
				return nil, fmt.Errorf("worktree: restoring .git/config: %w", rerr)
			}
			report.RestoredPaths = append(report.RestoredPaths, ".git/config")
		}
	}

	// 4. Check and restore .git/hooks/
	if err := checkAndRestoreHooks(filepath.Join(gitDir, "hooks"), snap.GitHooks, report); err != nil {
		return nil, err
	}

	// 5. Check and restore worktree-local git state (.git pointer and admin dir)
	if err := checkAndRestoreWorktreeGit(slotDir, snap, report); err != nil {
		return nil, err
	}

	slices.Sort(report.RestoredPaths)
	return report, nil
}
