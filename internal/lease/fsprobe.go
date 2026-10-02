package lease

import (
	"io/fs"
	"path/filepath"
	"time"
)

// LatestWrite returns an FSProbe that reports the newest modification time
// of any file or directory under root, the worktree slot. .git and the
// top-level keep-list directories (node_modules, .venv, target, ...) are
// skipped: an install churning them is not the agent making progress, and
// walking them every poll would be slow.
func LatestWrite(root string, keepList []string) func() (time.Time, error) {
	skip := map[string]bool{".git": true}
	for _, k := range keepList {
		if k != "" {
			skip[filepath.Clean(k)] = true
		}
	}
	return func() (time.Time, error) {
		var latest time.Time
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// A file removed mid-walk, one pending delete (access
				// denied on Windows) or an unreadable directory: skip
				// it and keep what the rest of the walk finds.
				if path == root {
					return err
				}
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if path != root && d.IsDir() {
				if rel, rerr := filepath.Rel(root, path); rerr == nil && skip[rel] {
					return filepath.SkipDir
				}
			}
			info, err := d.Info()
			if err != nil {
				return nil //nolint:nilerr // skip the entry, as above
			}
			if mt := info.ModTime(); mt.After(latest) {
				latest = mt
			}
			return nil
		})
		return latest, err
	}
}
