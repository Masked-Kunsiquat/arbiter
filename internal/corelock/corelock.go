// Package corelock implements the single-host invariant of spec §10.B:
// exactly one process hosts the core for a repo at a time.
//
// The lock is an OS advisory/mandatory lock on .arbiter/core.lock, taken
// with LockFileEx on Windows and flock on POSIX. Both are released by the
// OS when the holding process exits for any reason, including a crash or a
// hard kill, so a dead host never leaves a stale lock behind. The lock file
// itself is never deleted: its existence means nothing, only the lock does.
//
// Acquire never blocks. A caller that loses the race is expected to connect
// to the winning host as a client instead (see internal/core).
package corelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileName is the lock file's name inside the .arbiter directory.
const FileName = "core.lock"

// ErrLocked is returned by Acquire when another process (or another Lock in
// this process) already holds the core lock.
var ErrLocked = errors.New("corelock: core lock is held by another process")

// Lock is a held core lock. Release it with Release; the OS also releases it
// when the process exits.
type Lock struct {
	f    *os.File
	path string
}

// Acquire takes the exclusive core lock for the repo whose .arbiter
// directory is arbiterDir. It returns ErrLocked, without waiting, if the
// lock is already held.
//
// The file is opened close-on-exec (Go's default on POSIX; handles are
// non-inheritable by default on Windows), so harness processes the core
// launches never inherit the lock and can't keep it alive after the core
// dies.
func Acquire(arbiterDir string) (*Lock, error) {
	path := filepath.Join(arbiterDir, FileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("corelock: opening %s: %w", path, err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("corelock: locking %s: %w", path, err)
	}
	return &Lock{f: f, path: path}, nil
}

// Path returns the lock file's path.
func (l *Lock) Path() string { return l.path }

// Release unlocks and closes the lock file. It is safe to call more than
// once.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	uerr := unlockFile(f)
	cerr := f.Close()
	if uerr != nil {
		return fmt.Errorf("corelock: unlocking %s: %w", l.path, uerr)
	}
	if cerr != nil {
		return fmt.Errorf("corelock: closing %s: %w", l.path, cerr)
	}
	return nil
}
