package supervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// startSlack widens ScanStrays's since cutoff to absorb start-time
// precision (Linux reports it in clock ticks against a boot time in whole
// seconds).
const startSlack = 2 * time.Second

// Stray is a live process found by ScanStrays.
type Stray struct {
	PID     int
	Image   string // executable name
	Cmdline string
}

// CmdlineHash is hex(sha256(Cmdline)), as recorded in the ledger.
func (s Stray) CmdlineHash() string {
	h := sha256.Sum256([]byte(s.Cmdline))
	return hex.EncodeToString(h[:])
}

// procInfo is one process as the platform lister sees it. A field is
// empty (zero) when it couldn't be read (another user's or a protected
// process).
type procInfo struct {
	pid     int
	image   string
	cmdline string
	cwd     string
	started time.Time
}

// ScanStrays lists live processes, other than this one, started at or
// after since, whose command line names slot (or a path under it) or whose
// working directory is slot or below it. The Runner calls it after each
// invocation's Terminate with since = the invocation's spawn time: anything
// found escaped the container, e.g. through WMI or the Task Scheduler (§7),
// and is logged against the seat as a stray_processes ledger entry
// (StrayPayload). The since cutoff keeps out processes the agent can't have
// started, such as an editor or shell the user opened in the slot. A zero
// since, or an unreadable start time, doesn't filter. Processes whose
// command line and working directory can't be read are skipped.
func ScanStrays(slot string, since time.Time) ([]Stray, error) {
	abs, err := filepath.Abs(slot)
	if err != nil {
		return nil, fmt.Errorf("supervisor: scan strays: %w", err)
	}
	roots := []string{abs}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil && resolved != abs {
		roots = append(roots, resolved) // /proc reports resolved cwds
	}
	procs, err := listProcesses()
	if err != nil {
		return nil, fmt.Errorf("supervisor: scan strays: %w", err)
	}
	self := os.Getpid()
	var out []Stray
	for _, p := range procs {
		if p.pid == self {
			continue
		}
		if !since.IsZero() && !p.started.IsZero() && p.started.Before(since.Add(-startSlack)) {
			continue
		}
		for _, root := range roots {
			if underPath(p.cwd, root) || containsPath(p.cmdline, root) {
				out = append(out, Stray{PID: p.pid, Image: p.image, Cmdline: p.cmdline})
				break
			}
		}
	}
	return out, nil
}

// StrayPayload builds the payload for a stray_processes ledger entry
// (§8.E): invocation_id and processes[] of {pid, image, cmdline_hash}.
// Command lines are hashed, never recorded.
func StrayPayload(invocationID string, strays []Stray) map[string]any {
	procs := make([]any, 0, len(strays))
	for _, s := range strays {
		procs = append(procs, map[string]any{
			"pid":          s.PID,
			"image":        s.Image,
			"cmdline_hash": s.CmdlineHash(),
		})
	}
	return map[string]any{"invocation_id": invocationID, "processes": procs}
}

// normPath folds path spelling differences the OS ignores: on Windows,
// case and slash direction.
func normPath(p string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	}
	return p
}

// underPath reports whether dir is root or inside it.
func underPath(dir, root string) bool {
	if dir == "" {
		return false
	}
	dir, root = normPath(filepath.Clean(dir)), normPath(filepath.Clean(root))
	sep := string(filepath.Separator)
	return dir == root || strings.HasPrefix(dir, strings.TrimSuffix(root, sep)+sep)
}

// Characters that may precede / follow a path on a command line.
const (
	pathOpeners = " \t\"'=,"
	pathClosers = " \t\"'/\\=,"
)

// containsPath reports whether command line s names root or a path under
// it: an occurrence starting at a token boundary (start, space, quote, '=',
// ',') and ending at one or a path separator. So slot-1 doesn't match
// slot-10, and /tmp/slot doesn't match /mnt/tmp/slot.
func containsPath(s, root string) bool {
	if s == "" {
		return false
	}
	s, root = normPath(s), normPath(filepath.Clean(root))
	for i := 0; ; {
		j := strings.Index(s[i:], root)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(root)
		before := start == 0 || strings.ContainsRune(pathOpeners, rune(s[start-1]))
		after := end == len(s) || strings.ContainsRune(pathClosers, rune(s[end]))
		if before && after {
			return true
		}
		i = start + 1
	}
}
