package supervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

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

// procInfo is one process as the platform lister sees it. Cwd or Cmdline is
// empty when it couldn't be read (another user's or a protected process).
type procInfo struct {
	pid     int
	image   string
	cmdline string
	cwd     string
}

// ScanStrays lists live processes, other than this one, whose command line
// contains slot or whose working directory is slot or below it. The Runner
// calls it after each invocation's Terminate: anything found escaped the
// container, e.g. through WMI or the Task Scheduler (§7), and is logged
// against the seat as a stray_processes ledger entry (StrayPayload).
// Processes whose details can't be read are skipped.
func ScanStrays(slot string) ([]Stray, error) {
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

// containsPath reports whether s mentions root.
func containsPath(s, root string) bool {
	return s != "" && strings.Contains(normPath(s), normPath(filepath.Clean(root)))
}
