//go:build !linux && !windows

package supervisor

import (
	"errors"
	"fmt"
	"os"
)

// macOS needs a shim polling getppid() / kqueue NOTE_EXIT for supervisor-death
// cleanup (§7); deferred with the rest of macOS support.

func newSupervisor([]string) (Supervisor, error) { return nil, ErrUnsupported }

func defaultHelper() (string, error) { return os.Executable() }

func (s *supervisor) start(Cmd) (*proc, error) { return nil, ErrUnsupported }

func listProcesses() ([]procInfo, error) { return nil, errors.ErrUnsupported }

func runCtrlBreak([]string) int { return helperUnsupported(helperCtrlBreak) }

func runPGShim([]string) int { return helperUnsupported(helperPGShim) }

func helperUnsupported(name string) int {
	fmt.Fprintln(os.Stderr, name+": unsupported platform")
	return 2
}
