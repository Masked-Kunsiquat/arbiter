package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// deathSignal is the shim's PR_SET_PDEATHSIG. It must differ from SIGTERM,
// which the shim receives (and ignores) as part of every graceful stop.
const deathSignal = syscall.SIGUSR1

func newSupervisor(helper []string) (Supervisor, error) {
	return &supervisor{helper: helper}, nil
}

// start runs `<helper> _pgshim <our pid> -- <path> <args...>` as the leader
// of a new process group. The program is resolved here so a missing binary
// fails Spawn instead of surfacing as the shim's exit status.
func (s *supervisor) start(c Cmd) (*proc, error) {
	path := c.Path
	if filepath.Base(path) == path {
		lp, err := exec.LookPath(path)
		if err != nil {
			return nil, fmt.Errorf("supervisor: spawn: %w", err)
		}
		path = lp
	}
	argv := append([]string{}, s.helper...)
	argv = append(argv, helperPGShim, strconv.Itoa(os.Getpid()), "--", path)
	argv = append(argv, c.Args...)
	cmd := newExecCmd(argv, c)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: deathSignal}

	started := make(chan error, 1)
	var p *proc
	go func() {
		// PR_SET_PDEATHSIG fires when the *thread* that forked the child
		// exits, not the process. Pin this goroutine to its thread and keep
		// it alive until the leader exits. Never unlocked: the thread is
		// discarded when the goroutine returns.
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		pid := cmd.Process.Pid
		p = newProc(s, cmd, strconv.Itoa(pid), &pgroup{pgid: pid})
		started <- nil
		waitExitedNoReap(pid)
		close(p.exited)
	}()
	if err := <-started; err != nil {
		return nil, fmt.Errorf("supervisor: spawn %s: %w", c.Path, err)
	}
	return p, nil
}

// waitExitedNoReap blocks until pid has exited, leaving it a zombie so its
// PID (and so the PGID) can't be reused until Terminate reaps it.
func waitExitedNoReap(pid int) {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return // exited, or already reaped (ECHILD) by Terminate
		}
	}
}

// pgroup is a Linux process-group container.
type pgroup struct {
	pgid int
}

func (g *pgroup) alive() bool { return groupAlive(g.pgid) }

func (g *pgroup) signal() error {
	return unix.Kill(-g.pgid, unix.SIGTERM)
}

func (g *pgroup) kill() error {
	if err := unix.Kill(-g.pgid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("supervisor: kill -KILL -%d: %w", g.pgid, err)
	}
	return nil
}

func (g *pgroup) release() {}

// groupAlive reports whether any non-zombie process is in process group
// pgid. kill(-pgid, 0) can't answer that: the unreaped leader is a zombie
// that still counts as a member.
func groupAlive(pgid int) bool {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return true // can't tell; let the grace period run out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		state, pg, ok := procStat(pid)
		if ok && pg == pgid && state != 'Z' && state != 'X' {
			return true
		}
	}
	return false
}

// procStat reads the state and process group of pid from /proc/<pid>/stat.
func procStat(pid int) (state byte, pgrp int, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	// "pid (comm) state ppid pgrp ...": comm may contain spaces and parens,
	// so parse from the last ')'.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, 0, false
	}
	f := bytes.Fields(b[i+1:])
	if len(f) < 3 || len(f[0]) != 1 {
		return 0, 0, false
	}
	pg, err := strconv.Atoi(string(f[2]))
	if err != nil {
		return 0, 0, false
	}
	return f[0][0], pg, true
}

// runPGShim is the process-group leader: `_pgshim <ppid> -- <path> <args...>`.
// It runs the program as its child (same group, same stdio, env and dir),
// kills the whole group when its parent dies (deathSignal), ignores the
// graceful SIGTERM (the group signal reaches the program directly), and
// exits the way the program did.
func runPGShim(args []string) int {
	if len(args) < 3 || args[1] != "--" {
		fmt.Fprintln(os.Stderr, "usage: _pgshim <ppid> -- <program> [args...]")
		return 2
	}
	ppid, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "_pgshim: bad ppid:", args[0])
		return 2
	}
	// Handlers first: from here on the death signal can't kill the shim
	// without it taking the group down. Notify (not Ignore) so the program
	// gets default dispositions: SIG_IGN would survive exec.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, deathSignal, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	if os.Getppid() != ppid {
		// The supervisor died before the handler was installed.
		return 1
	}
	go func() {
		for s := range sigs {
			if s == deathSignal {
				_ = unix.Kill(-unix.Getpgrp(), unix.SIGKILL) // includes the shim
			}
		}
	}()

	cmd := exec.CommandContext(context.Background(), args[2], args[3:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "_pgshim:", err)
		return 127
	}
	_ = cmd.Wait()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return cmd.ProcessState.ExitCode()
	}
	// Die of the same signal so the supervisor sees it.
	sig := ws.Signal()
	signal.Reset(sig)
	_ = unix.Kill(os.Getpid(), sig)
	time.Sleep(time.Second)
	return 128 + int(sig)
}

func runCtrlBreak([]string) int {
	fmt.Fprintln(os.Stderr, "_ctrlbreak: Windows only")
	return 2
}
