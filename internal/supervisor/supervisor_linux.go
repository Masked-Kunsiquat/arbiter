package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// deathSignal is the shim's PR_SET_PDEATHSIG. It must differ from SIGTERM,
// which the shim receives (and ignores) as part of every graceful stop.
const deathSignal = syscall.SIGUSR1

// statusFD is the shim's inherited write end of the status pipe
// (exec.Cmd.ExtraFiles[0]).
const statusFD = 3

func newSupervisor(helper []string) (Supervisor, error) {
	return &supervisor{helper: helper}, nil
}

// defaultHelper is /proc/self/exe rather than os.Executable: it still
// execs this process's own binary after the file on disk is replaced or
// deleted (an upgrade while the core runs), so the shim always speaks
// this build's protocol.
func defaultHelper() (string, error) { return "/proc/self/exe", nil }

// start runs `<helper> _pgshim <our pid> -- <path> <args...>` as the leader
// of a new process group. The shim runs the program, reports how it exited
// on the status pipe, then stays alive as the group's anchor (PDEATHSIG
// holder, PGID pin) until teardown's group kill.
func (s *supervisor) start(c Cmd) (*proc, error) {
	path, err := resolveProgram(c)
	if err != nil {
		return nil, fmt.Errorf("supervisor: spawn: %w", err)
	}
	argv := append([]string{}, s.helper...)
	argv = append(argv, helperPGShim, strconv.Itoa(os.Getpid()), "--", path)
	argv = append(argv, c.Args...)
	cmd := newExecCmd(argv, c)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: deathSignal}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("supervisor: spawn: status pipe: %w", err)
	}
	cmd.ExtraFiles = []*os.File{w}

	started := make(chan error, 1)
	var p *proc
	go func() {
		// PR_SET_PDEATHSIG fires when the *thread* that forked the child
		// exits, not the process. Pin this goroutine to its thread and keep
		// it alive until the shim is gone. Never unlocked: the thread is
		// discarded when the goroutine returns.
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		pid := cmd.Process.Pid
		g := &pgroup{pgid: pid}
		p = newProc(s, cmd, strconv.Itoa(pid), g)
		started <- nil
		g.watch(r, p.exited)
	}()
	err = <-started
	_ = w.Close() // the shim has its copy
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("supervisor: spawn %s: %w", c.Path, err)
	}
	return p, nil
}

// resolveProgram fails a spawn early for a missing program, as os/exec
// does on Windows, instead of surfacing it as the shim's report. A bare
// name is looked up in PATH; a path is checked relative to c.Dir.
func resolveProgram(c Cmd) (string, error) {
	if filepath.Base(c.Path) == c.Path {
		return exec.LookPath(c.Path)
	}
	check := c.Path
	if !filepath.IsAbs(check) && c.Dir != "" {
		check = filepath.Join(c.Dir, check)
	}
	if _, err := exec.LookPath(check); err != nil {
		return "", err
	}
	return c.Path, nil // the shim runs in c.Dir, so relative still resolves
}

// pgroup is a Linux process-group container led by the shim.
type pgroup struct {
	pgid int

	// Set by watch before it closes exited.
	reported bool
	status   error
}

// watch reads the shim's one-line exit report, closes exited, then blocks
// until the shim dies (pipe EOF). Returning earlier would end the locked
// thread and fire the shim's PDEATHSIG.
func (g *pgroup) watch(r *os.File, exited chan struct{}) {
	defer func() { _ = r.Close() }()
	br := bufio.NewReader(r)
	if line, err := br.ReadString('\n'); err == nil {
		g.reported = true
		g.status = parseReport(line)
	}
	close(exited)
	_, _ = io.Copy(io.Discard, br)
}

// alive reports whether anything besides the shim is still running in the
// group; the shim itself only exits when killed.
func (g *pgroup) alive() bool { return groupAlive(g.pgid, g.pgid) }

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

// exitErr ignores the shim's own wait status (it is always killed) and
// returns what the shim reported about the program. No report means the
// program was still running when the group was killed.
func (g *pgroup) exitErr(error) error {
	if !g.reported {
		return &ExitError{Code: -1, Signal: "killed"}
	}
	return g.status
}

// Shim reports: "exit <code>\n" or "signal <number>\n".
func formatReport(ps *os.ProcessState) string {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("signal %d\n", int(ws.Signal()))
	}
	return fmt.Sprintf("exit %d\n", ps.ExitCode())
}

func parseReport(line string) error {
	kind, val, _ := strings.Cut(strings.TrimSpace(line), " ")
	n, err := strconv.Atoi(val)
	switch {
	case err != nil:
		return fmt.Errorf("supervisor: bad shim report %q", line)
	case kind == "signal":
		return &ExitError{Code: -1, Signal: unix.SignalName(syscall.Signal(n))}
	case n == 0:
		return nil
	default:
		return &ExitError{Code: n}
	}
}

// groupAlive reports whether any non-zombie process other than except is
// in process group pgid. kill(-pgid, 0) can't answer that: zombies still
// count as members.
func groupAlive(pgid, except int) bool {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return true // can't tell; let the grace period run out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == except {
			continue
		}
		state, pg, ok := procStat(pid)
		if ok && pg == pgid && state != 'Z' && state != 'X' {
			return true
		}
	}
	return false
}

// statFields returns the fields of /proc/<pid>/stat after "pid (comm)",
// so index 0 is field 3 (state) of proc(5).
func statFields(pid int) ([][]byte, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return nil, false
	}
	// comm may contain spaces and parens, so split after the last ')'.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return nil, false
	}
	return bytes.Fields(b[i+1:]), true
}

// procStat reads the state and process group of pid.
func procStat(pid int) (state byte, pgrp int, ok bool) {
	f, ok := statFields(pid)
	if !ok || len(f) < 3 || len(f[0]) != 1 {
		return 0, 0, false
	}
	pg, err := strconv.Atoi(string(f[2]))
	if err != nil {
		return 0, 0, false
	}
	return f[0][0], pg, true
}

// runPGShim is the process-group leader: `_pgshim <ppid> -- <path> <args...>`,
// with the status pipe as fd 3. It runs the program as its child (same
// group, stdio, env and dir), writes how it exited to the pipe, then stays
// alive so PDEATHSIG keeps covering whatever the program left running.
// On deathSignal it kills its whole group, itself included. It ignores the
// graceful SIGTERM: the group signal reaches the program directly.
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
	syscall.CloseOnExec(statusFD) // the program must not hold the pipe open
	status := os.NewFile(statusFD, "status")

	cmd := exec.CommandContext(context.Background(), args[2], args[3:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	report := "exit 127\n"
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "_pgshim:", err)
	} else {
		_ = cmd.Wait()
		report = formatReport(cmd.ProcessState)
	}
	// Drop our stdio so the supervisor's readers see EOF once the program's
	// own children close theirs; then report.
	_ = os.Stdin.Close()
	_ = os.Stdout.Close()
	_ = os.Stderr.Close()
	_, _ = status.WriteString(report)
	select {} // until teardown's group kill, or deathSignal
}

func runCtrlBreak([]string) int {
	fmt.Fprintln(os.Stderr, "_ctrlbreak: Windows only")
	return 2
}
