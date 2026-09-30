// Package supervisor starts, watches and reaps every sub-process Arbiter
// launches (agent harnesses, test runners, installs) inside an OS container
// that can be killed as a whole (spec §7 "Process Supervision").
//
//	Windows: a Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The child
//	is created suspended in a new process group with no window, assigned to
//	the job, then resumed, so no grandchild can start outside it. Graceful
//	stop is CTRL_BREAK_EVENT sent by a short-lived helper process
//	(`arbiter _ctrlbreak <pid>`); hard kill is TerminateJobObject.
//
//	Linux: a process group (Setpgid). Graceful stop is kill -TERM -<pgid>;
//	hard kill is kill -KILL -<pgid>. PR_SET_PDEATHSIG only reaches the
//	direct child, so the group leader is a tiny shim (`arbiter _pgshim`)
//	that receives the death signal and kills its whole group.
//
//	macOS is deferred (issue #15); New returns ErrUnsupported there.
//
// Containment is cleanup, not a sandbox: a process started through a system
// service (WMI, Task Scheduler, systemd-run, ...) is not the container's
// child. ScanStrays finds such survivors by slot path after each run.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// ErrUnsupported is returned by New on platforms without a supervisor
// implementation (macOS until its shim lands).
var ErrUnsupported = errors.New("supervisor: unsupported platform")

// Cmd describes a process to spawn. Nil Stdin/Stdout/Stderr connect to the
// null device, as with os/exec.
type Cmd struct {
	Path string   // program name or path; looked up in PATH when it has no separator
	Args []string // arguments, not including the program itself
	Dir  string   // working directory; "" means the supervisor's
	Env  []string // environment; nil means the supervisor's

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Handle is a spawned process and its container.
type Handle interface {
	// Pid is the container leader's process id. On Linux that is the
	// process-group shim, not the program named in Cmd.Path.
	Pid() int
	// ID identifies the container for invocations.supervisor_handle (§4):
	// the PGID on Linux, the Job Object name on Windows.
	ID() string
	// Exited is closed when the program exits. The container may still
	// hold processes it started; they live until Terminate or Wait.
	Exited() <-chan struct{}
	// Wait blocks until the program exits, tears the container down
	// (Terminate with no grace, killing anything left in it) and returns
	// nil for a zero exit status, else an *ExitError.
	Wait() error
}

// ExitError reports a program that exited with a nonzero status or was
// killed.
type ExitError struct {
	Code   int    // exit status; -1 when killed by a signal
	Signal string // the killing signal on Linux ("killed" when unknown); "" otherwise
}

func (e *ExitError) Error() string {
	if e.Signal != "" {
		return "supervisor: program killed by signal: " + e.Signal
	}
	return fmt.Sprintf("supervisor: program exit status %d", e.Code)
}

// ExitCode returns Code, matching exec.ExitError.
func (e *ExitError) ExitCode() int { return e.Code }

// Supervisor launches processes inside kill-able containers.
type Supervisor interface {
	// Spawn starts cmd inside a new container.
	Spawn(cmd Cmd) (Handle, error)
	// Terminate sends the graceful stop signal, waits up to grace for the
	// container to empty, then hard-kills the whole container regardless,
	// waits for it to empty, reaps the leader and releases the container.
	// It is idempotent and safe to call concurrently; later calls wait for
	// the first to finish. The error reports a failed hard kill (including
	// a container still not empty afterwards), never the exit status.
	Terminate(h Handle, grace time.Duration) error
}

// Options configures New.
type Options struct {
	// Helper is the argv prefix that runs this package's helper commands
	// (see RunHelper) in a separate process. Default: the running
	// executable, which must call RunHelper first thing in main.
	Helper []string
}

// New returns the Supervisor for this platform.
func New(opts Options) (Supervisor, error) {
	helper := opts.Helper
	if len(helper) == 0 {
		exe, err := defaultHelper()
		if err != nil {
			return nil, fmt.Errorf("supervisor: locate helper executable: %w", err)
		}
		helper = []string{exe}
	}
	return newSupervisor(helper)
}

// RunHelper runs a helper command if args (os.Args[1:]) name one, and
// reports its exit code. Binaries that host a Supervisor call it before
// anything else:
//
//	if code, ok := supervisor.RunHelper(os.Args[1:]); ok {
//		os.Exit(code)
//	}
func RunHelper(args []string) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case helperCtrlBreak:
		return runCtrlBreak(args[1:]), true
	case helperPGShim:
		return runPGShim(args[1:]), true
	}
	return 0, false
}

const (
	helperCtrlBreak = "_ctrlbreak"
	helperPGShim    = "_pgshim"

	// pollInterval is how often Terminate checks whether the container has
	// emptied during the grace period.
	pollInterval = 50 * time.Millisecond
	// killWait bounds how long Terminate waits, after the hard kill, for the
	// container to empty. Both hard kills are asynchronous: a process in
	// uninterruptible I/O dies late, and one still unwinding would show up
	// in a post-run ScanStrays as a false stray.
	killWait = 5 * time.Second
	// waitDelay bounds how long reaping waits for stdio copying after the
	// hard kill, in case an escaped process still holds a pipe.
	waitDelay = 5 * time.Second
)

// container is the platform half of a process's container.
type container interface {
	alive() bool   // whether any live process remains in the container
	signal() error // send the graceful stop signal (best effort)
	kill() error   // hard-kill every process in the container
	release()      // free OS resources once the leader is reaped

	// exitErr turns the leader's exec.Cmd.Wait result into Handle.Wait's
	// result. It runs after Exited is closed.
	exitErr(waitErr error) error
}

// supervisor is the platform-independent Supervisor; start (per platform)
// does the spawning.
type supervisor struct {
	helper []string
}

// proc is the Handle returned by Spawn.
type proc struct {
	owner  *supervisor
	cmd    *exec.Cmd
	id     string
	c      container
	exited chan struct{} // closed by the platform watcher when the program exits

	once    sync.Once
	done    chan struct{} // closed when teardown finishes
	killErr error
	waitErr error
}

func (s *supervisor) Spawn(c Cmd) (Handle, error) {
	if c.Path == "" {
		return nil, errors.New("supervisor: spawn: empty Path")
	}
	return s.start(c)
}

func (s *supervisor) Terminate(h Handle, grace time.Duration) error {
	p, ok := h.(*proc)
	if !ok || p.owner != s {
		return errors.New("supervisor: terminate: handle not from this supervisor")
	}
	p.terminate(grace)
	return p.killErr
}

func newProc(s *supervisor, cmd *exec.Cmd, id string, c container) *proc {
	return &proc{
		owner:  s,
		cmd:    cmd,
		id:     id,
		c:      c,
		exited: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

func (p *proc) Pid() int                { return p.cmd.Process.Pid }
func (p *proc) ID() string              { return p.id }
func (p *proc) Exited() <-chan struct{} { return p.exited }

func (p *proc) Wait() error {
	<-p.exited
	p.terminate(0)
	return p.waitErr
}

func (p *proc) terminate(grace time.Duration) {
	p.once.Do(func() { p.teardown(grace) })
	<-p.done
}

// teardown is §7's Terminate: graceful signal, wait out the grace period
// (ending early once the container is empty), hard kill regardless, wait
// for the container to empty, reap, release. The leader is reaped only
// after the hard kill, so on Linux the PGID can't be recycled before the
// group signal is sent.
func (p *proc) teardown(grace time.Duration) {
	defer close(p.done)
	if grace > 0 && p.c.alive() {
		// A failed graceful signal skips the wait: nothing will stop on it.
		if err := p.c.signal(); err == nil {
			p.waitEmpty(grace)
		}
	}
	if p.killErr = p.c.kill(); p.killErr != nil {
		// At least stop the leader, so reaping below can't block forever.
		_ = p.cmd.Process.Kill()
	} else if !p.waitEmpty(killWait) {
		p.killErr = fmt.Errorf("supervisor: container %s not empty %v after hard kill", p.id, killWait)
	}
	waitErr := p.cmd.Wait()
	<-p.exited
	p.waitErr = p.c.exitErr(waitErr)
	p.c.release()
}

// waitEmpty polls until the container is empty or d elapses, and reports
// whether it emptied.
func (p *proc) waitEmpty(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for p.c.alive() {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(min(pollInterval, time.Until(deadline)))
	}
	return true
}

// newExecCmd builds the exec.Cmd for argv with c's directory, environment
// and stdio.
func newExecCmd(argv []string, c Cmd) *exec.Cmd {
	// No context: the process lives until Terminate, not a deadline.
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...)
	cmd.Dir = c.Dir
	cmd.Env = c.Env
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	cmd.WaitDelay = waitDelay
	return cmd
}
