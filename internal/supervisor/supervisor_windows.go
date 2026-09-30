package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ctrlBreakTimeout bounds the _ctrlbreak helper run.
const ctrlBreakTimeout = 5 * time.Second

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procFreeConsole   = kernel32.NewProc("FreeConsole")
	procAttachConsole = kernel32.NewProc("AttachConsole")
)

func newSupervisor(helper []string) (Supervisor, error) {
	return &supervisor{helper: helper}, nil
}

// start creates the program suspended in a new process group with its own
// hidden console, assigns it to a fresh kill-on-close Job Object, then
// resumes it: nothing it starts can run outside the job.
func (s *supervisor) start(c Cmd) (*proc, error) {
	name, err := jobName()
	if err != nil {
		return nil, err
	}
	job, err := newJob(name)
	if err != nil {
		return nil, err
	}
	cmd := newExecCmd(append([]string{c.Path}, c.Args...), c)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("supervisor: spawn %s: %w", c.Path, err)
	}
	pid := uint32(cmd.Process.Pid)
	// os.Process holds its own handle, so pid can't be reused under us.
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		abortSpawn(cmd, job, 0)
		return nil, fmt.Errorf("supervisor: spawn: OpenProcess: %w", err)
	}
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		abortSpawn(cmd, job, ph)
		return nil, fmt.Errorf("supervisor: spawn: AssignProcessToJobObject: %w", err)
	}
	if err := resumeProcess(pid); err != nil {
		abortSpawn(cmd, job, ph)
		return nil, fmt.Errorf("supervisor: spawn: %w", err)
	}
	p := newProc(s, cmd, name, &jobObject{job: job, process: ph, pid: pid, helper: s.helper})
	go func() {
		_, _ = windows.WaitForSingleObject(ph, windows.INFINITE)
		close(p.exited)
	}()
	return p, nil
}

// abortSpawn kills and reaps a half-spawned (still suspended) process and
// frees its handles.
func abortSpawn(cmd *exec.Cmd, job, ph windows.Handle) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if ph != 0 {
		_ = windows.CloseHandle(ph)
	}
	_ = windows.CloseHandle(job)
}

// jobName returns a fresh, unguessable Job Object name. It is recorded as
// invocations.supervisor_handle; being unguessable, no other process can
// pre-create or open it.
func jobName() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("supervisor: job name: %w", err)
	}
	return `Local\arbiter-job-` + hex.EncodeToString(b[:]), nil
}

// newJob creates a Job Object that kills its processes when its last handle
// closes, which is how a crashed supervisor's trees die (§7).
func newJob(name string) (windows.Handle, error) {
	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("supervisor: job name: %w", err)
	}
	job, err := windows.CreateJobObject(nil, namep)
	if err != nil {
		return 0, fmt.Errorf("supervisor: CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("supervisor: SetInformationJobObject: %w", err)
	}
	return job, nil
}

// resumeProcess resumes the single thread of a process created suspended.
// os/exec closes the thread handle CreateProcess returned, so the thread is
// found with a Toolhelp snapshot.
func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("thread snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	te := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	n := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return fmt.Errorf("OpenThread: %w", err)
		}
		_, err = windows.ResumeThread(th)
		_ = windows.CloseHandle(th)
		if err != nil {
			return fmt.Errorf("ResumeThread: %w", err)
		}
		n++
	}
	if n != 1 {
		return fmt.Errorf("resume: found %d threads for pid %d, want 1", n, pid)
	}
	return nil
}

// jobObject is a Windows Job Object container.
type jobObject struct {
	job     windows.Handle
	process windows.Handle // the leader, for its exit and to hold its pid
	pid     uint32
	helper  []string
}

// jobAccounting is JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.
type jobAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

func (j *jobObject) alive() bool {
	var info jobAccounting
	if err := windows.QueryInformationJobObject(j.job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return true // can't tell; let the grace period run out
	}
	return info.ActiveProcesses > 0
}

// signal delivers CTRL_BREAK_EVENT to the leader's process group through
// the _ctrlbreak helper. The supervisor never attaches to a child's console
// itself: it would lose its own, process-wide (§7).
func (j *jobObject) signal() error {
	ctx, cancel := context.WithTimeout(context.Background(), ctrlBreakTimeout)
	defer cancel()
	argv := append(append([]string{}, j.helper...), helperCtrlBreak, strconv.FormatUint(uint64(j.pid), 10))
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("supervisor: %s %d: %w: %s", helperCtrlBreak, j.pid, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (j *jobObject) kill() error {
	if err := windows.TerminateJobObject(j.job, 1); err != nil {
		return fmt.Errorf("supervisor: TerminateJobObject: %w", err)
	}
	return nil
}

func (j *jobObject) release() {
	_ = windows.CloseHandle(j.job)
	_ = windows.CloseHandle(j.process)
}

// runCtrlBreak is `_ctrlbreak <pid>`: attach to the console of process
// group <pid> and send it CTRL_BREAK_EVENT. CTRL_BREAK only reaches groups
// on the caller's console, and a CREATE_NO_WINDOW child has its own hidden
// one, so the event must come from a process attached to that console.
func runCtrlBreak(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: _ctrlbreak <pid>")
		return 2
	}
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "_ctrlbreak: bad pid:", args[0])
		return 2
	}
	// We are not in the target group, but stay safe if the event reaches us.
	signal.Ignore(os.Interrupt)
	_, _, _ = procFreeConsole.Call()
	if r, _, err := procAttachConsole.Call(uintptr(pid)); r == 0 {
		fmt.Fprintln(os.Stderr, "_ctrlbreak: AttachConsole:", err)
		return 1
	}
	err = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid))
	_, _, _ = procFreeConsole.Call()
	if err != nil {
		fmt.Fprintln(os.Stderr, "_ctrlbreak: GenerateConsoleCtrlEvent:", err)
		return 1
	}
	return 0
}

func runPGShim([]string) int {
	fmt.Fprintln(os.Stderr, "_pgshim: Linux only")
	return 2
}
