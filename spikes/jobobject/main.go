//go:build windows

// Spike: Job Object containment for agent process trees. Throwaway; see FINDINGS.md.
//
//	go build -o jobspike.exe . && ./jobspike.exe [scenario...]
//
// Scenarios: terminate, parentdeath, ctrlbreak, escape, claude-terminate,
// claude-parentdeath, claude-ctrlbreak. Default: the non-claude ones.
// Internal modes (argv[1]): child, grandchild, supervisor.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var self string

func main() {
	var err error
	self, err = os.Executable()
	must(err)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "child":
			childMode(os.Args[2], os.Args[3:])
			return
		case "grandchild":
			grandchildMode(os.Args[2], os.Args[3])
			return
		case "supervisor":
			supervisorMode(os.Args[2], os.Args[3])
			return
		case "detached":
			// Re-run the given scenarios as a DETACHED_PROCESS (no console at all),
			// like a background `arbiter serve`, and print its output.
			out := filepath.Join(tmp("detached"), "out.txt")
			f, _ := os.Create(out)
			c := exec.Command(self, os.Args[2:]...)
			c.Stdout, c.Stderr = f, f
			c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008} // DETACHED_PROCESS
			must(c.Run())
			f.Close()
			b, _ := os.ReadFile(out)
			fmt.Print(string(b))
			return
		}
	}
	scenarios := os.Args[1:]
	if len(scenarios) == 0 {
		scenarios = []string{"terminate", "parentdeath", "ctrlbreak", "escape"}
	}
	fmt.Printf("driver pid=%d consoleWindow=%v consoleProcesses=%d\n", os.Getpid(), hasConsole(), consoleProcs())
	for _, s := range scenarios {
		fmt.Printf("\n=== %s\n", s)
		switch s {
		case "terminate":
			scenarioTerminate(false)
		case "parentdeath":
			scenarioParentDeath("plain")
		case "ctrlbreak":
			scenarioCtrlBreak(false)
		case "escape":
			scenarioEscape()
		case "claude-terminate":
			scenarioTerminate(true)
		case "claude-parentdeath":
			scenarioParentDeath("claude")
		case "claude-ctrlbreak":
			scenarioCtrlBreak(true)
		default:
			fmt.Println("unknown scenario")
		}
	}
}

// ---------- the Supervisor.Spawn candidate ----------

type jobProc struct {
	cmd *exec.Cmd
	job windows.Handle
}

// spawnInJob starts argv suspended in a new process group, assigns it to a fresh
// kill-on-close Job Object, then resumes it.
func spawnInJob(dir string, argv []string, stdin string) (*jobProc, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, _ := os.Create(filepath.Join(dir, "stdout.log"))
	cmd.Stdout = out
	cmd.Stderr = out
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NEW_PROCESS_GROUP)
	if os.Getenv("NOWINDOW") == "1" {
		flags |= windows.CREATE_NO_WINDOW
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	pid := uint32(cmd.Process.Pid)
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	n, err := resumeProcess(pid)
	if err != nil || n != 1 {
		return nil, fmt.Errorf("resume: resumed %d threads, err=%v", n, err)
	}
	return &jobProc{cmd: cmd, job: job}, nil
}

// resumeProcess resumes every thread of pid (a suspended new process has exactly one).
// os/exec drops the thread handle from CreateProcess, so we find it via Toolhelp.
func resumeProcess(pid uint32) (int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	n := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return n, err
		}
		_, err = windows.ResumeThread(th)
		windows.CloseHandle(th)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// jobPIDs lists the processes currently in the job.
func jobPIDs(job windows.Handle) []uint32 {
	var buf struct {
		Assigned, InList uint32
		IDs              [256]uintptr
	}
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&buf)), uint32(unsafe.Sizeof(buf)), nil)
	if err != nil {
		fmt.Println("  QueryInformationJobObject:", err)
		return nil
	}
	var pids []uint32
	for i := 0; i < int(buf.InList); i++ {
		pids = append(pids, uint32(buf.IDs[i]))
	}
	return pids
}

// ---------- scenarios ----------

func scenarioTerminate(claude bool) {
	dir := tmp("terminate")
	jp, pids := startTree(dir, claude)
	if jp == nil {
		return
	}
	fmt.Printf("  before TerminateJobObject: %s\n", describe(pids))
	must(windows.TerminateJobObject(jp.job, 1))
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("  after  TerminateJobObject: %s\n", describe(pids))
	fmt.Printf("  RESULT all dead=%v\n", noneAlive(pids))
	windows.CloseHandle(jp.job)
}

// scenarioParentDeath runs a separate supervisor process that owns the job, then
// hard-kills that supervisor (simulating an Arbiter crash) and checks the tree.
func scenarioParentDeath(mode string) {
	dir := tmp("parentdeath-" + mode)
	sup := exec.Command(self, "supervisor", dir, mode)
	sup.Stdout, sup.Stderr = os.Stdout, os.Stderr
	must(sup.Start())
	pids, ok := waitPIDFile(filepath.Join(dir, "job.pids"), 90*time.Second)
	if !ok {
		fmt.Println("  supervisor never reported job pids")
		sup.Process.Kill()
		return
	}
	fmt.Printf("  supervisor pid=%d; job tree: %s\n", sup.Process.Pid, describe(pids))
	must(sup.Process.Kill()) // TerminateProcess: no cleanup code runs in the supervisor
	sup.Wait()
	time.Sleep(1 * time.Second)
	fmt.Printf("  after killing supervisor: %s\n", describe(pids))
	fmt.Printf("  RESULT all dead=%v\n", noneAlive(pids))
	killAll(pids)
}

func scenarioCtrlBreak(claude bool) {
	dir := tmp("ctrlbreak")
	jp, pids := startTree(dir, claude)
	if jp == nil {
		return
	}
	defer windows.CloseHandle(jp.job)
	pgid := uint32(jp.cmd.Process.Pid)
	fmt.Printf("  tree: %s\n", describe(pids))
	err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pgid)
	fmt.Printf("  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, %d) err=%v\n", pgid, err)
	if err != nil {
		// Fallback: attach to the child's console and signal from there.
		err = ctrlBreakViaAttach(pgid)
		fmt.Printf("  fallback AttachConsole+GenerateConsoleCtrlEvent err=%v\n", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !noneAlive(pids) {
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Printf("  after 15s grace: %s\n", describe(pids))
	for _, f := range []string{"child.console", "child.sig", "grandchild.sig"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err == nil {
			fmt.Printf("  %s: %s", f, b)
		}
	}
	if claude {
		tail(filepath.Join(dir, "stdout.log"), 6)
	}
	fmt.Printf("  RESULT graceful (all exited without TerminateJobObject)=%v\n", noneAlive(pids))
	windows.TerminateJobObject(jp.job, 1)
}

// scenarioEscape: can a process in the job start something outside it?
func scenarioEscape() {
	dir := tmp("escape")
	jp, err := spawnInJob(dir, []string{self, "child", dir, "breakaway", "wmi"}, "")
	must(err)
	defer windows.CloseHandle(jp.job)
	if _, ok := waitPIDFile(filepath.Join(dir, "wmi.pid"), 30*time.Second); !ok {
		fmt.Println("  WMI grandchild never started")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "breakaway.txt"))
	fmt.Printf("  CREATE_BREAKAWAY_FROM_JOB from inside the job: %s\n", b)
	wmi, _ := waitPIDFile(filepath.Join(dir, "wmi.pid"), time.Second)
	inJob := map[uint32]bool{}
	for _, p := range jobPIDs(jp.job) {
		inJob[p] = true
	}
	for _, p := range wmi {
		fmt.Printf("  WMI-created grandchild pid=%d inJob=%v\n", p, inJob[p])
	}
	windows.TerminateJobObject(jp.job, 1)
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("  after TerminateJobObject: WMI grandchild %s\n", describe(wmi))
	fmt.Printf("  RESULT escaped=%v\n", !noneAlive(wmi))
	killAll(wmi)
}

// startTree spawns either our child (which spawns a grandchild) or claude (which
// runs a long shell command) in a job, and waits until the whole tree exists.
func startTree(dir string, claude bool) (*jobProc, []uint32) {
	if !claude {
		jp, err := spawnInJob(dir, []string{self, "child", dir}, "")
		must(err)
		if _, ok := waitPIDFile(filepath.Join(dir, "grandchild.pid"), 20*time.Second); !ok {
			fmt.Println("  grandchild never started")
			return nil, nil
		}
		return jp, jobPIDs(jp.job)
	}
	jp, err := spawnInJob(dir, claudeArgv(), claudePrompt)
	must(err)
	pids, ok := waitForExe(jp.job, "ping.exe", 90*time.Second)
	if !ok {
		fmt.Println("  claude never started ping.exe; tree:", describe(pids))
		tail(filepath.Join(dir, "stdout.log"), 10)
		windows.TerminateJobObject(jp.job, 1)
		return nil, nil
	}
	return jp, pids
}

const claudePrompt = "Run exactly this shell command and wait for it to finish: ping -n 120 127.0.0.1 . Then reply DONE."

func claudeArgv() []string {
	return []string{"claude", "-p", "--model", "claude-haiku-4-5-20251001",
		"--output-format", "stream-json", "--verbose",
		"--restricted", "--strict-mcp-config", "--disable-slash-commands", "--permission-prompts", "none",
		"--tools", "Bash,PowerShell", "--allowedTools", "Bash(ping *),PowerShell(ping *)"}
}

func waitForExe(job windows.Handle, exe string, d time.Duration) ([]uint32, bool) {
	deadline := time.Now().Add(d)
	var pids []uint32
	for time.Now().Before(deadline) {
		pids = jobPIDs(job)
		names := procNames()
		for _, p := range pids {
			if strings.EqualFold(names[p], exe) {
				time.Sleep(500 * time.Millisecond)
				return jobPIDs(job), true
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return pids, false
}

// ---------- internal modes ----------

func childMode(dir string, opts []string) {
	writePID(dir, "child")
	os.WriteFile(filepath.Join(dir, "child.console"),
		[]byte(fmt.Sprintf("consoleWindow=%v consoleProcesses=%d\n", hasConsole(), consoleProcs())), 0o644)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	gc := exec.Command(self, "grandchild", dir, "grandchild")
	must(gc.Start())
	for _, o := range opts {
		switch o {
		case "breakaway":
			bc := exec.Command(self, "grandchild", dir, "breakaway")
			bc.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB}
			err := bc.Start()
			os.WriteFile(filepath.Join(dir, "breakaway.txt"), []byte(fmt.Sprintf("err=%v", err)), 0o644)
		case "wmi":
			cl := fmt.Sprintf(`"%s" grandchild "%s" wmi`, self, dir)
			ps := fmt.Sprintf(`Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='%s'} | Out-Null`, cl)
			out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
			if err != nil {
				os.WriteFile(filepath.Join(dir, "wmi.err"), append(out, []byte(err.Error())...), 0o644)
			}
		}
	}
	s := <-sig
	os.WriteFile(filepath.Join(dir, "child.sig"), []byte(fmt.Sprintf("child got %v at %s\n", s, time.Now().Format(time.RFC3339Nano))), 0o644)
	done := make(chan struct{})
	go func() { gc.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	os.Exit(0)
}

func grandchildMode(dir, name string) {
	writePID(dir, name)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	os.WriteFile(filepath.Join(dir, name+".sig"), []byte(fmt.Sprintf("%s got %v at %s\n", name, s, time.Now().Format(time.RFC3339Nano))), 0o644)
	os.Exit(0)
}

func supervisorMode(dir, mode string) {
	var jp *jobProc
	var pids []uint32
	if mode == "claude" {
		jp, pids = startTree(dir, true)
	} else {
		jp, pids = startTree(dir, false)
	}
	if jp == nil {
		os.Exit(1)
	}
	var s []string
	for _, p := range pids {
		s = append(s, strconv.Itoa(int(p)))
	}
	os.WriteFile(filepath.Join(dir, "job.pids.tmp"), []byte(strings.Join(s, "\n")), 0o644)
	os.Rename(filepath.Join(dir, "job.pids.tmp"), filepath.Join(dir, "job.pids"))
	time.Sleep(time.Hour) // hold the job handle until killed
}

// ---------- helpers ----------

func ctrlBreakViaAttach(pid uint32) error {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	free, attach := k32.NewProc("FreeConsole"), k32.NewProc("AttachConsole")
	free.Call()
	if r, _, err := attach.Call(uintptr(pid)); r == 0 {
		return fmt.Errorf("AttachConsole: %w", err)
	}
	// Our own handler must ignore the event we're about to broadcast to the console.
	signal.Ignore(os.Interrupt)
	err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid)
	free.Call()
	return err
}

func hasConsole() bool {
	r, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	return r != 0
}

// consoleProcs is the number of processes attached to our console (0 = no console).
func consoleProcs() uint32 {
	var ids [64]uint32
	r, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList").
		Call(uintptr(unsafe.Pointer(&ids[0])), 64)
	return uint32(r)
}

func alive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if windows.GetExitCodeProcess(h, &code) != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func noneAlive(pids []uint32) bool {
	for _, p := range pids {
		if alive(p) {
			return false
		}
	}
	return true
}

func killAll(pids []uint32) {
	for _, p := range pids {
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, p); err == nil {
			windows.TerminateProcess(h, 1)
			windows.CloseHandle(h)
		}
	}
}

func procNames() map[uint32]string {
	m := map[uint32]string{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return m
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		m[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])
	}
	return m
}

func describe(pids []uint32) string {
	names := procNames()
	var parts []string
	for _, p := range pids {
		n := names[p]
		if n == "" {
			n = "?"
		}
		st := "dead"
		if alive(p) {
			st = "ALIVE"
		}
		parts = append(parts, fmt.Sprintf("%s(%d)=%s", n, p, st))
	}
	return strings.Join(parts, " ")
}

func writePID(dir, name string) {
	p := filepath.Join(dir, name+".pid")
	os.WriteFile(p+".tmp", []byte(strconv.Itoa(os.Getpid())), 0o644)
	os.Rename(p+".tmp", p)
}

func waitPIDFile(path string, d time.Duration) ([]uint32, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			var pids []uint32
			for _, f := range strings.Fields(string(b)) {
				n, _ := strconv.Atoi(f)
				pids = append(pids, uint32(n))
			}
			return pids, true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, false
}

func tail(path string, n int) {
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		if len(l) > 220 {
			l = l[:220] + "…"
		}
		fmt.Println("  | " + l)
	}
}

func tmp(name string) string {
	d, err := os.MkdirTemp("", "arbiter-job-"+name+"-")
	must(err)
	return d
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
