//go:build linux || windows

package supervisor

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/ledger"
)

// Every test spawns real process trees: this test binary re-executed in a
// mode from helper_test.go. "tree" is a child that starts a grandchild;
// both record the signals they get as <name>.sig files in the test dir.

func newTestSupervisor(t *testing.T) Supervisor {
	t.Helper()
	sup, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	return sup
}

// spawnTree starts a child+grandchild tree and returns the handle and the
// two pids once both processes have armed their signal handlers.
func spawnTree(t *testing.T, sup Supervisor, dir string, extraEnv ...string) (Handle, int, int) {
	t.Helper()
	h, err := sup.Spawn(Cmd{Path: os.Args[0], Env: childEnv(dir, "tree", extraEnv...)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Terminate(h, 0) })
	child := readPID(t, filepath.Join(dir, "child.pid"))
	grandchild := readPID(t, filepath.Join(dir, "grandchild.pid"))
	killOnCleanup(t, child, grandchild)
	if !processAlive(child) || !processAlive(grandchild) {
		t.Fatalf("tree not running: child %d alive=%v, grandchild %d alive=%v",
			child, processAlive(child), grandchild, processAlive(grandchild))
	}
	return h, child, grandchild
}

func TestSpawnStdioAndExitStatus(t *testing.T) {
	sup := newTestSupervisor(t)
	var stdout, stderr bytes.Buffer
	h, err := sup.Spawn(Cmd{
		Path:   os.Args[0],
		Env:    childEnv(t.TempDir(), "exit", envCode+"=3"),
		Stdin:  strings.NewReader("ping"),
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.Pid() <= 0 || h.ID() == "" {
		t.Fatalf("Pid() = %d, ID() = %q", h.Pid(), h.ID())
	}
	err = h.Wait()
	var ee *ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("Wait() = %v, want exit status 3", err)
	}
	if got := stdout.String(); !strings.Contains(got, "out:hello") || !strings.Contains(got, "in:ping") {
		t.Errorf("stdout = %q", got)
	}
	if got := stderr.String(); !strings.Contains(got, "err:oops") {
		t.Errorf("stderr = %q", got)
	}
}

func TestSpawnMissingProgram(t *testing.T) {
	sup := newTestSupervisor(t)
	if _, err := sup.Spawn(Cmd{Path: "arbiter-no-such-program-xyz"}); err == nil {
		t.Fatal("Spawn of a missing program succeeded")
	}
}

// The graceful signal reaches the whole tree, and Terminate returns as soon
// as the container is empty instead of sitting out the grace period.
func TestTerminateGraceful(t *testing.T) {
	sup := newTestSupervisor(t)
	dir := t.TempDir()
	h, child, grandchild := spawnTree(t, sup, dir)

	start := time.Now()
	if err := sup.Terminate(h, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("Terminate took %v; it should end once the tree exits", d)
	}
	for _, name := range []string{"child", "grandchild"} {
		if !fileExists(filepath.Join(dir, name+".sig")) {
			t.Errorf("%s never got the graceful signal", name)
		}
	}
	assertDead(t, child, grandchild)
	select {
	case <-h.Exited():
	default:
		t.Error("Exited() not closed after Terminate")
	}
}

// A tree that ignores the graceful signal is hard-killed once grace is up.
func TestTerminateHardKillsAfterGrace(t *testing.T) {
	sup := newTestSupervisor(t)
	dir := t.TempDir()
	h, child, grandchild := spawnTree(t, sup, dir, envStubborn+"=1")

	const grace = time.Second
	start := time.Now()
	if err := sup.Terminate(h, grace); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < grace {
		t.Errorf("Terminate returned after %v, before the %v grace period", d, grace)
	}
	for _, name := range []string{"child", "grandchild"} {
		if !fileExists(filepath.Join(dir, name+".sig")) {
			t.Errorf("%s never got the graceful signal", name)
		}
	}
	assertDead(t, child, grandchild)
	var ee *ExitError
	if err := h.Wait(); !errors.As(err, &ee) {
		t.Errorf("Wait() after hard kill = %v, want *ExitError", err)
	}
}

func TestTerminateWithoutGraceSkipsSignal(t *testing.T) {
	sup := newTestSupervisor(t)
	dir := t.TempDir()
	h, child, grandchild := spawnTree(t, sup, dir)

	if err := sup.Terminate(h, 0); err != nil {
		t.Fatal(err)
	}
	assertDead(t, child, grandchild)
	for _, name := range []string{"child", "grandchild"} {
		if fileExists(filepath.Join(dir, name+".sig")) {
			t.Errorf("%s got a graceful signal with zero grace", name)
		}
	}
}

// When the program exits but leaves a grandchild running, Exited fires while
// the grandchild lives, and Wait's teardown kills it.
func TestWaitKillsLeftovers(t *testing.T) {
	sup := newTestSupervisor(t)
	dir := t.TempDir()
	h, err := sup.Spawn(Cmd{Path: os.Args[0], Env: childEnv(dir, "orphaner")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Terminate(h, 0) })
	grandchild := readPID(t, filepath.Join(dir, "grandchild.pid"))
	killOnCleanup(t, grandchild)

	select {
	case <-h.Exited():
	case <-time.After(20 * time.Second):
		t.Fatal("leader never exited")
	}
	if !processAlive(grandchild) {
		t.Fatal("grandchild died with its parent; nothing left to test")
	}
	if err := h.Wait(); err != nil {
		t.Fatalf("Wait() = %v, want clean exit", err)
	}
	assertDead(t, grandchild)
}

// After the program exits, the graceful signal still reaches what it left
// behind in the container.
func TestTerminateGracefulAfterLeaderExit(t *testing.T) {
	sup := newTestSupervisor(t)
	dir := t.TempDir()
	h, err := sup.Spawn(Cmd{Path: os.Args[0], Env: childEnv(dir, "orphaner")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Terminate(h, 0) })
	grandchild := readPID(t, filepath.Join(dir, "grandchild.pid"))
	killOnCleanup(t, grandchild)
	<-h.Exited()

	if err := sup.Terminate(h, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if !fileExists(filepath.Join(dir, "grandchild.sig")) {
		t.Error("grandchild never got the graceful signal")
	}
	assertDead(t, grandchild)
}

// The graceful signal to a leaderless container must report success: a
// failure makes Terminate skip the grace period and hard-kill at once
// (#58: on Windows the _ctrlbreak helper died of its own CTRL_BREAK).
func TestSignalAfterLeaderExit(t *testing.T) {
	sup := newTestSupervisor(t)
	dir := t.TempDir()
	h, err := sup.Spawn(Cmd{Path: os.Args[0], Env: childEnv(dir, "orphaner")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Terminate(h, 0) })
	grandchild := readPID(t, filepath.Join(dir, "grandchild.pid"))
	killOnCleanup(t, grandchild)
	<-h.Exited()

	if err := h.(*proc).c.signal(); err != nil {
		t.Fatalf("signal: %v", err)
	}
	waitFile(t, filepath.Join(dir, "grandchild.sig"), 20*time.Second)
}

// assertDead fails unless every pid is already dead: Terminate and Wait
// return only once the container is empty.
func assertDead(t *testing.T, pids ...int) {
	t.Helper()
	for _, pid := range pids {
		if processAlive(pid) {
			t.Errorf("pid %d still alive after teardown", pid)
		}
	}
}

func TestTerminateIsIdempotentAndConcurrent(t *testing.T) {
	sup := newTestSupervisor(t)
	h, child, grandchild := spawnTree(t, sup, t.TempDir())

	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		wg.Go(func() { errs[i] = sup.Terminate(h, 2*time.Second) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Terminate #%d: %v", i, err)
		}
	}
	if err := sup.Terminate(h, time.Second); err != nil {
		t.Errorf("Terminate after teardown: %v", err)
	}
	_ = h.Wait() // must not block after teardown
	waitDead(t, child, 5*time.Second)
	waitDead(t, grandchild, 5*time.Second)
}

func TestTerminateForeignHandle(t *testing.T) {
	a, b := newTestSupervisor(t), newTestSupervisor(t)
	h, _, _ := spawnTree(t, a, t.TempDir())
	if err := b.Terminate(h, 0); err == nil {
		t.Error("Terminate accepted another supervisor's handle")
	}
}

// Kill-on-supervisor-death: a separate supervisor process spawns a tree and
// is then hard-killed (no cleanup code runs). The OS must take the tree
// down: KILL_ON_JOB_CLOSE on Windows, the PDEATHSIG shim on Linux. The
// orphaner case covers a program that already exited, leaving only its
// grandchild in the container.
func TestTreeDiesWithSupervisor(t *testing.T) {
	for _, submode := range []string{"tree", "orphaner"} {
		t.Run(submode, func(t *testing.T) {
			dir := t.TempDir()
			supProc := exec.Command(os.Args[0])
			supProc.Env = childEnv(dir, "supervisor", envSubmode+"="+submode)
			var stderr bytes.Buffer
			supProc.Stderr = &stderr
			if err := supProc.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = supProc.Process.Kill(); _ = supProc.Wait() })

			leader := readPID(t, filepath.Join(dir, "supervisor.ready"))
			grandchild := readPID(t, filepath.Join(dir, "grandchild.pid"))
			pids := []int{grandchild}
			if submode == "tree" {
				// Under "orphaner" the leader has exited on Windows (it is the
				// program) but lives on Linux (it is the shim).
				pids = append(pids, leader, readPID(t, filepath.Join(dir, "child.pid")))
			}
			killOnCleanup(t, pids...)
			for _, pid := range pids {
				if !processAlive(pid) {
					t.Fatalf("pid %d not running before the supervisor died (stderr: %s)", pid, stderr.String())
				}
			}

			if err := supProc.Process.Kill(); err != nil { // SIGKILL / TerminateProcess
				t.Fatal(err)
			}
			_ = supProc.Wait()
			for _, pid := range pids {
				waitDead(t, pid, 10*time.Second)
			}
		})
	}
}

func TestScanStrays(t *testing.T) {
	slot, pids := t.TempDir(), t.TempDir()

	// Two unsupervised processes: one whose working directory is inside the
	// slot, one that only names the slot on its command line.
	inSlot := filepath.Join(slot, "sub")
	if err := os.Mkdir(inSlot, 0o755); err != nil {
		t.Fatal(err)
	}
	byCwd := startLeaf(t, pids, "bycwd", inSlot)
	byArg := startLeaf(t, pids, "byarg", "", filepath.Join(slot, "marker"))
	unrelated := startLeaf(t, pids, "unrelated", "")

	strays, err := ScanStrays(slot, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	found := map[int]Stray{}
	for _, s := range strays {
		found[s.PID] = s
	}
	for name, pid := range map[string]int{"bycwd": byCwd, "byarg": byArg} {
		s, ok := found[pid]
		if !ok {
			t.Errorf("%s (pid %d) not found; got %+v", name, pid, strays)
			continue
		}
		if s.Image == "" {
			t.Errorf("%s: empty Image", name)
		}
	}
	if _, ok := found[unrelated]; ok {
		t.Errorf("unrelated process %d reported as a stray", unrelated)
	}
	if _, ok := found[os.Getpid()]; ok {
		t.Error("ScanStrays reported the scanning process itself")
	}

	// Processes started before the invocation aren't its strays.
	later, err := ScanStrays(slot, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range later {
		if s.PID == byCwd || s.PID == byArg {
			t.Errorf("pid %d started before since but reported", s.PID)
		}
	}
}

// startLeaf starts an unsupervised leaf process with working directory cwd
// ("" = inherit) and extra argv, and returns its pid once it's running.
func startLeaf(t *testing.T, pidDir, name, cwd string, args ...string) int {
	t.Helper()
	// Absolute: a relative os.Args[0] would resolve against cwd.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = childEnv(pidDir, "leaf", envName+"="+name)
	cmd.Dir = cwd
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Runs before t.TempDir's removal (cleanups are LIFO), which on Windows
	// fails while a process still has its cwd inside it.
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return readPID(t, filepath.Join(pidDir, name+".pid"))
}

func TestStrayPayload(t *testing.T) {
	strays := []Stray{{PID: 42, Image: "evil.exe", Cmdline: "evil.exe --slot C:\\slot-0"}}
	p := StrayPayload("inv-1", strays)
	if _, err := ledger.Canonicalize(p); err != nil {
		t.Fatalf("payload doesn't canonicalize: %v", err)
	}
	procs, ok := p["processes"].([]any)
	if p["invocation_id"] != "inv-1" || !ok || len(procs) != 1 {
		t.Fatalf("payload = %#v", p)
	}
	got := procs[0].(map[string]any)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"cmdline_hash", "image", "pid"}) {
		t.Errorf("process keys = %v", keys)
	}
	if h := got["cmdline_hash"].(string); len(h) != 64 || strings.Contains(h, "slot") {
		t.Errorf("cmdline_hash = %q, want hex sha256", h)
	}
}

func TestPathMatching(t *testing.T) {
	root := filepath.Join(t.TempDir(), "slot-0")
	cases := []struct {
		dir  string
		want bool
	}{
		{root, true},
		{filepath.Join(root, "node_modules", ".bin"), true},
		{root + "-other", false},
		{filepath.Dir(root), false},
		{"", false},
	}
	for _, c := range cases {
		if got := underPath(c.dir, root); got != c.want {
			t.Errorf("underPath(%q, %q) = %v, want %v", c.dir, root, got, c.want)
		}
	}
	sep := string(filepath.Separator)
	cmdlines := []struct {
		s    string
		want bool
	}{
		{"tool --cwd " + root + " --x", true},
		{"tool --cwd=" + root, true},
		{"tool --paths=" + root + ",/other", true},
		{"tool --opt=" + root + "=val", true},
		{`tool "` + root + sep + `a b"`, true},
		{"tool " + root + sep + "node_modules", true},
		{"tool " + root + "0", false},         // slot-00, not slot-0
		{"tool " + root + "-old", false},      // a sibling
		{"tool " + sep + "mnt" + root, false}, // a longer path ending in root
		{"", false},
	}
	for _, c := range cmdlines {
		if got := containsPath(c.s, root); got != c.want {
			t.Errorf("containsPath(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}
