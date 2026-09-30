package supervisor

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Environment variables that select and configure the re-exec test harness
// below: the test binary re-execs itself (via TestMain) as a leaf, tree,
// orphaner, exit or supervisor process for the cross-process supervisor_test.go
// scenarios.
const (
	envMode     = "ARBITER_SUPTEST_MODE"
	envDir      = "ARBITER_SUPTEST_DIR"
	envName     = "ARBITER_SUPTEST_NAME"
	envStubborn = "ARBITER_SUPTEST_STUBBORN"
	envCode     = "ARBITER_SUPTEST_CODE"
)

// TestMain lets the test binary double as three things: the supervisor's
// helper (_pgshim / _ctrlbreak, re-exec'd by the package under test), the
// harness processes above (re-exec'd by supervisor_test.go), and the actual
// tests.
func TestMain(m *testing.M) {
	// The supervisor re-execs the test binary itself as _pgshim / _ctrlbreak;
	// this must run before anything else touches os.Args or flags.
	if code, ok := RunHelper(os.Args[1:]); ok {
		os.Exit(code)
	}
	if mode := os.Getenv(envMode); mode != "" {
		os.Exit(runTestMode(mode))
	}
	os.Exit(m.Run())
}

// runTestMode dispatches to the harness process named by mode. Each mode is
// re-exec'd from supervisor_test.go via childEnv.
func runTestMode(mode string) int {
	dir := os.Getenv(envDir)
	switch mode {
	case "leaf":
		return runLeaf(dir)
	case "tree":
		return runTree(dir)
	case "orphaner":
		return runOrphaner(dir)
	case "exit":
		return runExit()
	case "supervisor":
		return runSupervisorMode(dir)
	default:
		_, _ = os.Stderr.WriteString("unknown mode\n")
		return 2
	}
}

// runLeaf installs signal handling, writes its pid file, then blocks forever.
// It is the bottom of the process tree the "tree" and "orphaner" modes build.
func runLeaf(dir string) int {
	name := os.Getenv(envName)
	if name == "" {
		name = "leaf"
	}
	handleSignals(dir, name, func() { os.Exit(0) })
	writePID(dir, name)
	select {}
}

// runTree starts a grandchild leaf, reaps it in the background, and installs
// signal handling that waits (briefly) for that reap before exiting, so a
// graceful stop of "child" can be observed to also end "grandchild".
func runTree(dir string) int {
	gc := exec.Command(os.Args[0]) //nolint:gosec // re-execs this same test binary
	gc.Env = childEnv(dir, "leaf", envName+"=grandchild")
	if stubborn := os.Getenv(envStubborn); stubborn != "" {
		gc.Env = append(gc.Env, envStubborn+"="+stubborn)
	}
	if err := gc.Start(); err != nil {
		_, _ = os.Stderr.WriteString("tree: start grandchild: " + err.Error() + "\n")
		return 1
	}

	done := make(chan struct{})
	go func() {
		_ = gc.Wait()
		close(done)
	}()

	handleSignals(dir, "child", func() {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		os.Exit(0)
	})
	writePID(dir, "child")
	select {}
}

// runOrphaner starts a grandchild leaf exactly like "tree", but returns
// immediately once the grandchild has reported itself alive, without waiting
// for or killing it: the grandchild is left orphaned under the supervisor's
// container for the test to check the container still catches it.
func runOrphaner(dir string) int {
	gc := exec.Command(os.Args[0]) //nolint:gosec // re-execs this same test binary
	gc.Env = childEnv(dir, "leaf", envName+"=grandchild")
	if stubborn := os.Getenv(envStubborn); stubborn != "" {
		gc.Env = append(gc.Env, envStubborn+"="+stubborn)
	}
	if err := gc.Start(); err != nil {
		_, _ = os.Stderr.WriteString("orphaner: start grandchild: " + err.Error() + "\n")
		return 1
	}
	writePID(dir, "child")

	deadline := time.Now().Add(10 * time.Second)
	for !fileExists(filepath.Join(dir, "grandchild.pid")) {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return 0
}

// runExit reads stdin and writes known markers to stdout/stderr, then exits
// with envCode, so supervisor_test.go can check Cmd's stdio wiring and exit
// status plumbing.
func runExit() int {
	in, _ := io.ReadAll(os.Stdin)
	_, _ = os.Stdout.WriteString("out:hello\n")
	_, _ = os.Stdout.WriteString("in:" + string(in) + "\n")
	_, _ = os.Stderr.WriteString("err:oops\n")
	code, err := strconv.Atoi(os.Getenv(envCode))
	if err != nil {
		return 0
	}
	return code
}

// runSupervisorMode spawns a "tree" child through a real Supervisor and
// reports its own pid, so a test can hard-kill this process from the outside
// and check the whole tree (child, grandchild) dies with it.
func runSupervisorMode(dir string) int {
	sup, err := New(Options{})
	if err != nil {
		_, _ = os.Stderr.WriteString("supervisor: New: " + err.Error() + "\n")
		return 1
	}
	h, err := sup.Spawn(Cmd{Path: os.Args[0], Env: childEnv(dir, "tree")})
	if err != nil {
		_, _ = os.Stderr.WriteString("supervisor: Spawn: " + err.Error() + "\n")
		return 1
	}

	deadline := time.Now().Add(10 * time.Second)
	for !fileExists(filepath.Join(dir, "grandchild.pid")) {
		if time.Now().After(deadline) {
			_, _ = os.Stderr.WriteString("supervisor: grandchild.pid did not appear\n")
			return 1
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := writeFileAtomic(filepath.Join(dir, "supervisor.ready"), []byte(strconv.Itoa(h.Pid()))); err != nil {
		_, _ = os.Stderr.WriteString("supervisor: write ready file: " + err.Error() + "\n")
		return 1
	}
	select {}
}

// writePID writes <dir>/<name>.pid for the current process, atomically.
func writePID(dir, name string) {
	_ = writeFileAtomic(filepath.Join(dir, name+".pid"), []byte(strconv.Itoa(os.Getpid())))
}

// handleSignals arms SIGTERM/os.Interrupt handling for a harness process:
// each signal is recorded to <dir>/<name>.sig, then exit runs unless
// envStubborn asks to ignore the signal instead (to test a hard kill after a
// grace period). It must be called before the pid file is written, so a test
// that waits on the pid file knows the handler is already armed.
func handleSignals(dir, name string, exit func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range ch {
			_ = writeFileAtomic(filepath.Join(dir, name+".sig"), []byte(sig.String()))
			if os.Getenv(envStubborn) == "1" {
				continue
			}
			exit()
		}
	}()
}

// writeFileAtomic writes data to path via a temp file and rename, so readers
// (waitFile, readPID) never observe a partial write.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// childEnv is the environment for a harness process re-exec'd from a test or
// from another harness process: the current environment with any prior
// ARBITER_SUPTEST_* selection stripped, then mode, dir and extra applied.
func childEnv(dir, mode string, extra ...string) []string {
	env := os.Environ()
	kept := env[:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "ARBITER_SUPTEST_") {
			continue
		}
		kept = append(kept, kv)
	}
	kept = append(kept, envMode+"="+mode, envDir+"="+dir)
	kept = append(kept, extra...)
	return kept
}

// waitFile polls for path to exist and returns its contents, failing the
// test if timeout elapses first.
func waitFile(t *testing.T, path string, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			return data
		}
		if time.Now().After(deadline) {
			t.Fatalf("waitFile: %s did not appear within %v", path, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// readPID reads and parses a harness pid file written by writePID.
func readPID(t *testing.T, path string) int {
	t.Helper()
	data := waitFile(t, path, 20*time.Second)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("readPID: parse %s: %v", path, err)
	}
	return pid
}

// waitDead polls until pid is no longer alive, failing the test if timeout
// elapses first.
func waitDead(t *testing.T, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still alive after %v", pid, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// killOnCleanup hard-kills any of pids still alive when the test ends, in
// case a test failure left a harness process behind.
func killOnCleanup(t *testing.T, pids ...int) {
	t.Helper()
	t.Cleanup(func() {
		for _, pid := range pids {
			if !processAlive(pid) {
				continue
			}
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	})
}

// fileExists reports whether path names an existing file.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
