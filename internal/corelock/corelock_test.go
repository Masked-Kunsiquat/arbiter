package corelock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// helperEnv makes the test binary act as a lock-holding child process (see
// TestMain), so cross-process contention and crash release can be tested
// against the real OS lock rather than two handles in one process.
const helperEnv = "ARBITER_CORELOCK_HELPER_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(helperEnv); dir != "" {
		l, err := Acquire(dir)
		if err != nil {
			os.Stdout.WriteString("ERR " + err.Error() + "\n")
			os.Exit(2)
		}
		os.Stdout.WriteString("LOCKED\n")
		// Hold the lock until killed (never released explicitly). KeepAlive
		// stops the GC finalizing the *os.File, which would close it and
		// drop the lock early.
		time.Sleep(time.Hour)
		runtime.KeepAlive(l)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestAcquire_ExclusiveWithinProcess(t *testing.T) {
	dir := t.TempDir()
	l1, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if _, err := Acquire(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Acquire: err = %v, want ErrLocked", err)
	}
	if err := l1.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	l2, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	if err := l2.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestRelease_Idempotent(t *testing.T) {
	l, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}
	var nilLock *Lock
	if err := nilLock.Release(); err != nil {
		t.Fatalf("nil Release: %v", err)
	}
}

func TestAcquire_LockFileLivesInArbiterDir(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer l.Release()
	if want := filepath.Join(dir, FileName); l.Path() != want {
		t.Errorf("Path = %q, want %q", l.Path(), want)
	}
	if _, err := os.Stat(l.Path()); err != nil {
		t.Errorf("lock file missing: %v", err)
	}
}

func TestAcquire_MissingDirIsNotErrLocked(t *testing.T) {
	_, err := Acquire(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want a non-ErrLocked open error", err)
	}
}

// TestAcquire_CrossProcessAndCrashRelease holds the lock in a child process,
// checks the parent is refused, then hard-kills the child and checks the OS
// released the lock (spec §10.B: "If the host crashes, the OS releases the
// lock").
func TestAcquire_CrossProcessAndCrashRelease(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	line := make([]byte, 64)
	n, err := out.Read(line)
	if err != nil || string(line[:n]) != "LOCKED\n" {
		t.Fatalf("helper did not report LOCKED: %q, %v", line[:n], err)
	}

	if _, err := Acquire(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("Acquire while child holds lock: err = %v, want ErrLocked", err)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_ = cmd.Wait()

	// The OS releases the lock on process exit; allow a short grace period
	// for the kernel to finish tearing the process down.
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := Acquire(dir)
		if err == nil {
			_ = l.Release()
			return
		}
		if !errors.Is(err, ErrLocked) || time.Now().After(deadline) {
			t.Fatalf("Acquire after child killed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
