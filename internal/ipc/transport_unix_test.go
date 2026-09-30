//go:build unix

package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

// TestDial_StaleSocketIsNotListening covers a host that crashed and left
// core.sock behind: dialing it must read as "nothing listening", and the
// next Listen (under the lock) must replace it.
func TestDial_StaleSocketIsNotListening(t *testing.T) {
	ep, err := Endpoint(newArbiterDir(t))
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	ln, err := net.Listen("unix", ep)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if _, err := os.Stat(ep); err != nil {
		t.Fatalf("stale socket file should remain: %v", err)
	}

	if _, err := Dial(context.Background(), ep); !errors.Is(err, ErrNotListening) {
		t.Fatalf("Dial stale socket: err = %v, want ErrNotListening", err)
	}

	ln2, err := Listen(ep)
	if err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	defer ln2.Close()
	conn, err := Dial(context.Background(), ep)
	if err != nil {
		t.Fatalf("Dial after re-Listen: %v", err)
	}
	_ = conn.Close()
}

func TestListen_SocketIsOwnerOnly(t *testing.T) {
	ep, err := Endpoint(newArbiterDir(t))
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	ln, err := Listen(ep)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	fi, err := os.Stat(ep)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %o, want 600", perm)
	}
}

func TestListen_PathTooLong(t *testing.T) {
	long := "/tmp/" + strings.Repeat("x", 200) + "/core.sock"
	if _, err := Listen(long); err == nil || !strings.Contains(err.Error(), "OS limit") {
		t.Fatalf("Listen: err = %v, want path-length error", err)
	}
}
