//go:build unix

package ipc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"runtime"
	"syscall"
)

func listen(path string) (net.Listener, error) {
	if len(path) > maxSocketPath() {
		return nil, fmt.Errorf("socket path is %d bytes, over the OS limit of %d; move the repo to a shorter path", len(path), maxSocketPath())
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, err
	}
	// Owner-only. The socket is created under the process umask first, so
	// there's a brief window before the chmod; .arbiter lives inside the
	// user's own repo, so that window is no wider than the repo's own
	// permissions.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// maxSocketPath is sizeof(sockaddr_un.sun_path) minus the NUL terminator:
// 108 on Linux, 104 on the BSDs and macOS.
func maxSocketPath() int {
	if runtime.GOOS == "linux" {
		return 107
	}
	return 103
}

func dial(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// isNotListening reports a missing socket file (no host has ever run, or
// the last one exited cleanly) or a refused connection (a stale socket
// file left behind by a crashed host).
func isNotListening(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}
