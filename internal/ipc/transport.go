package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNotListening is wrapped by Dial's error when no core is listening on
// the endpoint (no pipe, no socket file, or a stale socket file left by a
// crashed host). It is the one dial failure that means "host the core
// yourself"; every other dial error is a real failure.
var ErrNotListening = errors.New("ipc: no core is listening")

// DefaultDialTimeout bounds Dial when ctx has no earlier deadline. A named
// pipe whose every instance is busy makes the dialer retry until the
// deadline, so Dial must never run unbounded.
const DefaultDialTimeout = 2 * time.Second

// Listen creates the core's listener on endpoint (from Endpoint).
//
// The caller must hold the core lock (internal/corelock). On POSIX, Listen
// removes any socket file already at endpoint: under the lock, such a file
// can only be left over from a host that crashed.
func Listen(endpoint string) (net.Listener, error) {
	ln, err := listen(endpoint)
	if err != nil {
		return nil, fmt.Errorf("ipc: listening on %s: %w", endpoint, err)
	}
	return ln, nil
}

// Dial connects to the core listening on endpoint. When nothing is
// listening the returned error wraps ErrNotListening.
func Dial(ctx context.Context, endpoint string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultDialTimeout)
	defer cancel()
	conn, err := dial(ctx, endpoint)
	if err != nil {
		if isNotListening(err) {
			return nil, fmt.Errorf("%w on %s: %w", ErrNotListening, endpoint, err)
		}
		return nil, fmt.Errorf("ipc: dialing %s: %w", endpoint, err)
	}
	return conn, nil
}
