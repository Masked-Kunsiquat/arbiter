package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/corelock"
	"github.com/Masked-Kunsiquat/arbiter/internal/ipc"
)

// ConnectTimeout bounds how long Connect waits when the core lock is held
// but nothing answers on the endpoint yet: another command is between
// taking the lock and listening (opening state.db, running recovery), or is
// shutting down.
const ConnectTimeout = 10 * time.Second

// Session is a CLI command's connection to the core. It is either a client
// of another process's core, or the host of an in-process core that it
// shuts down on Close.
type Session struct {
	client *ipc.Client
	host   *Host // non-nil when this session hosts the core

	// arbiterDir is the client's own checkout, used to check what the
	// core asks the human to sign (§8.C).
	arbiterDir string
}

// Connect implements the client side of spec §10.B: try to connect to the
// core already serving arbiterDir's repo; only if nothing is listening,
// take the lock and host the core in-process for the life of the session.
//
// If the lock is held but nothing is listening, some other command is
// starting up or shutting down; Connect retries until it can connect to
// that host or take over from it, up to ConnectTimeout.
func Connect(ctx context.Context, arbiterDir string) (*Session, error) {
	repoHash, err := ipc.RepoHash(arbiterDir)
	if err != nil {
		return nil, err
	}
	endpoint, err := ipc.Endpoint(arbiterDir)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(ConnectTimeout)
	backoff := 10 * time.Millisecond
	for {
		s, retry, err := tryConnect(ctx, arbiterDir, endpoint, repoHash)
		if !retry {
			return s, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("core: no core answered on %s within %v, but %s is held by another process: %w",
				endpoint, ConnectTimeout, corelock.FileName, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 250*time.Millisecond)
	}
}

// tryConnect makes one attempt: dial, else host. retry reports a transient
// state (a host starting up or shutting down) worth another attempt.
func tryConnect(ctx context.Context, arbiterDir, endpoint, repoHash string) (_ *Session, retry bool, _ error) {
	conn, err := ipc.Dial(ctx, endpoint)
	if err == nil {
		c, err := ipc.Handshake(ctx, conn, repoHash)
		switch {
		case err == nil:
			return &Session{client: c, arbiterDir: arbiterDir}, false, nil
		case errors.Is(err, ipc.ErrHandshakeRefused), ctx.Err() != nil:
			return nil, false, err
		default:
			// The host dropped us mid-handshake: it is shutting down.
			return nil, true, err
		}
	}
	if !errors.Is(err, ipc.ErrNotListening) {
		return nil, false, err
	}

	h, err := Open(ctx, arbiterDir)
	if errors.Is(err, corelock.ErrLocked) {
		return nil, true, err
	}
	if err != nil {
		return nil, false, err
	}
	c, err := h.Client(ctx)
	if err != nil {
		return nil, false, errors.Join(err, h.Close())
	}
	return &Session{client: c, host: h, arbiterDir: arbiterDir}, false, nil
}

// Hosted reports whether this session hosts the core in-process.
func (s *Session) Hosted() bool { return s.host != nil }

// Host returns the in-process host, or nil if the session is a client of
// another process's core.
func (s *Session) Host() *Host { return s.host }

// ServerPID is the pid of the process hosting the core.
func (s *Session) ServerPID() int { return s.client.ServerPID() }

// Call invokes a core API method; see ipc.Client.Call.
func (s *Session) Call(ctx context.Context, method string, params, result any) error {
	return s.client.Call(ctx, method, params, result)
}

// Close disconnects, and if this session hosts the core, shuts it down and
// releases the core lock.
func (s *Session) Close() error {
	err := s.client.Close()
	if s.host != nil {
		err = errors.Join(err, s.host.Close())
	}
	return err
}
