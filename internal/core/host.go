// Package core hosts Arbiter's core for one repository and connects CLI
// commands to it (spec §10.A, §10.B "Local process model").
//
// Exactly one process hosts the core for a repo at a time. The host holds
// .arbiter/core.lock, is the only process that opens .arbiter/state.db,
// and serves the core API on the repo's named pipe or Unix socket. Every
// other arbiter command is a client: Connect dials the endpoint first and
// hosts the core in-process only if nothing is listening. Even then the
// command talks to its in-process core through the same protocol, so no
// CLI code ever touches the database directly (§10.A: that rule is what
// makes remote deployment possible later without a rewrite).
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/Masked-Kunsiquat/arbiter/internal/corelock"
	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/ipc"
)

// StateDBName is the repository database's name inside .arbiter.
const StateDBName = "state.db"

// Host is a running core: it holds the core lock, owns state.db, and
// serves the core API on the repo's endpoint until Close.
type Host struct {
	arbiterDir string
	repoHash   string
	endpoint   string

	lock *corelock.Lock
	db   *db.DB
	srv  *ipc.Server

	recovered []string

	serveCtx  context.Context
	stopServe context.CancelFunc
	serveDone chan struct{}
	serveErr  error
	connsMu   sync.Mutex
	closing   bool           // guarded by connsMu; no new conns once set
	conns     sync.WaitGroup // in-process client connections

	closeOnce sync.Once
	closeErr  error
}

// Open starts hosting the core for the repo whose .arbiter directory is
// arbiterDir. In order, it takes the core lock, opens state.db, recovers
// from any previous host that crashed, and starts serving on the repo's
// endpoint. If another process already hosts the core, Open returns an
// error wrapping corelock.ErrLocked.
//
// The caller must Close the host. A long-lived host (arbiter run) waits on
// Done; a short-lived one closes when its command finishes.
func Open(ctx context.Context, arbiterDir string) (_ *Host, retErr error) {
	repoHash, err := ipc.RepoHash(arbiterDir)
	if err != nil {
		return nil, err
	}
	endpoint, err := ipc.Endpoint(arbiterDir)
	if err != nil {
		return nil, err
	}

	h := &Host{arbiterDir: arbiterDir, repoHash: repoHash, endpoint: endpoint}

	h.lock, err = corelock.Acquire(arbiterDir)
	if err != nil {
		return nil, fmt.Errorf("core: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = h.lock.Release()
		}
	}()

	dbPath := filepath.Join(arbiterDir, StateDBName)
	h.db, err = db.Open(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("core: opening %s: %w", dbPath, err)
	}
	defer func() {
		if retErr != nil {
			_ = h.db.Close()
		}
	}()

	h.recovered, err = recoverInvocations(ctx, h.db)
	if err != nil {
		return nil, err
	}

	ln, err := ipc.Listen(endpoint)
	if err != nil {
		return nil, fmt.Errorf("core: %w", err)
	}

	h.srv = &ipc.Server{RepoHash: repoHash, Handler: h.handle}
	h.serveCtx, h.stopServe = context.WithCancel(context.Background())
	h.serveDone = make(chan struct{})
	go func() {
		defer close(h.serveDone)
		h.serveErr = h.srv.Serve(h.serveCtx, ln)
	}()
	return h, nil
}

// Endpoint returns the pipe name or socket path the host serves on.
func (h *Host) Endpoint() string { return h.endpoint }

// RepoHash returns the repo identifier pinned by the handshake.
func (h *Host) RepoHash() string { return h.repoHash }

// RecoveredInvocations returns the ids of invocations this host found
// still open at startup (left by a host that crashed) and marked killed.
// The Runner runs their autopsies (§7).
func (h *Host) RecoveredInvocations() []string {
	return append([]string(nil), h.recovered...)
}

// Done is closed when the host stops serving (Close, or a listener
// failure).
func (h *Host) Done() <-chan struct{} { return h.serveDone }

// Client returns a client connected to this host in-process over an
// in-memory pipe. It speaks the same protocol as a remote client.
func (h *Host) Client(ctx context.Context) (*ipc.Client, error) {
	h.connsMu.Lock()
	if h.closing {
		h.connsMu.Unlock()
		return nil, errors.New("core: host is closed")
	}
	a, b := net.Pipe()
	h.conns.Go(func() { h.srv.ServeConn(h.serveCtx, a) })
	h.connsMu.Unlock()
	return ipc.Handshake(ctx, b, h.repoHash)
}

// Close stops serving (dropping every client connection), closes state.db,
// and releases the core lock, in that order: the lock is released last so
// no other process can take over while this one still has the database
// open. It is safe to call more than once.
func (h *Host) Close() error {
	h.closeOnce.Do(func() {
		h.connsMu.Lock()
		h.closing = true
		h.connsMu.Unlock()
		h.stopServe()
		<-h.serveDone
		h.conns.Wait()
		h.closeErr = errors.Join(h.serveErr, h.db.Close(), h.lock.Release())
	})
	return h.closeErr
}

// ─────────────────────────────────────────────────────────────────────────────
// API
// ─────────────────────────────────────────────────────────────────────────────

// Method names served by the core.
const (
	MethodStatus    = "core.status"
	MethodSeatsList = "seats.list"
)

// Status is the result of MethodStatus.
type Status struct {
	PID                  int      `json:"pid"`
	RepoHash             string   `json:"repo_hash"`
	Endpoint             string   `json:"endpoint"`
	RecoveredInvocations []string `json:"recovered_invocations,omitempty"`
}

// ListSeatsParams are the params of MethodSeatsList.
type ListSeatsParams struct {
	PRDID string `json:"prd_id,omitempty"` // empty: all PRDs
}

func (h *Host) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case MethodStatus:
		return Status{
			PID:                  os.Getpid(),
			RepoHash:             h.repoHash,
			Endpoint:             h.endpoint,
			RecoveredInvocations: h.recovered,
		}, nil
	case MethodSeatsList:
		var p ListSeatsParams
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		return listSeats(ctx, h.db.SQLDB(), p.PRDID)
	default:
		return nil, ipc.Errorf(ipc.CodeUnknownMethod, "unknown method %q", method)
	}
}

func decodeParams(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return ipc.Errorf(ipc.CodeBadParams, "%v", err)
	}
	return nil
}
