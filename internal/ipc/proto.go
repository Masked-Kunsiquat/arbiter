package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// ProtocolVersion is the wire protocol version pinned by the handshake. A
// client and core that disagree refuse to talk rather than guess.
const ProtocolVersion = 1

// HandshakeTimeout bounds how long either side waits for the other's half
// of the handshake.
const HandshakeTimeout = 5 * time.Second

// ErrHandshakeRefused is wrapped by Handshake's error when the core
// answered but refused the connection (protocol or repo mismatch). Unlike
// an I/O failure during the handshake, retrying won't help.
var ErrHandshakeRefused = errors.New("ipc: handshake refused")

// Wire messages. Each is one JSON object terminated by a newline.
type (
	hello struct {
		Protocol int    `json:"protocol"`
		RepoHash string `json:"repo_hash"`
	}
	welcome struct {
		Protocol int    `json:"protocol"`
		RepoHash string `json:"repo_hash"`
		PID      int    `json:"pid"`
		Error    string `json:"error,omitempty"`
	}
	request struct {
		ID     uint64          `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params,omitempty"`
	}
	response struct {
		ID     uint64          `json:"id"`
		Result json.RawMessage `json:"result,omitempty"`
		Error  *RemoteError    `json:"error,omitempty"`
	}
)

// Error codes carried by RemoteError.
const (
	CodeUnknownMethod = "unknown_method"
	CodeBadParams     = "bad_params"
	CodeInternal      = "internal"
)

// RemoteError is an error returned by the core for one call. The
// connection stays usable after a RemoteError.
type RemoteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("core: %s (%s)", e.Message, e.Code)
}

// Errorf builds a RemoteError for a Handler to return.
func Errorf(code, format string, args ...any) *RemoteError {
	return &RemoteError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

// Handler serves one call. Returning a *RemoteError sends that code;
// any other error is sent as CodeInternal. The result is JSON-encoded.
type Handler func(ctx context.Context, method string, params json.RawMessage) (any, error)

// Server speaks the core side of the protocol.
type Server struct {
	RepoHash string
	Handler  Handler

	wg sync.WaitGroup
}

// Serve accepts connections on ln until ctx is canceled or ln is closed,
// then closes every open connection and waits for their handlers to
// return. It returns nil on a ctx-initiated shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var err error
	for {
		var conn net.Conn
		conn, err = ln.Accept()
		if err != nil {
			break
		}
		s.wg.Go(func() { s.ServeConn(ctx, conn) })
	}
	cancel()
	s.wg.Wait()
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("ipc: accept: %w", err)
}

// ServeConn runs the protocol on one connection until the client hangs up
// or ctx is canceled. It always closes conn.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	if !s.handshake(conn, dec, enc) {
		return
	}
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			return // EOF, closed, or garbage: drop the connection
		}
		if err := enc.Encode(s.call(ctx, req)); err != nil {
			return
		}
	}
}

func (s *Server) handshake(conn net.Conn, dec *json.Decoder, enc *json.Encoder) bool {
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	var h hello
	if err := dec.Decode(&h); err != nil {
		return false
	}
	w := welcome{Protocol: ProtocolVersion, RepoHash: s.RepoHash, PID: os.Getpid()}
	switch {
	case h.Protocol != ProtocolVersion:
		w.Error = fmt.Sprintf("protocol mismatch: client speaks v%d, core speaks v%d", h.Protocol, ProtocolVersion)
	case h.RepoHash != s.RepoHash:
		w.Error = fmt.Sprintf("repo mismatch: client wants %s, this core serves %s", h.RepoHash, s.RepoHash)
	}
	if err := enc.Encode(w); err != nil {
		return false
	}
	return w.Error == ""
}

func (s *Server) call(ctx context.Context, req request) response {
	resp := response{ID: req.ID}
	result, err := s.Handler(ctx, req.Method, req.Params)
	if err != nil {
		var re *RemoteError
		if !errors.As(err, &re) {
			re = &RemoteError{Code: CodeInternal, Message: err.Error()}
		}
		resp.Error = re
		return resp
	}
	raw, err := json.Marshal(result)
	if err != nil {
		resp.Error = Errorf(CodeInternal, "encoding result: %v", err)
		return resp
	}
	resp.Result = raw
	return resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Client
// ─────────────────────────────────────────────────────────────────────────────

// Client speaks the client side of the protocol on one connection. Calls
// are serialized; it is safe for concurrent use.
type Client struct {
	conn      net.Conn
	enc       *json.Encoder
	dec       *json.Decoder
	serverPID int

	mu     sync.Mutex
	nextID uint64
	broken error // set after an I/O failure; the stream is out of sync
}

// Handshake runs the client half of the handshake on conn, asking for the
// core of repoHash. On failure it closes conn.
func Handshake(ctx context.Context, conn net.Conn, repoHash string) (*Client, error) {
	c := &Client{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn)}

	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	release := c.bindDeadline(ctx)
	defer release()

	var w welcome
	err := c.enc.Encode(hello{Protocol: ProtocolVersion, RepoHash: repoHash})
	if err == nil {
		err = c.dec.Decode(&w)
	}
	switch {
	case err != nil:
		err = fmt.Errorf("ipc: handshake: %w", contextCause(ctx, err))
	case w.Error != "":
		err = fmt.Errorf("%w: %s", ErrHandshakeRefused, w.Error)
	case w.Protocol != ProtocolVersion || w.RepoHash != repoHash:
		err = fmt.Errorf("%w: core answered for protocol v%d repo %s", ErrHandshakeRefused, w.Protocol, w.RepoHash)
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.serverPID = w.PID
	return c, nil
}

// ServerPID is the process id the core reported in the handshake.
func (c *Client) ServerPID() int { return c.serverPID }

// Call invokes method with params (JSON-encoded; nil sends none) and
// decodes the result into result (skipped if nil). A *RemoteError means the
// core rejected this call; any other error means the connection is dead.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken != nil {
		return c.broken
	}

	c.nextID++
	req := request{ID: c.nextID, Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("ipc: encoding %s params: %w", method, err)
		}
		req.Params = raw
	}

	release := c.bindDeadline(ctx)
	defer release()

	var resp response
	err := c.enc.Encode(req)
	if err == nil {
		err = c.dec.Decode(&resp)
	}
	if err == nil && resp.ID != req.ID {
		err = fmt.Errorf("response id %d for request %d", resp.ID, req.ID)
	}
	if err != nil {
		err = contextCause(ctx, err)
		c.broken = fmt.Errorf("ipc: %s: connection to core lost: %w", method, err)
		return c.broken
	}
	if resp.Error != nil {
		return resp.Error
	}
	if result != nil {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("ipc: decoding %s result: %w", method, err)
		}
	}
	return nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// contextCause reports ctx's error in place of an I/O error that ctx
// caused. The conn deadline is ctx's deadline, and the two timers race: the
// read can time out a moment before ctx.Err() turns non-nil. A timeout under
// a ctx deadline was that deadline, so wait the instant for ctx to catch up.
func contextCause(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if _, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

// bindDeadline makes blocked I/O on c.conn honor ctx: its deadline becomes
// the conn deadline, and cancellation expires the conn deadline
// immediately. The returned func undoes both.
func (c *Client) bindDeadline(ctx context.Context) (release func()) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Unix(1, 0))
		close(fired)
	})
	return func() {
		if !stop() {
			// The cancel callback already started; let it finish so it
			// can't expire the deadline after we clear it below.
			<-fired
		}
		_ = c.conn.SetDeadline(time.Time{})
	}
}
