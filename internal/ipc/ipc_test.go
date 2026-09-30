package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// newArbiterDir returns a fresh <tmp>/repo/.arbiter. It uses a short
// os.MkdirTemp root rather than t.TempDir because t.TempDir embeds the test
// name, and a long path can overflow the ~104-byte Unix socket path limit.
func newArbiterDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "arb") //nolint:usetesting // t.TempDir embeds the test name; Unix socket paths must stay short
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	dir := filepath.Join(root, "repo", ".arbiter")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return dir
}

// echoHandler serves "echo" (returns params), "fail" (a RemoteError),
// "boom" (a plain error), and "block" (waits for ctx).
func echoHandler(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "echo":
		return params, nil
	case "fail":
		return nil, Errorf(CodeBadParams, "nope")
	case "boom":
		return nil, errors.New("kaboom")
	case "block":
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, Errorf(CodeUnknownMethod, "unknown method %q", method)
}

type harness struct {
	endpoint string
	repoHash string
	cancel   context.CancelFunc
	done     chan error
}

// startServer listens on a fresh repo's endpoint and serves echoHandler
// until the test ends.
func startServer(t *testing.T) *harness {
	t.Helper()
	dir := newArbiterDir(t)
	ep, err := Endpoint(dir)
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	hash, err := RepoHash(dir)
	if err != nil {
		t.Fatalf("RepoHash: %v", err)
	}
	ln, err := Listen(ep)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{endpoint: ep, repoHash: hash, cancel: cancel, done: make(chan error, 1)}
	srv := &Server{RepoHash: hash, Handler: echoHandler}
	go func() { h.done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-h.done
	})
	return h
}

func (h *harness) connect(t *testing.T) *Client {
	t.Helper()
	conn, err := Dial(context.Background(), h.endpoint)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	c, err := Handshake(context.Background(), conn, h.repoHash)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRepoHash_StableAndDistinct(t *testing.T) {
	a := newArbiterDir(t)
	b := newArbiterDir(t)
	ha1, err := RepoHash(a)
	if err != nil {
		t.Fatalf("RepoHash: %v", err)
	}
	ha2, _ := RepoHash(a + string(filepath.Separator) + ".")
	hb, _ := RepoHash(b)
	if ha1 != ha2 {
		t.Errorf("hash not stable across spellings: %s vs %s", ha1, ha2)
	}
	if ha1 == hb {
		t.Errorf("distinct repos share hash %s", ha1)
	}
	if len(ha1) != 16 {
		t.Errorf("hash length = %d, want 16", len(ha1))
	}
}

func TestRepoHash_CaseInsensitiveOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case folding applies only on Windows")
	}
	dir := newArbiterDir(t)
	h1, _ := RepoHash(dir)
	h2, err := RepoHash(strings.ToUpper(dir))
	if err != nil {
		t.Fatalf("RepoHash upper: %v", err)
	}
	if h1 != h2 {
		t.Errorf("case variants hash differently: %s vs %s", h1, h2)
	}
}

func TestEndpoint_Shape(t *testing.T) {
	dir := newArbiterDir(t)
	ep, err := Endpoint(dir)
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if runtime.GOOS == "windows" {
		hash, _ := RepoHash(dir)
		if want := `\\.\pipe\arbiter-` + hash; ep != want {
			t.Errorf("Endpoint = %q, want %q", ep, want)
		}
		return
	}
	abs, _ := filepath.Abs(dir)
	if want := filepath.Join(abs, "core.sock"); ep != want {
		t.Errorf("Endpoint = %q, want %q", ep, want)
	}
}

func TestDial_NotListening(t *testing.T) {
	ep, err := Endpoint(newArbiterDir(t))
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	start := time.Now()
	_, err = Dial(context.Background(), ep)
	if !errors.Is(err, ErrNotListening) {
		t.Fatalf("Dial: err = %v, want ErrNotListening", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Dial to missing endpoint took %v; should fail fast", d)
	}
}

func TestCall_RoundTrip(t *testing.T) {
	h := startServer(t)
	c := h.connect(t)
	if c.ServerPID() != os.Getpid() {
		t.Errorf("ServerPID = %d, want %d", c.ServerPID(), os.Getpid())
	}

	type msg struct {
		A string `json:"a"`
		B int    `json:"b"`
	}
	var got msg
	for i := range 3 { // several calls on one connection
		if err := c.Call(context.Background(), "echo", msg{A: "x", B: i}, &got); err != nil {
			t.Fatalf("Call %d: %v", i, err)
		}
		if got != (msg{A: "x", B: i}) {
			t.Fatalf("Call %d: got %+v", i, got)
		}
	}
}

func TestCall_RemoteErrorsKeepConnection(t *testing.T) {
	h := startServer(t)
	c := h.connect(t)

	cases := map[string]string{"fail": CodeBadParams, "boom": CodeInternal, "nope": CodeUnknownMethod}
	for method, code := range cases {
		err := c.Call(context.Background(), method, nil, nil)
		var re *RemoteError
		if !errors.As(err, &re) || re.Code != code {
			t.Errorf("%s: err = %v, want RemoteError code %s", method, err, code)
		}
	}
	if err := c.Call(context.Background(), "echo", 1, nil); err != nil {
		t.Errorf("connection unusable after remote errors: %v", err)
	}
}

func TestHandshake_RepoMismatchRefused(t *testing.T) {
	h := startServer(t)
	conn, err := Dial(context.Background(), h.endpoint)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_, err = Handshake(context.Background(), conn, "0000000000000000")
	if !errors.Is(err, ErrHandshakeRefused) || !strings.Contains(err.Error(), "repo mismatch") {
		t.Fatalf("Handshake: err = %v, want repo mismatch", err)
	}
}

func TestHandshake_ProtocolMismatchRefused(t *testing.T) {
	h := startServer(t)
	conn, err := Dial(context.Background(), h.endpoint)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = json.NewEncoder(conn).Encode(hello{Protocol: ProtocolVersion + 1, RepoHash: h.repoHash})
	var w welcome
	if err := json.NewDecoder(conn).Decode(&w); err != nil {
		t.Fatalf("reading welcome: %v", err)
	}
	if !strings.Contains(w.Error, "protocol mismatch") {
		t.Fatalf("welcome.Error = %q, want protocol mismatch", w.Error)
	}
}

func TestCall_ContextCancelUnblocks(t *testing.T) {
	h := startServer(t)
	c := h.connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.Call(ctx, "block", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call: err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Call took %v after its deadline", d)
	}
	// The stream is now out of sync, so the client must refuse further use.
	if err := c.Call(context.Background(), "echo", 1, nil); err == nil {
		t.Error("Call on broken client succeeded")
	}
}

func TestServe_ShutdownClosesClients(t *testing.T) {
	h := startServer(t)
	c := h.connect(t)

	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
		h.done <- nil // for the Cleanup receive
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	if err := c.Call(context.Background(), "echo", 1, nil); err == nil {
		t.Error("Call after server shutdown succeeded")
	}
	if _, err := Dial(context.Background(), h.endpoint); !errors.Is(err, ErrNotListening) {
		t.Errorf("Dial after shutdown: err = %v, want ErrNotListening", err)
	}
}

func TestServeConn_InMemory(t *testing.T) {
	srv := &Server{RepoHash: "abc", Handler: echoHandler}
	a, b := net.Pipe()
	go srv.ServeConn(context.Background(), a)
	c, err := Handshake(context.Background(), b, "abc")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	defer c.Close()
	var got string
	if err := c.Call(context.Background(), "echo", "hi", &got); err != nil || got != "hi" {
		t.Fatalf("Call = %q, %v", got, err)
	}
}
