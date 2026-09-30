package core

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/corelock"
	"github.com/Masked-Kunsiquat/arbiter/internal/db"
	"github.com/Masked-Kunsiquat/arbiter/internal/ipc"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

// helperEnv makes the test binary host the core for the given .arbiter dir
// in a child process (see TestMain), so the tests can exercise a real
// second process: a long-lived host that other "commands" connect to, and
// a host that crashes.
const helperEnv = "ARBITER_CORE_HELPER_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(helperEnv); dir != "" {
		os.Exit(runHelperHost(dir))
	}
	os.Exit(m.Run())
}

// runHelperHost hosts the core like `arbiter run` would, printing READY
// once it is serving, until killed or stdin closes.
func runHelperHost(dir string) int {
	h, err := Open(context.Background(), dir)
	if err != nil {
		os.Stdout.WriteString("ERR " + err.Error() + "\n")
		return 2
	}
	os.Stdout.WriteString("READY\n")
	go func() {
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		_ = h.Close()
	}()
	<-h.Done()
	_ = h.Close()
	return 0
}

type helperHost struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser // closing it asks the helper to shut down cleanly
}

// startHelperHost launches the child host and waits until it is serving.
func startHelperHost(t *testing.T, dir string) *helperHost {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "READY\n" {
		t.Fatalf("helper host did not start: %q, %v", line, err)
	}
	return &helperHost{cmd: cmd, stdin: stdin}
}

// newArbiterDir returns a fresh <tmp>/repo/.arbiter with an initialized
// state.db. It uses a short os.MkdirTemp root because t.TempDir embeds the
// test name and can overflow the ~104-byte Unix socket path limit.
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
	adb, err := db.Open(context.Background(), filepath.Join(dir, StateDBName))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	_ = adb.Close()
	return dir
}

// withDB opens state.db directly. Tests use it to seed fixtures and to
// inspect results; production code never does this outside the host.
func withDB(t *testing.T, dir string, fn func(raw *sql.DB)) {
	t.Helper()
	adb, err := db.Open(context.Background(), filepath.Join(dir, StateDBName))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer adb.Close()
	fn(adb.SQLDB())
}

// seedSeats inserts PRD-001 with a ringleader and a TASK-101 worker under
// it, returning their seat ids.
func seedSeats(t *testing.T, raw *sql.DB) (rlID, workerID string) {
	t.Helper()
	ctx := context.Background()
	mustExec(t, raw, `INSERT INTO prds (id, title, file_path, spec_hash, status, target_branch)
		VALUES ('PRD-001', 'T', 'p.md', 'h', 'locked', 'main')`)
	mustExec(t, raw, `INSERT INTO tasks (id, prd_id, title, intent, status)
		VALUES ('TASK-101', 'PRD-001', 'T', 'intent', 'in_progress')`)
	for id, role := range map[string]seat.Role{"cred:rl": seat.RoleRingleader, "cred:w": seat.RoleWorker} {
		if err := seat.RegisterCredential(ctx, raw, seat.Credential{
			ID: id, Kind: seat.KindAgent, EligibleRoles: []seat.Role{role}, Harness: "claude", Model: "m",
		}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	var err error
	rlID, err = seat.MintSeat(ctx, raw, seat.Minter{IsHuman: true}, seat.MintRequest{
		Role: seat.RoleRingleader, PRDID: "PRD-001", CredentialID: "cred:rl", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint ringleader: %v", err)
	}
	workerID, err = seat.MintSeat(ctx, raw, seat.Minter{RingleaderSeatID: rlID}, seat.MintRequest{
		Role: seat.RoleWorker, PRDID: "PRD-001", TaskID: "TASK-101",
		ParentSeatID: rlID, CredentialID: "cred:w", Binding: seat.BindingProcess,
	})
	if err != nil {
		t.Fatalf("mint worker: %v", err)
	}
	return rlID, workerID
}

func startInvocation(t *testing.T, raw *sql.DB, seatID string) string {
	t.Helper()
	id, err := seat.StartInvocation(context.Background(), raw, seat.StartInvocationRequest{
		SeatID: seatID, TaskID: "TASK-101", Purpose: seat.PurposeImplement, PID: 4242,
	})
	if err != nil {
		t.Fatalf("StartInvocation: %v", err)
	}
	return id
}

func mustExec(t *testing.T, raw *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := raw.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func connect(t *testing.T, dir string) *Session {
	t.Helper()
	s, err := Connect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-host invariant
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_SecondHostRefused(t *testing.T) {
	dir := newArbiterDir(t)
	h, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()
	if _, err := Open(context.Background(), dir); !errors.Is(err, corelock.ErrLocked) {
		t.Fatalf("second Open: err = %v, want ErrLocked", err)
	}
}

func TestHost_CloseReleasesLockAndEndpoint(t *testing.T) {
	dir := newArbiterDir(t)
	h, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ep := h.Endpoint()
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := ipc.Dial(context.Background(), ep); !errors.Is(err, ipc.ErrNotListening) {
		t.Errorf("Dial after Close: err = %v, want ErrNotListening", err)
	}
	if _, err := h.Client(context.Background()); err == nil {
		t.Error("Client after Close succeeded")
	}
	h2, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("re-Open after Close: %v", err)
	}
	_ = h2.Close()
}

func TestConnect_HostsInProcessWhenNothingListening(t *testing.T) {
	dir := newArbiterDir(t)
	s := connect(t, dir)
	if !s.Hosted() {
		t.Fatal("first Connect should host the core in-process")
	}
	var st Status
	if err := s.Call(context.Background(), MethodStatus, nil, &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.PID != os.Getpid() {
		t.Errorf("status pid = %d, want %d", st.PID, os.Getpid())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Closing a hosting session releases the lock for the next command.
	l, err := corelock.Acquire(dir)
	if err != nil {
		t.Fatalf("lock still held after hosting session closed: %v", err)
	}
	_ = l.Release()
}

func TestConnect_SecondCommandIsClient(t *testing.T) {
	dir := newArbiterDir(t)
	host := connect(t, dir)
	if !host.Hosted() {
		t.Fatal("first session should host")
	}
	client := connect(t, dir)
	if client.Hosted() {
		t.Fatal("second session should be a client of the first")
	}
	if client.ServerPID() != os.Getpid() {
		t.Errorf("ServerPID = %d, want %d", client.ServerPID(), os.Getpid())
	}
	var seats []SeatInfo
	if err := client.Call(context.Background(), MethodSeatsList, ListSeatsParams{}, &seats); err != nil {
		t.Fatalf("seats.list over the endpoint: %v", err)
	}
}

// TestConnect_WaitsForHostStartingUp: while the lock is held but nothing
// listens yet, Connect keeps retrying rather than failing or hosting a
// second core, and connects once a host appears.
func TestConnect_WaitsForHostStartingUp(t *testing.T) {
	dir := newArbiterDir(t)
	l, err := corelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	hostReady := make(chan *Host, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = l.Release()
		h, err := Open(context.Background(), dir)
		if err != nil {
			t.Errorf("Open: %v", err)
		}
		hostReady <- h
	}()

	s, err := Connect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer s.Close()
	if h := <-hostReady; h != nil {
		defer h.Close()
		if s.Hosted() {
			t.Error("Connect hosted a core while another process was starting one")
		}
	}
}

func TestConnect_ContextCanceledWhileWaiting(t *testing.T) {
	dir := newArbiterDir(t)
	l, err := corelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer l.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Connect(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect: err = %v, want DeadlineExceeded", err)
	}
}

func TestHandle_UnknownMethodAndBadParams(t *testing.T) {
	s := connect(t, newArbiterDir(t))
	var re *ipc.RemoteError
	if err := s.Call(context.Background(), "nope", nil, nil); !errors.As(err, &re) || re.Code != ipc.CodeUnknownMethod {
		t.Errorf("unknown method: err = %v", err)
	}
	if err := s.Call(context.Background(), MethodSeatsList, "not-an-object", nil); !errors.As(err, &re) || re.Code != ipc.CodeBadParams {
		t.Errorf("bad params: err = %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Crash recovery
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_RecoversOpenInvocations(t *testing.T) {
	dir := newArbiterDir(t)
	var openID, doneID string
	withDB(t, dir, func(raw *sql.DB) {
		_, workerID := seedSeats(t, raw)
		openID = startInvocation(t, raw, workerID)
		doneID = startInvocation(t, raw, workerID)
		cost := 0.5
		if err := seat.EndInvocation(context.Background(), raw, seat.EndInvocationRequest{
			InvocationID: doneID, ExitReason: seat.ExitOK, CostUSD: &cost,
		}); err != nil {
			t.Fatalf("EndInvocation: %v", err)
		}
	})

	h, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := h.RecoveredInvocations(); !slices.Equal(got, []string{openID}) {
		t.Errorf("RecoveredInvocations = %v, want [%s]", got, openID)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	withDB(t, dir, func(raw *sql.DB) {
		assertInvocation(t, raw, openID, "killed", false)
		assertInvocation(t, raw, doneID, "ok", true)
	})

	// Recovery is idempotent: a clean restart finds nothing open.
	h2, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer h2.Close()
	if got := h2.RecoveredInvocations(); len(got) != 0 {
		t.Errorf("second start recovered %v, want none", got)
	}
}

func assertInvocation(t *testing.T, raw *sql.DB, id, wantExit string, wantCost bool) {
	t.Helper()
	var exit sql.NullString
	var ended sql.NullString
	var cost sql.NullFloat64
	if err := raw.QueryRowContext(context.Background(),
		`SELECT exit_reason, ended_at, cost_usd FROM invocations WHERE id = ?`, id).Scan(&exit, &ended, &cost); err != nil {
		t.Fatalf("load invocation %s: %v", id, err)
	}
	if exit.String != wantExit {
		t.Errorf("%s exit_reason = %q, want %q", id, exit.String, wantExit)
	}
	if !ended.Valid {
		t.Errorf("%s ended_at is NULL", id)
	}
	if cost.Valid != wantCost {
		t.Errorf("%s cost_usd valid = %v, want %v", id, cost.Valid, wantCost)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-process
// ─────────────────────────────────────────────────────────────────────────────

// TestCrossProcess_ClientOfLongLivedHost is the `arbiter run` + `arbiter
// tasks` shape: one process hosts the core, a command in "another terminal"
// connects to it as a client and never hosts or opens the database.
func TestCrossProcess_ClientOfLongLivedHost(t *testing.T) {
	dir := newArbiterDir(t)
	withDB(t, dir, func(raw *sql.DB) { seedSeats(t, raw) })
	helper := startHelperHost(t, dir)

	s := connect(t, dir)
	if s.Hosted() {
		t.Fatal("Connect hosted a second core while the helper hosts one")
	}
	if pid := helper.cmd.Process.Pid; s.ServerPID() != pid {
		t.Errorf("ServerPID = %d, want helper pid %d", s.ServerPID(), pid)
	}
	var seats []SeatInfo
	if err := s.Call(context.Background(), MethodSeatsList, ListSeatsParams{PRDID: "PRD-001"}, &seats); err != nil {
		t.Fatalf("seats.list: %v", err)
	}
	if len(seats) != 2 {
		t.Errorf("got %d seats, want 2", len(seats))
	}
	if _, err := Open(context.Background(), dir); !errors.Is(err, corelock.ErrLocked) {
		t.Errorf("Open while helper hosts: err = %v, want ErrLocked", err)
	}
}

// TestCrossProcess_CrashedHostIsReplacedAndRecovered: hard-kill the host
// mid-invocation; the next command must find the lock released, host the
// core itself, and mark the orphaned invocation killed (spec §10.B).
func TestCrossProcess_CrashedHostIsReplacedAndRecovered(t *testing.T) {
	dir := newArbiterDir(t)
	var workerID string
	withDB(t, dir, func(raw *sql.DB) { _, workerID = seedSeats(t, raw) })
	helper := startHelperHost(t, dir)

	// Stand-in for the host's Runner starting a harness: a real Runner
	// would write this through the host itself.
	var invID string
	withDB(t, dir, func(raw *sql.DB) { invID = startInvocation(t, raw, workerID) })

	if err := helper.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_ = helper.cmd.Wait()

	s := connect(t, dir)
	if !s.Hosted() {
		t.Fatal("Connect after host crash should host the core itself")
	}
	var st Status
	if err := s.Call(context.Background(), MethodStatus, nil, &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !slices.Equal(st.RecoveredInvocations, []string{invID}) {
		t.Errorf("recovered = %v, want [%s]", st.RecoveredInvocations, invID)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	withDB(t, dir, func(raw *sql.DB) { assertInvocation(t, raw, invID, "killed", false) })
}

// TestCrossProcess_CleanShutdown: when the long-lived host exits normally
// its connected clients are dropped, and the next command hosts the core.
func TestCrossProcess_CleanShutdown(t *testing.T) {
	dir := newArbiterDir(t)
	helper := startHelperHost(t, dir)

	s := connect(t, dir)
	if s.Hosted() {
		t.Fatal("expected a client of the helper")
	}

	_ = helper.stdin.Close()
	if err := helper.cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
	if err := s.Call(context.Background(), MethodStatus, nil, nil); err == nil {
		t.Error("Call succeeded after the host shut down")
	}

	s2 := connect(t, dir)
	if !s2.Hosted() {
		t.Fatal("after the host exited, Connect should host")
	}
}
