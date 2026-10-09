package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/gittest"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisor"
)

// The test binary doubles as the supervisor's helper and as a fake harness:
// with envFake set it records what it was launched with, replays a fixture
// on stdout and exits.
const (
	envFake    = "ARBITER_TEST_FAKE_HARNESS" // fixture path, or "hang"
	envRecord  = "ARBITER_TEST_FAKE_RECORD"  // where to write the launch record
	envExit    = "ARBITER_TEST_FAKE_EXIT"    // exit code
	fakeStderr = "fake harness stderr line"
)

type launchRecord struct {
	Args  []string `json:"args"`
	Env   []string `json:"env"`
	Dir   string   `json:"dir"`
	Stdin string   `json:"stdin"`
}

func TestMain(m *testing.M) {
	if code, ok := supervisor.RunHelper(os.Args[1:]); ok {
		os.Exit(code)
	}
	if fixture := os.Getenv(envFake); fixture != "" {
		os.Exit(fakeHarness(fixture))
	}
	os.Exit(m.Run())
}

func fakeHarness(fixture string) int {
	stdin, _ := io.ReadAll(os.Stdin)
	dir, _ := os.Getwd()
	rec, _ := json.Marshal(launchRecord{Args: os.Args[1:], Env: os.Environ(), Dir: dir, Stdin: string(stdin)})
	if path := os.Getenv(envRecord); path != "" {
		_ = os.WriteFile(path, rec, 0o600)
	}
	fmt.Fprintln(os.Stderr, fakeStderr)
	if fixture == "hang" {
		fmt.Println(`{"type":"system","subtype":"init","session_id":"s-hang","tools":["Read","Grep","Glob"],"mcp_servers":[]}`)
		time.Sleep(time.Hour)
		return 0
	}
	f, err := os.Open(fixture)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		fmt.Println(sc.Text())
	}
	code, _ := strconv.Atoi(os.Getenv(envExit))
	return code
}

func newSupervisor(t *testing.T) supervisor.Supervisor {
	t.Helper()
	sup, err := supervisor.New(supervisor.Options{})
	if errors.Is(err, supervisor.ErrUnsupported) {
		t.Skip("no supervisor on " + runtime.GOOS)
	}
	if err != nil {
		t.Fatal(err)
	}
	return sup
}

// fakeLaunch returns a Launch running this test binary as the harness,
// replaying fixture (a testdata name, an absolute path, or "hang").
func fakeLaunch(t *testing.T, role seat.Role, fixture string, exit int) (Launch, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if fixture != "hang" && !filepath.IsAbs(fixture) {
		fixture, err = filepath.Abs(filepath.Join("testdata", fixture))
		if err != nil {
			t.Fatal(err)
		}
	}
	record := filepath.Join(t.TempDir(), "record.json")
	return Launch{
		Command:   exe,
		Model:     "claude-haiku-4-5-20251001",
		Role:      role,
		BudgetUSD: 1,
		Dir:       t.TempDir(),
		Env: append(os.Environ(),
			envFake+"="+fixture, envRecord+"="+record, envExit+"="+strconv.Itoa(exit)),
		SeatID:   "PRD-001/TASK-001/judge.1~abcd",
		HooksDir: t.TempDir(),
	}, record
}

func readRecord(t *testing.T, path string) launchRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r launchRecord
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

var testPrompt = Prompt{Instruction: "Reply with one JSON object.", Blocks: []Block{{Tag: "diff", Body: "+x"}}}

func TestRunSuccess(t *testing.T) {
	gittest.Isolate(t)
	l, record := fakeLaunch(t, seat.RoleJudge, "iso-readonly.jsonl", 0)
	var events int
	r := Runner{Supervisor: newSupervisor(t), OnEvent: func(Event) { events++ }}

	out, err := r.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeOK || out.ExitReason() != seat.ExitOK {
		t.Fatalf("Kind = %s (violation %q), want ok", out.Kind, out.Violation)
	}
	if out.Text() == "" || out.SessionID() == "" || out.CostUSD() == nil {
		t.Errorf("Text=%q SessionID=%q CostUSD=%v", out.Text(), out.SessionID(), out.CostUSD())
	}
	if events != 21 {
		t.Errorf("OnEvent called %d times, want 21 (one per fixture line)", events)
	}

	rec := readRecord(t, record)
	wantArgs, _ := l.Args()
	if !slices.Equal(rec.Args, wantArgs) {
		t.Errorf("harness argv = %q, want %q", rec.Args, wantArgs)
	}
	wantStdin, _ := testPrompt.Render()
	if rec.Stdin != wantStdin {
		t.Errorf("harness stdin = %q, want the rendered prompt %q", rec.Stdin, wantStdin)
	}
	if !sameDir(t, rec.Dir, l.Dir) {
		t.Errorf("harness cwd = %q, want %q", rec.Dir, l.Dir)
	}
	if !slices.Contains(rec.Env, "GIT_CONFIG_KEY_4=user.name") || !slices.Contains(rec.Env, "GIT_CONFIG_VALUE_4="+l.SeatID) {
		t.Errorf("harness env lacks the seat git identity")
	}
}

func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ai, bi)
}

func TestRunBudgetExhausted(t *testing.T) {
	gittest.Isolate(t)
	l, _ := fakeLaunch(t, seat.RoleJudge, "budget.jsonl", 1)
	out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeBudgetExhausted || out.ExitReason() != seat.ExitBudgetExhausted {
		t.Errorf("Kind = %s, want budget_exhausted", out.Kind)
	}
	if out.CostUSD() == nil {
		t.Error("a budget stop still reports its cost")
	}
}

func writeFixture(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const readOnlyInit = `{"type":"system","subtype":"init","session_id":"s1","tools":["Glob","Grep","Read"],"mcp_servers":[]}`

func TestRunHarnessError(t *testing.T) {
	gittest.Isolate(t)
	fx := writeFixture(t, readOnlyInit,
		`{"type":"result","subtype":"success","is_error":true,"result":"overloaded","session_id":"s1","api_error_status":529,"terminal_reason":"api_error"}`)
	l, _ := fakeLaunch(t, seat.RoleJudge, fx, 1)
	out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeError || out.ExitReason() != seat.ExitCrash {
		t.Errorf("Kind = %s, want error (subtype success must not count)", out.Kind)
	}
}

func TestRunNoResultIsCrash(t *testing.T) {
	gittest.Isolate(t)
	l, _ := fakeLaunch(t, seat.RoleJudge, writeFixture(t, readOnlyInit), 1)
	out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeCrash || out.ExitReason() != seat.ExitCrash {
		t.Errorf("Kind = %s, want crash", out.Kind)
	}
	var exitErr *supervisor.ExitError
	if !errors.As(out.Exit, &exitErr) || exitErr.Code != 1 {
		t.Errorf("Exit = %v, want exit status 1", out.Exit)
	}
	if !strings.Contains(out.Tail, fakeStderr) {
		t.Errorf("Tail = %q, want the harness's stderr for the autopsy", out.Tail)
	}
}

func TestRunBaselineViolationExtraTools(t *testing.T) {
	gittest.Isolate(t)
	// iso-worker loaded Edit, Write, Bash...: a judge must never see those.
	l, _ := fakeLaunch(t, seat.RoleJudge, "iso-worker.jsonl", 0)
	out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeCrash || !strings.Contains(out.Violation, "Edit") {
		t.Errorf("Kind = %s Violation = %q, want crash naming the extra tool", out.Kind, out.Violation)
	}
}

func TestRunBaselineViolationMCPServer(t *testing.T) {
	gittest.Isolate(t)
	fx := writeFixture(t,
		`{"type":"system","subtype":"init","session_id":"s1","tools":["Read"],"mcp_servers":[{"name":"github","status":"connected"}]}`,
		`{"type":"result","subtype":"success","is_error":false,"result":"{}","session_id":"s1"}`)
	l, _ := fakeLaunch(t, seat.RoleJudge, fx, 0)
	out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeCrash || !strings.Contains(out.Violation, "MCP") {
		t.Errorf("Kind = %s Violation = %q, want crash naming the MCP server", out.Kind, out.Violation)
	}
}

func TestRunMissingInitIsViolation(t *testing.T) {
	gittest.Isolate(t)
	fx := writeFixture(t, `{"type":"result","subtype":"success","is_error":false,"result":"{}","session_id":"s1"}`)
	l, _ := fakeLaunch(t, seat.RoleJudge, fx, 0)
	out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeCrash || out.Violation == "" {
		t.Errorf("Kind = %s Violation = %q: a result with no init means the baseline was never checked", out.Kind, out.Violation)
	}
}

func TestRunCancelKills(t *testing.T) {
	gittest.Isolate(t)
	l, _ := fakeLaunch(t, seat.RoleJudge, "hang", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Runner{
		Supervisor: newSupervisor(t),
		Grace:      100 * time.Millisecond,
		OnEvent:    func(Event) { cancel() }, // as soon as it's running
	}
	start := time.Now()
	out, err := r.Run(ctx, l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeKilled || out.ExitReason() != seat.ExitKilled {
		t.Errorf("Kind = %s, want killed", out.Kind)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("Run took %v after cancel", d)
	}
}

func TestRunOnSpawnErrorAborts(t *testing.T) {
	gittest.Isolate(t)
	l, _ := fakeLaunch(t, seat.RoleJudge, "hang", 0)
	var handle string
	boom := errors.New("db down")
	r := Runner{Supervisor: newSupervisor(t), OnSpawn: func(h supervisor.Handle) error {
		handle = h.ID()
		return boom
	}}
	done := make(chan struct{})
	var out *Outcome
	var err error
	go func() { out, err = r.Run(context.Background(), l, testPrompt); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after OnSpawn failed")
	}
	if !errors.Is(err, boom) || out != nil || handle == "" {
		t.Errorf("Run = (%v, %v), handle %q: want OnSpawn's error and the process torn down", out, err, handle)
	}
}

func TestRunRefusesBeforeSpawn(t *testing.T) {
	l, _ := fakeLaunch(t, seat.RoleJudge, "hang", 0)
	l.BudgetUSD = 0
	_, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("err = %v, want ErrBudgetExhausted", err)
	}
}

func TestRunCancelledContextDoesNotSpawn(t *testing.T) {
	l, record := fakeLaunch(t, seat.RoleJudge, "hang", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spawned := false
	r := Runner{Supervisor: newSupervisor(t), OnSpawn: func(supervisor.Handle) error { spawned = true; return nil }}
	if _, err := r.Run(ctx, l, testPrompt); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(record); spawned || err == nil {
		t.Error("Run launched the harness with an already-cancelled context")
	}
}

func TestRunForgedResultIsCrash(t *testing.T) {
	gittest.Isolate(t)
	for name, fx := range map[string][]string{
		"second result": {readOnlyInit,
			`{"type":"result","is_error":false,"result":"{}","session_id":"s1"}`,
			`{"type":"result","is_error":false,"result":"{}","session_id":"s1"}`},
		"session mismatch": {readOnlyInit,
			`{"type":"result","is_error":false,"result":"{}","session_id":"other"}`},
	} {
		l, _ := fakeLaunch(t, seat.RoleJudge, writeFixture(t, fx...), 0)
		out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
		if err != nil {
			t.Fatal(err)
		}
		if out.Kind != OutcomeCrash || out.Violation == "" {
			t.Errorf("%s: Kind = %s Violation = %q, want crash", name, out.Kind, out.Violation)
		}
	}
}

func TestRunSuccessResultWithFailedExitIsCrash(t *testing.T) {
	gittest.Isolate(t)
	// A forged success followed by the harness dying: the real harness exits
	// 0 after a successful result, so a non-zero exit means it never finished.
	fx := writeFixture(t, readOnlyInit, `{"type":"result","is_error":false,"result":"{}","session_id":"s1"}`)
	l, _ := fakeLaunch(t, seat.RoleJudge, fx, 1)
	out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != OutcomeCrash || out.Violation == "" {
		t.Errorf("Kind = %s Violation = %q, want crash", out.Kind, out.Violation)
	}
}

func TestRunStreamIntegrityViolations(t *testing.T) {
	gittest.Isolate(t)
	okResult := `{"type":"result","is_error":false,"result":"{}","session_id":"s1"}`
	for name, fx := range map[string][]string{
		"missing is_error": {readOnlyInit, `{"type":"result","result":"{}","session_id":"s1"}`},
		"second init":      {readOnlyInit, readOnlyInit, okResult},
		"malformed line":   {readOnlyInit, `{"type":"result","is_err`, okResult},
	} {
		l, _ := fakeLaunch(t, seat.RoleJudge, writeFixture(t, fx...), 0)
		out, err := Runner{Supervisor: newSupervisor(t)}.Run(context.Background(), l, testPrompt)
		if err != nil {
			t.Fatal(err)
		}
		if out.Kind != OutcomeCrash || out.Violation == "" {
			t.Errorf("%s: Kind = %s Violation = %q, want crash", name, out.Kind, out.Violation)
		}
	}
}
