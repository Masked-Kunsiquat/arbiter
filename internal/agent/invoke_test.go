package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/agent/schema"
	"github.com/Masked-Kunsiquat/arbiter/internal/gittest"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisor"
)

const sess = "11111111-2222-3333-4444-555555555555"

func initLine(session string) string {
	return `{"type":"system","subtype":"init","session_id":"` + session + `","tools":["Glob","Grep","Read"],"mcp_servers":[]}`
}

// resultLine is a successful result whose final message is text.
func resultLine(session, text string, cost float64) string {
	return fmt.Sprintf(`{"type":"result","subtype":"success","is_error":false,"result":%q,"session_id":%q,"total_cost_usd":%v}`,
		text, session, cost)
}

// fakeRecorder records what Invoke asked it to record.
type fakeRecorder struct {
	starts   []string // prompt hashes
	sessions []string
	ends     []seat.ExitReason
	startErr error
}

func (f *fakeRecorder) Start(_ context.Context, _ supervisor.Handle, promptHash string) (string, error) {
	if f.startErr != nil {
		return "", f.startErr
	}
	f.starts = append(f.starts, promptHash)
	return fmt.Sprintf("inv-%d", len(f.starts)), nil
}

func (f *fakeRecorder) SetSession(_ context.Context, sessionID string) error {
	f.sessions = append(f.sessions, sessionID)
	return nil
}

func (f *fakeRecorder) End(_ context.Context, invocationID string, reason seat.ExitReason, _ *Outcome) error {
	if want := fmt.Sprintf("inv-%d", len(f.ends)+1); invocationID != want {
		return fmt.Errorf("End(%s), want %s", invocationID, want)
	}
	f.ends = append(f.ends, reason)
	return nil
}

// invokeReq builds a summary request whose first run replays first and
// whose resume (if any) replays resume.
func invokeReq(t *testing.T, first, resume []string) (Request, string) {
	t.Helper()
	l, record := fakeLaunch(t, seat.RoleJudge, writeFixture(t, first...), 0)
	if resume != nil {
		l.Env = append(l.Env, envResume+"="+writeFixture(t, resume...))
	}
	return Request{
		Purpose: seat.PurposeAutopsySummary,
		Launch:  l,
		Prompt:  Prompt{Instruction: "Summarize the crash.", Blocks: []Block{{Tag: "tail", Body: "panic"}}},
	}, record
}

func TestInvokeValidFirstTime(t *testing.T) {
	gittest.Isolate(t)
	req, record := invokeReq(t, []string{initLine(sess), resultLine(sess, `{"root_cause_summary":"nil map"}`, 0.01)}, nil)
	rec := &fakeRecorder{}

	res, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.Runs != 1 || res.ExitReason != seat.ExitOK {
		t.Fatalf("Result = %+v, want valid on run 1", res)
	}
	if s, ok := res.Output.(*schema.AutopsySummary); !ok || s.RootCauseSummary != "nil map" {
		t.Errorf("Output = %#v", res.Output)
	}
	sum := sha256.Sum256([]byte(readRecord(t, record).Stdin))
	if len(rec.starts) != 1 || rec.starts[0] != hex.EncodeToString(sum[:]) {
		t.Errorf("Start prompt hashes %q, want sha256 of the stdin actually sent", rec.starts)
	}
	if !slices.Equal(rec.sessions, []string{sess}) || !slices.Equal(rec.ends, []seat.ExitReason{seat.ExitOK}) {
		t.Errorf("sessions %q ends %q", rec.sessions, rec.ends)
	}
}

func TestInvokeResumesOnceWithProblems(t *testing.T) {
	gittest.Isolate(t)
	req, record := invokeReq(t,
		[]string{initLine(sess), resultLine(sess, "The root cause was a nil map.", 0.25)},
		[]string{initLine(sess), resultLine(sess, `{"root_cause_summary":"nil map"}`, 0.1)})
	req.Launch.BudgetUSD = 1
	rec := &fakeRecorder{}

	res, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.Runs != 2 || res.ExitReason != seat.ExitOK {
		t.Fatalf("Result = %+v, want valid on run 2", res)
	}
	if !slices.Equal(rec.ends, []seat.ExitReason{seat.ExitInvalidOutput, seat.ExitOK}) {
		t.Errorf("ends = %q, want invalid_output then ok", rec.ends)
	}
	resumed := readRecord(t, record+".resume")
	i := slices.Index(resumed.Args, "--resume")
	if i < 0 || resumed.Args[i+1] != sess {
		t.Errorf("resume argv %q, want --resume %s", resumed.Args, sess)
	}
	b := slices.Index(resumed.Args, "--max-budget-usd")
	if got := resumed.Args[b+1]; got != "0.75" {
		t.Errorf("resume budget %s, want 0.75 (1 minus the first run's 0.25)", got)
	}
	if !strings.Contains(resumed.Stdin, "not a JSON object") {
		t.Errorf("resume prompt doesn't carry the problem:\n%s", resumed.Stdin)
	}
}

func TestInvokeInvalidTwiceIsCrash(t *testing.T) {
	gittest.Isolate(t)
	bad := resultLine(sess, `{"root_cause_summary":""}`, 0.01)
	req, _ := invokeReq(t, []string{initLine(sess), bad}, []string{initLine(sess), bad})
	rec := &fakeRecorder{}

	res, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Runs != 2 || res.ExitReason != seat.ExitCrash || res.Output != nil {
		t.Fatalf("Result = %+v, want a crash after two invalid runs", res)
	}
	if len(res.Problems) == 0 || !strings.Contains(res.Problems[0], "root_cause_summary") {
		t.Errorf("Problems = %q", res.Problems)
	}
	if !slices.Equal(rec.ends, []seat.ExitReason{seat.ExitInvalidOutput, seat.ExitCrash}) {
		t.Errorf("ends = %q, want invalid_output then crash", rec.ends)
	}
}

func TestInvokeCheckSharesTheOneResume(t *testing.T) {
	gittest.Isolate(t)
	good := resultLine(sess, `{"root_cause_summary":"nil map"}`, 0.01)
	req, record := invokeReq(t, []string{initLine(sess), good}, []string{initLine(sess), good})
	calls := 0
	req.Check = func(out schema.Output) []string {
		calls++
		if calls == 1 {
			return []string{"root_cause_summary: names no file"}
		}
		return nil
	}
	res, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, &fakeRecorder{}, req)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || res.Runs != 2 || calls != 2 {
		t.Fatalf("Result = %+v, Check calls %d: want the semantic problem resumed once", res, calls)
	}
	if !strings.Contains(readRecord(t, record+".resume").Stdin, "names no file") {
		t.Error("resume prompt doesn't carry the Check problem")
	}
}

func TestInvokeCheckNotCalledOnSchemaFailure(t *testing.T) {
	gittest.Isolate(t)
	bad := resultLine(sess, `nope`, 0.01)
	req, _ := invokeReq(t, []string{initLine(sess), bad}, []string{initLine(sess), bad})
	req.Check = func(schema.Output) []string { t.Error("Check called with no valid output"); return nil }
	if _, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, &fakeRecorder{}, req); err != nil {
		t.Fatal(err)
	}
}

func TestInvokeHarnessFailureIsNotResumed(t *testing.T) {
	gittest.Isolate(t)
	l, _ := fakeLaunch(t, seat.RoleJudge, "budget.jsonl", 1)
	rec := &fakeRecorder{}
	res, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, rec, Request{
		Purpose: seat.PurposeAutopsySummary, Launch: l, Prompt: testPrompt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Runs != 1 || res.ExitReason != seat.ExitBudgetExhausted {
		t.Fatalf("Result = %+v, want budget_exhausted with no resume", res)
	}
	if !slices.Equal(rec.ends, []seat.ExitReason{seat.ExitBudgetExhausted}) || len(rec.sessions) != 0 {
		t.Errorf("ends %q sessions %q", rec.ends, rec.sessions)
	}
}

func TestInvokeNoBudgetLeftForResume(t *testing.T) {
	gittest.Isolate(t)
	req, record := invokeReq(t,
		[]string{initLine(sess), resultLine(sess, "prose", 1.5)},
		[]string{initLine(sess), resultLine(sess, `{"root_cause_summary":"x"}`, 0.1)})
	req.Launch.BudgetUSD = 1
	rec := &fakeRecorder{}
	res, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.Runs != 1 || res.ExitReason != seat.ExitBudgetExhausted {
		t.Fatalf("Result = %+v, want budget_exhausted before the resume", res)
	}
	if _, err := os.Stat(record + ".resume"); err == nil {
		t.Error("resumed with no budget left")
	}
	if !slices.Equal(rec.ends, []seat.ExitReason{seat.ExitInvalidOutput}) {
		t.Errorf("ends = %q", rec.ends)
	}
}

func TestInvokeResumeWithNewSessionIsCrash(t *testing.T) {
	gittest.Isolate(t)
	other := "99999999-2222-3333-4444-555555555555"
	req, _ := invokeReq(t,
		[]string{initLine(sess), resultLine(sess, "prose", 0.01)},
		[]string{initLine(other), resultLine(other, `{"root_cause_summary":"x"}`, 0.01)})
	rec := &fakeRecorder{}
	res, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.ExitReason != seat.ExitCrash {
		t.Fatalf("Result = %+v: a resume that forked the conversation lost the edits' context", res)
	}
	if !slices.Equal(rec.ends, []seat.ExitReason{seat.ExitInvalidOutput, seat.ExitCrash}) {
		t.Errorf("ends = %q", rec.ends)
	}
}

func TestInvokeRecorderStartError(t *testing.T) {
	gittest.Isolate(t)
	req, _ := invokeReq(t, []string{initLine(sess), resultLine(sess, `{"root_cause_summary":"x"}`, 0.01)}, nil)
	boom := errors.New("db down")
	_, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, &fakeRecorder{startErr: boom}, req)
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the recorder's error", err)
	}
}

func TestInvokeUnknownPurposeLaunchesNothing(t *testing.T) {
	req, record := invokeReq(t, []string{initLine(sess)}, nil)
	req.Purpose = "plot"
	if _, err := Invoke(context.Background(), Runner{Supervisor: newSupervisor(t)}, &fakeRecorder{}, req); err == nil {
		t.Error("Invoke accepted an unknown purpose")
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("Invoke launched the harness for an unknown purpose")
	}
}
