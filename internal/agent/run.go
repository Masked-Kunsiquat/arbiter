package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisor"
)

// defaultGrace is how long a cancelled or violating run gets to stop on the
// graceful signal before the hard kill.
const defaultGrace = 5 * time.Second

// OutcomeKind classifies how an invocation ended (§9.A "Reading the stream").
type OutcomeKind string

const (
	// OutcomeOK: a result event with is_error false. The output still has to
	// pass its purpose's schema.
	OutcomeOK OutcomeKind = "ok"
	// OutcomeError: a result event with is_error true (API error, failed
	// resume, ...), other than a budget stop.
	OutcomeError OutcomeKind = "error"
	// OutcomeBudgetExhausted: the harness stopped at --max-budget-usd
	// (terminal_reason budget_exhausted, §5.8).
	OutcomeBudgetExhausted OutcomeKind = "budget_exhausted"
	// OutcomeCrash: no result event, or the isolation baseline didn't take
	// (Outcome.Violation says how).
	OutcomeCrash OutcomeKind = "crash"
	// OutcomeKilled: the context was cancelled before a result arrived.
	OutcomeKilled OutcomeKind = "killed"
)

// Outcome is what one invocation produced.
type Outcome struct {
	Kind      OutcomeKind
	Stream    *Stream
	Exit      error  // the harness's exit (Handle.Wait): nil or *supervisor.ExitError
	Tail      string // last 50 lines of stdout and stderr, for the autopsy (§7)
	Violation string // why the baseline check failed; "" if it passed
}

// ExitReason maps the outcome to invocations.exit_reason. A lease expiry is
// a cancellation the caller made, so the caller records lease_expired itself.
func (o *Outcome) ExitReason() seat.ExitReason {
	switch o.Kind {
	case OutcomeOK:
		return seat.ExitOK
	case OutcomeBudgetExhausted:
		return seat.ExitBudgetExhausted
	case OutcomeKilled:
		return seat.ExitKilled
	}
	return seat.ExitCrash
}

// Text is the model's final message, "" if none.
func (o *Outcome) Text() string {
	if r := o.Stream.Result; r != nil && r.Text != nil {
		return *r.Text
	}
	return ""
}

// SessionID is the harness conversation id: the result's, else init's.
func (o *Outcome) SessionID() string {
	if r := o.Stream.Result; r != nil && r.SessionID != "" {
		return r.SessionID
	}
	if o.Stream.Init != nil {
		return o.Stream.Init.SessionID
	}
	return ""
}

// CostUSD is the harness-reported cost, nil if no result arrived (§5.8).
func (o *Outcome) CostUSD() *float64 {
	if r := o.Stream.Result; r != nil {
		return r.TotalCostUSD
	}
	return nil
}

// Runner runs harness invocations under a supervisor.
type Runner struct {
	Supervisor supervisor.Supervisor
	// OnSpawn, if set, is called once the process is running (record the
	// invocation row, start the lease). An error tears the process down and
	// Run returns it.
	OnSpawn func(h supervisor.Handle) error
	// OnEvent, if set, is called for every stream event, from Run's
	// goroutine: liveness (§7) and the TUI feed. It must not block.
	OnEvent func(Event)
	// Grace before the hard kill when Run stops the process; 0 means 5s.
	Grace time.Duration
}

// Run launches l with prompt p on stdin, reads its output to EOF and
// classifies the result. Cancelling ctx stops the process (OutcomeKilled).
// The error is non-nil only when nothing was run (bad launch, spawn
// failure) or OnSpawn failed; every other ending is an Outcome.
func (r Runner) Run(ctx context.Context, l Launch, p Prompt) (*Outcome, error) {
	args, err := l.Args()
	if err != nil {
		return nil, err
	}
	profile, err := ProfileFor(l.Role, l.ShellAllow)
	if err != nil {
		return nil, err
	}
	text, err := p.Render()
	if err != nil {
		return nil, err
	}
	env := l.Env
	if env == nil {
		env = os.Environ()
	}
	grace := r.Grace
	if grace <= 0 {
		grace = defaultGrace
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	tail := supervisor.NewTailBuffer(0)
	pr, pw := io.Pipe()
	h, err := r.Supervisor.Spawn(supervisor.Cmd{
		Path:   l.Command,
		Args:   args,
		Dir:    l.Dir,
		Env:    GitEnv(env, l.SeatID, l.HooksDir),
		Stdin:  strings.NewReader(text),
		Stdout: io.MultiWriter(pw, tail.Stream()),
		Stderr: tail.Stream(),
	})
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("agent: launching %s: %w", l.Command, err)
	}

	// Reap in the background; closing pw after the process (and its stdout
	// copy) is done is what gives ReadStream its EOF.
	exited := make(chan error, 1)
	go func() {
		err := h.Wait()
		pw.Close()
		exited <- err
	}()

	var (
		stopOnce sync.Once
		stopped  = make(chan struct{})
	)
	// stop runs Terminate off the reading goroutine: reading must go on so
	// the harness never blocks writing to a full pipe.
	stop := func() {
		stopOnce.Do(func() {
			go func() { _ = r.Supervisor.Terminate(h, grace); close(stopped) }()
		})
	}

	var spawnErr error
	if r.OnSpawn != nil {
		if spawnErr = r.OnSpawn(h); spawnErr != nil {
			stop()
		}
	}

	var killed atomic.Bool
	readDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			killed.Store(true)
			stop()
		case <-readDone:
		}
	}()

	var violation string
	stream, readErr := ReadStream(pr, func(e Event) {
		if e.Type == "system" && e.Subtype == "init" && violation == "" {
			if v := checkBaseline(e.Raw, profile); v != "" {
				violation = v
				stop()
			}
		}
		if r.OnEvent != nil {
			r.OnEvent(e)
		}
	})
	if readErr != nil {
		_, _ = io.Copy(io.Discard, pr)
	}
	exitErr := <-exited
	close(readDone)
	stopOnce.Do(func() { close(stopped) }) // nothing to wait for if never stopped
	<-stopped

	if spawnErr != nil {
		return nil, spawnErr
	}
	out := &Outcome{Stream: stream, Exit: exitErr, Tail: tail.String()}
	if violation == "" {
		violation = checkResult(stream)
	}
	switch res := stream.Result; {
	case violation != "":
		out.Kind, out.Violation = OutcomeCrash, violation
	case res == nil && killed.Load():
		out.Kind = OutcomeKilled
	case res == nil:
		out.Kind = OutcomeCrash
	case res.IsError && res.TerminalReason == "budget_exhausted":
		out.Kind = OutcomeBudgetExhausted
	case res.IsError:
		out.Kind = OutcomeError
	default:
		out.Kind = OutcomeOK
	}
	return out, nil
}

// checkResult reports a result event that can't be trusted: one with no
// init before it (the baseline was never confirmed), more than one, or one
// from a different session than init's. The harness emits exactly one; the
// rest means something else wrote to its stdout. "" means it's fine.
func checkResult(s *Stream) string {
	switch {
	case s.Result == nil:
		return ""
	case s.Init == nil:
		return "no system/init event: the isolation baseline was never confirmed"
	case s.Results > 1:
		return fmt.Sprintf("%d result events: harness output was forged", s.Results)
	case s.Result.SessionID != s.Init.SessionID:
		return fmt.Sprintf("result session %q differs from init session %q: harness output was forged",
			s.Result.SessionID, s.Init.SessionID)
	}
	return ""
}

// checkBaseline reports how the system/init event in raw departs from the
// isolation baseline: a tool the role's profile doesn't list, or any MCP
// server. Tools the profile lists but the harness lacks (PowerShell on
// Linux) are fine. "" means it holds.
func checkBaseline(raw []byte, profile Profile) string {
	var init InitEvent
	if err := json.Unmarshal(raw, &init); err != nil {
		return "unreadable system/init event: " + err.Error()
	}
	var extra []string
	for _, tool := range init.Tools {
		if !slices.Contains(profile.Tools, tool) {
			extra = append(extra, tool)
		}
	}
	switch {
	case len(extra) > 0:
		return fmt.Sprintf("harness loaded tools outside the role profile: %s", strings.Join(extra, ", "))
	case len(init.MCPServers) > 0:
		return fmt.Sprintf("harness loaded %d MCP server(s)", len(init.MCPServers))
	}
	return ""
}
