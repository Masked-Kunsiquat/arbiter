package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Masked-Kunsiquat/arbiter/internal/agent/schema"
	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
	"github.com/Masked-Kunsiquat/arbiter/internal/supervisor"
)

// Recorder writes an invocation's bookkeeping: the invocations row and the
// ledger launch/exit entries (§4, §8.E), and the seat's harness session.
// SeatRecorder is the state.db implementation.
type Recorder interface {
	// Start records a launch once the process is running and returns the
	// invocation id. An error stops the process.
	Start(ctx context.Context, h supervisor.Handle, promptHash string) (invocationID string, err error)
	// SetSession stores the harness conversation id a successful run reported.
	SetSession(ctx context.Context, sessionID string) error
	// End records how the invocation ended.
	End(ctx context.Context, invocationID string, reason seat.ExitReason, out *Outcome) error
}

// Request is one agent invocation with a structured result.
type Request struct {
	Purpose seat.Purpose // selects the output schema
	Launch  Launch
	Prompt  Prompt
	// Check, if set, runs the core's semantic checks on schema-valid output
	// (plan cycles and boundaries, which tests a claim check covered, ...).
	// Its problems share the one resume with schema problems (§9.A).
	Check func(schema.Output) []string
}

// Result is how an Invoke ended.
type Result struct {
	Output schema.Output // the validated output; nil unless Valid
	Valid  bool
	// ExitReason is the disposition for the caller: ok when Valid; crash
	// after a second invalid output or a harness crash (autopsy);
	// budget_exhausted (awaiting_human, §5.8); killed.
	ExitReason seat.ExitReason
	Outcome    *Outcome // the last run's
	Runs       int      // 1, or 2 when the session was resumed
	Problems   []string // the last validation problems
}

// Invoke runs req and validates the model's final message against the
// purpose's schema and req.Check. Invalid output resumes the same session
// once with the problems, keeping the worker's edits; still invalid is a
// crash (§9.A). A run that fails in the harness (error, budget stop, crash,
// kill) is never resumed: its outcome is the caller's to act on.
//
// The error is non-nil only when bookkeeping failed or nothing could be
// launched; every agent-side ending is a Result.
func Invoke(ctx context.Context, r Runner, rec Recorder, req Request) (*Result, error) {
	if _, err := schema.New(req.Purpose); err != nil {
		return nil, err
	}
	res := &Result{}
	launch, prompt := req.Launch, req.Prompt
	for {
		res.Runs++
		out, invID, err := runRecorded(ctx, r, rec, launch, prompt)
		if err != nil {
			return nil, err
		}
		res.Outcome = out

		if out.Kind != OutcomeOK {
			res.ExitReason = out.ExitReason()
			return res, rec.End(ctx, invID, res.ExitReason, out)
		}
		session := out.SessionID()
		if launch.ResumeSessionID != "" && session != launch.ResumeSessionID {
			// The edits' context lives in the resumed conversation; a new one
			// means the resume didn't take.
			res.ExitReason, res.Problems = seat.ExitCrash, []string{
				fmt.Sprintf("resume of session %s reported session %s", launch.ResumeSessionID, session)}
			return res, rec.End(ctx, invID, res.ExitReason, out)
		}
		if err := rec.SetSession(ctx, session); err != nil {
			return nil, errors.Join(err, rec.End(ctx, invID, seat.ExitCrash, out))
		}

		output, problems, err := validate(req, out.Text())
		if err != nil {
			return nil, errors.Join(err, rec.End(ctx, invID, seat.ExitCrash, out))
		}
		res.Problems = problems
		if len(problems) == 0 {
			res.Output, res.Valid, res.ExitReason = output, true, seat.ExitOK
			return res, rec.End(ctx, invID, seat.ExitOK, out)
		}
		if res.Runs > 1 {
			res.ExitReason = seat.ExitCrash
			return res, rec.End(ctx, invID, seat.ExitCrash, out)
		}
		if err := rec.End(ctx, invID, seat.ExitInvalidOutput, out); err != nil {
			return nil, err
		}

		launch.ResumeSessionID = session
		if cost := out.CostUSD(); cost != nil {
			launch.BudgetUSD -= *cost
		}
		if _, err := launch.Args(); errors.Is(err, ErrBudgetExhausted) {
			res.ExitReason = seat.ExitBudgetExhausted
			return res, nil
		}
		prompt = resumePrompt(req.Purpose, problems)
	}
}

// runRecorded runs one launch with rec.Start wired into OnSpawn.
func runRecorded(ctx context.Context, r Runner, rec Recorder, l Launch, p Prompt) (*Outcome, string, error) {
	text, err := p.Render()
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256([]byte(text))
	hash := hex.EncodeToString(sum[:])

	var invID string
	onSpawn := r.OnSpawn
	r.OnSpawn = func(h supervisor.Handle) error {
		id, err := rec.Start(ctx, h, hash)
		if err != nil {
			return err
		}
		invID = id
		if onSpawn != nil {
			return onSpawn(h)
		}
		return nil
	}
	out, err := r.runText(ctx, l, text)
	if err != nil {
		if invID != "" {
			// Started, then the caller's OnSpawn failed: the row must still end.
			err = errors.Join(err, rec.End(ctx, invID, seat.ExitKilled, nil))
		}
		return nil, "", err
	}
	return out, invID, nil
}

// validate decodes text for req.Purpose and runs req.Check on a valid
// result. A non-nil error is a caller bug, not a model mistake.
func validate(req Request, text string) (schema.Output, []string, error) {
	output, err := schema.Decode(req.Purpose, text)
	if verr, ok := errors.AsType[*schema.ValidationError](err); ok {
		return nil, verr.Problems, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if req.Check != nil {
		if problems := req.Check(output); len(problems) > 0 {
			return nil, problems, nil
		}
	}
	return output, nil, nil
}

// resumePrompt asks the model to fix its reply. The problems go in a data
// block: they can quote the model's own output.
func resumePrompt(purpose seat.Purpose, problems []string) Prompt {
	return Prompt{
		Instruction: fmt.Sprintf("Your previous reply was not valid %s output. The problems are listed below. "+
			"Reply again with exactly one JSON object that fixes every one of them, and nothing else. "+
			"Your earlier work in the repository is kept; don't redo it.", purpose),
		Blocks: []Block{{Tag: "problems", Body: "- " + strings.Join(problems, "\n- ")}},
	}
}
