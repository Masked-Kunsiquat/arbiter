// Package schema decodes and validates the one JSON object each agent
// invocation must return, per its purpose (spec §9.A "Output schemas").
//
// Validation is strict: unknown fields, a missing required field, a value
// outside its enum, or a field that doesn't match status are all problems,
// and nothing is silently repaired. A *ValidationError lists every problem
// so the one resume (§9.A) can show the model all of them at once. Checks
// that need outside data (plan cycles against the PRD's boundaries, which
// tests a claim check was asked about) belong to the caller.
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

// MaxSummaryChars caps autopsy_summary's root_cause_summary (§9.A).
const MaxSummaryChars = 200

// taskIDPattern keeps task ids safe in git refs (checkpoint/<task>/attempt-N)
// and seat ids: letters, digits, '-' and '_', no dots.
var taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// Output is one purpose's decoded result.
type Output interface {
	// Validate returns every problem with the decoded value; none means valid.
	Validate() []string
}

// ValidationError is model output that doesn't satisfy its purpose's schema.
// Its message is what the resume prompt shows the model.
type ValidationError struct {
	Purpose  seat.Purpose
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s output: %s", e.Purpose, strings.Join(e.Problems, "; "))
}

// New returns an empty Output for purpose.
func New(purpose seat.Purpose) (Output, error) {
	switch purpose {
	case seat.PurposePlan:
		return &Plan{}, nil
	case seat.PurposeSpec:
		return &Spec{}, nil
	case seat.PurposeImplement, seat.PurposeFix:
		return &Work{}, nil
	case seat.PurposeAttack, seat.PurposeAttackMaint:
		return &Attack{}, nil
	case seat.PurposeClaimCheck:
		return &ClaimCheck{}, nil
	case seat.PurposeDisputeRuling:
		return &DisputeRuling{}, nil
	case seat.PurposeVerdict:
		return &Verdict{}, nil
	case seat.PurposeAutopsySummary:
		return &AutopsySummary{}, nil
	}
	return nil, fmt.Errorf("schema: no output schema for purpose %q", purpose)
}

// Decode parses the model's final message for purpose: one JSON object,
// optionally inside a single code fence. A *ValidationError means the model
// got it wrong; any other error means purpose is unknown (a caller bug).
func Decode(purpose seat.Purpose, text string) (Output, error) {
	out, err := New(purpose)
	if err != nil {
		return nil, err
	}
	invalid := func(problems ...string) (Output, error) {
		return nil, &ValidationError{Purpose: purpose, Problems: problems}
	}

	body := StripFence(text)
	if !strings.HasPrefix(body, "{") {
		return invalid("reply is not a JSON object: send exactly one JSON object and nothing else")
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return invalid(decodeProblem(err))
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		return invalid("reply must be exactly one JSON object, with nothing after it")
	}
	if problems := out.Validate(); len(problems) > 0 {
		return invalid(problems...)
	}
	return out, nil
}

// decodeProblem words a json decoding error for the model.
func decodeProblem(err error) string {
	if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return fmt.Sprintf("%s: wrong type (got a JSON %s)", typeErr.Field, typeErr.Value)
	}
	if syntaxErr, ok := errors.AsType[*json.SyntaxError](err); ok {
		return "reply is not valid JSON: " + syntaxErr.Error()
	}
	return strings.TrimPrefix(err.Error(), "json: ")
}

// StripFence removes one surrounding Markdown code fence (```, optionally
// with a language tag) and surrounding whitespace. Anything else, including
// an unclosed fence, comes back trimmed but otherwise unchanged.
func StripFence(text string) string {
	s := strings.TrimSpace(text)
	if !strings.HasPrefix(s, "```") || !strings.HasSuffix(s, "```") {
		return s
	}
	first, rest, ok := strings.Cut(s, "\n")
	if !ok {
		return s
	}
	lang := strings.TrimSpace(strings.TrimPrefix(first, "```"))
	for _, r := range lang {
		if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z') {
			return s
		}
	}
	inner, ok := strings.CutSuffix(rest, "```")
	if !ok || (inner != "" && !strings.HasSuffix(inner, "\n")) {
		return s
	}
	return strings.TrimSpace(inner)
}

// problems collects validation problems.
type problems []string

func (p *problems) addf(format string, args ...any) { *p = append(*p, fmt.Sprintf(format, args...)) }

func (p *problems) required(field, value string) {
	if strings.TrimSpace(value) == "" {
		p.addf("%s: required", field)
	}
}

func (p *problems) oneOf(field, value string, allowed ...string) {
	if slices.Contains(allowed, value) {
		return
	}
	p.addf("%s: must be one of %s (got %q)", field, strings.Join(allowed, ", "), value)
}

func (p *problems) taskID(field, id string) {
	if !taskIDPattern.MatchString(id) {
		p.addf("%s: must be letters, digits, '-' or '_' (got %q)", field, id)
	}
}

func (p *problems) paths(field string, paths []string) {
	for i, path := range paths {
		if strings.TrimSpace(path) == "" {
			p.addf("%s[%d]: empty path", field, i)
		}
	}
}

// Plan is the Ringleader's plan output.
type Plan struct {
	Tasks []PlanTask `json:"tasks"`
}

// PlanTask is one planned task.
type PlanTask struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Intent       string   `json:"intent"`
	Reservations []string `json:"reservations"`
	DependsOn    []string `json:"depends_on"`
	EstMinutes   int      `json:"est_minutes"`
}

// Validate checks each task and that dependencies name other tasks in the
// plan. Cycles, boundaries and the Triage Guard are the core's checks.
func (pl *Plan) Validate() []string {
	var p problems
	if len(pl.Tasks) == 0 {
		p.addf("tasks: at least one task required")
	}
	ids := map[string]bool{}
	for i, t := range pl.Tasks {
		f := fmt.Sprintf("tasks[%d]", i)
		p.taskID(f+".id", t.ID)
		if ids[t.ID] {
			p.addf("%s.id: duplicate id %q", f, t.ID)
		}
		ids[t.ID] = true
		p.required(f+".title", t.Title)
		p.required(f+".intent", t.Intent)
		if t.Reservations == nil {
			p.addf("%s.reservations: required (may be an empty list)", f)
		}
		p.paths(f+".reservations", t.Reservations)
		if t.DependsOn == nil {
			p.addf("%s.depends_on: required (may be an empty list)", f)
		}
		if t.EstMinutes <= 0 {
			p.addf("%s.est_minutes: must be a positive number of minutes", f)
		}
	}
	for i, t := range pl.Tasks {
		for _, dep := range t.DependsOn {
			switch {
			case dep == t.ID:
				p.addf("tasks[%d].depends_on: task %q depends on itself", i, t.ID)
			case !ids[dep]:
				p.addf("tasks[%d].depends_on: unknown task %q", i, dep)
			}
		}
	}
	return p
}

// Spec is the Ringleader's just-in-time spec for one task.
type Spec struct {
	TaskID       string   `json:"task_id"`
	SpecMarkdown string   `json:"spec_markdown"`
	Reservations []string `json:"reservations,omitempty"` // nil: unchanged; may narrow, never widen (core check)
}

func (s *Spec) Validate() []string {
	var p problems
	p.taskID("task_id", s.TaskID)
	p.required("spec_markdown", s.SpecMarkdown)
	if s.Reservations != nil && len(s.Reservations) == 0 {
		p.addf("reservations: when present, at least one path (omit it to keep the planned reservations)")
	}
	p.paths("reservations", s.Reservations)
	return p
}

// WorkStatus is how a worker's implement or fix run ended.
type WorkStatus string

const (
	WorkDone         WorkStatus = "done"
	WorkScopeRequest WorkStatus = "scope_request"
	WorkBlockedPRD   WorkStatus = "blocked_prd"
	WorkDispute      WorkStatus = "dispute"
)

// Work is the Worker's implement / fix output. The field matching Status is
// required, and the others must be absent.
type Work struct {
	Status        WorkStatus    `json:"status"`
	Summary       string        `json:"summary"`
	ScopeRequest  *ScopeRequest `json:"scope_request,omitempty"`
	BlockedReason *string       `json:"blocked_reason,omitempty"`
	Dispute       *Dispute      `json:"dispute,omitempty"`
}

// ScopeRequest asks for more paths (§5.3).
type ScopeRequest struct {
	Paths  []string `json:"paths"`
	Reason string   `json:"reason"`
}

// Dispute contests an attack test (§5.4).
type Dispute struct {
	AttackTestID string `json:"attack_test_id"`
	Argument     string `json:"argument"`
}

func (w *Work) Validate() []string {
	var p problems
	p.oneOf("status", string(w.Status), string(WorkDone), string(WorkScopeRequest), string(WorkBlockedPRD), string(WorkDispute))
	p.required("summary", w.Summary)

	conditional := func(field string, present bool, when WorkStatus) {
		switch {
		case w.Status == when && !present:
			p.addf("%s: required when status is %s", field, when)
		case w.Status != when && present:
			p.addf("%s: only allowed when status is %s", field, when)
		}
	}
	conditional("scope_request", w.ScopeRequest != nil, WorkScopeRequest)
	conditional("blocked_reason", w.BlockedReason != nil, WorkBlockedPRD)
	conditional("dispute", w.Dispute != nil, WorkDispute)

	if sr := w.ScopeRequest; sr != nil {
		if len(sr.Paths) == 0 {
			p.addf("scope_request.paths: at least one path required")
		}
		p.paths("scope_request.paths", sr.Paths)
		p.required("scope_request.reason", sr.Reason)
	}
	if w.BlockedReason != nil {
		p.required("blocked_reason", *w.BlockedReason)
	}
	if d := w.Dispute; d != nil {
		p.required("dispute.attack_test_id", d.AttackTestID)
		p.required("dispute.argument", d.Argument)
	}
	return p
}

// AttackStatus is how an Adversary run ended.
type AttackStatus string

const (
	AttackDone      AttackStatus = "done"
	AttackNoAttacks AttackStatus = "no_attacks"
)

// Attack is the Adversary's attack / attack_maintenance output. The tests
// themselves are discovered from the runner (§5.4).
type Attack struct {
	Status  AttackStatus `json:"status"`
	Summary string       `json:"summary"`
}

func (a *Attack) Validate() []string {
	var p problems
	p.oneOf("status", string(a.Status), string(AttackDone), string(AttackNoAttacks))
	p.required("summary", a.Summary)
	return p
}

// ClaimCheck is the Judge's claim_check output.
type ClaimCheck struct {
	Rulings []ClaimRuling `json:"rulings"`
}

// ClaimRuling rules on one ASSERTION_FAIL attack test.
type ClaimRuling struct {
	TestID string `json:"test_id"`
	Ruling string `json:"ruling"` // "upheld" | "rejected"
	Reason string `json:"reason"`
}

// Validate checks each ruling. Whether every asked-about test got exactly
// one ruling is the caller's check: only it knows which tests were sent.
func (c *ClaimCheck) Validate() []string {
	var p problems
	if len(c.Rulings) == 0 {
		p.addf("rulings: at least one ruling required")
	}
	seen := map[string]bool{}
	for i, r := range c.Rulings {
		f := fmt.Sprintf("rulings[%d]", i)
		p.required(f+".test_id", r.TestID)
		if seen[r.TestID] {
			p.addf("%s.test_id: duplicate test_id %q", f, r.TestID)
		}
		seen[r.TestID] = true
		p.oneOf(f+".ruling", r.Ruling, "upheld", "rejected")
		p.required(f+".reason", r.Reason)
	}
	return p
}

// DisputeRuling is a fresh Judge seat's ruling on a worker's dispute.
type DisputeRuling struct {
	Ruling string `json:"ruling"` // "upheld" | "dismissed" | "escalated"
	Reason string `json:"reason"`
}

func (d *DisputeRuling) Validate() []string {
	var p problems
	p.oneOf("ruling", d.Ruling, "upheld", "dismissed", "escalated")
	p.required("reason", d.Reason)
	return p
}

// Verdict is the Judge's verdict. There is no "reject": rejections come
// only from evidence (the Deterministic Gating axiom).
type Verdict struct {
	Verdict    string      `json:"verdict"` // "approve" | "needs_human"
	Reason     string      `json:"reason"`
	Injections []Injection `json:"injections,omitempty"`
}

// Injection resolves one injected lesson at verdict time (§6.A).
type Injection struct {
	LessonID    string `json:"lesson_id"`
	LessonTier  string `json:"lesson_tier"`       // "project" | "org"
	Relevance   string `json:"relevance"`         // "relevant" | "irrelevant"
	Outcome     string `json:"outcome,omitempty"` // "" | "catch" | "miss" | "contradiction"
	Description string `json:"description"`
}

func (v *Verdict) Validate() []string {
	var p problems
	p.oneOf("verdict", v.Verdict, "approve", "needs_human")
	p.required("reason", v.Reason)
	seen := map[[2]string]bool{}
	for i, in := range v.Injections {
		f := fmt.Sprintf("injections[%d]", i)
		p.required(f+".lesson_id", in.LessonID)
		p.oneOf(f+".lesson_tier", in.LessonTier, "project", "org")
		key := [2]string{in.LessonID, in.LessonTier}
		if seen[key] {
			p.addf("%s: duplicate lesson %s (%s)", f, in.LessonID, in.LessonTier)
		}
		seen[key] = true
		p.oneOf(f+".relevance", in.Relevance, "relevant", "irrelevant")
		if in.Outcome != "" {
			p.oneOf(f+".outcome", in.Outcome, "catch", "miss", "contradiction")
		}
		p.required(f+".description", in.Description)
	}
	return p
}

// AutopsySummary is the Judge's one-line root cause for a crash (§7).
type AutopsySummary struct {
	RootCauseSummary string `json:"root_cause_summary"`
}

func (a *AutopsySummary) Validate() []string {
	var p problems
	s := a.RootCauseSummary
	p.required("root_cause_summary", s)
	if strings.ContainsAny(s, "\r\n") {
		p.addf("root_cause_summary: must be one line")
	}
	if n := utf8.RuneCountInString(s); n > MaxSummaryChars {
		p.addf("root_cause_summary: at most %d characters (got %d)", MaxSummaryChars, n)
	}
	return p
}
