package prd

// Status is a PRD lifecycle state (§2.A).
type Status string

// PRD lifecycle states: draft → locked → executing → completed → archived,
// with amendment_needed as a side state.
const (
	StatusDraft           Status = "draft"
	StatusLocked          Status = "locked"
	StatusExecuting       Status = "executing"
	StatusCompleted       Status = "completed"
	StatusArchived        Status = "archived"
	StatusAmendmentNeeded Status = "amendment_needed"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	switch s {
	case StatusDraft, StatusLocked, StatusExecuting, StatusCompleted, StatusArchived, StatusAmendmentNeeded:
		return true
	}
	return false
}

// transitions lists every allowed lifecycle edge (§2.A).
var transitions = map[Status][]Status{
	// The human signs the spec-lock tag.
	StatusDraft: {StatusLocked},
	StatusLocked: {
		StatusExecuting,       // first task starts
		StatusLocked,          // re-sign an amendment before execution starts
		StatusAmendmentNeeded, // human accepts a blocked_prd claim
	},
	StatusExecuting: {
		StatusCompleted,       // all acceptance criteria met and merged
		StatusAmendmentNeeded, // human accepts a blocked_prd claim mid-run
	},
	// The amended PRD is re-signed.
	StatusAmendmentNeeded: {StatusLocked},
	// Finished PRDs are retired.
	StatusCompleted: {StatusArchived},
}

// CanTransition reports whether from → to is an allowed lifecycle edge.
// Anything else, including edges from or to invalid statuses, is false.
func CanTransition(from, to Status) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}
