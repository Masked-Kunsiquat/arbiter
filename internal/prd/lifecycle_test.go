package prd

import "testing"

func TestCanTransition(t *testing.T) {
	all := []Status{StatusDraft, StatusLocked, StatusExecuting, StatusCompleted, StatusArchived, StatusAmendmentNeeded, "", "bogus"}
	allowed := map[[2]Status]bool{
		{StatusDraft, StatusLocked}:              true,
		{StatusLocked, StatusExecuting}:          true,
		{StatusLocked, StatusLocked}:             true,
		{StatusLocked, StatusAmendmentNeeded}:    true,
		{StatusExecuting, StatusCompleted}:       true,
		{StatusExecuting, StatusAmendmentNeeded}: true,
		{StatusAmendmentNeeded, StatusLocked}:    true,
		{StatusCompleted, StatusArchived}:        true,
	}
	for _, from := range all {
		for _, to := range all {
			if got := CanTransition(from, to); got != allowed[[2]Status{from, to}] {
				t.Errorf("CanTransition(%q, %q) = %v", from, to, got)
			}
		}
	}
}

func TestStatusValid(t *testing.T) {
	for _, s := range []Status{StatusDraft, StatusLocked, StatusExecuting, StatusCompleted, StatusArchived, StatusAmendmentNeeded} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []Status{"", "Locked", "done"} {
		if s.Valid() {
			t.Errorf("%q should be invalid", s)
		}
	}
}
