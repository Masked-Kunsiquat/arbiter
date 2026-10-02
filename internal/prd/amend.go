package prd

import (
	"fmt"
	"strconv"
	"strings"
)

// CheckAmendment verifies next against its signed history (§2.C): IDs are
// never renumbered, and a removed ID is retired, not reused. prior holds the
// parsed versions v1..vN in order (at least one); next is the amended PRD.
// The error, if any, is a *ParseError.
func CheckAmendment(prior []*PRD, next *PRD) error {
	if len(prior) == 0 {
		return &ParseError{Errs: []LineError{{Msg: "no prior PRD versions to amend"}}}
	}
	var errs []LineError
	if next.ID != prior[0].ID {
		errs = append(errs, LineError{Msg: fmt.Sprintf("id %s does not match the original %s", next.ID, prior[0].ID)})
	}
	last := len(prior) - 1

	check := func(prefix, noun string, items func(*PRD) []Item) {
		inLast := map[string]bool{}
		ever := map[string]bool{}
		highest := 0
		for i, p := range prior {
			for _, it := range items(p) {
				if i == last {
					inLast[it.ID] = true
				}
				ever[it.ID] = true
				highest = max(highest, idNumber(it.ID))
			}
		}
		for _, it := range items(next) {
			switch {
			case inLast[it.ID]:
			case ever[it.ID]:
				errs = append(errs, LineError{it.Line, it.ID + " was retired; retired IDs are never reused"})
			case idNumber(it.ID) <= highest:
				errs = append(errs, LineError{it.Line, fmt.Sprintf("new %s must be numbered above %s-%d (IDs are never renumbered)", noun, prefix, highest)})
			}
		}
	}
	check("INVARIANT", "invariants", func(p *PRD) []Item { return p.Invariants })
	check("AC", "acceptance criteria", func(p *PRD) []Item { return p.Criteria })

	if len(errs) == 0 {
		return nil
	}
	return &ParseError{Errs: errs}
}

// idNumber returns the numeric part of an ID like "AC-12" (0 if unparsable).
func idNumber(id string) int {
	i := strings.LastIndexByte(id, '-')
	n, _ := strconv.Atoi(id[i+1:])
	return n
}
