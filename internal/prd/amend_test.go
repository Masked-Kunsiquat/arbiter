package prd

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func items(prefix string, nums ...int) []Item {
	var out []Item
	for i, n := range nums {
		out = append(out, Item{ID: prefix + "-" + strconv.Itoa(n), Line: 10 + i})
	}
	return out
}

func prdWith(id string, inv, ac []int) *PRD {
	return &PRD{ID: id, Invariants: items("INVARIANT", inv...), Criteria: items("AC", ac...)}
}

func TestCheckAmendment(t *testing.T) {
	v1 := prdWith("PRD-001", []int{1, 2, 3}, []int{1, 2})
	v2 := prdWith("PRD-001", []int{1, 3, 4}, []int{1, 2, 3}) // INVARIANT-2 retired
	tests := []struct {
		name  string
		prior []*PRD
		next  *PRD
		want  []string // substrings, one per expected error; nil means success
	}{
		{"unchanged", []*PRD{v1}, prdWith("PRD-001", []int{1, 2, 3}, []int{1, 2}), nil},
		{"append new", []*PRD{v1}, prdWith("PRD-001", []int{1, 2, 3, 4}, []int{1, 2, 5}), nil},
		{"remove is fine", []*PRD{v1}, prdWith("PRD-001", []int{1}, []int{2}), nil},
		{"changed text keeps ID", []*PRD{v1}, &PRD{ID: "PRD-001", Invariants: []Item{{ID: "INVARIANT-1", Text: "new"}}, Criteria: items("AC", 1)}, nil},
		{"after retire", []*PRD{v1, v2}, prdWith("PRD-001", []int{1, 3, 4, 5}, []int{1, 2, 3, 4}), nil},
		{"id mismatch", []*PRD{v1}, prdWith("PRD-002", []int{1, 2, 3}, []int{1, 2}), []string{"does not match"}},
		{"reuse retired invariant", []*PRD{v1, v2}, prdWith("PRD-001", []int{1, 2, 3, 4}, []int{1}), []string{"INVARIANT-2 was retired; retired IDs are never reused"}},
		{"reuse retired AC", []*PRD{v1}, prdWith("PRD-001", []int{1}, []int{1}), nil},
		{"renumbered invariant", []*PRD{v1}, prdWith("PRD-001", []int{1, 2, 3}, []int{1, 2}), nil},
		{"new below max", []*PRD{v1}, prdWith("PRD-001", []int{1, 0}, []int{1}), []string{"new invariants must be numbered above INVARIANT-3 (IDs are never renumbered)"}},
		{"gap-fill AC", []*PRD{prdWith("PRD-001", []int{1}, []int{1, 3})}, prdWith("PRD-001", []int{1}, []int{1, 2, 3}), []string{"new acceptance criteria must be numbered above AC-3"}},
		{"retired AC across versions", []*PRD{prdWith("PRD-001", nil, []int{1, 2}), prdWith("PRD-001", nil, []int{1})}, prdWith("PRD-001", nil, []int{1, 2}), []string{"AC-2 was retired"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAmendment(tc.prior, tc.next)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want *ParseError", err)
			}
			if len(pe.Errs) != len(tc.want) {
				t.Fatalf("errs = %v, want %d", pe.Errs, len(tc.want))
			}
			for i, w := range tc.want {
				if !strings.Contains(pe.Errs[i].Msg, w) {
					t.Errorf("err %d = %q, want %q", i, pe.Errs[i].Msg, w)
				}
			}
		})
	}
}

func TestCheckAmendmentLinesAndEmpty(t *testing.T) {
	v1 := prdWith("PRD-001", []int{1, 2}, nil)
	next := prdWith("PRD-001", []int{1, 2, 0}, nil)
	err := CheckAmendment([]*PRD{v1}, next)
	var pe *ParseError
	if !errors.As(err, &pe) || len(pe.Errs) != 1 || pe.Errs[0].Line != 12 {
		t.Errorf("err = %v", err)
	}
	if CheckAmendment(nil, next) == nil {
		t.Error("expected error with no prior versions")
	}
	if e := (&ParseError{Errs: []LineError{{Msg: "a"}, {Line: 5, Msg: "b"}}}).Error(); e != "line 5: b\na" {
		t.Errorf("Error() = %q", e)
	}
}
