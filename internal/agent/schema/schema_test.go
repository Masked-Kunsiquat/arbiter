package schema

import (
	"errors"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

func TestStripFence(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":1}`:                        `{"a":1}`,
		"  {\"a\":1}\n":                  `{"a":1}`,
		"```json\n{\"a\":1}\n```":        `{"a":1}`,
		"```\n{\"a\":1}\n```\n":          `{"a":1}`,
		"```JSON\r\n{\"a\":1}\r\n```":    `{"a":1}`,
		"```json\n```json\n{}\n```\n```": "```json\n{}\n```",   // only one fence
		"```json\n{\"a\":1}":             "```json\n{\"a\":1}", // unclosed: left alone
	} {
		if got := StripFence(in); got != want {
			t.Errorf("StripFence(%q) = %q, want %q", in, got, want)
		}
	}
}

// decodeProblems decodes text for purpose and returns its problems ("" if valid).
func decodeProblems(t *testing.T, purpose seat.Purpose, text string) string {
	t.Helper()
	_, err := Decode(purpose, text)
	if err == nil {
		return ""
	}
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Decode(%s) error %v is not a *ValidationError", purpose, err)
	}
	return strings.Join(verr.Problems, "; ")
}

func TestDecodeValid(t *testing.T) {
	for _, tc := range []struct {
		purpose seat.Purpose
		text    string
	}{
		{seat.PurposePlan, `{"tasks":[
			{"id":"TASK-001","title":"Schema","intent":"Add tables","reservations":["internal/db/**"],"depends_on":[],"est_minutes":30},
			{"id":"TASK-002","title":"API","intent":"Use them","reservations":["internal/api/**"],"depends_on":["TASK-001"],"est_minutes":45}]}`},
		{seat.PurposeSpec, `{"task_id":"TASK-001","spec_markdown":"# Spec"}`},
		{seat.PurposeSpec, `{"task_id":"TASK-001","spec_markdown":"# Spec","reservations":["internal/db/schema.sql"]}`},
		{seat.PurposeImplement, `{"status":"done","summary":"Added the table"}`},
		{seat.PurposeFix, `{"status":"scope_request","summary":"Need api","scope_request":{"paths":["internal/api/x.go"],"reason":"caller"}}`},
		{seat.PurposeImplement, `{"status":"blocked_prd","summary":"Conflict","blocked_reason":"INV-2 contradicts AC-1"}`},
		{seat.PurposeFix, `{"status":"dispute","summary":"Bad test","dispute":{"attack_test_id":"TestX","argument":"asserts undocumented behaviour"}}`},
		{seat.PurposeAttack, `{"status":"done","summary":"3 attacks"}`},
		{seat.PurposeAttackMaint, `{"status":"no_attacks","summary":"nothing to attack"}`},
		{seat.PurposeClaimCheck, `{"rulings":[{"test_id":"TestA","ruling":"upheld","reason":"cites INV-1"},{"test_id":"TestB","ruling":"rejected","reason":"no such AC"}]}`},
		{seat.PurposeDisputeRuling, `{"ruling":"escalated","reason":"ambiguous AC"}`},
		{seat.PurposeVerdict, `{"verdict":"approve","reason":"evidence is clean"}`},
		{seat.PurposeVerdict, `{"verdict":"needs_human","reason":"migration","injections":[
			{"lesson_id":"LESSON-12","lesson_tier":"project","relevance":"relevant","outcome":"catch","description":"applied"},
			{"lesson_id":"ORG-4","lesson_tier":"org","relevance":"irrelevant","description":"n/a"}]}`},
		{seat.PurposeAutopsySummary, `{"root_cause_summary":"Lease expired while the test suite hung on a network call"}`},
		{seat.PurposeAutopsySummary, "```json\n{\"root_cause_summary\":\"fenced\"}\n```"},
	} {
		if p := decodeProblems(t, tc.purpose, tc.text); p != "" {
			t.Errorf("%s %s: unexpected problems: %s", tc.purpose, tc.text, p)
		}
	}
}

func TestDecodeReturnsTypedOutput(t *testing.T) {
	out, err := Decode(seat.PurposeImplement, `{"status":"done","summary":"ok"}`)
	if err != nil {
		t.Fatal(err)
	}
	w, ok := out.(*Work)
	if !ok || w.Status != WorkDone || w.Summary != "ok" {
		t.Errorf("Decode = %#v, want *Work{done, ok}", out)
	}
}

func TestDecodeInvalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		purpose seat.Purpose
		text    string
		want    string // substring of the problems
	}{
		{"not json", seat.PurposeAttack, `done`, "not a JSON object"},
		{"array", seat.PurposeAttack, `[]`, "not a JSON object"},
		{"prose around", seat.PurposeAttack, `Here you go: {"status":"done","summary":"x"}`, "not a JSON object"},
		{"two objects", seat.PurposeAttack, `{"status":"done","summary":"x"} {"status":"done","summary":"y"}`, "exactly one JSON object"},
		{"unknown field", seat.PurposeAttack, `{"status":"done","summary":"x","verdict":"approve"}`, `unknown field "verdict"`},
		{"wrong type", seat.PurposeAttack, `{"status":1,"summary":"x"}`, "status"},
		{"empty", seat.PurposeAttack, ``, "not a JSON object"},

		{"plan no tasks", seat.PurposePlan, `{"tasks":[]}`, "tasks: at least one"},
		{"plan missing tasks", seat.PurposePlan, `{}`, "tasks: at least one"},
		{"plan dup id", seat.PurposePlan, `{"tasks":[
			{"id":"TASK-1","title":"a","intent":"a","reservations":[],"depends_on":[],"est_minutes":1},
			{"id":"TASK-1","title":"b","intent":"b","reservations":[],"depends_on":[],"est_minutes":1}]}`, `duplicate id "TASK-1"`},
		{"plan bad id", seat.PurposePlan, `{"tasks":[{"id":"../x","title":"a","intent":"a","reservations":[],"depends_on":[],"est_minutes":1}]}`, "tasks[0].id"},
		{"plan unknown dep", seat.PurposePlan, `{"tasks":[{"id":"T1","title":"a","intent":"a","reservations":[],"depends_on":["T9"],"est_minutes":1}]}`, `unknown task "T9"`},
		{"plan self dep", seat.PurposePlan, `{"tasks":[{"id":"T1","title":"a","intent":"a","reservations":[],"depends_on":["T1"],"est_minutes":1}]}`, "depends on itself"},
		{"plan missing depends_on", seat.PurposePlan, `{"tasks":[{"id":"T1","title":"a","intent":"a","reservations":[],"est_minutes":1}]}`, "tasks[0].depends_on: required"},
		{"plan missing reservations", seat.PurposePlan, `{"tasks":[{"id":"T1","title":"a","intent":"a","depends_on":[],"est_minutes":1}]}`, "tasks[0].reservations: required"},
		{"plan zero minutes", seat.PurposePlan, `{"tasks":[{"id":"T1","title":"a","intent":"a","reservations":[],"depends_on":[],"est_minutes":0}]}`, "est_minutes"},
		{"plan empty title", seat.PurposePlan, `{"tasks":[{"id":"T1","title":" ","intent":"a","reservations":[],"depends_on":[],"est_minutes":1}]}`, "tasks[0].title: required"},
		{"plan empty path", seat.PurposePlan, `{"tasks":[{"id":"T1","title":"a","intent":"a","reservations":[""],"depends_on":[],"est_minutes":1}]}`, "reservations[0]"},

		{"spec no markdown", seat.PurposeSpec, `{"task_id":"T1","spec_markdown":""}`, "spec_markdown: required"},
		{"spec empty reservations", seat.PurposeSpec, `{"task_id":"T1","spec_markdown":"x","reservations":[]}`, "reservations: when present"},

		{"work bad status", seat.PurposeImplement, `{"status":"finished","summary":"x"}`, `status: must be one of`},
		{"work no summary", seat.PurposeImplement, `{"status":"done"}`, "summary: required"},
		{"work scope missing", seat.PurposeImplement, `{"status":"scope_request","summary":"x"}`, "scope_request: required when status is scope_request"},
		{"work scope no paths", seat.PurposeImplement, `{"status":"scope_request","summary":"x","scope_request":{"paths":[],"reason":"r"}}`, "scope_request.paths"},
		{"work blocked missing", seat.PurposeImplement, `{"status":"blocked_prd","summary":"x"}`, "blocked_reason: required"},
		{"work dispute missing", seat.PurposeFix, `{"status":"dispute","summary":"x"}`, "dispute: required"},
		{"work dispute no test", seat.PurposeFix, `{"status":"dispute","summary":"x","dispute":{"attack_test_id":"","argument":"a"}}`, "dispute.attack_test_id"},
		{"work stray field", seat.PurposeImplement, `{"status":"done","summary":"x","blocked_reason":"y"}`, "blocked_reason: only allowed when status is blocked_prd"},

		{"attack bad status", seat.PurposeAttack, `{"status":"blocked_prd","summary":"x"}`, "status: must be one of"},

		{"claims empty", seat.PurposeClaimCheck, `{"rulings":[]}`, "rulings: at least one"},
		{"claims bad ruling", seat.PurposeClaimCheck, `{"rulings":[{"test_id":"T","ruling":"dismissed","reason":"r"}]}`, "rulings[0].ruling"},
		{"claims dup", seat.PurposeClaimCheck, `{"rulings":[{"test_id":"T","ruling":"upheld","reason":"r"},{"test_id":"T","ruling":"rejected","reason":"r"}]}`, `duplicate test_id "T"`},

		{"dispute bad ruling", seat.PurposeDisputeRuling, `{"ruling":"rejected","reason":"r"}`, "ruling: must be one of"},

		{"verdict reject", seat.PurposeVerdict, `{"verdict":"reject","reason":"r"}`, "verdict: must be one of"},
		{"verdict bad tier", seat.PurposeVerdict, `{"verdict":"approve","reason":"r","injections":[{"lesson_id":"L","lesson_tier":"team","relevance":"relevant","description":"d"}]}`, "injections[0].lesson_tier"},
		{"verdict bad relevance", seat.PurposeVerdict, `{"verdict":"approve","reason":"r","injections":[{"lesson_id":"L","lesson_tier":"org","relevance":"maybe","description":"d"}]}`, "injections[0].relevance"},
		{"verdict bad outcome", seat.PurposeVerdict, `{"verdict":"approve","reason":"r","injections":[{"lesson_id":"L","lesson_tier":"org","relevance":"relevant","outcome":"win","description":"d"}]}`, "injections[0].outcome"},
		{"verdict dup lesson", seat.PurposeVerdict, `{"verdict":"approve","reason":"r","injections":[
			{"lesson_id":"L","lesson_tier":"org","relevance":"relevant","description":"d"},
			{"lesson_id":"L","lesson_tier":"org","relevance":"irrelevant","description":"d"}]}`, "duplicate lesson"},

		{"summary too long", seat.PurposeAutopsySummary, `{"root_cause_summary":"` + strings.Repeat("é", 201) + `"}`, "at most 200 characters"},
		{"summary two lines", seat.PurposeAutopsySummary, `{"root_cause_summary":"a\nb"}`, "one line"},
	} {
		got := decodeProblems(t, tc.purpose, tc.text)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: problems %q, want one containing %q", tc.name, got, tc.want)
		}
	}
}

func TestDecodeSummaryAtLimit(t *testing.T) {
	text := `{"root_cause_summary":"` + strings.Repeat("é", 200) + `"}`
	if p := decodeProblems(t, seat.PurposeAutopsySummary, text); p != "" {
		t.Errorf("200 characters (400 bytes) rejected: %s", p)
	}
}

func TestDecodeReportsEveryProblem(t *testing.T) {
	p := decodeProblems(t, seat.PurposeImplement, `{"status":"nope"}`)
	if !strings.Contains(p, "status") || !strings.Contains(p, "summary") {
		t.Errorf("problems %q, want both status and summary reported", p)
	}
}

func TestDecodeUnknownPurpose(t *testing.T) {
	_, err := Decode("plot", `{}`)
	var verr *ValidationError
	if err == nil || errors.As(err, &verr) {
		t.Errorf("err = %v, want a plain error (a caller bug, not model output to resume on)", err)
	}
}
