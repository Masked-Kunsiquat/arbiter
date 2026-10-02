package gitsign

import (
	"strings"
	"testing"
)

const pinHash = "9c1e000000000000000000000000000000000000000000000000000000000abc"

func goodTrailers() TaskTrailers {
	return TaskTrailers{
		PRDID: "PRD-004", LockVersion: 1, TaskID: "TASK-101", SpecRevision: 2,
		Worker:     "PRD-004/TASK-101/worker.2~7f3a cred:claude-code/claude-opus-5-5 (launched)",
		Adversary:  "PRD-004/TASK-101/adversary.1~b20c cred:claude-code/claude-sonnet-5 (5 attacks, 0 upheld)",
		Judge:      "PRD-004/TASK-101/judge.1~e91d cred:claude-code/claude-opus-5-5 (verdict: low-risk)",
		ApprovedBy: "human:Masked-Kunsiquat",
		Ledger:     LedgerPin{Path: ".arbiter/ledger/PRD-004.jsonl", Seq: 148, Hash: pinHash},
		CoAuthors:  []string{"Claude Opus 5.5 <noreply@anthropic.com>"},
	}
}

func TestLedgerPinRoundTrip(t *testing.T) {
	for _, p := range []LedgerPin{
		{Path: ".arbiter/ledger/PRD-004.jsonl", Seq: 148, Hash: pinHash},
		{Path: ".arbiter/ledger/global.jsonl", Seq: 1, Hash: pinHash},
		{Path: ".arbiter/ledger/PRD-12345.jsonl", Seq: 9999999999, Hash: pinHash},
	} {
		got, err := ParseLedgerPin(p.String())
		if err != nil || got != p {
			t.Errorf("round trip %v: got %v, %v", p, got, err)
		}
	}
	if c := (LedgerPin{Path: ".arbiter/ledger/PRD-004.jsonl"}).Chain(); c != "PRD-004" {
		t.Errorf("Chain = %q", c)
	}
	if c := (LedgerPin{Path: ".arbiter/ledger/global.jsonl"}).Chain(); c != "global" {
		t.Errorf("Chain = %q", c)
	}
}

func TestParseLedgerPinRejects(t *testing.T) {
	ok := ".arbiter/ledger/PRD-004.jsonl#seq=148 sha256:" + pinHash
	if _, err := ParseLedgerPin(ok); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{
		"empty":         "",
		"bad path":      "ledger/PRD-004.jsonl#seq=1 sha256:" + pinHash,
		"traversal":     ".arbiter/ledger/../x.jsonl#seq=1 sha256:" + pinHash,
		"short prd":     ".arbiter/ledger/PRD-04.jsonl#seq=1 sha256:" + pinHash,
		"leading zero":  ".arbiter/ledger/PRD-004.jsonl#seq=01 sha256:" + pinHash,
		"zero":          ".arbiter/ledger/PRD-004.jsonl#seq=0 sha256:" + pinHash,
		"sign":          ".arbiter/ledger/PRD-004.jsonl#seq=+1 sha256:" + pinHash,
		"overflow":      ".arbiter/ledger/PRD-004.jsonl#seq=99999999999999999999 sha256:" + pinHash,
		"uppercase":     ".arbiter/ledger/PRD-004.jsonl#seq=1 sha256:" + strings.ToUpper(pinHash),
		"short hash":    ".arbiter/ledger/PRD-004.jsonl#seq=1 sha256:" + pinHash[1:],
		"two spaces":    ".arbiter/ledger/PRD-004.jsonl#seq=1  sha256:" + pinHash,
		"trailing text": ok + " x",
		"trailing ws":   ok + " ",
		"no algo":       ".arbiter/ledger/PRD-004.jsonl#seq=1 " + pinHash,
	} {
		if _, err := ParseLedgerPin(v); err == nil {
			t.Errorf("%s: %q accepted", name, v)
		}
	}
}

func TestLedgerPins(t *testing.T) {
	pin := LedgerPin{Path: ".arbiter/ledger/PRD-004.jsonl", Seq: 3, Hash: pinHash}
	msg := "subject\n\nArbiter-PRD: x\nArbiter-Ledger: " + pin.String() + "\r\nArbiter-Ledger: " + pin.String() + "\n"
	pins, err := LedgerPins(msg)
	if err != nil || len(pins) != 2 || pins[0] != pin {
		t.Fatalf("pins = %v, %v", pins, err)
	}
	if pins, err := LedgerPins("just a subject\n"); err != nil || len(pins) != 0 {
		t.Fatalf("pins = %v, %v", pins, err)
	}
	if _, err := LedgerPins("s\n\nArbiter-Ledger: garbage\n"); err == nil {
		t.Fatal("malformed pin accepted")
	}
}

func TestTaskMessage(t *testing.T) {
	got, err := TaskMessage("auth: rotate refresh tokens on /auth/refresh\r\n\r\n", goodTrailers())
	if err != nil {
		t.Fatal(err)
	}
	want := "auth: rotate refresh tokens on /auth/refresh\n\n" +
		"Arbiter-PRD: PRD-004@v1 (tag arbiter/prd/PRD-004/v1)\n" +
		"Arbiter-Task: TASK-101 (spec rev 2)\n" +
		"Arbiter-Worker: PRD-004/TASK-101/worker.2~7f3a cred:claude-code/claude-opus-5-5 (launched)\n" +
		"Arbiter-Adversary: PRD-004/TASK-101/adversary.1~b20c cred:claude-code/claude-sonnet-5 (5 attacks, 0 upheld)\n" +
		"Arbiter-Judge: PRD-004/TASK-101/judge.1~e91d cred:claude-code/claude-opus-5-5 (verdict: low-risk)\n" +
		"Arbiter-Approved-By: human:Masked-Kunsiquat\n" +
		"Arbiter-Ledger: .arbiter/ledger/PRD-004.jsonl#seq=148 sha256:" + pinHash + "\n" +
		"Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	pins, err := LedgerPins(got)
	if err != nil || len(pins) != 1 || pins[0] != goodTrailers().Ledger {
		t.Fatalf("pins = %v, %v", pins, err)
	}

	tr := goodTrailers()
	tr.ApprovedBy, tr.CoAuthors = "", nil
	got, err = TaskMessage("s", tr)
	if err != nil || strings.Contains(got, "Approved-By") || strings.Contains(got, "Co-Authored-By") {
		t.Fatalf("optional trailers: %q, %v", got, err)
	}
}

func TestTaskMessageRejects(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		mut     func(*TaskTrailers)
	}{
		{"empty subject", "\n", nil},
		{"trailer-like subject", "ok\nArbiter-Task: forged", nil},
		{"trailer-like indented", "ok\n  ARBITER-Judge: forged", nil},
		{"bad prd", "s", func(t *TaskTrailers) { t.PRDID = "PRD-4" }},
		{"lock version", "s", func(t *TaskTrailers) { t.LockVersion = 0 }},
		{"task id", "s", func(t *TaskTrailers) { t.TaskID = "" }},
		{"spec revision", "s", func(t *TaskTrailers) { t.SpecRevision = 0 }},
		{"worker", "s", func(t *TaskTrailers) { t.Worker = "" }},
		{"adversary", "s", func(t *TaskTrailers) { t.Adversary = "" }},
		{"judge", "s", func(t *TaskTrailers) { t.Judge = "" }},
		{"pin seq", "s", func(t *TaskTrailers) { t.Ledger.Seq = 0 }},
		{"pin path", "s", func(t *TaskTrailers) { t.Ledger.Path = "x.jsonl" }},
		{"pin hash", "s", func(t *TaskTrailers) { t.Ledger.Hash = "abc" }},
		{"newline in worker", "s", func(t *TaskTrailers) { t.Worker = "a\nArbiter-Judge: x" }},
		{"cr in approver", "s", func(t *TaskTrailers) { t.ApprovedBy = "a\rb" }},
		{"newline in coauthor", "s", func(t *TaskTrailers) { t.CoAuthors = []string{"A <a@b>\nX: y"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := goodTrailers()
			if tc.mut != nil {
				tc.mut(&tr)
			}
			if msg, err := TaskMessage(tc.subject, tr); err == nil {
				t.Fatalf("accepted:\n%s", msg)
			}
		})
	}
}
