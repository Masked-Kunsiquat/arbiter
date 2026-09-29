package ledger

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func ed25519Key(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

// testSigner returns a deterministic Ed25519 supervisor key.
func testSigner(t *testing.T, seed byte) *SSHSigner {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ed25519Key(seed))
	if err != nil {
		t.Fatal(err)
	}
	return NewSSHSigner(s)
}

// fixedClock advances one second per call from a fixed instant.
func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 28, 23, 0, 0, 123456000, time.FixedZone("EDT", -4*3600))
	return func() time.Time { t = t.Add(time.Second); return t }
}

func newChain(t *testing.T, name string, s Signer) *Chain {
	t.Helper()
	c, err := NewChain(name, s)
	if err != nil {
		t.Fatal(err)
	}
	c.Now = fixedClock()
	return c
}

func mustAppend(t *testing.T, c *Chain, seat, action, task string, payload map[string]any) Entry {
	t.Helper()
	e, err := c.Append(seat, action, task, payload)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// sampleChain covers null task_id, nested arrays/objects, floats, nulls, and non-ASCII text.
func sampleChain(t *testing.T, s Signer) *Chain {
	c := newChain(t, "PRD-004", s)
	mustAppend(t, c, "human", "prd_lock", "", map[string]any{
		"tag": "arbiter/prd/PRD-004/v1", "spec_hash": strings.Repeat("ab", 32), "tag_object_sha": strings.Repeat("cd", 20),
	})
	mustAppend(t, c, "core", "mint", "", map[string]any{
		"new_seat_id": "PRD-004/ringleader.1~a1b2", "role": "ringleader", "parent_seat_id": nil, "credential_id": "cred:claude-code/claude-opus-5-5",
	})
	mustAppend(t, c, "PRD-004/ringleader.1~a1b2", "plan", "", map[string]any{
		"plan_hash": strings.Repeat("11", 32), "task_ids": []string{"TASK-101", "TASK-102"},
	})
	mustAppend(t, c, "core", "exit", "TASK-101", map[string]any{
		"invocation_id": "inv-7", "exit_reason": "ok", "cost_usd": 0.0251729, "cost_estimated": false,
	})
	mustAppend(t, c, "core", "attack_run", "TASK-101", map[string]any{
		"commit": strings.Repeat("ef", 20),
		"tests": []any{
			map[string]any{"test_id": "TestAttack_INVARIANT_2_RawSQL", "targets": []string{"INVARIANT-2"}, "class": "PASS"},
			map[string]any{"test_id": "TestAttack_AC_1_Refresh", "targets": []string{"AC-1"}, "class": "ASSERTION_FAIL"},
		},
	})
	mustAppend(t, c, "PRD-004/TASK-101/judge.1~e91d", "verdict", "TASK-101", map[string]any{
		"verdict": "approve", "blast_radius": "low", "bundle_hash": strings.Repeat("22", 32),
		"note": "Überprüft ✓ — naïve café 🚀\r\nline2", // non-ASCII + CRLF inside a string
	})
	return c
}

func export(t *testing.T, c *Chain) string {
	t.Helper()
	var b bytes.Buffer
	if err := c.WriteJSONL(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func verifyString(s, chain string, pub ssh.PublicKey) (int64, string, error) {
	return VerifyJSONL(strings.NewReader(s), chain, pub)
}

func TestChainVerifies(t *testing.T) {
	s := testSigner(t, 1)
	c := sampleChain(t, s)
	seq, head, err := verifyString(export(t, c), "PRD-004", s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	wantSeq, wantHead := c.Head()
	if err := VerifyHead(seq, head, wantSeq, wantHead); err != nil {
		t.Fatal(err)
	}
	if c.Entries()[0].PrevHash != ZeroHash {
		t.Error("seq 1 prev_hash is not 64 zeros")
	}
}

// The same entry must hash (and, with Ed25519, sign) to the same bytes on every platform.
// These constants were produced on Windows and are checked unchanged on Linux (see FINDINGS).
func TestGoldenEntry(t *testing.T) {
	c := newChain(t, "PRD-004", testSigner(t, 7))
	e := mustAppend(t, c, "PRD-004/TASK-101/worker.2~7f3a", "result", "TASK-101", map[string]any{
		"invocation_id": "inv-1",
		"result_hash":   strings.Repeat("0f", 32),
		"status":        "done",
		"notes":         "Ünïcödé € 🚀 \"quoted\" back\\slash\r\nCRLF\ttab  ",
		"\U0001F600":    "emoji key sorts before דּ by UTF-16",
		"דּ":             1e21,
		"n":             []any{0.1, 1e-7, -0.0, 100, int64(1) << 53},
	})

	const wantCanon = `{"action":"result","chain":"PRD-004","created_at":"2026-09-29T03:00:01.123456Z",` +
		`"payload_json":{"invocation_id":"inv-1","n":[0.1,1e-7,0,100,9007199254740992],` +
		`"notes":"Ünïcödé € 🚀 \"quoted\" back\\slash\r\nCRLF\ttab ` + " " + `",` +
		`"result_hash":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","status":"done",` +
		`"` + "\U0001F600" + `":"emoji key sorts before ` + "דּ" + ` by UTF-16","` + "דּ" + `":1e+21},` +
		`"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000",` +
		`"seat_id":"PRD-004/TASK-101/worker.2~7f3a","seq":1,"task_id":"TASK-101","v":1}`
	canon, err := Canonicalize(e.hashedObject())
	if err != nil {
		t.Fatal(err)
	}
	if string(canon) != wantCanon {
		t.Fatalf("canonical form changed\n got  %s\n want %s", canon, wantCanon)
	}
	const wantHash = "f4ff26f58ab8dbb8a388bf31f2757ae06adaf7240502f5c837ee2ba36cf149a6"
	const wantSig = "-----BEGIN SSH SIGNATURE-----\n" +
		"U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg6kpsY+KcUgq+9VB7Ey7F+ZVHdq\n" +
		"6+vnuSQh7qaRRG0iwAAAAOYXJiaXRlci1sZWRnZXIAAAAAAAAABnNoYTUxMgAAAFMAAAAL\n" +
		"c3NoLWVkMjU1MTkAAABA3gkkJATXuspzOgqYsTSeKB9zmBpUzgZH3h3NusTZPdD33nWNcK\n" +
		"9ZNMdYhhQE3d2L46BtLeaMua5yAiirLguzCw==\n" +
		"-----END SSH SIGNATURE-----"
	if e.EntryHash != wantHash {
		t.Errorf("entry_hash = %s, want %s", e.EntryHash, wantHash)
	}
	if e.Signature != wantSig {
		t.Errorf("signature changed:\n%s", e.Signature)
	}
}

// Changing any single field anywhere in the exported ledger must fail verification. Each
// mutated line is re-encoded canonically, so the failure comes from the hash chain or the
// signature, not from the strict-format check.
func TestTamperAnySingleField(t *testing.T) {
	s := testSigner(t, 1)
	c := sampleChain(t, s)
	lines := splitLines(export(t, c))
	otherSig := c.Entries()[0].Signature

	count := 0
	for i := range lines {
		rec := decodeLine(t, lines[i])
		for _, path := range leafPaths(rec, nil) {
			mutations := []func(any) any{mutate}
			if path[0] == "supervisor_signature" {
				mutations = append(mutations, func(any) any { return otherSig }) // a real signature, wrong entry
			}
			for _, m := range mutations {
				mut := decodeLine(t, lines[i])
				setPath(mut, path, m(getPath(mut, path)))
				tampered := append([]string{}, lines...)
				tampered[i] = mustCanon(t, mut) + "\n"
				if i == 0 && fmt.Sprint(path) == "[supervisor_signature]" && tampered[i] == lines[i] {
					continue // substituting entry 1's own signature is not a change
				}
				count++
				if _, _, err := verifyString(strings.Join(tampered, ""), "PRD-004", s.PublicKey()); err == nil {
					t.Errorf("line %d: changing %v went undetected", i+1, path)
				}
			}
		}
	}
	t.Logf("%d single-field mutations, all detected", count)
}

// An attacker without the supervisor key can rewrite and rehash the whole chain consistently;
// only the signature catches it, which is why the verifying key must come from
// allowed_signers, never from the ledger file itself.
func TestRehashedChainNeedsTheKey(t *testing.T) {
	real := testSigner(t, 1)
	attacker := testSigner(t, 2)
	entries := sampleChain(t, real).Entries()

	entries[3].Payload["cost_usd"] = json.Number("0")
	prev := entries[2].EntryHash
	for i := 3; i < len(entries); i++ {
		entries[i].PrevHash = prev
		h, err := ComputeHash(&entries[i])
		if err != nil {
			t.Fatal(err)
		}
		entries[i].EntryHash = h
		if entries[i].Signature, err = attacker.Sign([]byte(h)); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
	if _, _, err := Verify(entries, "PRD-004", real.PublicKey()); err == nil {
		t.Fatal("rehashed chain verified against the real key")
	} else {
		t.Logf("detected: %v", err)
	}
	// Sanity: the forgery is internally consistent. Re-signed entirely with the attacker's key,
	// it verifies under that key, so the chain alone proves nothing without the right key.
	for i := range 3 {
		entries[i].Signature, _ = attacker.Sign([]byte(entries[i].EntryHash))
	}
	if _, _, err := Verify(entries, "PRD-004", attacker.PublicKey()); err != nil {
		t.Fatalf("sanity: expected the forged chain to verify under the attacker's key: %v", err)
	}
}

func TestReorderDeleteDuplicate(t *testing.T) {
	s := testSigner(t, 1)
	lines := splitLines(export(t, sampleChain(t, s)))
	cases := map[string][]string{
		"swap 2 and 3":       {lines[0], lines[2], lines[1], lines[3], lines[4], lines[5]},
		"last moved first":   {lines[5], lines[0], lines[1], lines[2], lines[3], lines[4]},
		"delete middle":      {lines[0], lines[1], lines[3], lines[4], lines[5]},
		"delete first":       lines[1:],
		"duplicate an entry": {lines[0], lines[1], lines[1], lines[2], lines[3], lines[4], lines[5]},
	}
	for name, ls := range cases {
		if _, _, err := verifyString(strings.Join(ls, ""), "PRD-004", s.PublicKey()); err == nil {
			t.Errorf("%s: went undetected", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

// Truncating the tail leaves a valid, shorter chain. Only the pinned head catches it.
func TestTruncationNeedsPinnedHead(t *testing.T) {
	s := testSigner(t, 1)
	c := sampleChain(t, s)
	full := export(t, c)
	truncated := full[:strings.LastIndex(strings.TrimSuffix(full, "\n"), "\n")+1]
	seq, head, err := verifyString(truncated, "PRD-004", s.PublicKey())
	if err != nil {
		t.Fatalf("truncated chain should verify on its own: %v", err)
	}
	wantSeq, wantHead := c.Head()
	if err := VerifyHead(seq, head, wantSeq, wantHead); err == nil {
		t.Fatal("truncation not detected by the pinned head")
	} else {
		t.Logf("chain alone: OK at seq %d; against pinned head: %v", seq, err)
	}
}

// Chains are independent: each export verifies alone; entries can't move between chains.
func TestPerChainIndependence(t *testing.T) {
	s := testSigner(t, 1)
	prd4 := newChain(t, "PRD-004", s)
	prd5 := newChain(t, "PRD-005", s)
	global := newChain(t, GlobalChain, s)
	lock := func(id string) map[string]any {
		return map[string]any{"tag": "arbiter/prd/" + id + "/v1", "spec_hash": strings.Repeat("ab", 32), "tag_object_sha": strings.Repeat("cd", 20)}
	}
	state := map[string]any{"from": "ready", "to": "in_progress", "reason": "dispatch"}
	// Interleaved appends, as the core would make them.
	mustAppend(t, prd4, "human", "prd_lock", "", lock("PRD-004"))
	mustAppend(t, global, "human", "promotion", "", map[string]any{"manifest_hash": strings.Repeat("33", 32), "lesson_ids": []string{"L-1"}})
	mustAppend(t, prd5, "human", "prd_lock", "", lock("PRD-005"))
	mustAppend(t, prd4, "core", "task_state", "TASK-101", state)
	mustAppend(t, prd5, "core", "task_state", "TASK-201", state)
	mustAppend(t, global, "human", "promotion", "", map[string]any{"manifest_hash": strings.Repeat("44", 32), "lesson_ids": []string{"L-2"}})

	files := map[string]string{"PRD-004": export(t, prd4), "PRD-005": export(t, prd5), GlobalChain: export(t, global)}
	for name, f := range files {
		if _, _, err := verifyString(f, name, s.PublicKey()); err != nil {
			t.Errorf("%s does not verify on its own: %v", name, err)
		}
	}
	if _, _, err := verifyString(files["PRD-004"], "PRD-005", s.PublicKey()); err == nil {
		t.Error("PRD-004's file verified as PRD-005")
	}
	// Same seq, same signer, different chain: splicing PRD-005's seq 2 into PRD-004 must fail.
	l4 := splitLines(files["PRD-004"])
	l5 := splitLines(files["PRD-005"])
	if _, _, err := verifyString(l4[0]+l5[1], "PRD-004", s.PublicKey()); err == nil {
		t.Error("an entry spliced in from another chain went undetected")
	}
}

// A Windows checkout with core.autocrlf=true turns the file's LF line endings into CRLF.
// That must still verify, and CRLF inside string values must be unaffected (it's escaped).
func TestCRLFCheckout(t *testing.T) {
	s := testSigner(t, 1)
	lf := export(t, sampleChain(t, s))
	if strings.Contains(lf, "\r") {
		t.Fatal("export contains a raw CR")
	}
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")
	if _, _, err := verifyString(crlf, "PRD-004", s.PublicKey()); err != nil {
		t.Fatalf("CRLF checkout failed verification: %v", err)
	}
	entries, err := ReadJSONL(strings.NewReader(crlf))
	if err != nil {
		t.Fatal(err)
	}
	if got := entries[5].Payload["note"]; got != "Überprüft ✓ — naïve café 🚀\r\nline2" {
		t.Errorf("string with CRLF changed: %q", got)
	}
}

func TestStrictFormat(t *testing.T) {
	s := testSigner(t, 1)
	full := export(t, sampleChain(t, s))
	first, rest, _ := strings.Cut(full, "\n")
	rec := decodeLine(t, first)
	rec["note"] = "extra field"
	extra := mustCanon(t, rec)

	cases := map[string]string{
		"extra field":     extra + "\n" + rest,
		"whitespace":      "{ " + first[1:] + "\n" + rest,
		"duplicate key":   `{"action":"hitl",` + first[1:] + "\n" + rest,
		"escaped slash":   strings.Replace(first, "arbiter/prd", `arbiter\/prd`, 1) + "\n" + rest,
		"blank line":      first + "\n\n" + rest,
		"not json":        "hello\n" + rest,
		"seq as a string": strings.Replace(first, `"seq":1`, `"seq":"1"`, 1) + "\n" + rest,
	}
	for name, f := range cases {
		if _, _, err := verifyString(f, "PRD-004", s.PublicKey()); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

func TestCatalog(t *testing.T) {
	c := newChain(t, "PRD-004", testSigner(t, 1))
	bad := []struct {
		action  string
		payload map[string]any
	}{
		{"not_an_action", map[string]any{}},
		{"exit", map[string]any{"invocation_id": "i", "exit_reason": "ok", "cost_estimated": false}}, // missing cost_usd
		{"dispute", map[string]any{"test_id": "T"}},                                                  // missing argument_hash
		{"dispute_ruling", map[string]any{"test_id": "T"}},                                           // missing ruling
		{"exit", nil},
		{"exit", map[string]any{"invocation_id": "i", "exit_reason": "ok", "cost_usd": int64(1) << 60, "cost_estimated": false}}, // not a double
	}
	for _, b := range bad {
		if _, err := c.Append("core", b.action, "", b.payload); err == nil {
			t.Errorf("%s %v: accepted", b.action, b.payload)
		}
	}
	if seq, _ := c.Head(); seq != 0 {
		t.Errorf("rejected appends advanced the chain to seq %d", seq)
	}
	// Required fields may be null (killed invocation: no cost reported, spike 2).
	mustAppend(t, c, "core", "exit", "TASK-1", map[string]any{"invocation_id": "i", "exit_reason": "killed", "cost_usd": nil, "cost_estimated": false})
	mustAppend(t, c, "PRD-004/TASK-1/worker.1~aaaa", "dispute", "TASK-1", map[string]any{"test_id": "T", "argument_hash": "a"})
	if _, err := NewChain("prd-4", testSigner(t, 1)); err == nil {
		t.Error("bad chain name accepted")
	}
}

// --- helpers ---

// splitLines splits an export into its lines, each keeping its trailing "\n".
func splitLines(s string) []string {
	lines := strings.SplitAfter(s, "\n")
	return lines[:len(lines)-1] // drop the empty string after the final "\n"
}

func decodeLine(t *testing.T, line string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func leafPaths(v any, prefix []any) [][]any {
	var out [][]any
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			out = append(out, leafPaths(c, append(append([]any{}, prefix...), k))...)
		}
	case []any:
		for i, c := range x {
			out = append(out, leafPaths(c, append(append([]any{}, prefix...), i))...)
		}
	default:
		out = append(out, prefix)
	}
	return out
}

func getPath(v any, path []any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func setPath(v any, path []any, val any) {
	parent := getPath(v, path[:len(path)-1])
	switch k := path[len(path)-1].(type) {
	case string:
		parent.(map[string]any)[k] = val
	case int:
		parent.([]any)[k] = val
	}
}

// mutate changes a leaf to a different value of a plausible shape.
func mutate(v any) any {
	switch x := v.(type) {
	case string:
		if hashRe.MatchString(x) { // stay a well-formed hash so we test the chain, not the regex
			if x[63] == '0' {
				return x[:63] + "1"
			}
			return x[:63] + "0"
		}
		return x + "x"
	case json.Number:
		f, _ := x.Float64()
		return f + 1
	case bool:
		return !x
	case nil:
		return "TASK-999"
	}
	panic(fmt.Sprintf("unexpected leaf %T", v))
}
