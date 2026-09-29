// Package ledger implements Arbiter's hash-chained, supervisor-signed audit ledger (spec §8.B,
// action catalog §8.E, export format §8.D).
//
// Each entry is hashed as (ledger format v1)
//
//	entry_hash = hex(sha256(JCS(entry)))
//
// where entry is the JSON object of every column except entry_hash and supervisor_signature:
// v, chain, seq, task_id, seat_id, action, payload_json (as parsed JSON), created_at and
// prev_hash. prev_hash is the previous entry's entry_hash (64 zeros for seq 1), so the chain is
// linked from inside the hashed object. The supervisor key signs the entry_hash hex string
// (SSHSIG, namespace "arbiter-ledger").
//
// The export is JSONL: one line per entry in seq order, each line exactly the JCS encoding of
// the hashed object plus entry_hash and supervisor_signature. Because every line is canonical,
// re-exporting a chain always produces the same bytes.
//
// This format is frozen once the first ledger is committed. Changing anything here bumps
// Version, and Verify must keep accepting every earlier version. Never a silent rehash.
package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Version is the ledger format written into every entry's v field.
const Version = 1

// ZeroHash is prev_hash for seq 1.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// GlobalChain holds entries with no PRD (credentials, org promotions).
const GlobalChain = "global"

// TimeFormat is how the core writes created_at: RFC 3339, UTC, fixed microsecond precision.
const TimeFormat = "2006-01-02T15:04:05.000000Z"

var (
	chainRe   = regexp.MustCompile(`^(global|PRD-\d{3,})$`)
	hashRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	createdRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)
)

// Entry is one ledger row. TaskID "" means NULL.
type Entry struct {
	V         int64
	Chain     string
	Seq       int64
	TaskID    string
	SeatID    string
	Action    string
	Payload   map[string]any
	CreatedAt string
	PrevHash  string
	EntryHash string
	Signature string
}

// hashedObject is the entry as hashed: every column except entry_hash and supervisor_signature.
func (e *Entry) hashedObject() map[string]any {
	var task any
	if e.TaskID != "" {
		task = e.TaskID
	}
	return map[string]any{
		"v":            e.V,
		"chain":        e.Chain,
		"seq":          e.Seq,
		"task_id":      task,
		"seat_id":      e.SeatID,
		"action":       e.Action,
		"payload_json": e.Payload,
		"created_at":   e.CreatedAt,
		"prev_hash":    e.PrevHash,
	}
}

// record is the exported form: the hashed object plus entry_hash and supervisor_signature.
func (e *Entry) record() map[string]any {
	r := e.hashedObject()
	r["entry_hash"] = e.EntryHash
	r["supervisor_signature"] = e.Signature
	return r
}

var recordKeys = []string{"action", "chain", "created_at", "entry_hash", "payload_json",
	"prev_hash", "seat_id", "seq", "supervisor_signature", "task_id", "v"}

// ComputeHash returns sha256(JCS(entry)) as lowercase hex.
func ComputeHash(e *Entry) (string, error) {
	c, err := Canonicalize(e.hashedObject())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c)
	return hex.EncodeToString(h[:]), nil
}

// Chain is one append-only chain (one PRD, or global) held in memory.
type Chain struct {
	name    string
	signer  Signer
	entries []Entry
	Now     func() time.Time // for tests; defaults to time.Now
}

// NewChain starts an empty chain.
func NewChain(name string, signer Signer) (*Chain, error) {
	if !chainRe.MatchString(name) {
		return nil, fmt.Errorf("ledger: invalid chain name %q", name)
	}
	return &Chain{name: name, signer: signer, Now: time.Now}, nil
}

// Append validates, hashes, signs and appends one entry.
func (c *Chain) Append(seatID, action, taskID string, payload map[string]any) (Entry, error) {
	if seatID == "" {
		return Entry{}, errors.New("ledger: seat_id is required")
	}
	if err := checkPayload(action, payload); err != nil {
		return Entry{}, err
	}
	seq, prev := c.Head()
	e := Entry{
		V:         Version,
		Chain:     c.name,
		Seq:       seq + 1,
		TaskID:    taskID,
		SeatID:    seatID,
		Action:    action,
		Payload:   clonePayload(payload),
		CreatedAt: c.Now().UTC().Format(TimeFormat),
		PrevHash:  prev,
	}
	var err error
	if e.EntryHash, err = ComputeHash(&e); err != nil {
		return Entry{}, fmt.Errorf("ledger: %s: %w", action, err)
	}
	if e.Signature, err = c.signer.Sign([]byte(e.EntryHash)); err != nil {
		return Entry{}, err
	}
	c.entries = append(c.entries, e)
	return e, nil
}

// Head returns the last seq and entry_hash (0 and ZeroHash for an empty chain). The
// Arbiter-Ledger commit trailer pins this; see VerifyHead.
func (c *Chain) Head() (int64, string) {
	if len(c.entries) == 0 {
		return 0, ZeroHash
	}
	last := c.entries[len(c.entries)-1]
	return last.Seq, last.EntryHash
}

// Entries returns a copy of the chain's entries.
func (c *Chain) Entries() []Entry { return slices.Clone(c.entries) }

// WriteJSONL exports the chain, one canonical line per entry, LF line endings.
func (c *Chain) WriteJSONL(w io.Writer) error {
	return WriteJSONL(w, c.entries)
}

// WriteJSONL writes entries as canonical JSONL.
func WriteJSONL(w io.Writer, entries []Entry) error {
	bw := bufio.NewWriter(w)
	for i := range entries {
		line, err := Canonicalize(entries[i].record())
		if err != nil {
			return fmt.Errorf("ledger: seq %d: %w", entries[i].Seq, err)
		}
		bw.Write(line)
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

// ReadJSONL parses an exported chain. Each line must be exactly the canonical encoding of its
// record (so extra fields, duplicate keys, reformatting and non-canonical escapes are all
// rejected). A trailing CR per line is tolerated for checkouts with core.autocrlf.
func ReadJSONL(r io.Reader) ([]Entry, error) {
	var entries []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSuffix(sc.Bytes(), []byte("\r"))
		if len(line) == 0 {
			return nil, fmt.Errorf("ledger: line %d: empty line", n)
		}
		e, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("ledger: line %d: %w", n, err)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ledger: read: %w", err)
	}
	return entries, nil
}

func parseLine(line []byte) (Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return Entry{}, err
	}
	if got := slices.Sorted(maps.Keys(raw)); !slices.Equal(got, recordKeys) {
		return Entry{}, fmt.Errorf("fields %v, want %v", got, recordKeys)
	}
	var e Entry
	var ok bool
	str := func(k string) string {
		s, isStr := raw[k].(string)
		ok = ok && isStr
		return s
	}
	ok = true
	e.Chain, e.SeatID, e.Action = str("chain"), str("seat_id"), str("action")
	e.CreatedAt, e.PrevHash, e.EntryHash, e.Signature = str("created_at"), str("prev_hash"), str("entry_hash"), str("supervisor_signature")
	if !ok {
		return Entry{}, errors.New("a string field has the wrong type")
	}
	if raw["task_id"] != nil {
		if e.TaskID, ok = raw["task_id"].(string); !ok || e.TaskID == "" {
			return Entry{}, errors.New("task_id must be a non-empty string or null")
		}
	}
	var err error
	for _, f := range []struct {
		key string
		dst *int64
	}{{"v", &e.V}, {"seq", &e.Seq}} {
		n, isNum := raw[f.key].(json.Number)
		if !isNum {
			return Entry{}, fmt.Errorf("%s must be a number", f.key)
		}
		if *f.dst, err = n.Int64(); err != nil {
			return Entry{}, fmt.Errorf("%s: %w", f.key, err)
		}
	}
	if e.Payload, ok = raw["payload_json"].(map[string]any); !ok {
		return Entry{}, errors.New("payload_json must be an object")
	}
	canon, err := Canonicalize(e.record())
	if err != nil {
		return Entry{}, err
	}
	if !bytes.Equal(canon, line) {
		return Entry{}, errors.New("line is not in canonical (JCS) form")
	}
	return e, nil
}

// Verify checks one chain's entries: chain name, contiguous seq from 1, prev_hash links,
// recomputed entry_hash, and the supervisor signature on every entry. It returns the head.
//
// Verify cannot detect entries removed from the end: a truncated chain is still a valid chain.
// Compare the head against the one pinned by the signed commit trailer (VerifyHead).
func Verify(entries []Entry, chain string, pub ssh.PublicKey) (seq int64, head string, err error) {
	prev := ZeroHash
	for i := range entries {
		e := &entries[i]
		fail := func(format string, a ...any) (int64, string, error) {
			return 0, "", fmt.Errorf("ledger: %s seq %d: %s", chain, e.Seq, fmt.Sprintf(format, a...))
		}
		switch {
		case e.V != Version:
			return fail("unsupported ledger version %d", e.V)
		case e.Chain != chain:
			return fail("belongs to chain %q", e.Chain)
		case e.Seq != int64(i+1):
			return fail("out of order at position %d", i+1)
		case e.PrevHash != prev:
			return fail("prev_hash does not match the previous entry")
		case !createdRe.MatchString(e.CreatedAt):
			return fail("created_at %q is not in %s form", e.CreatedAt, TimeFormat)
		case !hashRe.MatchString(e.EntryHash):
			return fail("malformed entry_hash")
		}
		if err := checkPayload(e.Action, e.Payload); err != nil {
			return fail("%v", err)
		}
		h, err := ComputeHash(e)
		if err != nil {
			return fail("%v", err)
		}
		if h != e.EntryHash {
			return fail("entry_hash mismatch (content was modified)")
		}
		if err := VerifySSHSig(pub, Namespace, []byte(e.EntryHash), e.Signature); err != nil {
			return fail("%v", err)
		}
		if blob, _ := dearmor(e.Signature); armor(blob) != e.Signature {
			return fail("signature is not in canonical armor")
		}
		prev = e.EntryHash
	}
	if len(entries) == 0 {
		return 0, ZeroHash, nil
	}
	return int64(len(entries)), prev, nil
}

// VerifyHead checks that a verified chain ends exactly at the pinned head (seq and hash).
func VerifyHead(gotSeq int64, gotHash string, wantSeq int64, wantHash string) error {
	if gotSeq != wantSeq || gotHash != wantHash {
		return fmt.Errorf("ledger: head is seq %d %s, pinned head is seq %d %s", gotSeq, gotHash, wantSeq, wantHash)
	}
	return nil
}

// VerifyJSONL reads and verifies an exported chain.
func VerifyJSONL(r io.Reader, chain string, pub ssh.PublicKey) (int64, string, error) {
	entries, err := ReadJSONL(r)
	if err != nil {
		return 0, "", err
	}
	return Verify(entries, chain, pub)
}

// catalog lists the required payload fields per action (§8.E). A field is required to be
// present; its value may be null (e.g. parent_seat_id for the ringleader, cost_usd for a
// killed invocation).
var catalog = map[string][]string{
	"credential":      {"credential_id", "kind", "harness", "model", "model_provenance"},
	"prd_lock":        {"tag", "spec_hash", "tag_object_sha"},
	"plan":            {"plan_hash", "task_ids"},
	"spec":            {"task_id", "spec_revision", "spec_hash"},
	"mint":            {"new_seat_id", "role", "parent_seat_id", "credential_id"},
	"launch":          {"invocation_id", "seat_id", "purpose", "prompt_hash", "injected_lesson_ids"},
	"exit":            {"invocation_id", "exit_reason", "cost_usd", "cost_estimated"},
	"result":          {"invocation_id", "result_hash", "status"},
	"submit":          {"submit_commit", "base_commit", "diff_check", "build_check"},
	"unseen_state":    {"changed_paths", "action"},
	"stray_processes": {"invocation_id", "processes"},
	"attack_run":      {"commit", "tests"},
	"claim_ruling":    {"test_id", "ruling", "reason_hash"},
	"dispute":         {"test_id", "argument_hash"},
	"dispute_ruling":  {"test_id", "ruling"},
	"verdict":         {"verdict", "blast_radius", "bundle_hash"},
	"hitl":            {"decision", "note_hash"},
	"scope_grant":     {"paths", "trigger"},
	"integration":     {"result", "failing_tests", "routing"},
	"merge":           {"tree", "parent", "trailers_hash"},
	"merge_commit":    {"sha"},
	"outcome":         {"lesson_id", "lesson_tier", "outcome_type", "evidence_backed"},
	"autopsy":         {"invocation_id", "tail_hash", "checkpoint_ref"},
	"task_state":      {"from", "to", "reason"},
	"promotion":       {"manifest_hash", "lesson_ids"},
}

func checkPayload(action string, payload map[string]any) error {
	required, ok := catalog[action]
	if !ok {
		return fmt.Errorf("ledger: unknown action %q", action)
	}
	if payload == nil {
		return fmt.Errorf("ledger: %s: payload is required", action)
	}
	for _, k := range required {
		if _, ok := payload[k]; !ok {
			return fmt.Errorf("ledger: %s: payload is missing %q", action, k)
		}
	}
	return nil
}

// clonePayload round-trips the payload through JCS so the stored entry is detached from the
// caller's maps and holds only canonical JSON types.
func clonePayload(p map[string]any) map[string]any {
	b, err := Canonicalize(p)
	if err != nil {
		return p // Append's ComputeHash reports the error
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var out map[string]any
	if dec.Decode(&out) != nil {
		return p
	}
	return out
}
