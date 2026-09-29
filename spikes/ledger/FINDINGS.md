# Spike 4: the ledger (§8.B, §8.D, §8.E)

The code is real and lives in `internal/ledger/`; this file holds the spike notes.
Go 1.27.1, golang.org/x/crypto v0.57.0. Tests pass on Windows 11 and on Linux (WSL2 Ubuntu, same
test binary cross-compiled with `GOOS=linux`), including the golden hash and signature.

## What's implemented

| File | What |
|---|---|
| `jcs.go` | `Canonicalize`: Arbiter's input rules, then stdlib `encoding/json/jsontext` `Value.Canonicalize` |
| `sshsig.go` | OpenSSH SSHSIG sign/verify on `x/crypto/ssh`, namespace `arbiter-ledger` |
| `ledger.go` | `Entry`, `Chain.Append/Head/WriteJSONL`, `ReadJSONL`, `Verify`, `VerifyHead`, §8.E catalog |
| `jcs_oracle_test.go` | an independent hand-written RFC 8785 implementation, used only as a test oracle |

> **Update:** the spike first implemented v3's `sha256(prev_hash || JCS(entry))` literally. The
> changes listed at the end were applied in Spec v3.1, and `internal/ledger` now implements them:
> `entry_hash = hex(sha256(JCS(entry)))` with `v: 1` and `prev_hash` inside the hashed object, plus
> the revised catalog. The golden entry below is the v3.1 value. The v3 notes are kept as the record
> of why.

As first spiked (v3): `entry_hash = hex(sha256(prev_hash_hex_ascii || JCS(entry)))`, where
`entry` has every column except `entry_hash` and `supervisor_signature` (so `prev_hash` is also
inside it), `payload_json` as parsed JSON, and `task_id` as JSON `null` when absent.

## JCS choice: stdlib, with a hand-written oracle

- **Go 1.27 ships RFC 8785 in the standard library.** `JSONv2` is in the default experiment
  baseline, and `encoding/json/jsontext` (including `(*Value).Canonicalize`) is listed in
  `api/go1.27.txt`, so it's covered by the Go 1 compatibility promise. It's maintained by the Go team,
  has zero module dependencies, and is the smallest thing a human owner has to audit.
- **A thin validation layer runs first**, because the ledger must fail loudly rather than record
  something other than what the core meant: integers must satisfy |n| ≤ 2^53 (JCS numbers are doubles and would be
  rounded silently); NaN/Inf, invalid UTF-8, `[]byte` (which `encoding/json` would base64 without
  comment) and structs are errors.
- **The hand-written implementation became a test oracle** (`jcs_oracle_test.go`). It agrees with the stdlib
  byte for byte on 20,000 random values (arbitrary float bit patterns, subnormals, surrogate-pair
  keys, U+2028, control chars) and on the RFC 8785 vectors (Appendix B numbers, §3.2.2 example,
  §3.2.3 UTF-16 key order). If a future Go release ever changes canonical output, this test and
  the golden entry fail before any ledger silently rehashes.
- Third-party libraries (e.g. `gowebpki/jcs`) were not needed once the stdlib had it.

## Signing choice: in-process SSHSIG on x/crypto/ssh

- Same wire format as `ssh-keygen -Y sign` and git SSH signing. Verified in both directions:
  our signatures pass `ssh-keygen -Y verify` (OpenSSH_for_Windows 9.5 and Ubuntu's OpenSSH), and
  `ssh-keygen`'s signatures pass ours. Ed25519 is deterministic, and the two produce **identical bytes**.
- Chosen over shelling out to `ssh-keygen` per entry: no subprocess per ledger write, no PATH
  dependency in the core, and no key-file permission quirks. An `ssh.Signer` can also come from an agent
  (`x/crypto/ssh/agent`), so keychain or 1Password storage still works. x/crypto/ssh is needed
  for the §10.B SSH transport anyway.

```
ssh-keygen -Y verify: Good "arbiter-ledger" signature for arbiter@test with ED25519 key SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8
```

## Test results (same on Windows and Linux)

```
--- PASS: TestCanonicalizeDifferential (0.36s)        stdlib vs oracle, 20,000 random values
--- PASS: TestCanonicalizeNumbersRFC8785AppendixB     both implementations
--- PASS: TestCanonicalizeRFC8785Example
--- PASS: TestCanonicalizeKeyOrderUTF16
--- PASS: TestGoldenEntry                             exact canonical bytes + entry_hash + signature
--- PASS: TestTamperAnySingleField                    90 single-field mutations, all detected (83 under v3)
--- PASS: TestRehashedChainNeedsTheKey                detected: PRD-004 seq 4: sshsig: signed by a different key
--- PASS: TestReorderDeleteDuplicate                  swap / move / delete first / delete middle / duplicate
--- PASS: TestTruncationNeedsPinnedHead               chain alone: OK at seq 5; against pinned head: mismatch
--- PASS: TestPerChainIndependence                    3 interleaved chains verify alone; cross-chain splice fails
--- PASS: TestCRLFCheckout                            CRLF file verifies; CRLF inside strings unchanged
--- PASS: TestStrictFormat                            extra field, whitespace, dup key, \/ escape, blank line rejected
--- PASS: TestCatalog
--- PASS: TestSSHSigRejects / TestSSHSigInterop*
```

Golden entry (`TestGoldenEntry`), produced on Windows and checked unchanged on Linux:
`entry_hash = f4ff26f58ab8dbb8a388bf31f2757ae06adaf7240502f5c837ee2ba36cf149a6` (v3.1 format;
under v3 it was `20a3873664b0b229827c91abd2d8de1614ab08570769801850b10946b423cc0e`).
The locale can't matter (Go's `strconv` and sorting ignore it). The WSL image only has `C.utf8`
installed, so a Turkish-locale run was not a meaningful test and isn't claimed as one.

## Implementation decisions the spec leaves open (all in `ledger.go`)

- (v3 only) `prev_hash` in the concatenation was the 64 lowercase hex ASCII bytes, not the raw 32 bytes.
- Signed message = the `entry_hash` hex string, no newline. Armor: 70-column lines, LF, no trailing newline.
- `created_at` = `2006-01-02T15:04:05.000000Z` (UTC, fixed microseconds); `Verify` rejects other forms.
- Each JSONL line must be *exactly* `JCS(record)`. This one rule rejects extra fields, duplicate
  keys, reformatting and non-canonical escapes, and makes re-exports byte-identical.
  A trailing `\r` per line is tolerated (`core.autocrlf` checkouts).
- Required payload fields must be present but may be `null` (ringleader's `parent_seat_id`;
  `cost_usd` for a killed invocation, spike 2).

## §8.B / §8.E changes to make before the first ledger is committed (applied in Spec v3.1)


1. Add a version field (`"v": 1`) to every entry now. §8.B says any change needs a new
   `ledger_version` field, but adding a field later is itself a format change that v1 verifiers
   can't tell apart from tampering.
2. Drop the `prev_hash ||` concatenation: `prev_hash` is already inside `JCS(entry)`. The
   concatenation adds nothing and adds an encoding ambiguity (hex vs raw) for every external verifier.
3. Pin the signature format: SSHSIG, namespace `arbiter-ledger`, message = hex entry_hash, and the
   verifying key from `allowed_signers` (`namespaces="git,arbiter-ledger"`), never from the file.
   `TestRehashedChainNeedsTheKey` shows a rewritten, re-signed chain is internally valid.
4. Correct the claim "deleting any past entry is detectable": dropping entries from the *end*
   leaves a valid chain; only the head pinned in a signed commit trailer catches it, and entries
   after the last task commit aren't pinned at all.
5. Pin `created_at` precision and the "each line is `JCS(record)`" rule; add
   `.arbiter/ledger/*.jsonl text eol=lf` to `.gitattributes`.
6. §8.E: add a `merge_commit` row; split `dispute` into `dispute` (worker) and `dispute_ruling`
   (judge) rather than a union payload; allow `cost_usd: null` (or use integer `cost_micro_usd`);
   add a global-chain action for credential registration (§4 says the global chain holds credentials,
   but the catalog has no such action).
