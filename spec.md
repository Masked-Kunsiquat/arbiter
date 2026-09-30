# Arbiter Engine: Architecture & System Specification (v3.2)

A lean, local-first execution arbiter, task governor, and multi-agent coordination layer built on native Git primitives, embedded SQLite, and signed audit records.

> **Changes from v3.1** (§7 Process Supervision implementation, PR #48):
>
> | Issue | Resolution | Section |
> |---|---|---|
> | `Terminate` had no return error; failed hard kill could go unnoticed | `Terminate(h Handle, grace time.Duration) error`; returns error on failed hard kill or if container fails to empty | §7 |
> | Linux `PR_SET_PDEATHSIG` only covers direct child, leaving orphan grandchildren if program dies or exits | `supervisor.start` launches `_pgshim` with `PDEATHSIG` while pinned via `LockOSThread` through `watch`; shim kills its group on death signal, reports exit status via fd-3 pipe, and anchors PGID | §7 |
> | Hard kill is asynchronous on Windows and Linux; dying processes could be logged as false strays | `Terminate` waits (bounded) for container to empty after hard kill before reaping leader and returning | §7 |
> | Windows graceful stop fails if leader exited; `AttachConsole` and group id require a live leader | `_ctrlbreak` accepts candidate attach PIDs from job members, attaches through first viable (non-conhost) process, and signals group 0 | §7 |

> **Changes from v3** (pre-build spikes; evidence in `spikes/*/FINDINGS.md`):
>
> | Issue | Resolution | Section |
> |---|---|---|
> | A plain `claude -p` inherits the user's plugins, hooks, MCP servers and memory; `--allowedTools` is a permission allow-list, not a tool list | Isolation baseline on every launch; roles defined by `--tools` plus shell allow rules | §9.A, §9.C |
> | Ledger format had no version field and hashed `prev_hash` twice; signature and line format unpinned | `v` field from entry 1; `entry_hash = sha256(JCS(entry))`; SSHSIG details, `created_at` form and canonical lines pinned | §4, §8.B, §8.D |
> | An app compile error became an ASSERTION_FAIL with nothing for the claim check to check | Build + vet + test-compile at submit; rule 4 no longer covers build failures | §5.3, §5.4 |
> | One panicking or timed-out attack hides every later attack in its package; `-json` has no file per test and no test ids on build failure | Attacks run one per test from a compiled test binary; attacks found by parsing adversary files; build failures classified per file | §5.4, §9.C |
> | `CTRL_BREAK` fails from a console-less supervisor and silently doesn't arrive with `CREATE_NO_WINDOW` | `CREATE_NO_WINDOW` always; break sent through an `AttachConsole` helper; hard kill always follows | §7 |
> | Killed invocations report no cost | `cost_usd` nullable with a usage-based fallback; `--max-budget-usd` caps spend in the harness | §4, §5.8 |
> | `result` isn't always the last event; API errors report `subtype: "success"` | Read to EOF, succeed on `is_error == false`, no `result` = crash; instruction-first prompts | §9.A |
> | A process can leave the Job Object through WMI | Listed as not defended; post-run process scan | §7, §8.A |
> | "Deleting any entry is detectable" overclaimed; verifying key unspecified | Tail truncation caught only by the pinned head; key from `allowed_signers` with namespaces | §8.B, §8.D |
> | Catalog gaps (`merge_commit`, union `dispute`, no credential action, non-null cost) | Rows added and split; required fields may be null | §8.E |
> | Go test cache could replay a PASS | `-count=1` on every test command | §9.C |
> | Liveness and process-tree wording | `thinking_tokens` counts as activity; `claude.exe` is native; Go spawn-race detail | §7 |

> **Changes from v2** (design round 3: stress test of §5.4, §6.B, §9.A):
>
> | Issue | Resolution | Section |
> |---|---|---|
> | Renames hid adversary-test deletions and `.arbiter/**` moves from the diff check | `--no-renames --name-status -z`; rules apply to both sides of every change | §5.3 |
> | Ignored dependency dirs and `.git` hooks/config are invisible to the diff | Snapshot-and-restore of unseen state before every test run; supervisor git pins `core.hooksPath` | §5.3, §7 |
> | Hallucinated-API attack tests were classified as defects | Classify by throw site + reproduction, not by the runner's label | §5.4 |
> | Integration failures in files the worker may not touch had no legal fix | Route gate failures by file: adversary maintenance run or automatic scope request | §5.6 |
> | Upfront specs went stale in v0.1 with no staleness check until v0.2 | Just-in-time specs in single-lane; symbol-drift staleness moves to Fleet | §5.1, §12 |
> | Headless launch recipe didn't work (silent stdout, Windows arg limits, permissions, signing prompts) | Pinned launch recipe: `stream-json`, prompt on stdin, per-role tool profiles, git config overrides | §9.A |
> | "Submission" undefined; merges described as fast-forwards | Arbiter snapshots the slot into the submit commit; task merges are signed squash commits | §5.3, §5.6 |
> | Seat-per-process would bloat the agent tree | Seats span invocations; new seats only on abnormal end or for independence | §8.B |
> | Unbounded retry loops; no source for `spent_usd` | One attempt ceiling for every relaunch; spend from harness-reported cost | §5.8 |
> | Hash chain covered only the payload; global vs per-PRD chain unclear | Hash covers every column (RFC 8785); one chain per PRD plus a global chain | §8.B |
> | Adversary pattern undiscoverable by `go test` / pytest | Per-ecosystem path glob in config; targets encoded in test names | §5.4, §9.C |
> | Attack lifecycle across attempts, disputes in v0.1 | Defined: ERROR exhaustion, incremental re-review, dispute field, fresh judge seat | §5.4 |
> | Adversary could log catches for its own tests | Judge (and the deterministic core) are the only agent outcome authors | §6.A |
> | `catch` measured compliance, not prevention | Gate 2 requires an evidence-backed catch | §6.A, §6.E |
> | Judge could mark misses irrelevant | Fingerprint recurrence forces a deterministic miss | §6.A |
> | Ranking floor erased negative U; specificity 0 zeroed broad/org lessons | Prior-based `U_rank`; specificity = 1 + literal segments; repo-agnostic org patterns | §6.C |
> | v0.1 needed tree-sitter (cgo) for blast radius | v0.1 blast radius is path-based; tree-sitter arrives in v0.2 | §5.5, §11 |
> | Underspecified for coding | Project config, role output schemas, Judge evidence bundle, ledger action catalog, PRD grammar, terminal states, local process model | §2.C, §5.8, §8.E, §9.A, §9.C, §10.B |

> **Changes from v1** (see git history), responding to `spec-review.md` and later design discussion:
>
> | Issue | Resolution | Section |
> |---|---|---|
> | DAG edges not persisted | `task_edges` table + `ready` / `stale` task states | §4, §5.1 |
> | Cascading interface drift | Symbol-diff staleness detection; Ringleader re-specs tasks without human re-signing unless the PRD itself changes (v3: single-lane avoids drift with just-in-time specs) | §5.1, §12 |
> | Reservation deadlocks | Single-lane core has no contention; Fleet uses atomic all-or-nothing acquisition | §5.2, §12 |
> | Adversary hallucinated tests | Attack Validation Protocol: ERROR ≠ defect, claim check, worker disputes, retries count only upheld rejections | §5.4 |
> | Semantic merge breakage | Integration gate before every merge; serialized merge queue under Fleet | §5.6, §12 |
> | Worktree install cost | Warm worktree slot, lockfile-hash reinstall, shared caches | §7 |
> | Blank Utility formula / miss attribution | Formula defined; Judge auto-resolves every injection at verdict time | §6 |
> | Context dilution / conflicting lessons | Ranked, token-budgeted injection; conflict check at Gate 1 | §6 |
> | Stack-trace clustering false positives | Deterministic trace fingerprints; embeddings only on root-cause summaries | §6 |
> | Windows has no PGIDs | `Supervisor` interface: Job Objects on Windows, PGID + PDEATHSIG on Linux | §7 |
> | Crypto as security theater | Explicit threat model; per-agent keypairs dropped; seats + hash-chained ledger | §8 |
> | Human SSH fatigue | ~2 signatures per feature; batch org promotions | §8.C |
> | Harness tools bypass the "tool layer" | Boundaries enforced by a deterministic diff check at submit time | §5.3 |
> | Scope risk | Single-lane core first; parallelism is the deferred Fleet module | §11, §12 |
> | Agent organization | Credentials + seats form an explicit agent tree; role/knowledge-flow map | §5.0, §8.B |
> | Identity routed through the model (Graphban-style seat codes in prompts) | Seats are bound to the process/connection Arbiter launched; the model never handles tokens; no MCP in v0.1 | §8.B, §9.A |
> | Long-term attribution | Supervisor-signed commits with trailers + committed ledger, verifiable on GitHub | §8.D |
> | Laptop vs server | Core / Runner / Client split; one binary locally, `arbiter serve` on a home server later; SSH transport; client-side human signing | §10 |
> | Self-hosting risk | Bootstrap rule: gate code is human-reviewed; dogfood with a pinned known-good binary | §13 |

---

## 1. System Overview & Core Axioms

The Arbiter is a governance plane and execution supervisor. It sits between local codebases and agent harnesses (Claude Code, Cursor, Aider, custom sub-shells). It does not write application code; it governs state, enforces role separation, orchestrates worktrees, executes test gates, and manages a three-tiered epistemic memory pipeline.

```
                         ┌───────────────────────────────┐
                         │          Human Admin          │
                         │     (CLI / TUI / SSH Key)     │
                         └───────────────┬───────────────┘
                                         │ Signs PRD locks & final merges
                                         ▼
                         ┌───────────────────────────────┐
                         │       The PRD Contract        │
                         │ (.arbiter/prds/PRD-XXX.md)    │
                         │  Locked via signed git tag    │
                         └───────────────┬───────────────┘
                                         │ Compiles into Task DAG
                                         ▼
                         ┌───────────────────────────────┐
                         │       Ringleader Agent        │
                         │ (High Reasoning / Decomposer) │
                         └───────────────┬───────────────┘
                                         │ Dispatches Atomic Specs
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             The Arbiter Supervisor                          │
│  - Embedded SQLite (Tasks, Edges, Reservations, PRDs, Knowledge Pipeline)   │
│  - Runner: Worktree Slot & Process Supervisor (Job Objects / PGIDs)         │
│  - Seats (agent tree) & Hash-Chained Signed Ledger                          │
│  - Symbol Index (v0.2+: tree-sitter blast radius, Fleet interface drift)    │
│  - Integration Gate (full suite + attack tests before every merge)          │
│  - Knowledge Synthesizer (fingerprint clustering & promotion)               │
└──────────────┬───────────────────────┬───────────────────────────────┬──────┘
               │ Dispatches            │ Dispatches                    │
               ▼                       ▼                               ▼
    ┌────────────────────┐  ┌────────────────────┐          ┌───────────────────┐
    │    Worker Agent    │  │ Adversary Reviewer │          │     The Judge     │
    │  (Isolated Tree)   │  │   (Attack Tests)   │          │  (Neutral Arbiter)│
    │  Sub-Process       │  │   Sub-Process      │          │   Evaluates Proof │
    └────────────────────┘  └────────────────────┘          └─────────┬─────────┘
                                                                      │
                                                ┌─────────────────────┴───────┐
                                                ▼                             ▼
                                         [Routine Task]             [Ambiguous / High Risk]
                                       Integration Gate                  HITL Prompt
                                        → Feature Branch               (Human Approval)
```

### Core Axioms

- **No Self-Grading:** The agent writing code cannot review, test, or approve its own work.
- **Deterministic Gating:** State transitions require deterministic evidence (test runner results, static analysis, diff checks) rather than agent declarations. Where an LLM judgment is unavoidable (claim checks, relevance), it is recorded as a judgment, not as proof, and ambiguous cases escalate to the human.
- **Enforce at the Diff, Not the Tool:** Harnesses ship their own shell and file tools, so the Arbiter cannot rely on intercepting writes. Every boundary rule is enforced by inspecting the submitted diff, and state the diff cannot see (ignored dependency dirs, `.git` config and hooks) is snapshot-checked before any test runs.
- **Physical Isolation over Permissions:** Agents operate in dedicated git worktrees under OS-level process containment (Job Objects on Windows, process groups on POSIX).
- **Git as the Ledger of Record:** PRD locks are signed tags, merges are signed commits carrying attribution trailers, and each PRD's hash-chained ledger is committed into the repo (§8.D).
- **Seats, Not Sessions:** Every agent acts through a minted, role-bound seat. Seats form the agent tree, and every ledger entry names the seat that did it.
- **Identity Never Passes Through the Model:** A seat is bound to the process or connection Arbiter created, never to a code the model must remember and repeat.
- **Contract-Driven Scope (PRD-First):** Features originate as machine-parseable, human-signed contracts. Diffs outside the declared file boundaries are rejected.
- **Hierarchical Epistemic Lifecycle:** Memories distill into Project Lessons, which earn promotion into Org Invariants through an efficacy threshold plus human sign-off.
- **Honest Accountability:** Signatures provide provenance and tamper-evidence, not sandboxing. See the threat model (§8.A).

---

## 2. Product Requirements Documents (PRDs) as Executable Contracts

PRDs are version-controlled, machine-parseable contracts stored in the repository.

### A. Lifecycle

`draft → locked → executing → completed → archived` (side state: `amendment_needed`)

- **The Spec-Lock:** Once drafted with Ringleader assistance, the PRD is committed and the human creates a signed tag `arbiter/prd/PRD-004/v1` using git's native SSH signing (`gpg.format = ssh`). The tag pins the exact content; `spec_hash` is recorded for fast lookup.
- **Zero Unilateral Drift:** Workers and reviewers cannot alter PRD invariants or file boundaries (enforced by the diff check on `.arbiter/**`). If a worker reports a design flaw (`status: blocked_prd`, §9.A), the task goes to `awaiting_human`; the human either rejects the claim or moves the PRD to `amendment_needed`. Agents cannot trigger an amendment on their own, so "the PRD is wrong" is not an escape hatch from hard work.
- **What needs re-signing:** Only changes to the PRD itself (invariants, boundaries, acceptance criteria). Task specs are *derived* by the Ringleader and may be regenerated without human signatures as long as they stay within the signed PRD (§5.1).

### B. Format & Structure (`.arbiter/prds/PRD-XXX.md`)

```markdown
---
id: PRD-004
title: JWT Refresh Token Rotation & Session Revocation
status: locked
created_by: human:Masked-Kunsiquat
spec_hash: 8f4b2c19e782a10d8e28f...
target_branch: feature/auth-rotation
max_budget_usd: 5.00
---

## 1. Intent & Context
Replace static long-lived JWTs with rotating refresh tokens backed by local SQLite storage.
Mitigate replay attacks by revoking the entire token family if a reused token is detected.

## 2. Invariants (Non-Negotiable Constraints)
<!-- Adversary and Judge enforce these across ALL child tasks -->
- [INVARIANT-1] No token secrets may ever be written to plaintext logs.
- [INVARIANT-2] Database queries must use parameterized statements; zero raw string interpolation.
- [INVARIANT-3] Breaking API changes to `/api/v1/auth/login` are strictly forbidden.

## 3. Allowed File Boundaries (The Sandbox Scope)
<!-- Enforced by the submit-time diff check and task reservations -->
- `src/auth/**`
- `src/db/migrations/**`
- `tests/auth/**`

## 4. Acceptance Criteria & Testable Outcomes
- [ ] AC-1: POST `/auth/refresh` returns a new access/refresh pair and invalidates the old token.
- [ ] AC-2: Reusing an invalidated token terminates all active sessions for that user ID.
- [ ] AC-3: Integration tests pass in both native and mock runtimes.
```

### C. Parser Rules

The PRD parser is strict; anything it cannot parse blocks `prd lock` with a line-numbered error.

- **Frontmatter:** YAML between `---` fences. Required: `id` (`^PRD-\d{3,}$`), `title`, `target_branch`. Optional: `max_budget_usd` (default 5.00). `status`, `spec_hash`, and `created_by` are written by Arbiter, not the author, and are excluded from `spec_hash`.
- **Sections** are recognized by `##` headings whose text *contains* (case-insensitive) `Intent`, `Invariants`, `File Boundaries`, `Acceptance Criteria`. Leading numbering (`## 2.`) is ignored. All four are required.
- **IDs:** invariants match `^- \[(INVARIANT-\d+)\] (.+)$`, acceptance criteria match `^- \[[ x]\] (AC-\d+): (.+)$`. IDs are unique within the PRD and never renumbered across amendments (a removed ID is retired, not reused), so ledger references stay valid.
- **Boundaries:** one backticked glob per bullet, repo-relative, forward slashes. Glob syntax is doublestar (`**` crosses directories, `*` does not). Patterns are compared case-sensitively for allow rules and case-insensitively for deny rules (§5.3).
- **`spec_hash`** = SHA-256 of the file with the Arbiter-written frontmatter fields removed and line endings normalized to LF, so a Windows checkout with `core.autocrlf` hashes the same as Linux.

---

## 3. Epistemic Knowledge Architecture: The Three Tiers

The system separates high-entropy transient telemetry from persistent, battle-tested principles.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TIER 3: ORG / GLOBAL RULE                       │
│  - Stored: ~/.config/arbiter/global_registry.db (Shared across machine)│
│  - Promotion Gate: U >= 0.80 (Gate 2) + Human SSH Signature (Gate 3)   │
│  - Example: "All SQLite DBs must set PRAGMA busy_timeout = 5000"       │
└──────────────────────────────────▲─────────────────────────────────────┘
                                   │ Promoted via Human Key (Gate 3)
┌──────────────────────────────────┴─────────────────────────────────────┐
│                       TIER 2: PROJECT LESSON                           │
│  - Stored: .arbiter/state.db (Repository Scoped)                       │
│  - Outcome weights: Catch (+1.0), Miss (-1.5), Contradiction (-3.0)    │
│  - Circuit Breaker: Auto-quarantined if Contradictions >= 2            │
│  - Example: "On Android, Jest mocks for SQLite must use mock-sqlite.ts"│
└──────────────────────────────────▲─────────────────────────────────────┘
                                   │ Promoted via Judge/Human (Gate 1)
┌──────────────────────────────────┴─────────────────────────────────────┐
│                       TIER 1: EPHEMERAL MEMORY                         │
│  - Stored: Scoped strictly to task execution run                       │
│  - Content: Crash autopsies, test stack traces, terminal tails         │
│  - Example: "Worker timed out on line 42 of auth.test.ts"              │
└────────────────────────────────────────────────────────────────────────┘
```

- **Tier 1: Ephemeral Memory (Task-Scoped):** Transient runtime telemetry, failure traces, crash autopsies. From v0.2 each record carries a deterministic trace fingerprint (§6.D). Never injected into prompts except as an autopsy note to the *same task's* next attempt.
- **Tier 2: Project Lessons (Repository-Scoped):** Concrete technical rules tied to file globs. Every injection is tracked and resolved to an outcome.
- **Tier 3: Org Invariants (Machine-Global):** Architectural standards applied across projects on the host, filtered by detected tech stack.

---

## 4. Data & Storage Layer

All persistence is local and embedded: SQLite in WAL mode with `PRAGMA busy_timeout = 5000` and `PRAGMA foreign_keys = ON`. Storage needs no server; exactly one process hosts the core (and writes the database) at a time (§10.B).

### A. Repository-Level Schema (`.arbiter/state.db`)

```sql
-- Executable Feature Contracts (PRDs)
CREATE TABLE prds (
    id TEXT PRIMARY KEY,                     -- e.g. "PRD-004"
    title TEXT NOT NULL,
    file_path TEXT NOT NULL,                 -- .arbiter/prds/PRD-004.md
    spec_hash TEXT NOT NULL,                 -- SHA-256 of locked content
    lock_tag TEXT,                           -- signed git tag, e.g. arbiter/prd/PRD-004/v1
    status TEXT NOT NULL CHECK (status IN (
        'draft', 'locked', 'executing', 'completed', 'archived', 'amendment_needed'
    )),
    target_branch TEXT NOT NULL,
    max_budget_usd REAL DEFAULT 5.00,
    spent_usd REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Atomic Tasks
CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    prd_id TEXT NOT NULL,
    title TEXT NOT NULL,
    intent TEXT NOT NULL,                    -- one paragraph, written at planning time
    spec_markdown TEXT,                      -- full spec, written just-in-time when the task becomes 'ready' (§5.1)
    spec_hash TEXT,
    spec_revision INTEGER DEFAULT 0,         -- 0 = not yet specced
    author_seat_id TEXT,                     -- worker seat whose commit is under review; outlives the seat's lease
    status TEXT NOT NULL CHECK (status IN (
        'backlog',        -- dependencies not yet done
        'ready',          -- dependencies done, waiting for a slot (and reservations under Fleet)
        'in_progress',
        'under_review',
        'awaiting_human',
        'integrating',    -- in the integration gate (queued, under Fleet)
        'done',
        'stale',          -- Fleet only: an upstream interface changed; needs re-spec (§12)
        'failed'          -- terminal; set only by the human (§5.8)
    )),
    base_commit TEXT,                        -- feature-branch commit the worktree started from
    submit_commit TEXT,                      -- Arbiter-made snapshot of the slot at worker exit (§5.3)
    worktree_slot INTEGER,                   -- worktree slot (always 0 single-lane)
    upheld_rejections INTEGER DEFAULT 0,     -- only upheld rejections count toward the rejection cap
    attempt INTEGER DEFAULT 0,               -- every agent relaunch for this task, of any kind (§5.8)
    spent_usd REAL DEFAULT 0,                -- sum of invocations.cost_usd for this task
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(prd_id) REFERENCES prds(id)
);

-- DAG edges: task_id cannot start until depends_on is 'done'
CREATE TABLE task_edges (
    task_id TEXT NOT NULL,
    depends_on TEXT NOT NULL,
    PRIMARY KEY (task_id, depends_on),
    CHECK (task_id <> depends_on),
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(depends_on) REFERENCES tasks(id) ON DELETE CASCADE
);
-- Cycle check runs in the supervisor on insert (DFS); the Ringleader's DAG is rejected if cyclic.

-- Symbols a task's spec relies on. Fleet only (§12): single-lane specs are written just-in-time and cannot go stale.
CREATE TABLE task_symbol_deps (
    task_id TEXT NOT NULL,
    symbol TEXT NOT NULL,                    -- e.g. "src/auth/utils.ts#signToken"
    signature_hash TEXT NOT NULL,            -- tree-sitter signature hash when the spec was written
    PRIMARY KEY (task_id, symbol),
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

-- Path reservations. Prefixes compare by whole path segment: "src/auth/" covers "src/auth/token.ts"
-- but not "src/authz/x.ts". Stored with forward slashes and a trailing slash for directories.
-- Populated in single-lane mode too (they drive the submit-time diff check); only contended under Fleet.
CREATE TABLE reservations (
    path_prefix TEXT NOT NULL,
    task_id TEXT NOT NULL,
    acquired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (path_prefix, task_id),
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

-- Ephemeral Memories (Tier 1)
CREATE TABLE task_memories (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    commit_sha TEXT,
    observation_type TEXT CHECK (observation_type IN ('autopsy', 'test_failure', 'execution_log')),
    fingerprint TEXT,                        -- normalized trace fingerprint (§6.D); NULL in v0.1
    root_cause_summary TEXT,                 -- Judge-written natural-language summary
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);
CREATE INDEX idx_task_memories_fp ON task_memories(fingerprint);

-- Project Lessons (Tier 2)
CREATE TABLE project_lessons (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    file_pattern TEXT NOT NULL,              -- e.g. "src/db/**/*.ts"
    context_trigger TEXT NOT NULL,
    rule_markdown TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'review_needed', 'quarantined', 'staged_for_org', 'promoted_to_org')),
    source_fingerprint TEXT,
    source_cluster_count INTEGER DEFAULT 1,
    activated_by TEXT NOT NULL CHECK (activated_by IN ('human', 'judge')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Every time a lesson is placed into a task's context
CREATE TABLE lesson_injections (
    id TEXT PRIMARY KEY,
    lesson_id TEXT NOT NULL,
    lesson_tier TEXT NOT NULL CHECK (lesson_tier IN ('project', 'org')),
    task_id TEXT NOT NULL,
    rank INTEGER NOT NULL,                   -- position in the injected set
    relevance TEXT CHECK (relevance IN ('relevant', 'irrelevant')),  -- set by Judge at verdict
    injected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (lesson_id, task_id),
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- Outcome Ledger: at most one outcome per (lesson, task).
-- Precedence when rows would collide: human > core > judge (a higher author replaces the row).
-- No FK on lesson_id: org lessons live in global_registry.db; lesson_tier says which table to join.
CREATE TABLE lesson_outcomes (
    id TEXT PRIMARY KEY,
    lesson_id TEXT NOT NULL,
    lesson_tier TEXT NOT NULL CHECK (lesson_tier IN ('project', 'org')),
    task_id TEXT NOT NULL,
    seat_id TEXT NOT NULL,                   -- judge seat, 'core', or 'human'
    author_role TEXT NOT NULL CHECK (author_role IN ('human', 'core', 'judge')),
                                             -- core: deterministic rules (§6.A), e.g. fingerprint recurrence
    outcome_type TEXT NOT NULL CHECK (outcome_type IN ('catch', 'miss', 'contradiction')),
    evidence_backed INTEGER NOT NULL DEFAULT 0,
                                             -- 1 for a catch that shows prevention, not just compliance (§6.A)
    description TEXT NOT NULL,               -- Mandatory narrative
    context_diff_or_trace TEXT,
    audit_chain TEXT NOT NULL,               -- pointer into the signed ledger (§8.B)
    audit_seq INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (lesson_id, lesson_tier, task_id)
);

-- Attack-test disputes (§5.4). At most one per task, across all attempts.
CREATE TABLE disputes (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE,
    attack_test_id TEXT NOT NULL,
    worker_seat_id TEXT NOT NULL,
    worker_argument TEXT NOT NULL,
    judge_seat_id TEXT,                      -- a fresh judge seat, never the one that upheld the claim
    ruling TEXT CHECK (ruling IN ('upheld', 'dismissed', 'escalated')),
                                             -- upheld: the worker is right, the attack is dismissed
    ruling_reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- Who an agent is. For agents Arbiter launches this is a descriptor, not a secret.
CREATE TABLE credentials (
    id TEXT PRIMARY KEY,                     -- e.g. "cred:claude-code/claude-opus-5-5", "cred:human/Masked-Kunsiquat"
    kind TEXT NOT NULL CHECK (kind IN ('human', 'agent')),
    harness TEXT,                            -- 'claude-code' | 'cursor' | 'aider' | ...
    model TEXT,
    model_provenance TEXT CHECK (model_provenance IN ('launched', 'claimed')),
                                             -- launched: Arbiter set --model itself; claimed: self-reported by an attached session
    eligible_roles TEXT NOT NULL,            -- JSON array: which roles this credential may be seated as
    secret_hash TEXT,                        -- only for attached (not launched) sessions; NULL otherwise
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Ephemeral, role-bound seats. The seat id is the agent's identity in the ledger.
-- A seat spans one or more invocations (§8.B); the tree stays one node per logical agent.
CREATE TABLE seats (
    id TEXT PRIMARY KEY,                     -- readable + suffix: "PRD-004/TASK-101/worker.2~7f3a"
    role TEXT NOT NULL CHECK (role IN ('ringleader', 'worker', 'adversary', 'judge')),
    task_id TEXT,                            -- bound seats claim their task at creation; NULL for the ringleader
    prd_id TEXT NOT NULL,
    parent_seat_id TEXT,                     -- who minted it → forms the agent tree
    minted_by TEXT NOT NULL,                 -- seat id or 'human'
    credential_id TEXT NOT NULL,
    binding TEXT NOT NULL CHECK (binding IN ('process', 'connection')),
                                             -- process: Arbiter launched it (v0.1); connection: attached MCP session (later)
    harness_session_id TEXT,                 -- harness conversation resumed across invocations (e.g. claude --resume)
    code_hash TEXT,                          -- one-time attach code, only for 'connection' seats
    status TEXT NOT NULL CHECK (status IN ('minted', 'active', 'closed', 'expired', 'revoked')),
                                             -- closed: finished normally; expired: lease ran out (autopsy); revoked: killed by core/human
    code_expires_at DATETIME,                -- attach codes are short-lived (5 min)
    FOREIGN KEY(parent_seat_id) REFERENCES seats(id),
    FOREIGN KEY(credential_id) REFERENCES credentials(id)
);

-- One row per process launch. Leases and supervisor handles live here, not on the seat.
CREATE TABLE invocations (
    id TEXT PRIMARY KEY,
    seat_id TEXT NOT NULL,
    task_id TEXT,
    purpose TEXT NOT NULL,                   -- 'plan' | 'spec' | 'implement' | 'fix' | 'attack' | 'attack_maintenance'
                                             -- | 'claim_check' | 'dispute_ruling' | 'verdict' | 'autopsy_summary'
    supervisor_handle TEXT,                  -- PGID (POSIX) or Job Object name (Windows)
    pid INTEGER,
    lease_expires_at DATETIME,               -- renewed by supervisor observation, not by the model
    exit_reason TEXT CHECK (exit_reason IN ('ok', 'invalid_output', 'crash', 'lease_expired', 'killed')),
    cost_usd REAL,                           -- from the harness's final result event (§9.A); NULL if none arrived (killed)
    cost_estimated INTEGER NOT NULL DEFAULT 0, -- 1 when cost_usd was summed from streamed usage instead (§5.8)
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ended_at DATETIME,
    FOREIGN KEY(seat_id) REFERENCES seats(id)
);

-- Hash-chained, supervisor-signed audit log (§8.B, action catalog in §8.E).
-- One chain per PRD (chain = 'PRD-004'), plus chain = 'global' for entries with no PRD
-- (credentials, org promotions), so each exported ledger file verifies on its own.
CREATE TABLE audit_log (
    v INTEGER NOT NULL DEFAULT 1,            -- ledger format version (§8.B); part of the hash
    chain TEXT NOT NULL,
    seq INTEGER NOT NULL,                    -- 1, 2, 3... within the chain
    task_id TEXT,
    seat_id TEXT NOT NULL,                   -- 'human', 'core', or a seat id; the role is looked up via the seat
    action TEXT NOT NULL,                    -- see §8.E
    payload_json TEXT NOT NULL,              -- hashes + summaries, never secrets or full transcripts
    created_at TEXT NOT NULL,                -- UTC, exactly YYYY-MM-DDTHH:MM:SS.ffffffZ, set by the core (part of the hash)
    prev_hash TEXT NOT NULL,                 -- entry_hash of seq-1 in the same chain; 64 zeros for seq 1
    entry_hash TEXT NOT NULL,                -- hex(sha256(JCS(every other column except supervisor_signature)))
    supervisor_signature TEXT NOT NULL,      -- SSHSIG over entry_hash, namespace arbiter-ledger (§8.B)
    PRIMARY KEY (chain, seq)
);
```

Attestations live in **signed commit trailers** plus a **committed per-PRD ledger file** (§8.D). An earlier draft used git notes; they were dropped because GitHub does not display them and they are not pushed by default.

### B. Machine-Global Registry (`~/.config/arbiter/global_registry.db`)

```sql
CREATE TABLE registered_projects (
    project_id TEXT PRIMARY KEY,
    repo_path TEXT UNIQUE NOT NULL,
    tech_stack_tags TEXT NOT NULL,           -- JSON array, auto-detected from manifests
    last_indexed_at DATETIME
);

CREATE TABLE org_lessons (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    tech_stack_tag TEXT NOT NULL,            -- e.g. "sqlite", "react-native", "caddy"
    file_pattern TEXT NOT NULL,              -- repo-agnostic: extension/basename globs only, e.g. "**/*.sql" (§6.E)
    rule_markdown TEXT NOT NULL,
    origin_project_id TEXT NOT NULL,
    origin_lesson_id TEXT NOT NULL,
    promotion_manifest_hash TEXT NOT NULL,   -- manifest signed by the human (§8.C)
    human_signature TEXT NOT NULL,
    promoted_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 5. Agent Roles & Execution Protocol

### 5.0 The Agent Tree & Knowledge Flow

Every agent is a **seat** (§8.B). Seats are minted top-down, so each PRD run forms a tree:

```
human (cred:human/Masked-Kunsiquat)
└── PRD-004 lock (signed tag)
    └── PRD-004/ringleader.1         cred:claude-code/claude-opus-5-5 (launched)
        ├── TASK-101
        │   ├── worker.1             (expired: lease ran out → autopsy)
        │   ├── worker.2             ← author (3 invocations: implement, fix, fix)
        │   ├── adversary.1          cred:claude-code/claude-sonnet-5 (launched)
        │   ├── judge.1              (claim checks + verdict)
        │   └── judge.2              (dispute ruling: fresh seat for independence)
        └── TASK-102
            ├── worker.1
            ├── adversary.1
            └── judge.1
```

- Seat ids are readable paths plus a random suffix (`PRD-004/TASK-101/worker.2~7f3a`), so the ledger stays legible years later.
- **One node per logical agent.** A seat covers every process launch (invocation) it needs; a fix after a rejection resumes the same seat. New seats appear only for the reasons in §8.B, so the tree stays readable.
- **Only the Ringleader seat or the human can mint seats.** A worker cannot mint an adversary or judge seat to review its own work. This restriction is the core of the no-self-grading guarantee.
- **Independence:** the adversary and judge seats for a task must differ from the author seat, must not descend from it, and should use a different credential (a different model) where one is configured. Authorship is stored on the task (`author_seat_id`), so it outlives the worker's lease.
- **Harness-internal subagents** (for example, Claude Code's own Task tool) run *inside* their parent's seat. Arbiter treats them as the same agent. The tree only contains seats Arbiter minted.

**What each role reads and writes:**

| Role | Reads | Writes | Never |
|---|---|---|---|
| Human | Everything | PRD + amendments, HITL decisions, outcome overrides, Gate 3 | — |
| Ringleader | PRD, code index, lesson summaries | Task plan (tasks, edges, reservations, intents), then each task's spec just-in-time; seat requests (the core mints them) | Code, verdicts, outcomes, lesson selection |
| Worker | Task spec, PRD invariants/boundaries, injected lessons, own prior-attempt autopsy | Working-tree changes (Arbiter commits them) + JSON result | Adversary test files, `.arbiter/**`, outcomes |
| Adversary | Task spec, PRD invariants, the worker's **diff** (not its transcript, to avoid anchoring), injected lessons | Attack-test files only | Application code, outcomes |
| Judge | Evidence bundle (§9.A): spec, diff, attack results, disputes, injections, blast radius | Verdict, claim rulings, dispute rulings, injection resolutions, root-cause summaries, Gate 1 activation | Code, tests |
| Core (deterministic, no LLM) | Everything in `state.db` | Seats, injections (ranking, §6.C), deterministic outcomes (§6.A), ledger | — |
| Synthesizer (deterministic, no LLM) | Tier 1 fingerprints | Gate 1 candidates, precision warnings | Anything in the repo |

**How knowledge moves:**

```
            ┌──────────── downward: ranked injection (§6.C) ─────────────┐
            │                                                            ▼
 Tier 3 Org ◄── Gate 3 (human) ── Tier 2 Project ◄── Gate 1 ── Tier 1 Autopsies/Traces
                                   ▲    │                           ▲
       outcomes (Judge/Core/Human)      └── injected into ──► Worker/Adversary
                                   │                                │
                                   └──────── resolved at verdict ◄──┘  (failures fingerprinted)
```

- Raw telemetry (Tier 1) never reaches another task's prompt. It moves upward only as a Judge-written summary that passes Gate 1.
- Lessons move downward only through ranked, budgeted injection. Every injection is recorded, and every injection comes back as an outcome. That loop is what makes U computable.

### 5.1–5.8 Single-Lane Pipeline (core)

The core runs **one task at a time** in DAG order. Parallel dispatch is the Fleet module (§12).

```
1. Locked PRD ──► Ringleader (Plan → tasks + edges + reservations + one-paragraph intents)
                      │
                      ├── Task touches > 3 files or est. > 15m? ──► Split, or HITL proposal
                      └── Within atomic limits?                 ──► 'backlog' / 'ready'
                                                                        │
┌───────────────────────────────────────────────────────────────────────┘
▼
2. Next 'ready' task in topological order
   - Ringleader writes its full spec now, against the current feature-branch code (just-in-time)
   - Core assembles injected lessons (§6.C); worker/adversary/judge seats minted under the Ringleader
   ▼
3. Worker (worktree slot, process-bound seat)
   - Edits files + unit tests, exits with a JSON result
   - Arbiter snapshots the slot into the submit commit (§5.3)
   - Diff check (boundaries, protected files) ──► reject if violated (counts as an attempt)
   - Build check (build, vet, compile tests)  ──► reject if it fails (counts as an attempt)
   ▼
4. Adversary (separate process) writes attack-test files; Arbiter commits them separately
   ▼
   Unseen-state check (§5.3), then Attack Validation Protocol (§5.4)
   ├── ERROR (test mechanics: build/import/collection, throw site in test code, timeout, flaky)
   │                                            ──► back to Adversary (max 2 regenerations), worker untouched
   ├── ASSERTION_FAIL + claim upheld            ──► back to Worker (counts toward cap of 3); one dispute allowed
   ├── ASSERTION_FAIL + claim rejected          ──► attack dismissed, logged against Adversary
   └── All remaining attacks PASS               ──► Judge
                                                      │
┌─────────────────────────────────────────────────────┘
▼
5. Judge
   ├── Low blast radius  ──► Integration Gate
   └── High blast radius ──► 'awaiting_human' ──► Integration Gate on approval
   (From v0.2: resolves every lesson injection for the task — §6)
   ▼
6. Integration gate: rebase onto feature tip → unseen-state check → full suite + all accumulated attack tests
   ├── Green ──► supervisor-signed squash commit on the feature branch + ledger
   └── Red   ──► routed by failing file (§5.6)

Every relaunch in steps 2–6 increments the task's attempt counter; the ceiling and budget are in §5.8.
```

### 5.1 The Ringleader (Planning, Triage, Replanning)

- High-reasoning model (configurable; harness-agnostic).
- **Plan (once per PRD):** compiles the locked PRD into tasks, `task_edges`, per-task reservation prefixes (each must fall within PRD boundaries), and a one-paragraph `intent` per task. The plan is cheap to review and does not describe code that doesn't exist yet.
- **Spec (just-in-time, once per task):** when a task becomes `ready`, the same Ringleader seat writes its full spec against the *current* feature branch, after every upstream task has merged. The spec references real signatures, not the ones an upstream task was expected to produce. In single-lane mode nothing merges between spec and execution, so a spec cannot go stale; symbol-drift staleness is a Fleet concern (§12).
- **Triage Scope Guard:** no task may reserve more than 3 files (or 1 directory prefix) or exceed ~15 minutes of estimated runtime. Ambiguous decompositions prompt the human.
- **Injection is not the Ringleader's job.** The core assembles each task's context deterministically (PRD invariants plus ranked lessons, §6.C). The Ringleader sees lesson summaries for planning but cannot choose what gets injected, so it cannot bias which lessons collect outcomes.
- **Spec stays inside the PRD:** a spec is validated against the task's reservations and the PRD's boundaries before dispatch. If a spec cannot be written without touching paths outside PRD boundaries, the PRD moves to `amendment_needed`. Specs need **no human signature** because the PRD is unchanged.

### 5.2 Reservations (single-lane)

- The Ringleader declares each task's reservations: path prefixes inside the PRD boundaries.
- In single-lane mode nothing competes for them. They define the scope that the submit-time diff check enforces.
- **Scope expansion (v0.1):** the worker ends its run with `status: scope_request` (§9.A). If the paths are inside the PRD boundaries and the enlarged set still satisfies the Triage Scope Guard, the core grants it and **resumes the same worker seat** (same harness session, worktree left as is) with the enlarged reservation set. Paths outside PRD boundaries, or growth past the guard, send the task to `awaiting_human`. Each grant counts as an attempt (§5.8). From v0.3, attached MCP sessions can call `arbiter_reserve` mid-run instead. Fleet-mode contention rules are in §12.
- The integration gate can also create a scope request automatically (§5.6).

### 5.3 The Worker (Execution Sub-Process)

- Runs in the worktree slot (§7) under a supervisor-managed process container.
- Launched by the Runner with its seat already bound to the process (§8.B). It needs no Arbiter tools in v0.1: it edits files and exits with a result (§9.A).
- **Arbiter commits, not the agent.** When the worker exits, the Runner stages the slot's working tree (`git add -A`) and writes it as one commit whose parent is `base_commit`, using `git commit-tree`. Whatever the agent did with refs (extra commits, amends, rebases, checkouts, other branches) is ignored, and a forgotten commit is not a failure. That commit is `submit_commit`. Its committer is the user's identity, and the author is the seat (`PRD-004/TASK-101/worker.2~7f3a <arbiter@localhost>`).
- **Diff check (the real boundary):** `git diff --no-renames --name-status -z <base_commit> <submit_commit>`. Rename detection is off so a rename shows up as a delete plus an add, and every path on either side is checked:
  - every added or modified path must fall inside the task's reservations;
  - no path, added, modified, or **deleted**, may match `.arbiter/**` or the project's adversary test pattern (§9.C);
  - deny rules compare case-insensitively (on Windows, `.ARBITER/x` and `.arbiter/x` are the same file); allow rules compare case-sensitively.

  A violation rejects the submission deterministically, whatever tools the harness used to produce it. The adversary pattern is a path glob only; there is no content marker, because a worker can delete a marker.
- **Build check:** after the diff check passes, the Runner runs the project's `test.build` command (§9.C; for Go, `go build ./... && go vet ./...` plus compiling the tests without running them, `go test -count=1 -run '^$' ./...`). A failure is a deterministic rejection back to the worker with the compiler output. It counts as an attempt and needs no claim check. Once the worker's code is known to build, any build failure during an attack run belongs to the attack files (§5.4). Without this check, a worker's compile error would surface as an attack failure with no attack behind it.
- **Unseen state (what the diff cannot show):** the diff sees tracked files only. Two kinds of change bypass it and would otherwise carry into the gates:
  1. *Ignored dependency dirs* kept in the warm slot (`node_modules`, `target`, `.venv`, per the keep-list). A worker could patch a dependency until the tests pass.
  2. *`.git` config and hooks*, which linked worktrees share with the main repo. A hook or a `core.fsmonitor` setting would run inside Arbiter's own git commands, including the signed merge.

  Before any agent launch, the Runner records a snapshot: the lockfile hash, plus size and mtime for every file under the keep-list dirs, `.git/config`, and `.git/hooks/`. Before any test run (attack validation and integration gate) it compares against the snapshot. Changed dependency dirs are reinstalled from the lockfile; changed `.git` config or hooks are restored and logged as a violation against the seat. The liveness watcher (§7) already sees these writes, so the common case costs nothing. Separately, every git command Arbiter runs itself passes `-c core.hooksPath=<empty arbiter dir> -c core.fsmonitor=false`.

### 5.4 The Adversarial Reviewer & Attack Validation Protocol

- **Rule:** never modifies application code. It may only add or modify files that match the adversary test pattern (§9.C) inside the PRD boundaries. Arbiter commits them on top of `submit_commit`, and the result is diff-checked like the worker's.
- **Test identity comes from the code and the runner, not the model.** Each attack test's name must encode the INVARIANT or AC it targets, e.g. `TestAttack_INVARIANT_2_RawSQLInRefresh` or `attack INVARIANT-2: raw SQL in refresh`. Targets are extracted with `(INVARIANT|AC)[-_](\d+)`; a test with no parseable target is an ERROR. The Adversary does not list its tests in JSON, so its list and Arbiter's can't disagree.
  - **Which tests are attacks** is decided deterministically from the files matching the adversary pattern. Runner reports don't reliably say which file a test lives in (`go test -json` never does), so for `go-json` Arbiter parses the adversary files (`go/parser`) and takes their top-level `Test*` functions. For JUnit/TAP it uses the report's file attribute where present. This list is also what reveals an attack that never ran.
  - **Results** come from the runner's machine-readable report (`go test -json`, JUnit XML, or TAP; §9.C).
- **One attack per run.** A panic or timeout kills the whole test process, so every later attack in the same package or file would never run and leave no trace. Attacks are therefore executed one at a time, each with its own timeout (`limits.attack_timeout_seconds`). For Go: build each affected package's test binary once (`go test -c -o <pkg>.test`), then run `<pkg>.test -test.run '^Name$' -test.timeout <t> -test.count=1 -test.v=test2json` with cwd set to the package directory, piped through `go tool test2json -p <pkg>`. Other ecosystems use their single-test selector (`jest -t`, `pytest <file>::<name>`).
- **A run with no terminal event is still a result.** A test that started but has no pass/fail event, while the process failed, crashed under that test (goroutine panics and timeouts in Go look like this). It is classified by its panic output or as a timeout, using the process exit code, not the report, as the failure signal.

**Classification: by where the failure comes from, not by the runner's label.** Runners disagree about what an "error" is. Jest and pytest both report a `TypeError` from calling a made-up API *inside the test body* as an ordinary failure, and in Go a single broken `_test.go` file fails the whole package's build. So each attack result is classified by these rules, applied in order:

1. **ERROR: build, import, or collection failure.** Application code already passed the build check (§5.3), so a build failure during an attack run belongs to the attack files. Build failures carry no test ids (in Go they arrive as `build-output` events keyed by import path, before any test runs), so they are classified **per file**: every attack in an affected file or package gets the same ERROR, with the compiler output. Only primary error lines (`file:line:col: message`) name the culprit file; indented note lines such as "other declaration of X" may point at application code and are ignored.
2. **ERROR: timeout.**
3. **ERROR: throw site in test code.** The failure is not an assertion-library failure, and the top in-repo stack frame is in an adversary file or any other test file. That includes a test helper the worker wrote: the attack chose to depend on it. Stack frames are extracted with the same normalizer as §6.D.
4. **Candidate ASSERTION_FAIL:** an assertion-library failure (testify, `t.Error`/`t.Fatal`, `expect`, `assert`), or an exception whose top in-repo frame is in non-test code.
5. **Reproduction:** each candidate is rerun once, with the same single-test command. If it passes on the rerun it is **ERROR (flaky)** and is not kept. Because every run is already isolated, a pass on rerun can't be an ordering effect between attacks.

Outcomes:

- **ERROR** is evidence about the *test*, not the code. Erroring tests go back to the Adversary with their output (max 2 regenerations) and don't touch the worker's counts. Tests still erroring after the second regeneration are **dropped** (for build failures, the offending files are removed from the attack commit), logged against the Adversary, and the review continues with the rest. If no valid attack remains, the task skips the automatic path and goes to `awaiting_human` with "no adversarial coverage", whatever the blast radius.
- **ASSERTION_FAIL** is a candidate defect. The Judge performs a **claim check**: does the cited invariant/AC actually require the asserted behavior? Upheld → rejection to the Worker with the trace and the test. Not upheld → attack dismissed and logged against the Adversary.
- **PASS:** no defect found by this attack.

**Across attempts.** When the worker resubmits after an upheld rejection:

- Every earlier attack (kept and upheld) is rerun deterministically; the upheld ones must now pass.
- The same Adversary seat gets one pass over the **incremental** diff only (previous `submit_commit` → new one). It can't restart the review from scratch, which would give the worker a moving target, but a fix doesn't go unreviewed either.

**Worker dispute (once per task).** When resumed with an upheld rejection, the worker may return `dispute: {attack_test_id, argument}` in its result instead of a fix (§9.A). Code changes from a disputing run are discarded. A **fresh judge seat** (not the one that upheld the claim; a different credential if configured) rules `upheld` (the worker is right, attack dismissed, rejection no longer counts), `dismissed` (the rejection stands, and the worker is resumed to fix it), or `escalated` (goes to the human). There's no numeric confidence: the Judge picks one of the three.

- **Rejection cap:** the worker gets at most 3 **upheld** rejections, then the task goes to `awaiting_human`. The overall attempt ceiling (§5.8) applies too.
- **Terminology:** a failing attack test is *evidence* of a defect, not proof. Proof comes only from an upheld claim.
- **Dismissed attacks** are counted per adversary credential (`arbiter seats --stats`), so you can see which model writes bad attacks. They carry no other penalty.
- Passing attack tests are kept. They join the PRD's regression suite that the integration gate runs (§5.6).

### 5.5 The Judge (Neutral Arbiter)

- Evaluates the evidence bundle (§9.A): worker diff, attack results, the frozen spec, and the blast radius.
- **Blast radius is computed by the core, not judged.** The Judge may escalate a low-radius task to `awaiting_human`, but it can never approve a high-radius task on its own.
  - **v0.1 (path-based):** high if the diff touches any `high_risk` glob in project config (§9.C: migrations, auth config, root schema, CI files), or any §13 protected path. Otherwise low. (Paths outside the task's reservations never reach the Judge; the diff check has already rejected them.)
  - **v0.2+ (symbol-based):** adds tree-sitter: exported-signature changes consumed outside the task's reservations are high. Tree-sitter's Go bindings need cgo, so taking them on in v0.2 is a deliberate decision; v0.1 stays cgo-free.
- Rules on attack claims (§5.4). Dispute rulings go to a fresh judge seat.
- From v0.2: **resolves every lesson injection** for the task at verdict time (§6.A).
- Writes Tier 1 root-cause summaries for autopsies (an `autopsy_summary` invocation of the task's judge seat, minted on demand if needed).

### 5.6 Integration Gate

Even one task at a time, a task tested against only its own tests can break earlier work. Before any merge:

1. Rebase the task's commits (worker submit + attack tests) onto the current feature-branch tip. A conflict resumes the worker seat with a rebase instruction; it does not count as a rejection but does count as an attempt. Conflicts are rare single-lane, routine under Fleet.
2. Unseen-state check (§5.3).
3. Run the full test suite **plus every accumulated attack test for the PRD**. Each failing test is rerun once; a test that then passes is reported as flaky and does not block, but is flagged for the human.
4. **Green** → create **one supervisor-signed squash commit** on the feature branch: worker changes + attack tests + the ledger update, with attribution trailers (§8.D). The feature branch moves to it (`update-ref`); the task's intermediate commits are not kept on the branch.
5. **Red** → route each failure by the file where it originates (top in-repo frame or build error location):

| Failure is in | Goes to | Why |
|---|---|---|
| The task's own reservations | Worker seat (resume, with the failing output) | The worker can fix it |
| An adversary test file (e.g. an earlier task's attack test still calls a signature this task legitimately changed) | **Attack maintenance**: the *current* task's adversary seat (the file's original seat closed with its task) updates the test to the new interface without weakening its assertion; the Judge checks the diff for weakened assertions | The worker may not touch adversary files |
| Another non-adversary path inside PRD boundaries | Automatic scope request for that path (§5.2), then the worker | The worker needs the path reserved first |
| Outside PRD boundaries | `awaiting_human` | Probably needs a PRD amendment |

Every red counts as an attempt (§5.8), so this loop always terminates. Under Fleet the gate becomes a serialized merge queue (§12).

### 5.7 Human in the Loop (HITL)

```
[JUDGE VERDICT: READY FOR HUMAN REVIEW]
Task: AUTH-102 (Rotate refresh tokens) | Parent: PRD-004
Worker: Done (14 tests passed)
Adversary: 5 attacks passed (INVARIANT-1, INVARIANT-2); 1 dismissed (claim not upheld)
Blast Radius: Touches 2 critical files in src/auth; changes signature of signToken()

[A]pprove   [R]etry with note   [F]ail task   [P]RD amendment   [I]nspect Diff   [S]hell into worktree
> _
```

- Approvals are keypresses recorded in the audit log, not SSH signatures. The human's signature on the final feature → main merge covers them.
- Retries send the task back to the worker, count as upheld rejections, and prompt for an optional lesson outcome (v0.2+). The other exits are defined in §5.8.

### 5.8 Attempts, Budget & Terminal States

Every retry path has one shared bound.

- **Attempt ceiling:** every agent relaunch for a task increments `tasks.attempt`, whatever the reason: diff-check rejection, upheld rejection, integration red, rebase conflict, crash or lease expiry, granted scope request, invalid-output retry. At `attempt > max_attempts` (default 6, set in project config) the task goes to `awaiting_human`. The narrower caps (3 upheld rejections, 2 adversary regenerations, 1 schema retry) still apply inside it.
- **Budget:** each invocation records `cost_usd` from the harness's final result event (§9.A). Task spend and PRD spend (`prds.spent_usd`) are sums of that. Before every launch the core checks `prds.spent_usd < max_budget_usd`; if the budget is used up, the task goes to `awaiting_human` and nothing new launches for that PRD. On subscription plans the reported cost is notional but still works as a relative brake.
  - **The harness enforces the cap too.** Every launch passes `--max-budget-usd <max_budget_usd − prds.spent_usd>`, so a runaway invocation stops mid-run instead of being noticed at exit.
  - **Killed invocations report no cost.** A process stopped by lease expiry, `Terminate`, or a crash emits no `result` event. The core then sums the per-message `usage` from the streamed `assistant` events against a model price table, stores that as `cost_usd`, and sets `invocations.cost_estimated = 1`. If even that is unavailable, `cost_usd` stays NULL and the ledger `exit` entry records `null`. The budget check counts estimates and treats a NULL as unknown, flagged to the human at the next HITL prompt.
- **Ways out of `awaiting_human`** (the HITL prompt, §5.7):
  - **Approve**: continue to the next step (integration gate, or the verdict for "no adversarial coverage").
  - **Retry with note**: resume the worker seat with the note; counts as an upheld rejection, and resets `attempt` to 0 once so the human can buy more tries.
  - **Fail task**: sets `failed`, which is terminal. Downstream tasks stay in `backlog`, and the PRD can't complete until you amend it (removing or replacing the task) or reset the task.
  - **Amend PRD**: moves the PRD to `amendment_needed`; you edit it and re-sign it (`arbiter prd amend`), and the Ringleader re-plans tasks that aren't done yet.
- **PRD completion:** when every task is `done`, the PRD becomes `completed` and `arbiter prd review` offers the final signed merge to main. It moves to `archived` after that merge lands.

---

## 6. Epistemic Gates & Outcome Telemetry

```
[ Raw Memories (fingerprinted) ]
       │
       ▼  GATE 1: Candidate Activation (same fingerprint in >= 2 distinct tasks + Judge/Human sign-off + conflict check)
[ Active Project Lesson ]
       │
       ▼  GATE 2: Efficacy Threshold (U >= 0.80, relevant samples >= 5 distinct tasks, Contradictions == 0,
       │          >= 1 evidence-backed catch)
[ Staged for Org Promotion ]
       │
       ▼  GATE 3: Human SSH Signature (batched manifest)
[ Global Org Invariant ]
```

### 6.A Outcome Resolution (automatic miss/catch attribution)

Misses and catches are not left to manual bookkeeping. When the Judge renders a verdict, it resolves **every** `lesson_injections` row for the task:

| Resolution | Meaning | Effect |
|---|---|---|
| `irrelevant` | The diff never touched the lesson's concern | Excluded from U; lowers precision P |
| `catch` | The concern came up and the final code complies | +1.0 |
| `catch` (evidence-backed) | The lesson was cited in an upheld rejection and the next submission fixed it, or a human logged the catch | +1.0, and sets `evidence_backed = 1` |
| `miss` | The concern came up and a defect in that area still reached the Adversary, Judge, integration gate, or human | −1.5 |
| `contradiction` | Following the lesson caused a failure, or the lesson is wrong for this code | −3.0 |

- **Compliance is not prevention.** A plain `catch` only shows the code agreed with the lesson; the model may have complied anyway. Rules it already follows ("use parameterized queries") would otherwise pile up catches and get promoted as no-ops, and judges of the same model that wrote the lesson would keep confirming it. So plain catches count toward U, but Gate 2 also requires at least one evidence-backed catch (§6.E).
- **Deterministic misses (author `core`).** If a lesson's `source_fingerprint` shows up again in any failure (attack, integration red, autopsy) in a task it was injected into, the core records that injection as `relevant` + `miss` itself, before the Judge runs. The Judge cannot mark it `irrelevant`; only a human override can. This closes the easiest way to hide a miss.
- **Only the Judge, the core, and the human author outcomes.** The Adversary does not: it would be grading its own tests. An attack test may name a lesson in its test name as evidence, and the Judge weighs it. The **worker role cannot author outcomes** either. This replaces v1's per-key "no self-endorsement" rule.
- **Post-merge misses** (a bug found in production weeks later) are optional: `arbiter lesson outcome <id> --miss --task <task-id> -m "..."` overrides the entry for that task at human weight. U is designed to work without them.
- **Org lessons** are resolved like project lessons (`lesson_tier = 'org'`). Their outcomes stay in each project's `state.db`; `arbiter org stage` rolls them up across registered projects.

### 6.B The Utility Formula

The original formulation:

$$U = \frac{C - 1.5M - 3.0X}{N_{\text{injections}}}$$

This has two problems. (1) Most injections do not touch the lesson's concern, so a correct lesson with a broad glob can never reach 0.80. The metric ends up measuring relevance × efficacy. (2) The signer weights from v1 (human 1.0, judge 0.7) are not applied.

**Formula (since v2).** Over resolved **relevant** injections only, with signer weight $w$ (human and core 1.0, judge 0.7) and shrinkage constant $k = 1$:

$$U = \frac{\sum w_i\,[\text{catch}_i] \;-\; 1.5\sum w_i\,[\text{miss}_i] \;-\; 3.0\sum w_i\,[\text{contradiction}_i]}{\sum w_i \;+\; k}$$

Plain text: `U = (Σw·catch − 1.5·Σw·miss − 3.0·Σw·contradiction) / (Σw + k)`

- With equal weights and `k = 0`, this reduces to the original formula restricted to relevant injections.
- `k` keeps small samples from scoring as perfect: 3 catches alone never reach 0.80.
- Range is (−3, 1). Uniqueness on `(lesson_id, lesson_tier, task_id)` keeps it bounded.
- When every outcome has the same weight, `w` cancels between numerator and denominator except against `k`. In effect, judge-only evidence just needs more samples (acting like `k ≈ 1.43`); mixed evidence counts human and core entries more.
- Break-even for Gate 2: ignoring `k`, U ≥ 0.80 needs C ≥ 11.5·M. A lesson must be right about 92% of the time it matters.
- **Precision** `P = relevant / total injections` is tracked separately. When P < 0.3 over ≥ 10 injections, the synthesizer proposes a narrower `file_pattern`.

Worked examples (judge-signed, w = 0.7):

| Catches | Misses | U | Gate 2 |
|---|---|---|---|
| 5 | 0 | 3.5 / 4.5 = 0.78 | ✗ |
| 6 | 0 | 4.2 / 5.2 = 0.81 | ✓ |
| 5 (human, w=1.0) | 0 | 5 / 6 = 0.83 | ✓ |
| 12 | 1 | 7.35 / 10.1 = 0.73 | ✗ |
| 20 | 1 | 12.95 / 15.7 = 0.82 | ✓ |
| any | any, with ≥1 contradiction | — | ✗ (hard rule) |
| any | any, with no evidence-backed catch | — | ✗ (hard rule) |

Because Gate 2 already requires zero contradictions, the −3.0 weight matters mainly for **injection ranking** (§6.C). There, a single contradiction drops a lesson below any new lesson of the same specificity, and out of injection entirely unless it has several catches behind it, well before the circuit breaker quarantines it at two.

### 6.C Injection Ranking & Context Budget

The **core** assembles injections deterministically; no agent chooses them.

- **Candidates:** project lessons whose `file_pattern` overlaps any of the task's reservations, plus org lessons whose `tech_stack_tag` is in the project's detected stack and whose (repo-agnostic) `file_pattern` overlaps a reservation. Quarantined lessons are never candidates.
- **Overlap** between a reservation prefix and a glob: the glob matches at least one tracked file under the prefix at the task's `base_commit`, or, when no files match yet, the glob's literal leading segments and the prefix are segment-prefixes of each other.
- **Ranking score:** `score = specificity × U_rank`, where
  - `specificity = 1 + (number of literal, non-wildcard path segments)`, so `**/*.sql` scores 1 rather than 0, and `src/db/**/*.ts` scores 3;
  - `U_rank = (Σw·catch − 1.5·Σw·miss − 3.0·Σw·contradiction + 0.5·k) / (Σw + k)`: the §6.B formula with a prior of 0.5 in place of v2's `max(U, 0.5)` floor. A new lesson scores 0.5. A lesson with 5 judge catches and 1 contradiction scores 0.37. A lesson contradicted on its first relevant use scores −0.94. The old floor gave all three the same 0.5.
  - Lessons with `U_rank < 0` are not injected. Gate 2 uses the §6.B formula without the prior.
- Inject the top lessons until a **token budget** (default 1,500 tokens, max 8 lessons) is hit. Ties break by lesson id so ranking is reproducible. Everything injected is recorded in `lesson_injections`.
- **Conflicts:** at Gate 1, the Judge compares a candidate against active lessons with overlapping patterns. A suspected conflict goes to the human instead of auto-activating.

### 6.D Trace Fingerprinting (Gate 1 clustering)

Raw stack traces embed poorly: most `TypeError: Cannot read properties of undefined` traces look alike. Gate 1 therefore clusters deterministically first, the way crash reporters group errors:

1. **Normalize:** strip line/column numbers, hex addresses, absolute paths (→ repo-relative), temp dirs, timestamps, UUIDs, and numeric literals in messages.
2. **Fingerprint** = `sha256(error_class | top in-repo frame (file#function) | failing test id)`.
3. **Candidate** = same fingerprint in ≥ 2 distinct tasks.
4. The Judge's natural-language `root_cause_summary` is what becomes the lesson text. Embedding-based clustering of *summaries* (not raw traces) is an optional v0.3 addition for cross-fingerprint grouping.

### 6.E The Three Knowledge Gates

- **Gate 1 (Memory → Project Lesson):** fingerprint cluster ≥ 2 distinct tasks, conflict check passes, activated by Judge or human.
- **Gate 2 (Project → Org Staging):** ≥ 5 distinct relevant tasks, U ≥ 0.80, zero contradictions, and at least one evidence-backed catch (§6.A). Status becomes `staged_for_org`.
- **Gate 3 (Org Invariant):** the human signs a promotion manifest (§8.C). Each staged lesson's `file_pattern` must be rewritten to be repo-agnostic, using only extension or basename globs such as `**/*.sql` or `**/migrations/*.sql`. Paths like `src/db/**` mean nothing in another repo, and the manifest step rejects them. Agents cannot write to `global_registry.db`.

### 6.F Contradiction Circuit Breaker

Any project lesson with ≥ 2 contradictions is immediately `quarantined`: it stops being injected and is flagged for human review. An org lesson with ≥ 2 contradictions summed across registered projects stops being injected everywhere and is flagged for human review.

---

## 7. Process Control, Worktrees, Autopsies & Leases

### Process Supervision (cross-platform)

All sub-processes (every agent role, test runners, installs) are launched through a `Supervisor` interface:

```go
type Supervisor interface {
    Spawn(cmd Cmd) (Handle, error)                  // starts the process inside a kill-able container
    Terminate(h Handle, grace time.Duration) error  // graceful signal, then hard kill of the whole tree
}
```

| | Windows | Linux | macOS |
|---|---|---|---|
| Container | Job Object (`CreateJobObject`) | Process group (`Setpgid`) | Process group (`Setpgid`) |
| Spawn flags | `CREATE_SUSPENDED \| CREATE_NEW_PROCESS_GROUP \| CREATE_NO_WINDOW` | `Setpgid` | `Setpgid` |
| Spawn race | Create suspended, assign to job, then resume, so no grandchild escapes. Go's `os/exec` drops the main-thread handle, so resume via a Toolhelp thread snapshot (`TH32CS_SNAPTHREAD` → `ResumeThread`), or create the process directly inside the job with `PROC_THREAD_ATTRIBUTE_JOB_LIST` | n/a | n/a |
| Graceful stop | `CTRL_BREAK_EVENT`, sent by a helper process (`arbiter _ctrlbreak <group> [<attach>...]`: `FreeConsole` → `AttachConsole` → `GenerateConsoleCtrlEvent`), never by the supervisor itself | `kill -TERM -<pgid>` | `kill -TERM -<pgid>` |
| Hard kill | `TerminateJobObject` | `kill -KILL -<pgid>` | `kill -KILL -<pgid>` |
| Supervisor-death cleanup | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: the OS kills the job when the supervisor's handle closes | `PR_SET_PDEATHSIG` configured by `supervisor.start` when launching the group-leader shim (`arbiter _pgshim`), with the supervisor goroutine remaining pinned via `runtime.LockOSThread()` through `watch` (plain `PDEATHSIG` only reaches the direct child). On receiving the death signal, the shim kills its whole process group (`kill -KILL -<pgid>`); it reports program exit status over an fd-3 pipe and anchors the PGID until teardown | No PDEATHSIG; a tiny shim polls `getppid()` / kqueue `NOTE_EXIT` and kills its group |

- **Why the break goes through a helper.** `CTRL_BREAK_EVENT` only reaches a process group attached to the *caller's* console. A console-less supervisor (`arbiter serve`, a background launch) gets "handle is invalid". A child with its own console (`CREATE_NO_WINDOW`, which stops a console window popping up for every agent) gets nothing, *and the call still reports success*. Attaching to the child's console detaches the caller from its own and is process-global, so it runs in a short-lived helper (`arbiter _ctrlbreak <group> [<attach>...]`). If the leader process has already exited, `AttachConsole(pid)` on its PID fails, and a group ID whose leader is gone reaches nobody; the helper accepts candidate job member PIDs to attach through (skipping `conhost.exe`, which cannot be attached through) and signals group 0 (all processes on that console).
- **Linux process group plus a shim.** `PR_SET_PDEATHSIG` only reaches the direct child; if the program is killed or exits, any background processes its shell launched keep running. Arbiter runs the program under `arbiter _pgshim` as group leader. When launching the shim, `supervisor.start` configures `PR_SET_PDEATHSIG` and keeps the supervisor goroutine pinned to its OS thread with `runtime.LockOSThread()` through `watch` so thread exit does not prematurely trigger the signal. On receiving the death signal, the shim kills its whole process group (`kill -KILL -<pgid>`). The shim ignores graceful `SIGTERM` (which reaches the program directly via the group signal), reports the program's exit status over a pipe (fd 3), and remains alive as the group anchor until teardown's group kill. This ensures supervisor-death cleanup covers processes left behind after program exit, and prevents PGID recycling before `Terminate` signals the group. The helper defaults to `/proc/self/exe` so it survives binary replacement during upgrades.
- **`Terminate(h, grace)` always ends in a hard kill:** send the graceful signal, wait up to `grace` (exiting early once the container is empty), then send `TerminateJobObject` / `kill -KILL -<pgid>` regardless. Both hard kills are asynchronous, so `Terminate` waits (bounded) for the container to actually empty before reaping the leader and releasing the container/closing the job handle; otherwise dying processes could appear as false strays in the post-run scan. `Terminate` returns an error if the hard kill fails or the container fails to empty. The graceful signal is best effort and can silently not arrive.
- **What's in the container.** `claude.exe` is a single native binary; its tree is whatever its shell tools start (powershell/cmd/bash and their commands) plus `conhost.exe`.
- **Containment is cleanup, not a sandbox.** Children can't break away from the job (`CREATE_BREAKAWAY_FROM_JOB` is denied), but a process started *through a system service* is not the job's child: WMI (`Win32_Process.Create`), the Task Scheduler, or a service can start processes that survive `TerminateJobObject`, without admin rights. After every invocation the Runner scans for live processes whose command line or working directory contains the slot path and logs any as a violation against the seat (§8.A).

### Warm Worktree Slot

Fresh worktrees per task would mean `npm install` / `cargo build` every time. Instead:

- Single-lane uses one persistent worktree (`.arbiter/worktrees/slot-0`). Fleet extends this to a pool of N slots (§12).
- Between tasks, the slot is reset with `git checkout --detach <base> && git clean -fdx -e node_modules -e target -e .venv ...` (per-ecosystem keep-list), so dependency directories survive.
- Dependencies reinstall only when the lockfile hash differs from the slot's last install, **or** when the unseen-state check (§5.3) finds the keep-list dirs changed during an agent run. Keeping these dirs is a speed optimization and must never let one task's edits leak into the next task's tests.
- Shared caches: pnpm store, `GOCACHE`, `sccache`; per-slot `CARGO_TARGET_DIR`.
- Windows: recommend placing the repo on a Dev Drive (ReFS) for faster I/O and copy-on-write.

### Liveness & Leases

- Liveness = process alive **and** activity within the last 120s. Activity means a stdout event or a worktree fs write. Harnesses run with streaming output (§9.A), so a role that only reads and thinks (Ringleader, Judge) still emits an event per turn or tool call, and Claude Code emits a `system/thinking_tokens` event about once a second while the model thinks. With buffered JSON output it would look dead until it exited. The supervisor observes all of this itself; the model never has to heartbeat.
  - A long single generation with thinking off could still go quiet for its whole length. If that trips the 120s rule in practice, launch with `--include-partial-messages`, which streams per-chunk deltas.
- Leases belong to invocations (§4, `invocations.lease_expires_at`). Standard lease: 15 minutes, renewed automatically while the process is live and active, up to an absolute ceiling (default 60 minutes). Test runs launched by the Runner pause the lease clock.
- **Expiry kills, it doesn't error.** When a lease ends, the supervisor terminates the process and runs the autopsy. The model is never handed an "expired" error it might try to work around.
- `awaiting_human` freezes all timers.

### Automated Crash Autopsy

When an agent times out or crashes:

1. `Terminate` the container, and record the invocation's cost from streamed usage (§5.8), since a killed harness emits no `result` event.
2. Capture the last 50 lines of stdout/stderr and `git diff`. From v0.2, also compute the trace fingerprint (§6.D).
3. Evaluate progress deterministically: if the diff is non-empty **and** the project builds/type-checks → checkpoint commit (`checkpoint/<task>/attempt-N`), and the next seat starts from it. Otherwise `git reset --hard <base_commit>`.
4. The seat is marked `expired` (lease) or `revoked` (crash), and the Judge writes a one-line root-cause summary into the autopsy memory (an `autopsy_summary` invocation).
5. A **new** worker seat with a fresh harness session gets the next attempt, with this in its prompt: *"WARNING: Previous attempt failed with <summary>. Do NOT repeat that approach."* Resuming the crashed session would carry the failed approach forward in context.

---

## 8. Identity, Signing & Threat Model

### 8.A Threat Model

Everything runs locally as one OS user. Any process running as that user can read memory, env vars, and files. Cryptography cannot stop a hostile local process, and this spec does not claim otherwise.

**Defended against:**
1. *Agent overreach:* scope creep, editing tests to pass (including patching ignored dependency dirs or planting git hooks), touching the PRD, self-grading. Enforced by submit-time diff checks, the unseen-state check (§5.3), per-role tool profiles (§9.A), planner-only seat minting, and role-restricted outcome authoring.
2. *Confused or prompt-injected agents* acting outside their role through Arbiter's own APIs. Seats are role- and task-bound and end with the task.
3. *After-the-fact tampering* with history, attribution, or the outcome ledger: hash-chained ledger, signed commits and tags.
4. *A compromised or remote core forging your approval:* the core never holds your key; human signatures are always produced client-side (§8.C).

**Not defended against (through v0.3):** a malicious process with the user's privileges, or an agent using its harness shell to exfiltrate data or damage files outside the repo. Nor an agent leaving processes behind: Job Objects and process groups clean up cooperative trees, but a process started through WMI, the Task Scheduler, or a service is outside the container and survives the hard kill (§7). The post-run scan detects the obvious cases; it doesn't prevent them. Real containment needs an OS sandbox (container, Windows Sandbox, bubblewrap, Seatbelt). That is future work (§11).

### 8.B Agent Identity: Credentials & Seats

v1's per-agent ephemeral Ed25519 keypairs are **removed**. The supervisor held every private key, so a signature only proved which IPC connection asked for it. Identity follows Graphban's credentials-and-seats shape, with one important change: **identity never passes through the model.** Graphban puts the seat code in the agent's instructions and relies on the model calling `register_agent` with it. That makes identity probabilistic: the model can forget, mistype, re-register, or lose the code to context compaction.

- **Credential:** what kind of agent this is, e.g. `cred:claude-code/claude-opus-5-5`, plus one for the human. For agents Arbiter launches, a credential is a **descriptor, not a secret**: the Runner knows which harness and `--model` it started, so `model_provenance = launched`. Secrets exist only for sessions attached from outside (v0.3+), whose model name is `claimed`.
- **Seat:** an ephemeral, role-bound identity for one task, e.g. `PRD-004/TASK-101/worker.2~7f3a`. It answers *"who did this, in what role, under whom?"*
- **Seats and invocations:** a seat is one logical agent; an **invocation** is one process launch (§4 `invocations`). A seat usually has several invocations. The worker's implement and fix runs resume the same harness session (`claude -p --resume <harness_session_id>`) so feedback lands in context. The judge's claim checks and verdict run under one judge seat. The Ringleader's plan and every just-in-time spec run under one Ringleader seat. A **new seat** is minted only when:
  1. the previous seat ended abnormally (crash or lease expiry): fresh session plus autopsy (§7);
  2. independence requires it: dispute rulings get a fresh judge seat (§5.4);
  3. the task's first invocation of that role, or a human reset.

  Seats become `closed` when their task reaches `done` or `failed`.
- **Binding:**
  - `process` (v0.1): the Runner launches the harness for the seat. Every git commit and result from that process belongs to the seat. There is no token for the model to see, leak, or lose.
  - `connection` (v0.3+, MCP): the Runner writes a per-seat MCP config for the harness it launches, with the seat token in an env var (stdio) or `Authorization` header (HTTP). The token authenticates every call and never enters the prompt. For a session you attach by hand, you run `arbiter seat attach`, which prints a one-time code (5-minute TTL) to put in *your* MCP config, not in a prompt.
- **Minting rule:** only the Ringleader seat or the human can request seats; the core mints them. Workers, adversaries, and judges cannot. Every seat records `parent_seat_id`, which is how the agent tree in §5.0 is built.
- **Role-filtered tools:** when MCP arrives, `tools/list` returns only the seat's role's tools. A worker never sees `verdict`, so it can't waste turns trying it.
- **Leases:** codes expire fast (they're used immediately); each invocation's lease is renewed by supervisor observation (§7). On expiry the process is killed and the seat is marked `expired`. Seat ids stay in the ledger permanently. Secrets (attach codes, tokens) never enter the ledger or the repo.
- **Supervisor key:** one Ed25519 SSH signing key held by the core (`~/.config/arbiter/`, optionally the OS keychain or an SSH agent). It signs ledger entries and the task-level commits described in §8.D. Ed25519 signatures are deterministic, so the same entry signs to the same bytes on every platform.
- **Hash chain (ledger format v1):** `entry_hash = hex(sha256(JCS(entry)))`, where `entry` is the row as a JSON object with every column except `entry_hash` and `supervisor_signature`: `v`, `chain`, `seq`, `task_id` (`null` when absent), `seat_id`, `action`, `payload_json` (as parsed JSON), `created_at`, and `prev_hash`. `prev_hash` is the previous entry's `entry_hash` (lowercase hex), 64 zeros for `seq = 1`; it links the chain from *inside* the hashed object, so nothing is concatenated outside it. `JCS` is RFC 8785 JSON canonicalization. There is one chain per PRD (`chain = 'PRD-004'`) plus a `global` chain, so each exported ledger file verifies on its own.
  - **Pinned details:** `v` is `1` on every entry from the first one. `created_at` is UTC in exactly `YYYY-MM-DDTHH:MM:SS.ffffffZ` form. Payload numbers must be exactly representable as IEEE-754 doubles (integers within ±2^53); anything else is rejected at write time, never rounded.
  - **Signature:** OpenSSH SSHSIG (the `ssh-keygen -Y sign` format), namespace `arbiter-ledger` (distinct from git's `git`, so a ledger signature can't be replayed as a commit signature), over the message = the 64-character `entry_hash` with no newline. Stored armored: 70-column base64 lines, LF endings, no trailing newline. It checks with `ssh-keygen -Y verify -n arbiter-ledger`.
  - **What it detects:** editing, re-attributing, reordering, or deleting any entry *before the last one*. Removing entries from the end leaves a shorter valid chain; that is detected only against a head pinned elsewhere, the `Arbiter-Ledger` trailer of a signed commit (§8.D). Entries written after the last signed task commit are not pinned by anything yet.
  - **Frozen:** this format is frozen once the first ledger is committed. Any change bumps `v`, and verifiers keep accepting every earlier version. Never a silent rehash.

### 8.C Human Signatures (git-native, minimal prompts)

Human authority uses git's native SSH signing (`git config gpg.format ssh`, `user.signingkey`, an `allowed_signers` file) and `ssh-keygen -Y sign/verify`. It works with ssh-agent, YubiKeys, and 1Password's SSH agent.

**Signing is always client-side.** The core never holds your key. It prepares the object to sign (tag, merge commit, promotion manifest), your CLI signs it locally, and sends the signature back. This works the same whether the core is on your laptop or a server (§10).

Signatures are required **only** for:

| Action | Mechanism | Frequency |
|---|---|---|
| PRD lock | Signed tag `arbiter/prd/<id>/v<n>` | 1 per feature |
| PRD amendment (invariants / boundaries / ACs) | New signed tag `v<n+1>` | Rare |
| Final feature → main merge | Signed merge commit | 1 per feature |
| Org promotion | One signature over a manifest listing all staged lessons | 1 per batch |

Task-level merges into the feature branch are signed automatically by the **supervisor key** (§8.D), with no prompt. HITL approvals are keypresses recorded in the ledger. Typical cost: about 2 human signature prompts per feature.

### 8.D Attribution You Can Verify on GitHub

Goal: years later, someone looking at a commit on GitHub can tell which agents, in which roles, produced and approved it, and check that the record wasn't rewritten.

**1. Signed commits with trailers.** Every task merge is one squash commit (§5.6) signed by the supervisor key, which you register on GitHub as an SSH *signing* key (e.g. titled `arbiter@<hostname>`). GitHub only shows **Verified** when the *committer* email is a verified email on the account that owns the signing key. So the committer is always you (your `user.email`), and the agents appear in the author field and the trailers. The commit message carries trailers:

```
auth: rotate refresh tokens on /auth/refresh

Arbiter-PRD: PRD-004@v1 (tag arbiter/prd/PRD-004/v1)
Arbiter-Task: TASK-101 (spec rev 2)
Arbiter-Worker: PRD-004/TASK-101/worker.2~7f3a cred:claude-code/claude-opus-5-5 (launched)
Arbiter-Adversary: PRD-004/TASK-101/adversary.1~b20c cred:claude-code/claude-sonnet-5 (5 attacks, 0 upheld)
Arbiter-Judge: PRD-004/TASK-101/judge.1~e91d cred:claude-code/claude-opus-5-5 (verdict: low-risk)
Arbiter-Approved-By: human:Masked-Kunsiquat          (only when the task went through HITL)
Arbiter-Ledger: .arbiter/ledger/PRD-004.jsonl#seq=148 sha256:9c1e...
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

The signature covers the trailers, so attribution can't be edited without breaking **Verified**.

**2. Committed ledger.** Each PRD's chain is exported to `.arbiter/ledger/<PRD>.jsonl` and committed in each task's squash commit. Each line is exactly `JCS(hashed form + entry_hash + supervisor_signature)`, in `seq` order, with LF line endings. Verifiers reject any line that isn't byte-identical to its own canonical form, which rules out extra fields, duplicate keys, reformatting and non-canonical escapes in one check, and makes a re-export byte-identical. A trailing CR per line is tolerated for `core.autocrlf` checkouts; `arbiter init` adds `.arbiter/ledger/*.jsonl text eol=lf` to `.gitattributes`. The file holds the actions in §8.E: hashes and short summaries only, no transcripts or secrets. The `Arbiter-Ledger` trailer pins the chain head, so the signed commit vouches for the entire history before it. The `merge` entry for a commit can't contain that commit's own sha, so it records the tree hash of the merged content, and the next entry records the commit sha.

**3. Human capstone.** The final feature → main merge is signed with *your* key. That key's signature covers everything the supervisor key did on the branch.

**Verification:** `arbiter audit verify [<commit>]` (v0.1) checks commit signatures against `allowed_signers`, recomputes the ledger hash chain, verifies every entry's signature, and confirms that the chain ends exactly at each trailer's pinned head (which is what catches truncation). The verifying key always comes from `allowed_signers`, never from the ledger file: a rewritten chain re-signed with another key is internally consistent. The supervisor key's line restricts its namespaces, e.g. `arbiter@host namespaces="git,arbiter-ledger" ssh-ed25519 AAAA…`. It ships with the ledger because it is also the ledger's test oracle. Plain `git log --show-signature`, `ssh-keygen -Y verify`, and reading the JSONL get most of the way without Arbiter installed.

**What this proves, honestly:** that *your* Arbiter installation recorded these seats doing these things, and that the record hasn't changed since it was signed. It does not cryptographically prove a particular model wrote a particular line; nothing running locally could. This is the same trust level as a signed `Co-Authored-By` trailer, only far more detailed and tamper-evident.

### 8.E Ledger Action Catalog

Every entry has `seat_id` and, where relevant, `task_id`. The payload fields listed are required to be *present*; a value may be `null` where the table says so (e.g. the ringleader's `parent_seat_id`). Unknown actions are rejected at write time. Payloads never contain secrets, prompts, or transcripts (hashes of them are allowed).

| Action | Seat | Payload |
|---|---|---|
| `credential` | core (global chain) | `credential_id`, `kind`, `harness`, `model`, `model_provenance` |
| `prd_lock` | human | `tag`, `spec_hash`, `tag_object_sha` |
| `plan` | ringleader | `plan_hash`, `task_ids[]` |
| `spec` | ringleader | `task_id`, `spec_revision`, `spec_hash` |
| `mint` | core | `new_seat_id`, `role`, `parent_seat_id` (`null` for the ringleader), `credential_id` |
| `launch` | core | `invocation_id`, `seat_id`, `purpose`, `prompt_hash`, `injected_lesson_ids[]` |
| `exit` | core | `invocation_id`, `exit_reason`, `cost_usd` (`null` when unknown), `cost_estimated` (§5.8) |
| `result` | the invoking seat | `invocation_id`, `result_hash`, `status` |
| `submit` | core | `submit_commit`, `base_commit`, `diff_check` (`pass`/violations), `build_check` (`pass`/`fail`/`null` when the diff check failed) |
| `unseen_state` | core | `changed_paths[]`, `action` (`reinstalled`/`restored`) |
| `stray_processes` | core | `invocation_id`, `processes[]` (`{pid, image, cmdline_hash}` found by the post-run scan, §7) |
| `attack_run` | core | `commit`, `tests[]` (`{test_id, targets[], class}`) |
| `claim_ruling` | judge | `test_id`, `ruling`, `reason_hash` |
| `dispute` | worker | `test_id`, `argument_hash` |
| `dispute_ruling` | judge (fresh seat) | `test_id`, `ruling` |
| `verdict` | judge | `verdict`, `blast_radius`, `bundle_hash` |
| `hitl` | human | `decision`, `note_hash` |
| `scope_grant` | core | `paths[]`, `trigger` (`worker`/`integration`) |
| `integration` | core | `result`, `failing_tests[]`, `routing` |
| `merge` | core | `tree`, `parent`, `trailers_hash` |
| `merge_commit` | core | `sha` (the commit made from the preceding `merge` entry, §8.D) |
| `outcome` | judge / core / human | `lesson_id`, `lesson_tier`, `outcome_type`, `evidence_backed` |
| `autopsy` | core | `invocation_id`, `tail_hash`, `checkpoint_ref` |
| `task_state` | core / human | `from`, `to`, `reason` |
| `promotion` | human (global chain) | `manifest_hash`, `lesson_ids[]` |

---

## 9. Interfaces

### 9.A Agent I/O Contract (v0.1, no MCP)

In v0.1 agents talk to Arbiter only through their process, their working tree, and one JSON result. There is no `submit` or `heartbeat` tool: submitting is exiting, liveness is observed (§7), and Arbiter makes the commits (§5.3).

**Launch recipe (Claude Code, the v0.1 harness).** Every invocation runs in the slot (`cwd = .arbiter/worktrees/slot-0`) as:

```
claude -p --model <model> --output-format stream-json --verbose \
       --restricted --strict-mcp-config --disable-slash-commands --permission-prompts none \
       --max-budget-usd <remaining PRD budget> \
       [--resume <harness_session_id>] <role tool profile flags>
```

- **Isolation baseline (every role).** Without it, a headless `claude -p` loads the user's whole environment: plugins and their hooks, every configured MCP server (including ones with write access to GitHub or mail), skills, the subagent tool, auto-memory, and CLAUDE.md. That's 100+ tools the role never asked for. The baseline flags drop all of it:
  - `--restricted` ignores user, project and local settings files (so a `.claude/settings.json` a worker commits can't grant permissions), removes code-running tools unless `--tools` names them, and confines file tools to the working directory;
  - `--strict-mcp-config` loads no MCP servers (none are passed);
  - `--disable-slash-commands` disables skills;
  - `--permission-prompts none` denies anything that would prompt.

  `--bare` would be leaner but accepts only `ANTHROPIC_API_KEY`, never subscription (OAuth) login, so it isn't used.
- **Prompt on stdin, never in argv.** A prompt carrying a diff easily overflows Windows' 32,767-character command-line limit, or 8,191 if the command goes through `cmd.exe`. On Windows, `harness.command` must resolve to a native `.exe`; startup validation (§13) rejects a `.cmd`/`.bat` shim.
- **Prompt layout: instruction first, data fenced.** Every prompt starts with the role instruction; diffs, test output, specs and other untrusted material follow in delimited blocks (`<diff>…</diff>`). An instruction placed after a large blob reads like prompt injection, and the model may refuse it.
- **Streaming output** gives the supervisor a stdout event per turn and tool call (liveness, §7) and a live feed for the TUI. The final `result` event carries the model's final message, `session_id` (stored as `seats.harness_session_id`; it stays the same across `--resume`), `is_error`, and `total_cost_usd` (stored as `invocations.cost_usd`, §5.8).
- **Reading the stream.** Read stdout to EOF: `result` is not always the last event (hook events can follow it). The invocation succeeded only if `is_error == false`. Never go by `subtype`: an API error arrives as `subtype: "success"` with `is_error: true`. No `result` event at all (killed, crashed) is a crash (autopsy). `terminal_reason` and `api_error_status` are recorded with the invocation. `rate_limit_event` carries subscription utilization; it's shown in the TUI and logged.
- **Git environment** is overridden per process with `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` (git ≥ 2.31): `commit.gpgsign=false` and `tag.gpgsign=false` (so a global signing setup never prompts you for an agent's commit), `core.hooksPath=<empty arbiter dir>`, and `user.name`/`user.email` = the seat. `GIT_TERMINAL_PROMPT=0` as well.
- **Role tool profiles** (defense in depth on top of the diff check). A role is defined by `--tools`, which decides which tools *exist*, plus allow rules for which shell commands may run. `--allowedTools` alone is only a permission allow-list: every other tool stays loaded, and anything else that grants permission (a permission mode, a settings file) lets it through.

| Role | Profile flags (on top of the baseline) | After exit |
|---|---|---|
| Ringleader | `--tools "Read,Grep,Glob"` | Runner asserts `git status --porcelain` is empty; otherwise the changes are discarded and a violation is logged |
| Worker | `--tools "Read,Grep,Glob,Edit,Write,Bash,PowerShell" --permission-mode acceptEdits --allowedTools "<harness.shell_allow>"` | Snapshot commit + diff check + build check (§5.3) |
| Adversary | same as Worker | Commit of adversary files + diff check |
| Judge | `--tools "Read,Grep,Glob"` | Same assertion as the Ringleader |

  `harness.shell_allow` (§9.C) lists the shell commands the edit roles may run, as Claude Code allow rules (e.g. `Bash(go test *)`); everything else is denied. The list doesn't stop a test file from running arbitrary code; the diff check and unseen-state check remain the boundary.

**Result.** The model's final message must be exactly one JSON object; Arbiter strips a single surrounding code fence if present. It's validated against the schema for the invocation's `purpose`. Invalid output → **resume the same session once** with the validation error (the worker's edits are kept), then treat it as a crash (autopsy). Either way it counts as an attempt.

**Output schemas** (fields are required unless marked `?`):

| Role / purpose | Input (prompt) | Output JSON |
|---|---|---|
| Ringleader `plan` | PRD, repo file tree, lesson summaries | `{tasks: [{id, title, intent, reservations: [path], depends_on: [id], est_minutes}]}` The core rejects cycles, reservations outside PRD boundaries, and Triage Guard violations, and resumes the session once with the errors. |
| Ringleader `spec` | Plan, this task's intent and reservations, current code (read via tools) | `{task_id, spec_markdown, reservations?: [path]}` Reservations may narrow, never widen. |
| Worker `implement` / `fix` | Spec, invariants, ACs, boundaries, reservations, injected lessons (v0.2), prior autopsy or rejection trace | `{status: "done" \| "scope_request" \| "blocked_prd" \| "dispute", summary, scope_request?: {paths: [path], reason}, blocked_reason?, dispute?: {attack_test_id, argument}}` The field matching `status` is required. |
| Adversary `attack` / `attack_maintenance` | Spec, invariants, ACs, worker diff (or incremental diff, or the failing test plus the interface change), adversary pattern and naming rule | `{status: "done" \| "no_attacks", summary}` Tests themselves are discovered from the runner (§5.4). |
| Judge `claim_check` | Each ASSERTION_FAIL test: source, failure output, cited invariant/AC text | `{rulings: [{test_id, ruling: "upheld" \| "rejected", reason}]}` |
| Judge `dispute_ruling` (fresh seat) | Test source, failure, worker argument, cited invariant/AC | `{ruling: "upheld" \| "dismissed" \| "escalated", reason}` |
| Judge `verdict` | Evidence bundle (below) | `{verdict: "approve" \| "needs_human", reason, injections?: [{lesson_id, lesson_tier, relevance, outcome?, description}]}` There's no "reject": rejections come only from evidence (upheld attacks, gate failures), per the Deterministic Gating axiom. A concern the Judge can't back with evidence goes to the human. |
| Judge `autopsy_summary` | Output tail, diff stat, exit reason | `{root_cause_summary}` One line, ≤ 200 characters. |

**Judge evidence bundle (`verdict`).** Built by the core, hashed into the ledger (`bundle_hash`), and capped at about 60k tokens (4 characters/token estimate):

1. Task spec, PRD invariants and ACs (never truncated).
2. Computed blast radius and the reasons for it (never truncated).
3. Attack results: each test's id, targets, class, claim ruling, and dispute, plus the history of earlier upheld rejections and how each was fixed.
4. Injected lessons with their text (v0.2+).
5. The worker diff and the attack-test diff.
6. Output of passing tests.

When over the cap, items are cut from the bottom up: passing-test output first, then the attack-test diff is replaced by `git diff --stat` lines, then the largest worker file diffs are replaced by stat lines, one at a time. The Judge runs read-only in the slot with `submit_commit` checked out, so it can open any truncated file itself.

MCP (v0.3+) adds mid-run tools (`reserve`, `get_context`, `ask_judge`) and attached interactive sessions, using `connection` binding (§8.B). The I/O contract above stays valid; MCP is an addition, not a replacement.

### 9.B Human Interface

Built as a single terminal binary with no web dashboard.

### TUI Layout (v0.3)

```
┌─ Arbiter: Active Tasks ────────────┬─ Worker Stream [TASK-102] ──────────────────────┐
│ [IN_PROGRESS] TASK-102: Auth Refresh│ Running: npm run test:auth                      │
│   Worker: slot-0 | Res: src/auth/   │ PASS src/auth/token.test.ts                     │
│ [UNDER_REVIEW] TASK-101: SQLite Init│ FAIL src/auth/rotation.test.ts (Expected 401)   │
│   Adversary: running 4 attacks      │                                                 │
│ [AWAITING_HUMAN] TASK-99: Migration │ Adversary generating attack patch...            │
│ [READY]       TASK-104: Repo Queries│                                                 │
├─────────────────────────────────────┼─────────────────────────────────────────────────┤
│ PRD-004 (2/5 done) | Seats: 4      │ Token Burn: 42,100 / 150,000 | Est: $0.42       │
│ Lessons Injected: LESSON-12, ORG-04 │ Lease Remaining: 08:42                          │
└─────────────────────────────────────┴─────────────────────────────────────────────────┘
```

### CLI Command Suite

- `arbiter init` — create `.arbiter/`, detect tech stack, configure the worktree pool.
- `arbiter prd init "<title>"` — draft a new PRD template.
- `arbiter prd lock <prd-id>` — commit and create the signed lock tag.
- `arbiter prd amend <prd-id>` — edit and re-sign (new tag version).
- `arbiter prd review <prd-id>` — full integration pass, then signed merge into main.
- `arbiter run <prd-id>` — Ringleader plan, then dispatch in DAG order with just-in-time specs. Hosts the core in the foreground (§10.B).
- `arbiter tasks` — tasks, DAG status, seat tree, leases, reservations.
- `arbiter task reset <task-id>` — return a `failed` task to `ready` with a fresh attempt count.
- `arbiter seats [<prd-id>] [--stats]` — print the agent tree with roles, credentials, invocations, and outcomes; `--stats` adds dismissed-attack and upheld-claim rates per credential.
- `arbiter seat attach --role <role> --task <task-id>` — (v0.3+) mint a connection seat for a session you run yourself.
- `arbiter review <task-id>` — diff viewer with HITL prompt.
- `arbiter lesson list [--injections]` — lessons with U, P, and outcome counts.
- `arbiter lesson outcome <id> --<catch|miss|contradiction> --task <task-id> -m "<reason>"` — human override for one (lesson, task).
- `arbiter org stage` — lessons meeting Gate 2.
- `arbiter org promote [<id>... | --all-staged]` — sign one manifest and promote.
- `arbiter audit verify [<commit>]` — (v0.1) verify commit signatures, the ledger hash chains, and the trailer heads.
- `arbiter prune` — reset dead worktree slots, orphaned branches, dangling reservations.
- `arbiter serve` — (later) run core + runner headless on a server; clients connect over SSH (§10).

### 9.C Project Configuration (`.arbiter/config.toml`)

Committed with the repo; validated at startup (§13). `arbiter init` writes one from detected ecosystems. Keys needed for v0.1:

```toml
[harness]
command = "claude"                 # must resolve to a native executable on Windows (§9.A)
ringleader_model = "claude-opus-5-5"
worker_model     = "claude-opus-5-5"
adversary_model  = "claude-sonnet-5"   # a different model from the worker, where possible (§5.0)
judge_model      = "claude-opus-5-5"
shell_allow = ["Bash(go test *)", "Bash(go build *)", "Bash(go vet *)", "Bash(git status*)", "Bash(git diff*)",
               "PowerShell(go test *)", "PowerShell(go build *)", "PowerShell(go vet *)"]
                                   # shell commands the Worker/Adversary may run (§9.A); everything else is denied

[limits]
max_attempts = 6                   # §5.8
lease_minutes = 15
lease_ceiling_minutes = 60
judge_bundle_tokens = 60000        # §9.A
attack_timeout_seconds = 120       # per attack test (§5.4)

[test]
# Every command runs uncached: a cached PASS would replay without executing, even after the
# unseen-state check reinstalled dependencies.
build    = "go build ./... && go vet ./... && go test -count=1 -run ^$ ./..."   # build check (§5.3)
all      = "go test -json -count=1 ./..."              # full suite
files    = "go test -json -count=1 {packages}"         # subset; {files} or {packages} is substituted
reporter = "go-json"                          # go-json | junit-xml | tap
                                              # go-json: attacks run one per test from `go test -c` binaries (§5.4)
junit_path = ""                               # when reporter = junit-xml: where the file lands

[adversary]
pattern = "**/*_adversary_test.go"            # path glob only, no content marker (§5.3)
                                              # e.g. JS/TS: "**/*.adversary.test.ts", Python: "**/test_adversary_*.py"

[deps]
install   = "go mod download"
lockfiles = ["go.sum"]
keep      = []                                # e.g. ["node_modules", ".venv", "target"]

[blast_radius]
high_risk = ["**/migrations/**", ".github/**", "**/auth/config*"]   # §5.5, v0.1 path-based

[protected]
paths = ["internal/gate/**", "internal/ledger/**"]                   # §13: always awaiting_human
```

The adversary pattern must be one the project's test runner discovers by default (Go needs `_test.go`, pytest needs `test_*.py` or `*_test.py`). Startup validation checks this for known ecosystems.

---

## 10. Architecture, Deployment & Technology Stack

### 10.A Core / Runner / Client

```
┌──────────── Client ────────────┐      ┌──────────────── Core ─────────────────┐
│ CLI / TUI                      │ API  │ SQLite, seats, ledger, gates,         │
│ Signs with YOUR key, locally   │─────►│ supervisor key. The only authority.   │
└────────────────────────────────┘      └───────────────────┬───────────────────┘
                                                            │ asks
                                        ┌───────────────────▼───────────────────┐
                                        │ Runner (no authority)                 │
                                        │ worktree slot(s), process supervisor, │
                                        │ harness launch, test execution        │
                                        └───────────────────────────────────────┘
```

- **Core** holds all authority. Only the core writes to the database or mints seats.
- **Runner** starts, watches, and reaps processes and runs tests. It cannot mint, approve, or merge. The Fleet spawner (§12) is a Runner extension.
- **Clients** only use the core's API; they never open the database directly. That rule is what makes remote deployment possible later without a rewrite.

### 10.B Deployment Modes

| Mode | Where things run | When |
|---|---|---|
| **Local (default, v0.1)** | One binary on your laptop; core, runner, and client in one process; API over a named pipe (Windows) or Unix socket | Single lane. Arbiter itself is light; the load is one harness plus one test run. |
| **Home server (later)** | `arbiter serve` in an LXC/VM. Repo and worktrees live on the server; you edit via VS Code Remote-SSH; the laptop is a thin client. | Fleet, heavy builds (Gradle, emulators), or a laptop that's struggling. |
| **Split runners (maybe never)** | Core in one place, runners on other machines | Only if a real need appears. |

**Local process model (v0.1).** Exactly one process hosts the core for a repo at a time:

- The first `arbiter` command that needs the core takes an exclusive lock (`.arbiter/core.lock`, via `LockFileEx` on Windows and `flock` on POSIX), opens `state.db`, and listens on `\\.\pipe\arbiter-<repo-hash>` (Windows) or `.arbiter/core.sock` (POSIX).
- Any other `arbiter` command first tries to connect to that pipe or socket and acts as a client. Only if nothing is listening does it take the lock and host the core in-process for the duration of the command.
- `arbiter run` is simply a long-lived host: it keeps the core (and the Runner) up until the PRD finishes or hits `awaiting_human`. `arbiter tasks` in another terminal connects to it. The CLI never opens `state.db` directly, even when it hosts the core in-process.
- If the host crashes, the OS releases the lock and the Job Object kills its agents (§7). On the next start the core marks open invocations `killed` and runs autopsies on them.

Remote-access rules, decided now so the server mode stays simple:
- **Transport is SSH** (or Tailscale), e.g. `ssh box arbiter tasks`, the way git works. Human authentication reuses your SSH keys; there is no separate human API-key system and no built-in public HTTP listener. Internet exposure, if ever wanted, is a reverse proxy's job.
- **One binary, one port** (for MCP over HTTP, when enabled). There's no separate web UI process to collide with. Startup fails loudly on a port conflict or invalid config.
- **Human signing stays on the client** (§8.C).

### 10.C Technology Stack

- **Core language: Go.** Windows Job Objects (`golang.org/x/sys/windows`), POSIX process groups, and single static binary distribution are all native. From Node, Job Objects would need a native addon. TUI via bubbletea.
- **Database:** SQLite (WAL, FTS5) via `modernc.org/sqlite` (pure Go, no cgo, easier cross-compile).
- **Code intelligence (v0.2+):** Tree-sitter for symbol extraction, signature hashing, and blast radius. Its Go bindings require cgo, which on Windows means a gcc toolchain (e.g. MSYS2/mingw-w64) and gives up the pure-Go build `modernc.org/sqlite` was chosen for. That trade is made deliberately in v0.2; v0.1 stays cgo-free with path-based blast radius (§5.5).
- **Canonical JSON:** RFC 8785 (JCS) for ledger hashing (§8.B), via the standard library's `encoding/json/jsontext` (released API since Go 1.27, so Go ≥ 1.27 is required), behind Arbiter's stricter input validation. An independent implementation is kept as a test oracle, so a Go release that changed canonical output would fail tests before any ledger rehashed.
- **Harness integration:** headless launch with the §9.A I/O contract in v0.1. An MCP server (stdio + HTTP) arrives in v0.3 with connection-bound seats and role-filtered tools. Enforcement never depends on the harness calling Arbiter tools (§5.3).
- **Embeddings (v0.3, optional):** local `bge-small` / `nomic-embed-text` via ONNX Runtime, applied to root-cause summaries only.
- **Crypto:** Ed25519 supervisor key with SSHSIG signatures produced in-process via `golang.org/x/crypto/ssh` (byte-compatible with `ssh-keygen -Y sign`; no subprocess per ledger entry); OpenSSH / `ssh-keygen -Y` and git SSH signing for humans, client-side.
- **VCS:** Git CLI via sub-process (`git worktree`, `git commit -S`, `git interpret-trailers`, `git tag -s`).

---

## 11. Build Order (scope control)

Build in this order. Each stage should be usable on its own.

| Stage | Scope | Explicitly deferred |
|---|---|---|
| **v0.1: Single lane** | One PRD, tasks run **sequentially** in DAG order, one worktree slot, local mode. Ringleader plan + just-in-time specs. Credentials, process-bound seats with invocations, agent tree. Worker → Adversary (Attack Validation Protocol) → Judge → integration gate, via the §9.A I/O contract and launch recipe. Arbiter-made submit commits, diff check, unseen-state check. Path-based blast radius. Attempt ceiling + budget. Signed PRD lock tag, supervisor-signed squash commits with trailers, committed per-PRD ledger, minimal `audit verify`, client-signed final merge. Project config (§9.C). Windows + Linux supervisor. Tier 1 autopsies (raw tail + summary). CLI only. One harness (Claude Code headless). | MCP, lessons, TUI, org tier, tree-sitter, server mode, Fleet |
| **v0.2: Memory** | Fingerprinting, Gate 1, `lesson_injections`, Judge + core outcome resolution, U, U_rank and P, ranking + token budget, circuit breaker. Tree-sitter symbol index (cgo decision) for symbol-based blast radius. | Org tier, embeddings |
| **v0.3: Connect & polish** | MCP server (connection-bound seats, role-filtered tools, `seat attach`), TUI with agent tree view, Tier 3 org promotion, summary embeddings, additional harnesses. | |
| **Server mode** | `arbiter serve`, SSH transport, client-side signing over the wire. | |
| **Fleet (power users)** | See §12. Pairs naturally with server mode. | |
| **Later** | OS-level sandboxing, macOS shim. | |

Sequential execution sidesteps deadlocks, semantic merge conflicts, and worktree contention entirely. Build Fleet only once the single-lane loop has shown it produces better code than one agent working alone.

---

## 12. Fleet (Parallel Execution, deferred)

An opt-in module (`arbiter run --fleet N`), realistically run in server mode (§10.B). **The Fleet spawner is a Runner extension and holds no authority of its own.** It cannot mint seats, approve work, or merge. It spawns, waits, and reaps processes, and asks the core for everything else. This keeps every core guarantee unchanged under parallelism. The schema already supports it (`reservations`, `worktree_slot`, `task_edges`, `task_symbol_deps`, the `stale` state), so no migration is needed.

**Scheduling & reservations (deadlock freedom)**
- A task is dispatched only if it is `ready`, a pool slot is free, and its whole reservation set can be acquired **atomically** (one SQLite transaction, all or nothing). No task holds some reservations while waiting for others, so circular wait is impossible.
- Two reservations conflict if one path prefix is a segment-prefix of the other.

**Interface drift (why staleness lives here)**
- Just-in-time specs (§5.1) are still written at dispatch, but under Fleet other tasks merge while a specced task waits or runs. When writing a spec, the core records `task_symbol_deps`: the existing symbols the spec references, with their tree-sitter signature hashes (v0.2 index).
- After every merge, the core diffs exported-symbol signature hashes. A `ready` task with a changed dependency becomes `stale`, and its Ringleader seat rewrites the spec (`spec_revision += 1`), with no human signature because the PRD is unchanged. A running task with a changed dependency must rebase, and pass a fresh drift check, before its result is accepted.
- **Mid-flight expansion:** a free path inside the PRD boundaries is granted. A held path is not waited on: the task checkpoints, releases everything, and re-enters `ready` with the enlarged set.

**Worktree pool**
- N persistent slots (`slot-0..N-1`) with the same reset, keep-list, and lockfile-hash rules as §7. Suggested default N = 2.

**Merge queue**
- The §5.6 integration gate becomes a serialized queue, because parallel tasks can each pass alone and still break the branch together.
- Optional later: batch several queued tasks per full-suite run and bisect on failure.

**Wave report**
After each wave, the spawner reports:
- files that more than one task changed
- changes outside declared reservations (already rejected by the diff check, but surfaced for tuning)
- how far the feature branch moved while each task ran, which predicts rebase pain
- tasks marked `stale` by symbol drift

---

## 13. Building Arbiter with Arbiter (Bootstrap Rule)

Arbiter will eventually be used to develop itself. That creates a specific risk: a bug in a gate could approve the "fix" for that same bug.

- **Gate code is human-owned.** The diff check, unseen-state check, attack classification, integration gate, seat minting, ledger, and signing live in protected paths (`[protected]` in §9.C, e.g. `internal/gate/**`, `internal/ledger/**`). Agents may *propose* changes there, but every such change goes to `awaiting_human` regardless of blast radius and needs real tests.
- **Arbiter's own adversary tests use `*_adversary_test.go`**, so `go test` discovers them (§9.C).
- **Dogfood with a pinned binary.** When Arbiter works on its own repo, it runs a pinned, known-good release (`stage0`), never the build under change. Promote a new stage0 only after it has passed CI and some real use. Compilers bootstrap the same way.
- **Main stays green.** Nothing merges to `main` unless CI passes, which is exactly the rule Arbiter enforces on everyone else.
- **Config is validated at startup.** Port conflicts, missing keys, bad paths, a harness command that resolves to a `.cmd`/`.bat` shim on Windows, git older than 2.31, or an adversary pattern the test runner won't discover all fail loudly instead of producing a half-working install.
