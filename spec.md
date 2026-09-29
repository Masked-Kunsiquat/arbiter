# Arbiter Engine: Architecture & System Specification (v2)

A lean, local-first execution arbiter, task governor, and multi-agent coordination layer built on native Git primitives, embedded SQLite, and signed audit records.

> **Changes from v1** (see git history), responding to `spec-review.md` and later design discussion:
>
> | Issue | Resolution | Section |
> |---|---|---|
> | DAG edges not persisted | `task_edges` table + `ready` / `stale` task states | §4, §5.1 |
> | Cascading interface drift | Symbol-diff staleness detection; Ringleader re-specs tasks without human re-signing unless the PRD itself changes | §5.1 |
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
│  - Tree-sitter Symbol Index (blast radius, interface drift)                 │
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
- **Enforce at the Diff, Not the Tool:** Harnesses ship their own shell and file tools, so the Arbiter cannot rely on intercepting writes. Every boundary rule is enforced by inspecting the committed diff at submit time.
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
- **Zero Unilateral Drift:** Workers and reviewers cannot alter PRD invariants or file boundaries (enforced by the diff check on `.arbiter/**`). If a design flaw is uncovered, the task halts and the PRD moves to `amendment_needed`.
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

- **Tier 1: Ephemeral Memory (Task-Scoped):** Transient runtime telemetry, failure traces, crash autopsies. Each record carries a deterministic trace fingerprint (§6.C). Never injected into prompts except as an autopsy note to the *same task's* next attempt.
- **Tier 2: Project Lessons (Repository-Scoped):** Concrete technical rules tied to file globs. Every injection is tracked and resolved to an outcome.
- **Tier 3: Org Invariants (Machine-Global):** Architectural standards applied across projects on the host, filtered by detected tech stack.

---

## 4. Data & Storage Layer

All persistence is local and embedded: SQLite in WAL mode with `PRAGMA busy_timeout = 5000` and `PRAGMA foreign_keys = ON`. Storage needs no server; the Arbiter supervisor process is only required while tasks are running.

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
    spec_markdown TEXT NOT NULL,
    spec_hash TEXT NOT NULL,                 -- changes when the Ringleader re-specs a stale task
    spec_revision INTEGER DEFAULT 1,
    author_seat_id TEXT,                     -- worker seat whose commit is under review; outlives the seat's lease
    status TEXT NOT NULL CHECK (status IN (
        'backlog',        -- dependencies not yet done
        'ready',          -- dependencies done, waiting for a slot (and reservations under Fleet)
        'in_progress',
        'under_review',
        'awaiting_human',
        'integrating',    -- in the integration gate (queued, under Fleet)
        'done',
        'stale',          -- an upstream interface changed; needs re-spec
        'failed'
    )),
    base_commit TEXT,                        -- feature-branch commit the worktree started from
    worktree_slot INTEGER,                   -- worktree slot (always 0 single-lane)
    supervisor_handle TEXT,                  -- PGID (POSIX) or Job Object name (Windows)
    upheld_rejections INTEGER DEFAULT 0,     -- only upheld rejections count toward the retry cap
    attempt INTEGER DEFAULT 1,
    lease_expires_at DATETIME,
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

-- Symbols a task's spec relies on (used for staleness detection)
CREATE TABLE task_symbol_deps (
    task_id TEXT NOT NULL,
    symbol TEXT NOT NULL,                    -- e.g. "src/auth/utils.ts#signToken"
    signature_hash TEXT NOT NULL,            -- tree-sitter signature hash when the spec was written
    PRIMARY KEY (task_id, symbol),
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

-- Path reservations (prefix semantics: "src/auth/" conflicts with "src/auth/token.ts").
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
    fingerprint TEXT,                        -- normalized trace fingerprint (§6.C)
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

-- Outcome Ledger: at most one outcome per (lesson, task); a human entry overrides a judge entry
CREATE TABLE lesson_outcomes (
    id TEXT PRIMARY KEY,
    lesson_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    seat_id TEXT NOT NULL,                   -- who logged it
    author_role TEXT NOT NULL CHECK (author_role IN ('human', 'judge', 'adversary')),
    outcome_type TEXT NOT NULL CHECK (outcome_type IN ('catch', 'miss', 'contradiction')),
    description TEXT NOT NULL,               -- Mandatory narrative
    context_diff_or_trace TEXT,
    audit_seq INTEGER NOT NULL,              -- pointer into the signed audit log
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (lesson_id, task_id),
    FOREIGN KEY(lesson_id) REFERENCES project_lessons(id)
);

-- Attack-test disputes (§5.4)
CREATE TABLE disputes (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    attack_test_id TEXT NOT NULL,
    worker_argument TEXT NOT NULL,
    ruling TEXT CHECK (ruling IN ('upheld', 'dismissed', 'escalated')),
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
CREATE TABLE seats (
    id TEXT PRIMARY KEY,                     -- readable + suffix: "PRD-004/TASK-101/worker.2~7f3a"
    role TEXT NOT NULL CHECK (role IN ('ringleader', 'worker', 'adversary', 'judge')),
    task_id TEXT,                            -- bound seats claim their task at creation
    prd_id TEXT NOT NULL,
    parent_seat_id TEXT,                     -- who minted it → forms the agent tree
    minted_by TEXT NOT NULL,                 -- seat id or 'human'
    credential_id TEXT NOT NULL,
    binding TEXT NOT NULL CHECK (binding IN ('process', 'connection')),
                                             -- process: Arbiter launched it (v0.1); connection: attached MCP session (later)
    code_hash TEXT,                          -- one-time attach code, only for 'connection' seats
    status TEXT NOT NULL CHECK (status IN ('minted', 'active', 'expired', 'revoked')),
    code_expires_at DATETIME,                -- attach codes are short-lived (5 min)
    lease_expires_at DATETIME,               -- renewed by supervisor observation, not by the model
    FOREIGN KEY(parent_seat_id) REFERENCES seats(id),
    FOREIGN KEY(credential_id) REFERENCES credentials(id)
);

-- Hash-chained, supervisor-signed audit log (§8)
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    prd_id TEXT,
    task_id TEXT,
    seat_id TEXT NOT NULL,                   -- 'human' or a seat id; the role is looked up via the seat
    action TEXT NOT NULL,                    -- e.g. 'mint', 'launch', 'result', 'verdict', 'merge', 'outcome'
    payload_json TEXT NOT NULL,              -- hashes + summaries, never secrets or full transcripts
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,                -- sha256(prev_hash || canonical(payload))
    supervisor_signature TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

Attestations live in **signed commit trailers** plus a **committed per-PRD ledger file** (§8.D). v2 used git notes; they were dropped because GitHub does not display them and they are not pushed by default.

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
    file_pattern TEXT NOT NULL,
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
        │   ├── worker.1             (expired: autopsy)
        │   ├── worker.2             ← author
        │   ├── adversary.1          cred:claude-code/claude-sonnet-5 (launched)
        │   └── judge.1
        └── TASK-102
            ├── worker.1
            ├── adversary.1
            └── judge.1
```

- Seat ids are readable paths plus a random suffix (`PRD-004/TASK-101/worker.2~7f3a`), so the ledger stays legible years later.
- **Only the Ringleader seat or the human can mint seats.** A worker cannot mint an adversary or judge seat to review its own work. This restriction is the core of the no-self-grading guarantee.
- **Independence:** the adversary and judge seats for a task must differ from the author seat, must not descend from it, and should use a different credential (a different model) where one is configured. Authorship is stored on the task (`author_seat_id`), so it outlives the worker's lease.
- **Harness-internal subagents** (for example, Claude Code's own Task tool) run *inside* their parent's seat. Arbiter treats them as the same agent. The tree only contains seats Arbiter minted.

**What each role reads and writes:**

| Role | Reads | Writes | Never |
|---|---|---|---|
| Human | Everything | PRD + amendments, HITL decisions, outcome overrides, Gate 3 | — |
| Ringleader | PRD, code index, lesson summaries | Tasks, edges, specs, reservations, seat requests (the core mints them) | Code, verdicts, outcomes |
| Worker | Task spec, PRD invariants/boundaries, injected lessons, own prior-attempt autopsy | Code commit + JSON result | Tests marked `@adversary`, `.arbiter/**`, outcomes |
| Adversary | Task spec, PRD invariants, the worker's **diff** (not its transcript, to avoid anchoring), injected lessons | Attack-test commit, `catch` outcomes | Application code |
| Judge | Spec, diff, attack results, disputes, injections, blast radius | Verdict, claim rulings, injection resolutions, root-cause summaries, Gate 1 activation | Code, tests |
| Synthesizer (deterministic, no LLM) | Tier 1 fingerprints | Gate 1 candidates, precision warnings | Anything in the repo |

**How knowledge moves:**

```
            ┌──────────── downward: ranked injection (§6.C) ─────────────┐
            │                                                            ▼
 Tier 3 Org ◄── Gate 3 (human) ── Tier 2 Project ◄── Gate 1 ── Tier 1 Autopsies/Traces
                                   ▲    │                           ▲
          outcomes (Judge/Adv/Human)    └── injected into ──► Worker/Adversary
                                   │                                │
                                   └──────── resolved at verdict ◄──┘  (failures fingerprinted)
```

- Raw telemetry (Tier 1) never reaches another task's prompt. It moves upward only as a Judge-written summary that passes Gate 1.
- Lessons move downward only through ranked, budgeted injection. Every injection is recorded, and every injection comes back as an outcome. That loop is what makes U computable.

### 5.1–5.7 Single-Lane Pipeline (core)

The core runs **one task at a time** in DAG order. Parallel dispatch is the Fleet module (§12).

```
1. Locked PRD ──► Ringleader (Decompose → Task DAG + reservations + symbol deps)
                      │
                      ├── Task touches > 3 files or est. > 15m? ──► Split, or HITL proposal
                      └── Within atomic limits?                 ──► 'backlog' / 'ready'
                                                                        │
┌───────────────────────────────────────────────────────────────────────┘
▼
2. Next 'ready' task in topological order; worker/adversary/judge seats minted under the Ringleader
   ▼
3. Worker (worktree slot, process-bound seat)
   - Writes code + unit tests, submits commit
   - Submit-time diff check (boundaries, protected files) ──► reject if violated
   ▼
4. Adversary (separate process, own token) writes attack tests as a separate commit
   ▼
   Attack Validation Protocol
   ├── ERROR (syntax/import/collection/timeout) ──► back to Adversary (max 2), worker untouched
   ├── ASSERTION_FAIL + claim upheld            ──► back to Worker (counts toward cap of 3)
   ├── ASSERTION_FAIL + claim rejected          ──► attack dismissed, logged against Adversary
   └── All attacks PASS                         ──► Judge
                                                      │
┌─────────────────────────────────────────────────────┘
▼
5. Judge
   ├── Low blast radius  ──► Integration Gate
   └── High blast radius ──► 'awaiting_human' ──► Integration Gate on approval
   (Resolves every lesson injection for the task — §6)
   ▼
6. Integration gate: rebase onto feature tip → full suite + all accumulated attack tests → signed fast-forward
   ▼
7. Staleness sweep: changed exported symbols ──► downstream tasks marked 'stale' ──► Ringleader re-specs
```

### 5.1 The Ringleader (Planning, Triage, Replanning)

- High-reasoning model (configurable; harness-agnostic).
- Compiles the locked PRD into a DAG: tasks, `task_edges`, per-task reservation prefixes (each must fall within PRD boundaries), and `task_symbol_deps` (the existing symbols each task's spec relies on).
- **Triage Scope Guard:** no task may reserve more than 3 files (or 1 directory prefix) or exceed ~15 minutes of estimated runtime. Ambiguous decompositions prompt the human.
- **Injection:** assembles each task's context from PRD invariants, ranked Org Invariants and Project Lessons (§6.B).
- **Interface drift / cascading invalidation:** after every merge, the supervisor diffs tree-sitter signature hashes of exported symbols. Any task in `backlog`/`ready` with a `task_symbol_deps` row whose hash changed is set to `stale`. The Ringleader regenerates its spec (`spec_revision += 1`) against the new code. This needs **no human signature** because the PRD is unchanged. Under Fleet, a task already running when its deps change must rebase before its result is accepted. Only if the new spec would require touching files outside PRD boundaries or violate an invariant does the PRD move to `amendment_needed`.

### 5.2 Reservations (single-lane)

- The Ringleader declares each task's reservations: path prefixes inside the PRD boundaries.
- In single-lane mode nothing competes for them. They define the scope that the submit-time diff check enforces.
- **Scope expansion (v0.1):** the worker ends its run with a structured `scope_request` in its result (§9.A). The core grants it if the paths are inside the PRD boundaries and re-runs the task with the enlarged reservation set; otherwise the PRD goes to `amendment_needed`. From v0.3, attached MCP sessions can call `arbiter_reserve` mid-run instead. Fleet-mode contention rules are in §12.

### 5.3 The Worker (Execution Sub-Process)

- Runs in the worktree slot (§7) under a supervisor-managed process container.
- Launched by the Runner with its seat already bound to the process (§8.B). It needs no Arbiter tools in v0.1: it edits files, commits, and exits with a result (§9.A).
- **Submit-time diff check (the real boundary):** `git diff --name-only <base_commit>..<submit_commit>` must be a subset of the task's reservations and must not touch `.arbiter/**` or any adversary test file (`**/*.adversary.test.*` or files carrying an `@adversary` marker). A violation rejects the submission deterministically, whatever tools the harness used to produce it.

### 5.4 The Adversarial Reviewer & Attack Validation Protocol

- **Rule:** never modifies application code. Its commit may only add/modify files matching the adversary test pattern (diff-checked like the worker's).
- Each attack test must cite the INVARIANT or AC it targets (in the test name or an `@targets INVARIANT-2` annotation).
- Attack tests run via the project's test runner with a machine-readable reporter (JUnit XML / JSON / TAP). Each attack test is classified:
  - **ERROR:** the test failed to parse, import, collect, or finished by timeout. This is evidence about the *test*, not the code. It goes back to the Adversary (max 2 regenerations) and does not touch the worker's retry count.
  - **ASSERTION_FAIL:** candidate defect. The Judge performs a **claim check**: does the cited invariant/AC actually require the asserted behavior? Upheld → rejection to Worker with the trace and diff. Not upheld → attack dismissed and recorded against the Adversary.
  - **PASS:** no defect found by this attack.
- **Worker dispute:** on an upheld rejection, the worker may file one dispute (`disputes` table) arguing the test is wrong. The Judge rules; if confidence is low the dispute escalates to the human.
- **Retry cap:** the worker gets at most 3 **upheld** rejections, then the task goes to `awaiting_human`.
- **Terminology:** a failing attack test is *evidence* of a defect, not proof. Proof comes only from an upheld claim.
- Passing attack tests are kept. They join the PRD's regression suite that the integration gate runs (§5.6).

### 5.5 The Judge (Neutral Arbiter)

- Evaluates the worker commit, attack results, the frozen spec, and the tree-sitter blast radius:
  - **Low blast radius** (pure logic, docs, tests; no exported-signature changes outside the task's reservations): approve to the integration gate.
  - **High blast radius** (migrations, auth config, root schema, exported-signature changes consumed elsewhere): `awaiting_human`.
- Rules on attack claims and disputes (§5.4).
- **Resolves every lesson injection** for the task at verdict time (§6.A).
- Writes Tier 1 root-cause summaries for autopsies.

### 5.6 Integration Gate

Even one task at a time, a task tested against only its own tests can break earlier work. Before any merge:

1. Rebase the task branch onto the current feature-branch tip. A conflict sends the task back to the worker with a rebase instruction; it does not count as a rejection. Conflicts are rare single-lane, routine under Fleet.
2. Run the full test suite **plus every accumulated attack test for the PRD**.
3. Green → fast-forward the feature branch with a supervisor-signed commit carrying attribution trailers (§8.D), append to the ledger, and run the staleness sweep (§5.1). Red → the task goes back to the worker with the failing output.

Under Fleet this becomes a serialized merge queue (§12).

### 5.7 Human in the Loop (HITL)

```
[JUDGE VERDICT: READY FOR HUMAN REVIEW]
Task: AUTH-102 (Rotate refresh tokens) | Parent: PRD-004
Worker: Done (14 tests passed)
Adversary: 5 attacks passed (INVARIANT-1, INVARIANT-2); 1 dismissed (claim not upheld)
Blast Radius: Touches 2 critical files in src/auth; changes signature of signToken()

[A]pprove   [R]eject with note   [I]nspect Diff   [S]hell into worktree
> _
```

- Approvals are keypresses recorded in the audit log, not SSH signatures. The human's signature on the final feature → main merge covers them.
- Rejections send the task back to the worker, count as upheld rejections, and prompt for an optional lesson outcome.

---

## 6. Epistemic Gates & Outcome Telemetry

```
[ Raw Memories (fingerprinted) ]
       │
       ▼  GATE 1: Candidate Activation (same fingerprint in >= 2 distinct tasks + Judge/Human sign-off + conflict check)
[ Active Project Lesson ]
       │
       ▼  GATE 2: Efficacy Threshold (U >= 0.80, relevant samples >= 5 distinct tasks, Contradictions == 0)
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
| `catch` | The concern came up and the final code complies, or the lesson was cited in an upheld rejection that was then fixed | +1.0 |
| `miss` | The concern came up and a defect in that area still reached the Adversary, Judge, integration gate, or human | −1.5 |
| `contradiction` | Following the lesson caused a failure, or the lesson is wrong for this code | −3.0 |

- The Adversary may also log `catch` when an attack test targeting a lesson's concern passes.
- The **worker role cannot author outcomes.** This replaces v1's per-key "no self-endorsement" rule.
- **Post-merge misses** (a bug found in production weeks later) are optional: `arbiter lesson outcome <id> --miss --task <task-id> -m "..."` overrides the Judge's entry for that task at human weight. U is designed to work without them.

### 6.B The Utility Formula

The original formulation:

$$U = \frac{C - 1.5M - 3.0X}{N_{\text{injections}}}$$

This has two problems. (1) Most injections do not touch the lesson's concern, so a correct lesson with a broad glob can never reach 0.80. The metric ends up measuring relevance × efficacy. (2) The signer weights from v1 (human 1.0, judge 0.7) are not applied.

**v2 formula.** Over resolved **relevant** injections only, with signer weight $w$ (human 1.0, judge/adversary 0.7) and shrinkage constant $k = 1$:

$$U = \frac{\sum w_i\,[\text{catch}_i] \;-\; 1.5\sum w_i\,[\text{miss}_i] \;-\; 3.0\sum w_i\,[\text{contradiction}_i]}{\sum w_i \;+\; k}$$

Plain text: `U = (Σw·catch − 1.5·Σw·miss − 3.0·Σw·contradiction) / (Σw + k)`

- With equal weights and `k = 0`, this reduces to the original formula restricted to relevant injections.
- `k` keeps small samples from scoring as perfect: 3 catches alone never reach 0.80.
- Range is (−3, 1). Uniqueness on `(lesson_id, task_id)` keeps it bounded.
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

Because Gate 2 already requires zero contradictions, the −3.0 weight matters mainly for **injection ranking**. There it quickly buries a lesson that has been contradicted once, before the circuit breaker quarantines it at two.

### 6.C Injection Ranking & Context Budget

- Candidates are lessons whose `file_pattern` matches any of the task's reservations, plus org lessons whose `tech_stack_tag` is in the project's detected stack.
- `score = specificity(file_pattern) × max(U, 0.5)`. Specificity is the number of literal (non-wildcard) path segments. New lessons use the 0.5 floor so they can accumulate evidence.
- Inject the top lessons until a **token budget** (default 1,500 tokens, max 8 lessons) is hit. Everything injected is recorded in `lesson_injections`.
- **Conflicts:** at Gate 1, the Judge compares a candidate against active lessons with overlapping patterns. A suspected conflict goes to the human instead of auto-activating.

### 6.D Trace Fingerprinting (Gate 1 clustering)

Raw stack traces embed poorly: most `TypeError: Cannot read properties of undefined` traces look alike. Gate 1 therefore clusters deterministically first, the way crash reporters group errors:

1. **Normalize:** strip line/column numbers, hex addresses, absolute paths (→ repo-relative), temp dirs, timestamps, UUIDs, and numeric literals in messages.
2. **Fingerprint** = `sha256(error_class | top in-repo frame (file#function) | failing test id)`.
3. **Candidate** = same fingerprint in ≥ 2 distinct tasks.
4. The Judge's natural-language `root_cause_summary` is what becomes the lesson text. Embedding-based clustering of *summaries* (not raw traces) is an optional v0.3 addition for cross-fingerprint grouping.

### 6.E The Three Knowledge Gates

- **Gate 1 (Memory → Project Lesson):** fingerprint cluster ≥ 2 distinct tasks, conflict check passes, activated by Judge or human.
- **Gate 2 (Project → Org Staging):** ≥ 5 distinct relevant tasks, U ≥ 0.80, zero contradictions. Status becomes `staged_for_org`.
- **Gate 3 (Org Invariant):** the human signs a promotion manifest (§8.C). Agents cannot write to `global_registry.db`.

### 6.F Contradiction Circuit Breaker

Any project lesson with ≥ 2 contradictions is immediately `quarantined`: it stops being injected and is flagged for human review.

---

## 7. Process Control, Worktrees, Autopsies & Leases

### Process Supervision (cross-platform)

All sub-processes (Worker, Adversary, test runners) are launched through a `Supervisor` interface:

```go
type Supervisor interface {
    Spawn(cmd Cmd) (Handle, error)            // starts the process inside a kill-able container
    Terminate(h Handle, grace time.Duration)  // graceful signal, then hard kill of the whole tree
}
```

| | Windows | Linux | macOS |
|---|---|---|---|
| Container | Job Object (`CreateJobObject`) | Process group (`Setpgid`) | Process group (`Setpgid`) |
| Spawn race | Create with `CREATE_SUSPENDED`, assign to job, then resume, so no grandchild escapes | n/a | n/a |
| Graceful stop | `CTRL_BREAK_EVENT` (spawned with `CREATE_NEW_PROCESS_GROUP`) | `kill -TERM -<pgid>` | `kill -TERM -<pgid>` |
| Hard kill | `TerminateJobObject` | `kill -KILL -<pgid>` | `kill -KILL -<pgid>` |
| Supervisor-death cleanup | `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: the OS kills the job when the supervisor's handle closes | `PR_SET_PDEATHSIG`. Go gotcha: it fires when the *spawning OS thread* exits, so spawn from a `runtime.LockOSThread()` goroutine | No PDEATHSIG; a tiny shim polls `getppid()` / kqueue `NOTE_EXIT` and kills its group |

### Warm Worktree Slot

Fresh worktrees per task would mean `npm install` / `cargo build` every time. Instead:

- Single-lane uses one persistent worktree (`.arbiter/worktrees/slot-0`). Fleet extends this to a pool of N slots (§12).
- Between tasks, the slot is reset with `git checkout --detach <base> && git clean -fdx -e node_modules -e target -e .venv ...` (per-ecosystem keep-list), so dependency directories survive.
- Dependencies reinstall only when the lockfile hash differs from the slot's last install.
- Shared caches: pnpm store, `GOCACHE`, `sccache`; per-slot `CARGO_TARGET_DIR`.
- Windows: recommend placing the repo on a Dev Drive (ReFS) for faster I/O and copy-on-write.

### Liveness & Leases

- Liveness = process alive **and** activity (stdout or worktree fs writes) within the last 120s. The supervisor observes this itself; the model never has to heartbeat.
- Standard lease: 15 minutes, renewed automatically while the process is live and active, up to an absolute ceiling (default 60 minutes). Test runs launched by the Runner pause the lease clock.
- **Expiry kills, it doesn't error.** When a lease ends, the supervisor terminates the process and runs the autopsy. The model is never handed an "expired" error it might try to work around.
- `awaiting_human` freezes all timers.

### Automated Crash Autopsy

When an agent times out or crashes:

1. `Terminate` the container.
2. Capture the last 50 lines of stdout/stderr and `git diff`, and compute the trace fingerprint.
3. Evaluate progress deterministically: if the diff is non-empty **and** the project builds/type-checks → checkpoint commit (`checkpoint/<task>/attempt-N`). Otherwise `git reset --hard <base_commit>`.
4. The Judge writes a one-line root-cause summary into the autopsy memory.
5. The next attempt's prompt gets: *"WARNING: Previous attempt failed with <summary>. Do NOT repeat that approach."*

---

## 8. Identity, Signing & Threat Model

### 8.A Threat Model

Everything runs locally as one OS user. Any process running as that user can read memory, env vars, and files. Cryptography cannot stop a hostile local process, and v2 does not claim otherwise.

**Defended against:**
1. *Agent overreach:* scope creep, editing tests to pass, touching the PRD, self-grading. Enforced by submit-time diff checks, planner-only seat minting, and role-restricted outcome authoring.
2. *Confused or prompt-injected agents* acting outside their role through Arbiter's own APIs. Seats are role- and task-bound and expire with the lease.
3. *After-the-fact tampering* with history, attribution, or the outcome ledger: hash-chained ledger, signed commits and tags.
4. *A compromised or remote core forging your approval:* the core never holds your key; human signatures are always produced client-side (§8.C).

**Not defended against (through v0.3):** a malicious process with the user's privileges, or an agent using its harness shell to exfiltrate data or damage files outside the repo. Real containment needs an OS sandbox (container, Windows Sandbox, bubblewrap, Seatbelt). That is future work (§11).

### 8.B Agent Identity: Credentials & Seats

v1's per-agent ephemeral Ed25519 keypairs are **removed**. The supervisor held every private key, so a signature only proved which IPC connection asked for it. Identity follows Graphban's credentials-and-seats shape, with one important change: **identity never passes through the model.** Graphban puts the seat code in the agent's instructions and relies on the model calling `register_agent` with it. That makes identity probabilistic: the model can forget, mistype, re-register, or lose the code to context compaction.

- **Credential:** what kind of agent this is, e.g. `cred:claude-code/claude-opus-5-5`, plus one for the human. For agents Arbiter launches, a credential is a **descriptor, not a secret**: the Runner knows which harness and `--model` it started, so `model_provenance = launched`. Secrets exist only for sessions attached from outside (v0.3+), whose model name is `claimed`.
- **Seat:** an ephemeral, role-bound identity for one task, e.g. `PRD-004/TASK-101/worker.2~7f3a`. It answers *"who did this, in what role, under whom?"*
- **Binding:**
  - `process` (v0.1): the Runner launches the harness for the seat. Every git commit and result from that process belongs to the seat. There is no token for the model to see, leak, or lose.
  - `connection` (v0.3+, MCP): the Runner writes a per-seat MCP config for the harness it launches, with the seat token in an env var (stdio) or `Authorization` header (HTTP). The token authenticates every call and never enters the prompt. For a session you attach by hand, you run `arbiter seat attach`, which prints a one-time code (5-minute TTL) to put in *your* MCP config, not in a prompt.
- **Minting rule:** only the Ringleader seat or the human can request seats; the core mints them. Workers, adversaries, and judges cannot. Every seat records `parent_seat_id`, which is how the agent tree in §5.0 is built.
- **Role-filtered tools:** when MCP arrives, `tools/list` returns only the seat's role's tools. A worker never sees `verdict`, so it can't waste turns trying it.
- **Leases:** codes expire fast (they're used immediately); the seat's lease is renewed by supervisor observation (§7). On expiry the process is killed. Seat ids stay in the ledger permanently. Secrets (attach codes, tokens) never enter the ledger or the repo.
- **Supervisor key:** one SSH signing key held by the core (`~/.config/arbiter/`, optionally the OS keychain). It signs ledger entries and the task-level commits described in §8.D.
- **Hash chain:** each ledger `entry_hash` covers the previous one, so deleting or editing any past entry is detectable.

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

**1. Signed commits with trailers.** Every task merge is a commit signed by the supervisor key, which you register on GitHub as an SSH *signing* key (e.g. titled `arbiter@<hostname>`). GitHub shows it as **Verified** under your account. The commit message carries trailers:

```
auth: rotate refresh tokens on /auth/refresh

Arbiter-PRD: PRD-004@v1 (tag arbiter/prd/PRD-004/v1)
Arbiter-Task: TASK-101 (spec rev 2)
Arbiter-Worker: PRD-004/TASK-101/worker.2~7f3a cred:claude-code/claude-opus-5-5 (launched)
Arbiter-Adversary: PRD-004/TASK-101/adversary.1~b20c cred:claude-code/claude-sonnet-5 (5 attacks, 0 upheld)
Arbiter-Judge: PRD-004/TASK-101/judge.1~e91d cred:claude-code/claude-opus-5-5 (verdict: low-risk)
Arbiter-Approved-By: human:Masked-Kunsiquat
Arbiter-Ledger: .arbiter/ledger/PRD-004.jsonl#seq=148 sha256:9c1e...
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

The signature covers the trailers, so attribution can't be edited without breaking **Verified**.

**2. Committed ledger.** Each PRD's `audit_log` entries are exported to `.arbiter/ledger/<PRD>.jsonl` and committed with each merge. The file holds seat mints, registrations, submits, verdicts, rulings, and outcomes: hashes and short summaries only, no transcripts or secrets. The `Arbiter-Ledger` trailer pins the chain head, so the signed commit vouches for the entire history before it.

**3. Human capstone.** The final feature → main merge is signed with *your* key. That key's signature covers everything the supervisor key did on the branch.

**Verification:** `arbiter audit verify [<commit>]` checks commit signatures against `allowed_signers`, recomputes the ledger hash chain, and confirms that each trailer's head hash matches. Plain `git log --show-signature` plus reading the JSONL gets most of the way without Arbiter installed.

**What this proves, honestly:** that *your* Arbiter installation recorded these seats doing these things, and that the record hasn't changed since it was signed. It does not cryptographically prove a particular model wrote a particular line; nothing running locally could. This is the same trust level as a signed `Co-Authored-By` trailer, only far more detailed and tamper-evident.

---

## 9. Interfaces

### 9.A Agent I/O Contract (v0.1, no MCP)

In v0.1 agents talk to Arbiter only through their process and git. The Runner launches each harness headless (e.g. `claude -p --model <m> --output-format json`) with the role prompt, and reads the result when it exits:

| Role | Input (prompt) | Output |
|---|---|---|
| Ringleader | PRD, code index summary, lesson summaries | JSON: tasks, edges, reservations, symbol deps (schema-validated) |
| Worker | Task spec, invariants, boundaries, injected lessons, prior autopsy | Commit(s) in the slot + JSON result: `{status, summary, scope_request?}` |
| Adversary | Task spec, invariants, worker diff, injected lessons | Attack-test commit + JSON: `{attacks: [{test_id, targets}]}` |
| Judge | Evidence bundle | JSON: verdict, claim rulings, injection resolutions, root-cause summaries |

- Every JSON result is validated against a schema. Invalid output → one retry with the validation error, then autopsy.
- There is no `submit` or `heartbeat` tool. Submitting is exiting; liveness is observed (§7).
- MCP (v0.3+) adds mid-run tools (`reserve`, `get_context`, `ask_judge`) and attached interactive sessions, using `connection` binding (§8.B). The I/O contract above stays valid; MCP is an addition, not a replacement.

### 9.B Human Interface

Built as a single terminal binary with no web dashboard.

### TUI Layout (v0.3)

```
┌─ Arbiter: Active Tasks ────────────┬─ Worker Stream [TASK-102] ──────────────────────┐
│ [IN_PROGRESS] TASK-102: Auth Refresh│ Running: npm run test:auth                      │
│   Worker: slot-0 | Res: src/auth/   │ PASS src/auth/token.test.ts                     │
│ [REVIEW]      TASK-101: SQLite Init │ FAIL src/auth/rotation.test.ts (Expected 401)   │
│   Adversary: running 4 attacks      │                                                 │
│ [HUMAN_GATE]  TASK-99: Schema Migr  │ Adversary generating attack patch...            │
│ [STALE]       TASK-104: Repo Queries│                                                 │
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
- `arbiter run <prd-id>` — Ringleader decomposition and DAG dispatch.
- `arbiter tasks` — tasks, DAG status, seat tree, leases, reservations.
- `arbiter seats [<prd-id>]` — print the agent tree with roles, credentials, and outcomes.
- `arbiter seat attach --role <role> --task <task-id>` — (v0.3+) mint a connection seat for a session you run yourself.
- `arbiter review <task-id>` — diff viewer with HITL prompt.
- `arbiter lesson list [--injections]` — lessons with U, P, and outcome counts.
- `arbiter lesson outcome <id> --<catch|miss|contradiction> --task <task-id> -m "<reason>"` — human override for one (lesson, task).
- `arbiter org stage` — lessons meeting Gate 2.
- `arbiter org promote [<id>... | --all-staged]` — sign one manifest and promote.
- `arbiter audit verify` — verify the ledger hash chains against the signed commit trailers.
- `arbiter prune` — reset dead worktree slots, orphaned branches, dangling reservations.
- `arbiter serve` — (later) run core + runner headless on a server; clients connect over SSH (§10).

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

Remote-access rules, decided now so the server mode stays simple:
- **Transport is SSH** (or Tailscale), e.g. `ssh box arbiter tasks`, the way git works. Human authentication reuses your SSH keys; there is no separate human API-key system and no built-in public HTTP listener. Internet exposure, if ever wanted, is a reverse proxy's job.
- **One binary, one port** (for MCP over HTTP, when enabled). There's no separate web UI process to collide with. Startup fails loudly on a port conflict or invalid config.
- **Human signing stays on the client** (§8.C).

### 10.C Technology Stack

- **Core language: Go.** Windows Job Objects (`golang.org/x/sys/windows`), POSIX process groups, and single static binary distribution are all native. From Node, Job Objects would need a native addon. TUI via bubbletea.
- **Database:** SQLite (WAL, FTS5) via `modernc.org/sqlite` (pure Go, no cgo, easier cross-compile).
- **Code intelligence:** Tree-sitter for symbol extraction, signature hashing, and blast radius.
- **Harness integration:** headless launch with the §9.A I/O contract in v0.1. An MCP server (stdio + HTTP) arrives in v0.3 with connection-bound seats and role-filtered tools. Enforcement never depends on the harness calling Arbiter tools (§5.3).
- **Embeddings (v0.3, optional):** local `bge-small` / `nomic-embed-text` via ONNX Runtime, applied to root-cause summaries only.
- **Crypto:** Go stdlib `crypto/ed25519` / SSH signing for the supervisor key; OpenSSH / `ssh-keygen -Y` and git SSH signing for humans, client-side.
- **VCS:** Git CLI via sub-process (`git worktree`, `git commit -S`, `git interpret-trailers`, `git tag -s`).

---

## 11. Build Order (scope control)

Build in this order. Each stage should be usable on its own.

| Stage | Scope | Explicitly deferred |
|---|---|---|
| **v0.1: Single lane** | One PRD, tasks run **sequentially** in DAG order, one worktree slot, local mode. Credentials + process-bound seats + agent tree. Worker → Adversary (Attack Validation Protocol) → Judge → integration gate, via the §9.A I/O contract. Submit-time diff check. Signed PRD lock tag, supervisor-signed task commits with trailers, committed ledger, client-signed final merge. Windows + Linux supervisor. Tier 1 autopsies. CLI only. One harness (Claude Code headless). | MCP, lessons, TUI, org tier, server mode, Fleet |
| **v0.2: Memory** | Fingerprinting, Gate 1, `lesson_injections`, Judge outcome resolution, U and P, ranking + token budget, circuit breaker, symbol-drift staleness + re-spec. | Org tier, embeddings |
| **v0.3: Connect & polish** | MCP server (connection-bound seats, role-filtered tools, `seat attach`), TUI with agent tree view, Tier 3 org promotion, `audit verify`, summary embeddings, additional harnesses. | |
| **Server mode** | `arbiter serve`, SSH transport, client-side signing over the wire. | |
| **Fleet (power users)** | See §12. Pairs naturally with server mode. | |
| **Later** | OS-level sandboxing, macOS shim. | |

Sequential execution sidesteps deadlocks, semantic merge conflicts, and worktree contention entirely. Build Fleet only once the single-lane loop has shown it produces better code than one agent working alone.

---

## 12. Fleet (Parallel Execution, deferred)

An opt-in module (`arbiter run --fleet N`), realistically run in server mode (§10.B). **The Fleet spawner is a Runner extension and holds no authority of its own.** It cannot mint seats, approve work, or merge. It spawns, waits, and reaps processes, and asks the core for everything else. This keeps every core guarantee unchanged under parallelism. The schema already supports it (`reservations`, `worktree_slot`, `task_edges`), so no migration is needed.

**Scheduling & reservations (deadlock freedom)**
- A task is dispatched only if it is `ready`, a pool slot is free, and its whole reservation set can be acquired **atomically** (one SQLite transaction, all or nothing). No task holds some reservations while waiting for others, so circular wait is impossible.
- Two reservations conflict if one path prefix is a prefix of the other.
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

- **Gate code is human-owned.** The diff check, attack validation, integration gate, seat minting, ledger, and signing live in a protected path (e.g. `internal/gate/**`, `internal/ledger/**`). Agents may *propose* changes there, but every such change goes to `awaiting_human` regardless of blast radius and needs real tests.
- **Dogfood with a pinned binary.** When Arbiter works on its own repo, it runs a pinned, known-good release (`stage0`), never the build under change. Promote a new stage0 only after it has passed CI and some real use. Compilers bootstrap the same way.
- **Main stays green.** Nothing merges to `main` unless CI passes, which is exactly the rule Arbiter enforces on everyone else.
- **Config is validated at startup.** Port conflicts, missing keys, or bad paths fail loudly instead of producing a half-working install.
