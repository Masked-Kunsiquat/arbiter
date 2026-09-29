Arbiter Engine: Full Architecture & System Specification
A lean, local-first execution arbiter, task governor, and multi-agent coordination layer built on native Git primitives, embedded SQLite, and cryptographic attestations.
1. System Overview & Core Axioms
The Arbiter is an operating-system-level governance plane and execution engine. It sits between local codebases and agent harnesses (Claude Code, Cursor, Aider, custom sub-shells). It does not write application code; it governs state, enforces role separation, orchestrates worktrees, executes test gates, and manages a three-tiered epistemic memory pipeline.
                         ┌───────────────────────────────┐
                         │          Human Admin          │
                         │     (CLI / TUI / SSH Key)     │
                         └───────────────┬───────────────┘
                                         │ Signs PRDs & Root Vetoes
                                         ▼
                         ┌───────────────────────────────┐
                         │       The PRD Contract        │
                         │ (.arbiter/prds/PRD-XXX.md)    │
                         │ SHA-256 Frozen & Human-Signed │
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
│                             The Arbiter Daemon                              │
│  - Embedded SQLite (Tasks, Locks, PRDs, Epistemic Knowledge Pipeline)       │
│  - Git Worktree Lifecycle & Process Group (-PGID) Manager                   │
│  - Ephemeral Ed25519 Authority & Time-Bound Capability Leases               │
│  - Tree-sitter Code Symbol & Blast Radius Indexer                           │
│  - Background Knowledge Synthesizer (Clustering & Promotion Engine)         │
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
                                         Auto-Merge                      HITL Prompt
                                         to Feature                    (Human Approval)

Core Axioms
 * No Self-Grading: The agent writing code cannot review, test, or approve its own work.
 * Deterministic Gating: State transitions require deterministic proof (passing test suites, static analysis, explicit contracts) rather than agent declarations.
 * Physical Isolation over Permissions: Agents operate strictly in dedicated git worktrees isolated by OS Process Groups (-PGID).
 * Git as the Ledger of Record: State, branches, diffs, and cryptographic attestations map directly to Git commits and history.
 * Contract-Driven Scope (PRD-First): Features originate as machine-parseable, cryptographically locked architectural contracts. Scope creep outside specified file boundaries is rejected at the tool boundary.
 * Hierarchical Epistemic Lifecycle: Memories distill into Project Lessons, which earn promotion into global Org Invariants through mathematical efficacy thresholds.
 * Cryptographic Accountability: All actions, attestations, and outcome entries are signed using asymmetric Ed25519 keypairs.
2. Product Requirements Documents (PRDs) as Executable Contracts
PRDs are not passive documentation; they are version-controlled, machine-parseable architectural contracts stored directly in the repository.
A. Lifecycle
draft \longrightarrow locked (Signed by Human SSH Key) \longrightarrow executing \longrightarrow completed \longrightarrow archived
 * The Spec-Lock: Once drafted with Ringleader assistance, the Arbiter hashes the document (sha256(prd.md)). The human signs this hash using ~/.ssh/id_ed25519.
 * Zero Unilateral Drift: Child workers and reviewers cannot alter PRD invariants or file boundaries. If a design flaw is uncovered, the task halts and demands an explicit Human PRD Amendment.
B. Format & Structure (.arbiter/prds/PRD-XXX.md)
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
<!-- Tree-sitter and file reservation locks enforce these boundaries -->
- `src/auth/**`
- `src/db/migrations/**`
- `tests/auth/**`

## 4. Acceptance Criteria & Testable Outcomes
- [ ] AC-1: POST `/auth/refresh` returns a new access/refresh pair and invalidates the old token.
- [ ] AC-2: Reusing an invalidated token terminates all active sessions for that user ID.
- [ ] AC-3: Integration tests pass in both native and mock runtimes.

3. Epistemic Knowledge Architecture: The Three Tiers
The system separates high-entropy transient telemetry from persistent, battle-tested principles.
┌────────────────────────────────────────────────────────────────────────┐
│                        TIER 3: ORG / GLOBAL RULE                       │
│  - Stored: ~/.config/arbiter/org_lessons.db (Shared across machine)    │
│  - Promotion Gate: Human SSH Key Signature + Efficacy Score (U >= 0.8) │
│  - Example: "All SQLite DBs must set PRAGMA busy_timeout = 5000"       │
└──────────────────────────────────▲─────────────────────────────────────┘
                                   │ Promoted via Human Key (Gate 3)
┌──────────────────────────────────┴─────────────────────────────────────┐
│                       TIER 2: PROJECT LESSON                           │
│  - Stored: .arbiter/project_lessons.db (Repository Scoped)             │
│  - Tracked Telemetry: Catches (+), Misses (-1.5), Contradictions (-3.0)│
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

 * Tier 1: Ephemeral Memory (Task-Scoped): Transient runtime telemetry, failure traces, and crash autopsies. Kept isolated in task run storage; never directly injected into global prompts.
 * Tier 2: Project Lessons (Repository-Scoped): Concrete technical rules tied to file globs. Maintains an active ledger of real-world outcomes (catch, miss, contradiction).
 * Tier 3: Org Invariants (Machine-Global): Universal architectural standards applied across every project on the host machine.
4. Data & Storage Layer
All persistence is local, embedded, and daemonless via SQLite in WAL mode.
A. Repository-Level Schema (.arbiter/state.db)
-- Executable Feature Contracts (PRDs)
CREATE TABLE prds (
    id TEXT PRIMARY KEY,                     -- e.g. "PRD-004"
    title TEXT NOT NULL,
    file_path TEXT NOT NULL,                 -- .arbiter/prds/PRD-004.md
    spec_hash TEXT NOT NULL,                 -- SHA256 of locked content
    status TEXT NOT NULL CHECK (status IN (
        'draft', 'locked', 'executing', 'completed', 'amendment_needed'
    )),
    target_branch TEXT NOT NULL,
    max_budget_usd REAL DEFAULT 5.00,
    human_pubkey TEXT NOT NULL,              -- Signed by human SSH key
    human_signature TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Atomic Tasks
CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    prd_id TEXT,                             -- Foreign key to parent PRD
    title TEXT NOT NULL,
    spec_markdown TEXT NOT NULL,
    spec_hash TEXT NOT NULL,                 -- SHA-256 frozen upon locking
    status TEXT NOT NULL CHECK (status IN (
        'backlog', 'spec_locked', 'in_progress', 
        'under_review', 'verified', 'awaiting_human', 'done', 'failed'
    )),
    assigned_worker_pubkey TEXT,
    assigned_reviewer_pubkey TEXT,
    worktree_path TEXT,
    target_branch TEXT NOT NULL,
    active_pgid INTEGER,                    -- OS Process Group ID
    retry_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(prd_id) REFERENCES prds(id)
);

-- File Reservation Locks
CREATE TABLE file_reservations (
    file_path TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    acquired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

-- Ephemeral Memories (Tier 1)
CREATE TABLE task_memories (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    commit_sha TEXT,
    observation_type TEXT CHECK (observation_type IN ('autopsy', 'test_failure', 'execution_log')),
    content TEXT NOT NULL,
    reporter_pubkey TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- Project Lessons (Tier 2)
CREATE TABLE project_lessons (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    file_pattern TEXT NOT NULL,              -- e.g. "src/db/**/*.ts"
    context_trigger TEXT NOT NULL,
    rule_markdown TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'review_needed', 'quarantined', 'promoted_to_org')),
    source_cluster_count INTEGER DEFAULT 1,
    promoted_by_pubkey TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Signed Outcome Ledger
CREATE TABLE lesson_outcomes (
    id TEXT PRIMARY KEY,
    lesson_id TEXT NOT NULL,
    task_id TEXT,
    author_type TEXT NOT NULL CHECK (author_type IN ('human', 'agent')),
    author_pubkey TEXT NOT NULL,
    outcome_type TEXT NOT NULL CHECK (outcome_type IN ('catch', 'miss', 'contradiction')),
    description TEXT NOT NULL,               -- Mandatory narrative description
    context_diff_or_trace TEXT,
    signature TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(lesson_id) REFERENCES project_lessons(id)
);

-- Attestations (Cryptographic Proof of Sign-off)
CREATE TABLE attestations (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    worker_pubkey TEXT NOT NULL,
    reviewer_pubkey TEXT NOT NULL,
    judge_verdict TEXT NOT NULL,
    raw_payload TEXT NOT NULL,
    worker_signature TEXT NOT NULL,
    reviewer_signature TEXT NOT NULL,
    judge_signature TEXT NOT NULL,
    human_signed BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

B. Machine-Global Registry (~/.config/arbiter/global_registry.db)
CREATE TABLE registered_projects (
    project_id TEXT PRIMARY KEY,
    repo_path TEXT UNIQUE NOT NULL,
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
    promoted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    human_signature TEXT NOT NULL            -- MUST be signed by Human Root Key
);

5. Agent Roles & Execution Protocol
1. Locked PRD ──► Ringleader (Decompose & Compile Task DAG)
                      │
                      ├── Scope > 3 files or > 15m? ──► Interactive HITL Proposal
                      └── Within Atomic Limits?    ──► Dispatches Worker
                                                           │
┌──────────────────────────────────────────────────────────┘
▼
2. Worker (Isolated Worktree, Ephemeral Worker Key)
   - Operates strictly within PRD file boundaries
   - Writes code + unit tests
   - Submits work commit
   ▼
3. Adversarial Reviewer (Isolated Sub-Process, Ephemeral Reviewer Key)
   - Evaluates code against PRD Invariants
   - Writes adversarial attack test
   ├── Attack FAILS? (Defect Proven) ──► Rejection Loop back to Worker (Max 3)
   └── Attack PASSES? (No defects)   ──► Pass to Judge
                                           │
┌──────────────────────────────────────────┘
▼
4. The Judge (Evaluates balance of proof & blast radius)
   ├── Low risk & green tests  ──► Auto-merge to Feature Branch
   └── High risk / schema diff ──► Stage for Human-in-the-Loop Sign-off

1. The Ringleader (Planning & Triage)
 * High-reasoning model (Claude Sonnet / OpenAI o-series).
 * Reads the locked PRD contract and compiles it into an atomic Directed Acyclic Graph (DAG) of tasks.
 * Triage Scope Guard: Enforces that no child task touches > 3 modules or exceeds an estimated 15 minutes of uninterrupted tool runtime. Prompts for human interactive confirmation if decomposition is ambiguous.
 * Injects matching Org Invariants, Project Lessons, and PRD Invariants into task context windows.
2. The Worker (Execution Sub-Process)
 * Operates inside ./worktrees/<task-id> under a dedicated Process Group (-PGID).
 * Holds an ephemeral worker key leased for 15 minutes.
 * Confined to the Allowed File Boundaries defined in the parent PRD. Modifications outside these globs are rejected by the Arbiter tool layer.
 * Prohibited from modifying spec.md or any test files marked @adversary.
3. The Adversarial Reviewer (Critic & Defect Hunter)
 * Rule: Never modifies or fixes application code.
 * Specifically authors attack test files (e.g., tests/adversary_attack.test.ts) covering PRD Invariants and edge cases.
 * Deterministic Gate:
   * Attack test fails \rightarrow Defect mathematically proven. Bounces task back to Worker with stack trace and git diff.
   * Attack test passes \rightarrow Verifies diff adheres to spec; passes evidence to Judge.
4. The Judge (Neutral Arbiter)
 * Evaluates Worker code commits, Adversary test executions, and the frozen spec SHA.
 * Resolves whether to auto-merge or escalate based on Tree-sitter blast radius:
   * Low Blast Radius (pure logic/docs, passing adversary tests): Auto-signs attestation and merges to feature branch.
   * High Blast Radius (database migrations, auth config, root schema): Escalates to awaiting_human.
5. Human in the Loop (HITL)
 * Root authority via terminal prompt:
   [JUDGE VERDICT: READY FOR HUMAN REVIEW]
Task: AUTH-102 (Rotate refresh tokens) | Parent: PRD-004
Worker: Done (14 tests passed)
Adversary: Passed (Edge cases verified against INVARIANT-1 & 2)
Blast Radius: Touches 2 critical files in src/auth.

[A]pprove & Merge   [R]eject with note   [I]nspect Diff   [S]hell into worktree
> _

 * Rejections trigger the Worker loop and record an outcome.
6. Epistemic Gates & Outcome Telemetry
[ Raw Memories ]
       │
       ▼  GATE 1: Candidate Activation (Synthesizer cluster >= 2 + Judge/Human signoff)
[ Active Project Lesson ]
       │
       ▼  GATE 2: Efficacy Threshold (U >= 0.80, Samples >= 5, Contradictions == 0)
[ Staged for Org Promotion ]
       │
       ▼  GATE 3: Human SSH Key Veto (Signed via ~/.ssh/id_ed25519)
[ Global Org Invariant ]

The Three Knowledge Gates
 * Gate 1: Candidate Activation (Memory \rightarrow Project Lesson):
   * Background Synthesizer clusters \ge 2 task autopsies or failure traces with semantic similarity > 0.82.
   * Promoted to Active status via Judge or Human key signature.
 * Gate 2: Efficacy Threshold (Project \rightarrow Org Staging):
   * Evaluated across the Outcome Ledger using the Utility Formula (U):
     
   * Requirements: Sample size \ge 5 distinct tasks, U \ge 0.80, and \text{Contradictions} == 0.
 * Gate 3: Human Root Veto (Org Invariant):
   * The daemon stages the promotion proposal.
   * Only the Human SSH Key (~/.ssh/id_ed25519) can execute the write to org_lessons.db. Agents cannot promote to Org level.
Outcome Enforcement & Sybil Resistance
 * Mandatory Narrative: Every outcome logged (catch, miss, contradiction) must provide a descriptive explanation and relevant error log or diff snippet.
 * No Self-Endorsement: An agent's key cannot sign a catch for a lesson that the same agent generated within the same task. Catches must be signed by the Adversary, the Judge, or the Human.
 * Differential Key Weighting:
   * Human Signature: Weight = 1.0
   * Adversary / Judge Signature: Weight = 0.7
   * Worker Signature: Weight = 0.3
 * The Contradiction Circuit Breaker (Downward Quarantine):
   * If any project lesson accumulates \ge 2 contradictions, it is immediately set to quarantined.
   * The Arbiter halts injection of that lesson into all worktrees and flags it for human review.
7. Process Control, Autopsies & Leases
Process Management
 * Every sub-process (Worker, Adversary, Test Runner) is spawned with a dedicated Process Group (-PGID).
 * Kill Switch: Terminations target -PGID (kill -TERM -<PGID> followed by kill -KILL -<PGID>) to nuke child processes, test runners, and dangling compilers simultaneously.
 * Dead Man's Switch: Workers must send IPC/MCP heartbeats every 30 seconds. On Linux hosts, sub-processes configure PR_SET_PDEATHSIG to auto-terminate if the Arbiter daemon dies.
Dynamic Leases vs. Hard Walls
 * Standard task lease: 15 minutes.
 * Long operations (device test suites, native compilations) emit heartbeat extensions (heartbeat({ status: "running_integration_tests" })), extending the lease up to an absolute ceiling.
 * Human Pause: When a task enters awaiting_human, all timers freeze completely.
Automated Crash Autopsy
When an agent times out or crashes:
 * Arbiter sends SIGKILL to -PGID.
 * Captures last 50 lines of stdout/stderr and runs git diff.
 * Evaluates progress:
   * Dead End / Infinite Loop: Runs git reset --hard HEAD and logs an autopsy memory: "Attempt 1 died: Infinite loop mocking native SQLite bindings."
   * Legitimate Progress: Creates a checkpoint commit (checkpoint/attempt-1-timeout).
 * Replacement Worker Spawn: Injects the autopsy note into Attempt 2's prompt: "WARNING: Previous worker failed with X. Do NOT repeat that approach."
8. Cryptographic Identity & Attestation Model
All logical authority maps to Ed25519 asymmetric keypairs.
                [ Human Admin ]
             (Local ~/.ssh/id_ed25519)
                       │ Signs PRD Locks, Org Invariants & Final Merges
                       ▼
            [ Arbiter Root Authority ]
                       │ Issues 15-min Time-Bound Capability Leases
                       ▼
       ┌───────────────────────────────┐
       │   Ephemeral Agent Keypair     │ (Generated in RAM on task spawn)
       │ - Stored outside workspace    │
       │ - Wiped from memory on exit   │
       └───────────────┬───────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
[ Worker Role ]             [ Reviewer Role ]
Signs Git Commits           Signs Attack-Test Attestations

Protocol Details
 * Ephemeral Generation: Generated in RAM on task dispatch; never saved to disk or repository files.
 * No Direct Agent Exposure: The Arbiter daemon holds the private key in memory and acts as a local signing proxy over a secure IPC pipe. Agents cannot leak their private keys via prompt injection or file dump.
 * Time-Bound Capabilities: Public keys are registered in SQLite with strict 15-minute lease expirations. Once expired, the Arbiter rejects any API or git operation signed by that key.
 * Permanent Provenance: When the task ends, the private key is wiped. The public key remains in attestations and lesson_outcomes forever, allowing permanent verification of historical decisions against Git commit SHAs.
9. User Interface & CLI / TUI Design
Built as a single terminal binary without external web dashboards or headless browser requirements.
Terminal UI (TUI) Layout
┌─ Arbiter: Active Tasks ────────────┬─ Worker Stream [TASK-102] ──────────────────────┐
│ [IN_PROGRESS] TASK-102: Auth Refresh│ Running: npm run test:auth                      │
│   Worker: sub-01 | Lock: src/auth/* │ PASS src/auth/token.test.ts                     │
│ [REVIEW]      TASK-101: SQLite Init │ FAIL src/auth/rotation.test.ts (Expected 401)   │
│   Adversary: adv-02 (Running attack)│                                                 │
│ [HUMAN_GATE]  TASK-99: Schema Migr  │ Adversary generating attack patch...            │
├─────────────────────────────────────┼─────────────────────────────────────────────────┤
│ Active PRD: PRD-004 (2/3 tasks done)│ Token Burn: 42,100 / 150,000 | Est: $0.42       │
│ Lessons Injected: LESSON-12, ORG-04 │ Lease Remaining: 08:42                          │
└─────────────────────────────────────┴─────────────────────────────────────────────────┘

CLI Command Suite
 * arbiter prd init "<title>": Drafts a new PRD template.
 * arbiter prd lock <prd-id>: Hashes the PRD, prompts for human SSH signature, and freezes scope.
 * arbiter prd review <prd-id>: Runs the full integration test pass and prompts for final merge into main.
 * arbiter run "<prompt>": Invokes Ringleader planning, triage, and task DAG dispatch.
 * arbiter tasks: Displays active tasks, leases, worktrees, and held locks.
 * arbiter review <task-id>: Opens diff viewer with interactive HITL sign-off prompt.
 * arbiter lesson outcome <id> --<catch|miss|contradiction> -m "<reason>": Logs an outcome to the ledger.
 * arbiter org stage: Lists project lessons currently meeting Gate 2 (U \ge 0.80) ready for human review.
 * arbiter org promote <id>: Promotes a staged lesson to Org level, signed via ~/.ssh/id_ed25519.
 * arbiter prune: Cleans up dead worktrees, orphaned branches, and dangling locks.
10. Technology Stack
 * Core Language: Go (recommended for single static binary distribution, native OS process group control, and performant TUI via bubbletea) or TypeScript on Bun/Node (for native @modelcontextprotocol/sdk and better-sqlite3).
 * Database: SQLite in WAL mode with FTS5.
 * Code Intelligence: Tree-sitter for deterministic AST parsing, symbol extraction, and blast-radius mapping.
 * Embedding Synthesizer: Lightweight local embeddings (e.g., bge-small or nomic-embed-text) executed locally via ONNX Runtime for offline memory clustering.
 * Crypto Primitives: Native standard library ed25519 for ephemeral signatures; standard ssh-agent / OpenSSH tooling for human root signatures.
 * VCS Operations: Native Git CLI via sub-process execution (git worktree, git commit, git notes).
