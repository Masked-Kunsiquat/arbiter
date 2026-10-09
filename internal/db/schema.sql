-- Arbiter state.db schema (spec §4.A, v3.1)
-- Applied by internal/db.Open; never modified by hand.

-- WAL + timeout + FK enforcement are set by the Go layer (PRAGMA calls in Open).

-- ─────────────────────────────────────────────────────────────────────────────
-- Executable Feature Contracts (PRDs)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS prds (
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

-- ─────────────────────────────────────────────────────────────────────────────
-- Atomic Tasks
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    prd_id TEXT NOT NULL,
    title TEXT NOT NULL,
    intent TEXT NOT NULL,                    -- one paragraph, written at planning time
    spec_markdown TEXT,                      -- full spec, written just-in-time when task becomes 'ready' (§5.1)
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

-- ─────────────────────────────────────────────────────────────────────────────
-- DAG edges: task_id cannot start until depends_on is 'done'
-- Cycle check runs in the supervisor on insert (DFS); the Ringleader's DAG is
-- rejected if cyclic.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS task_edges (
    task_id TEXT NOT NULL,
    depends_on TEXT NOT NULL,
    PRIMARY KEY (task_id, depends_on),
    CHECK (task_id <> depends_on),
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY(depends_on) REFERENCES tasks(id) ON DELETE CASCADE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Symbols a task's spec relies on.
-- Fleet only (§12): single-lane specs are written just-in-time and cannot go stale.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS task_symbol_deps (
    task_id TEXT NOT NULL,
    symbol TEXT NOT NULL,                    -- e.g. "src/auth/utils.ts#signToken"
    signature_hash TEXT NOT NULL,            -- tree-sitter signature hash when the spec was written
    PRIMARY KEY (task_id, symbol),
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Path reservations.
-- Prefixes compare by whole path segment: "src/auth/" covers "src/auth/token.ts"
-- but not "src/authz/x.ts". Stored with forward slashes and a trailing slash
-- for directories. Populated in single-lane mode too (they drive the
-- submit-time diff check); only contended under Fleet.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reservations (
    path_prefix TEXT NOT NULL,
    task_id TEXT NOT NULL,
    acquired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (path_prefix, task_id),
    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Ephemeral Memories (Tier 1)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS task_memories (
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
CREATE INDEX IF NOT EXISTS idx_task_memories_fp ON task_memories(fingerprint);

-- ─────────────────────────────────────────────────────────────────────────────
-- Project Lessons (Tier 2)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS project_lessons (
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

-- ─────────────────────────────────────────────────────────────────────────────
-- Every time a lesson is placed into a task's context
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lesson_injections (
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

-- ─────────────────────────────────────────────────────────────────────────────
-- Outcome Ledger: at most one outcome per (lesson, task).
-- Precedence when rows would collide: human > core > judge (a higher author
-- replaces the row). No FK on lesson_id: org lessons live in
-- global_registry.db; lesson_tier says which table to join.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lesson_outcomes (
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

-- ─────────────────────────────────────────────────────────────────────────────
-- Attack-test disputes (§5.4). At most one per task, across all attempts.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS disputes (
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

-- ─────────────────────────────────────────────────────────────────────────────
-- Who an agent is. For agents Arbiter launches this is a descriptor, not a secret.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS credentials (
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

-- ─────────────────────────────────────────────────────────────────────────────
-- Ephemeral, role-bound seats. The seat id is the agent's identity in the ledger.
-- A seat spans one or more invocations (§8.B); the tree stays one node per
-- logical agent.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS seats (
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

-- ─────────────────────────────────────────────────────────────────────────────
-- One row per process launch. Leases and supervisor handles live here, not on
-- the seat.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invocations (
    id TEXT PRIMARY KEY,
    seat_id TEXT NOT NULL,
    task_id TEXT,
    purpose TEXT NOT NULL,                   -- 'plan' | 'spec' | 'implement' | 'fix' | 'attack' | 'attack_maintenance'
                                             -- | 'claim_check' | 'dispute_ruling' | 'verdict' | 'autopsy_summary'
    supervisor_handle TEXT,                  -- PGID (POSIX) or Job Object name (Windows)
    pid INTEGER,
    lease_expires_at DATETIME,               -- renewed by supervisor observation, not by the model
    exit_reason TEXT CHECK (exit_reason IN ('ok', 'invalid_output', 'crash', 'lease_expired', 'killed', 'budget_exhausted')),
    cost_usd REAL,                           -- from the harness's final result event (§9.A); NULL if none arrived (killed)
    cost_estimated INTEGER NOT NULL DEFAULT 0, -- 1 when cost_usd was summed from streamed usage instead (§5.8)
    terminal_reason TEXT,                    -- the result event's terminal_reason (§9.A); NULL if none arrived
    api_error_status INTEGER,                -- the result event's api_error_status (e.g. 404, 529); NULL if none
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ended_at DATETIME,
    FOREIGN KEY(seat_id) REFERENCES seats(id)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Hash-chained, supervisor-signed audit log (§8.B, action catalog in §8.E).
-- One chain per PRD (chain = 'PRD-004'), plus chain = 'global' for entries with
-- no PRD (credentials, org promotions), so each exported ledger file verifies
-- on its own.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
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
