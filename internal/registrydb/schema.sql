-- Arbiter global_registry.db schema (spec §4.B, v3.1)
-- Applied by internal/registrydb.Open; never modified by hand.
--
-- Location: ~/.config/arbiter/global_registry.db (shared across the machine,
-- one instance regardless of how many repos use Arbiter).
--
-- Agents never write to this database (spec §6.E): only the core, at Gate 3
-- (human-signed promotion), and the human CLI write here. Package registrydb
-- exposes no agent-facing invocation path; callers are core/CLI code only.

-- WAL + timeout + FK enforcement are set by the Go layer (PRAGMA calls in Open).

-- ─────────────────────────────────────────────────────────────────────────────
-- Projects that have run `arbiter init` on this machine.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS registered_projects (
    project_id TEXT PRIMARY KEY,
    repo_path TEXT UNIQUE NOT NULL,
    tech_stack_tags TEXT NOT NULL,           -- JSON array, auto-detected from manifests
    last_indexed_at DATETIME
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Tier 3 org lessons, promoted from a project's Tier 2 lessons via a
-- human-signed manifest (Gate 3, §6.E). file_pattern must be repo-agnostic
-- (extension/basename globs only, e.g. "**/*.sql") — enforced by the promotion
-- code path, not by this schema.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS org_lessons (
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
