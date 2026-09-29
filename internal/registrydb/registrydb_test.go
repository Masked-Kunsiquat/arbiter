package registrydb_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/registrydb"
)

// open returns a DB backed by a temp file that is automatically cleaned up.
func open(t *testing.T) *registrydb.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "global_registry.db")
	rdb, err := registrydb.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { rdb.Close() })
	return rdb
}

// ─────────────────────────────────────────────────────────────────────────────
// PRAGMAs
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_WALMode(t *testing.T) {
	rdb := open(t)
	mode, err := rdb.PragmaString(context.Background(), "journal_mode")
	if err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want \"wal\"", mode)
	}
}

func TestOpen_BusyTimeout(t *testing.T) {
	rdb := open(t)
	v, err := rdb.PragmaInt(context.Background(), "busy_timeout")
	if err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if v != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", v)
	}
}

func TestOpen_ForeignKeys(t *testing.T) {
	rdb := open(t)
	v, err := rdb.PragmaInt(context.Background(), "foreign_keys")
	if err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if v != 1 {
		t.Errorf("foreign_keys = %d, want 1", v)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema: all expected tables exist
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_AllTablesExist(t *testing.T) {
	rdb := open(t)
	want := []string{
		"registered_projects",
		"org_lessons",
	}
	raw := rdb.SQLDB()
	for _, tbl := range want {
		var name string
		err := raw.QueryRowContext(context.Background(),
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing: %v", tbl, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// registered_projects: repo_path is UNIQUE
// ─────────────────────────────────────────────────────────────────────────────

func TestRegisteredProjects_RepoPathUnique(t *testing.T) {
	rdb := open(t)
	raw := rdb.SQLDB()
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO registered_projects (project_id, repo_path, tech_stack_tags)
		VALUES ('proj-1', '/repo/a', '["go"]')`)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO registered_projects (project_id, repo_path, tech_stack_tags)
		VALUES ('proj-2', '/repo/a', '["go"]')`)
	if err == nil {
		t.Fatal("expected UNIQUE violation on duplicate repo_path, got nil")
	}
}

func TestRegisteredProjects_PKUnique(t *testing.T) {
	rdb := open(t)
	raw := rdb.SQLDB()
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO registered_projects (project_id, repo_path, tech_stack_tags)
		VALUES ('proj-1', '/repo/a', '["go"]')`)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, err = raw.ExecContext(context.Background(), `
		INSERT INTO registered_projects (project_id, repo_path, tech_stack_tags)
		VALUES ('proj-1', '/repo/b', '["go"]')`)
	if err == nil {
		t.Fatal("expected PK violation on duplicate project_id, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// org_lessons: basic insert round-trip
// ─────────────────────────────────────────────────────────────────────────────

func TestOrgLessons_Insert(t *testing.T) {
	rdb := open(t)
	raw := rdb.SQLDB()
	_, err := raw.ExecContext(context.Background(), `
		INSERT INTO org_lessons
		  (id, title, tech_stack_tag, file_pattern, rule_markdown,
		   origin_project_id, origin_lesson_id, promotion_manifest_hash, human_signature)
		VALUES
		  ('org-1', 'Always index FKs', 'sqlite', '**/*.sql', 'rule text',
		   'proj-1', 'lesson-1', 'deadbeef', '---- BEGIN SSH SIGNATURE ----')`)
	if err != nil {
		t.Fatalf("insert org_lesson: %v", err)
	}

	var title string
	err = raw.QueryRowContext(context.Background(),
		`SELECT title FROM org_lessons WHERE id = 'org-1'`).Scan(&title)
	if err != nil {
		t.Fatalf("select org_lesson: %v", err)
	}
	if title != "Always index FKs" {
		t.Errorf("title = %q, want %q", title, "Always index FKs")
	}
}

func TestOrgLessons_PKUnique(t *testing.T) {
	rdb := open(t)
	raw := rdb.SQLDB()
	insert := func() error {
		_, err := raw.ExecContext(context.Background(), `
			INSERT INTO org_lessons
			  (id, title, tech_stack_tag, file_pattern, rule_markdown,
			   origin_project_id, origin_lesson_id, promotion_manifest_hash, human_signature)
			VALUES
			  ('org-1', 'x', 'sqlite', '**/*.sql', 'x', 'proj-1', 'lesson-1', 'h', 's')`)
		return err
	}
	if err := insert(); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insert(); err == nil {
		t.Fatal("expected PK violation on duplicate id, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Open is idempotent: calling it twice on the same file works
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "global_registry.db")

	rdb1, err := registrydb.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	rdb1.Close()

	rdb2, err := registrydb.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	rdb2.Close()
}
