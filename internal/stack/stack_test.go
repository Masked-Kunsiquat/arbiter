package stack_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/stack"
)

func writeFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func TestDetect_Go(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod")

	got, err := stack.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].Name != "go" {
		t.Fatalf("Detect: got %+v, want single go ecosystem", got)
	}
	if got[0].Adversary.Pattern != "**/*_adversary_test.go" {
		t.Errorf("Adversary.Pattern = %q", got[0].Adversary.Pattern)
	}
}

func TestDetect_Node(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json")

	got, err := stack.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].Name != "node" {
		t.Fatalf("Detect: got %+v, want single node ecosystem", got)
	}
}

func TestDetect_PythonDedupesMarkers(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml")
	writeFile(t, dir, "requirements.txt")

	got, err := stack.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].Name != "python" {
		t.Fatalf("Detect: got %+v, want a single deduped python ecosystem", got)
	}
}

func TestDetect_Polyglot(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod")
	writeFile(t, dir, "package.json")

	got, err := stack.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Detect: got %d ecosystems, want 2", len(got))
	}
	if got[0].Name != "go" {
		t.Errorf("Detect: first result = %q, want %q (detector priority order)", got[0].Name, "go")
	}
}

func TestDetect_Empty(t *testing.T) {
	dir := t.TempDir()

	got, err := stack.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Detect: got %+v, want none", got)
	}
}
