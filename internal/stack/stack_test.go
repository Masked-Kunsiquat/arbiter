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

func TestDetect_Rust(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml")

	got, err := stack.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 || got[0].Name != "rust" {
		t.Fatalf("Detect: got %+v, want single rust ecosystem", got)
	}
	if got[0].Test.Build != "cargo test --no-run" {
		t.Errorf("Rust Test.Build = %q, want 'cargo test --no-run'", got[0].Test.Build)
	}
	if got[0].Adversary.Pattern != "tests/*_adversary_test.rs" {
		t.Errorf("Rust Adversary.Pattern = %q, want 'tests/*_adversary_test.rs'", got[0].Adversary.Pattern)
	}
	if len(got[0].Deps.Keep) != 1 || got[0].Deps.Keep[0] != "target" {
		t.Errorf("Rust Deps.Keep = %v, want [target]", got[0].Deps.Keep)
	}
	if got[0].Deps.Install != "cargo fetch" {
		t.Errorf("Rust Deps.Install = %q, want 'cargo fetch'", got[0].Deps.Install)
	}
	if len(got[0].Deps.Lockfiles) != 1 || got[0].Deps.Lockfiles[0] != "Cargo.lock" {
		t.Errorf("Rust Deps.Lockfiles = %v, want [Cargo.lock]", got[0].Deps.Lockfiles)
	}
}

func writeManifest(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetect_RustVirtualWorkspace(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		members  []string
		want     string // "" means Detect must fail
	}{
		{"package manifest", "[package]\nname = \"x\"\n[workspace]\nmembers = [\"crates/a\"]\n", []string{"crates/a"}, "tests/*_adversary_test.rs"},
		{"glob member", "[workspace]\nmembers = [\"crates/*\"]\n", []string{"crates/b", "crates/a"}, "crates/a/tests/*_adversary_test.rs"},
		{"default-members win", "[workspace]\nmembers = [\"crates/*\"]\ndefault-members = [\"crates/b\"]\n", []string{"crates/a", "crates/b"}, "crates/b/tests/*_adversary_test.rs"},
		{"excluded member skipped", "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/a\"]\n", []string{"crates/a", "crates/b"}, "crates/b/tests/*_adversary_test.rs"},
		{"no members", "[workspace]\nmembers = []\n", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeManifest(t, filepath.Join(dir, "Cargo.toml"), tc.manifest)
			for _, m := range tc.members {
				writeManifest(t, filepath.Join(dir, filepath.FromSlash(m), "Cargo.toml"), "[package]\nname = \"m\"\n")
			}
			got, err := stack.Detect(dir)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("Detect: got %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if got[0].Adversary.Pattern != tc.want {
				t.Errorf("Adversary.Pattern = %q, want %q", got[0].Adversary.Pattern, tc.want)
			}
		})
	}
}

func TestKeepListPerEcosystem(t *testing.T) {
	cases := []struct {
		file     string
		wantName string
		wantKeep []string
	}{
		{"go.mod", "go", nil},
		{"package.json", "node", []string{"node_modules"}},
		{"pyproject.toml", "python", []string{".venv"}},
		{"Cargo.toml", "rust", []string{"target"}},
	}

	for _, tc := range cases {
		t.Run(tc.wantName, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, tc.file)
			got, err := stack.Detect(dir)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(got) != 1 || got[0].Name != tc.wantName {
				t.Fatalf("Detect: got %+v, want ecosystem %s", got, tc.wantName)
			}
			if len(got[0].Deps.Keep) != len(tc.wantKeep) {
				t.Fatalf("%s Keep = %v, want %v", tc.wantName, got[0].Deps.Keep, tc.wantKeep)
			}
			for i := range tc.wantKeep {
				if got[0].Deps.Keep[i] != tc.wantKeep[i] {
					t.Errorf("%s Keep[%d] = %q, want %q", tc.wantName, i, got[0].Deps.Keep[i], tc.wantKeep[i])
				}
			}
		})
	}
}
