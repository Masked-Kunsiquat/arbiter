// Package stack detects a repository's ecosystem from lockfiles and
// manifests, and supplies the config defaults arbiter init scaffolds for it
// (spec §9.C).
package stack

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"
)

// Ecosystem is a detected project ecosystem.
type Ecosystem struct {
	Name string // matches internal/config's adversary-pattern-rule keys ("go", "node", "python", "rust")

	Harness struct {
		ShellAllow []string
	}
	Test struct {
		Build     string
		All       string
		Files     string
		Reporter  string
		JUnitPath string // non-empty only when Reporter == "junit-xml"
	}
	Adversary struct {
		Pattern string
	}
	Deps struct {
		Install   string
		Lockfiles []string
		Keep      []string
	}
}

// marker is one file, relative to the repo root, whose presence identifies
// an ecosystem, in priority order (checked top to bottom; first match
// wins per detector).
type marker struct {
	file  string
	build func() Ecosystem
}

var detectors = []marker{
	{"go.mod", goEcosystem},
	{"package.json", nodeEcosystem},
	{"pyproject.toml", pythonEcosystem},
	{"requirements.txt", pythonEcosystem},
	{"setup.py", pythonEcosystem},
	{"Cargo.toml", rustEcosystem},
}

// Detect inspects dir for known lockfiles/manifests and returns every
// ecosystem it finds, in the order listed in detectors. A repo can be
// polyglot (e.g. a Go backend with a Node frontend); the caller (arbiter
// init) decides how to merge or pick among multiple results.
func Detect(dir string) ([]Ecosystem, error) {
	var found []Ecosystem
	seen := map[string]bool{}

	for _, d := range detectors {
		_, err := os.Stat(filepath.Join(dir, d.file))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("stack: stat %s: %w", d.file, err)
		}
		eco := d.build()
		if seen[eco.Name] {
			continue
		}
		if eco.Name == "rust" {
			if err := setRustAdversaryPattern(dir, &eco); err != nil {
				return nil, err
			}
		}
		seen[eco.Name] = true
		found = append(found, eco)
	}
	return found, nil
}

func goEcosystem() Ecosystem {
	var e Ecosystem
	e.Name = "go"
	e.Harness.ShellAllow = []string{
		"Bash(go test *)", "Bash(go build *)", "Bash(go vet *)",
		"Bash(git status*)", "Bash(git diff*)",
		"PowerShell(go test *)", "PowerShell(go build *)", "PowerShell(go vet *)",
	}
	e.Test.Build = "go build ./... && go vet ./... && go test -count=1 -run ^$ ./..."
	e.Test.All = "go test -json -count=1 ./..."
	e.Test.Files = "go test -json -count=1 {packages}"
	e.Test.Reporter = "go-json"
	e.Adversary.Pattern = "**/*_adversary_test.go"
	e.Deps.Install = "go mod download"
	e.Deps.Lockfiles = []string{"go.sum"}
	return e
}

func nodeEcosystem() Ecosystem {
	var e Ecosystem
	e.Name = "node"
	e.Harness.ShellAllow = []string{
		"Bash(npm test*)", "Bash(npm run build*)", "Bash(npm ci*)",
		"Bash(git status*)", "Bash(git diff*)",
	}
	e.Test.Build = "npm run build"
	e.Test.All = "npm test"
	e.Test.Files = "npm test -- {files}"
	e.Test.Reporter = "tap"
	e.Adversary.Pattern = "**/*.adversary.test.ts"
	e.Deps.Install = "npm ci"
	e.Deps.Lockfiles = []string{"package-lock.json"}
	e.Deps.Keep = []string{"node_modules"}
	return e
}

func pythonEcosystem() Ecosystem {
	var e Ecosystem
	e.Name = "python"
	e.Harness.ShellAllow = []string{
		"Bash(pytest*)", "Bash(git status*)", "Bash(git diff*)",
	}
	e.Test.Build = "python -m py_compile ."
	// junit-xml reporter requires a path; pytest emits JUnit XML via --junitxml.
	e.Test.All = "pytest --junitxml=.arbiter/test-results.xml"
	e.Test.Files = "pytest --junitxml=.arbiter/test-results.xml {files}"
	e.Test.Reporter = "junit-xml"
	e.Test.JUnitPath = ".arbiter/test-results.xml"
	e.Adversary.Pattern = "**/test_adversary_*.py"
	e.Deps.Install = "pip install -r requirements.txt"
	e.Deps.Lockfiles = []string{"requirements.txt"}
	e.Deps.Keep = []string{".venv"}
	return e
}

func rustEcosystem() Ecosystem {
	var e Ecosystem
	e.Name = "rust"
	e.Harness.ShellAllow = []string{
		"Bash(cargo test*)", "Bash(cargo build*)", "Bash(cargo check*)",
		"Bash(git status*)", "Bash(git diff*)",
		"PowerShell(cargo test*)", "PowerShell(cargo build*)", "PowerShell(cargo check*)",
	}
	e.Test.Build = "cargo test --no-run"
	e.Test.All = "cargo test"
	// Cargo selects integration tests by target name (--test <name>), not by
	// file path, so neither documented placeholder ({files}, {packages}) fits.
	// Run the full suite for subsets: a superset is always correct.
	e.Test.Files = "cargo test"
	e.Test.Reporter = "tap"
	e.Adversary.Pattern = "tests/*_adversary_test.rs"
	e.Deps.Install = "cargo fetch"
	e.Deps.Lockfiles = []string{"Cargo.lock"}
	e.Deps.Keep = []string{"target"}
	return e
}

// cargoManifest is the subset of Cargo.toml needed to tell a virtual
// workspace (a [workspace] with no [package]) from a package manifest.
type cargoManifest struct {
	Package   *struct{} `toml:"package"`
	Workspace *struct {
		Members        []string `toml:"members"`
		DefaultMembers []string `toml:"default-members"`
		Exclude        []string `toml:"exclude"`
	} `toml:"workspace"`
}

// setRustAdversaryPattern points e's adversary pattern at a member crate's
// tests/ dir when dir's Cargo.toml is a virtual workspace: Cargo builds no
// package at the workspace root, so a root tests/ dir would never run. The
// member is the first one `cargo test` runs from the root (default-members,
// else members). A manifest that doesn't parse keeps the root default;
// cargo itself will report that error.
func setRustAdversaryPattern(dir string, e *Ecosystem) error {
	var m cargoManifest
	if _, err := toml.DecodeFile(filepath.Join(dir, "Cargo.toml"), &m); err != nil {
		return nil
	}
	if m.Package != nil || m.Workspace == nil {
		return nil
	}
	candidates := m.Workspace.DefaultMembers
	if len(candidates) == 0 {
		candidates = m.Workspace.Members
	}
	for _, c := range candidates {
		matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(c)))
		if err != nil {
			continue
		}
		slices.Sort(matches)
		for _, mp := range matches {
			rel, err := filepath.Rel(dir, mp)
			if err != nil || !filepath.IsLocal(rel) {
				continue
			}
			rel = filepath.ToSlash(rel)
			if slices.Contains(m.Workspace.Exclude, rel) {
				continue
			}
			if fi, err := os.Stat(filepath.Join(mp, "Cargo.toml")); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			e.Adversary.Pattern = rel + "/tests/*_adversary_test.rs"
			return nil
		}
	}
	return errors.New("stack: Cargo.toml is a virtual workspace with no resolvable member crate; " +
		"add a member (or default-members) so arbiter init can place adversary tests in it")
}
