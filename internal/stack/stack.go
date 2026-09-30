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
	e.Test.Files = "cargo test --test {test}"
	e.Test.Reporter = "tap"
	e.Adversary.Pattern = "tests/**/*_adversary_test.rs"
	e.Deps.Install = "cargo fetch"
	e.Deps.Lockfiles = []string{"Cargo.lock"}
	e.Deps.Keep = []string{"target"}
	return e
}
