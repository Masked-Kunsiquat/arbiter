// Spike: classify attack tests from `go test -json` per spec §5.4. Throwaway; see FINDINGS.md.
//
//	go run . [scratch-dir]
//
// Attack tests are the Test* funcs declared in files matching *_adversary_test.go. go test -json
// doesn't say which file a test is in, so we find them by parsing the source.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

type event struct {
	Action      string
	Package     string
	ImportPath  string
	Test        string
	Output      string
	OutputType  string
	FailedBuild string
}

type testState struct {
	ran, passed, failed bool
	output              []string
}

type pkgState struct {
	buildOutput []string
	buildFailed bool
	failed      bool
	tests       map[string]*testState
}

type attack struct {
	pkg, name, file string // file: repo-relative, forward slashes
}

type verdict struct {
	class  string // PASS | ERROR | ASSERTION_FAIL | (intermediate) CANDIDATE | NOT_RUN
	reason string
}

var (
	targetRe  = regexp.MustCompile(`(INVARIANT|AC)[-_](\d+)`)
	buildLoc  = regexp.MustCompile(`^([^\s].*?\.go):\d+:\d+: `) // primary compiler/vet error lines only (not tab-indented notes)
	frameFile = regexp.MustCompile(`^\t(.+?\.go):\d+`)
	module    string
	root      string
	goroot    string
)

func main() {
	root = "scratch"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	root, _ = filepath.Abs(root)
	goroot = filepath.ToSlash(runtime.GOROOT())
	module = readModule(root)

	attacks := findAttacks()
	fmt.Printf("found %d attack tests by parsing *_adversary_test.go\n", len(attacks))

	pkgs := runTests("./...")
	results := map[string]verdict{}
	for _, a := range attacks {
		results[a.pkg+"."+a.name] = classify(a, pkgs[a.pkg])
	}

	// Rule 5 (reproduction) and collateral: rerun candidates and not-run tests once, in isolation.
	for _, a := range attacks {
		k := a.pkg + "." + a.name
		v := results[k]
		if v.class != "CANDIDATE" && v.class != "NOT_RUN" {
			continue
		}
		iso := runTests("./"+strings.TrimPrefix(strings.TrimPrefix(a.pkg, module), "/"), "-run", "^"+regexp.QuoteMeta(a.name)+"$")
		rv := classify(a, iso[a.pkg])
		switch {
		case v.class == "NOT_RUN":
			if rv.class == "CANDIDATE" { // a collateral test that fails alone still needs the flake check
				rv = rerunOnce(a, rv)
			}
			rv.reason = "never ran in the full run (a sibling killed the test binary); isolated run: " + rv.reason
			results[k] = rv
		case rv.class == "PASS":
			results[k] = verdict{"ERROR", "flaky: " + v.reason + "; passed on isolated rerun"}
		default:
			results[k] = verdict{"ASSERTION_FAIL", v.reason + "; reproduced on isolated rerun"}
		}
	}

	fmt.Println()
	for _, a := range attacks {
		v := results[a.pkg+"."+a.name]
		fmt.Printf("%-15s %-48s %-15s %s\n", strings.TrimPrefix(a.pkg, module+"/"), a.name, v.class, v.reason)
	}
}

func rerunOnce(a attack, v verdict) verdict {
	iso := runTests("./"+strings.TrimPrefix(strings.TrimPrefix(a.pkg, module), "/"), "-run", "^"+regexp.QuoteMeta(a.name)+"$")
	if classify(a, iso[a.pkg]).class == "PASS" {
		return verdict{"ERROR", "flaky: " + v.reason}
	}
	return verdict{"ASSERTION_FAIL", v.reason + "; reproduced"}
}

// classify applies §5.4 rules 1–4 to one attack test.
func classify(a attack, p *pkgState) verdict {
	if !targetRe.MatchString(a.name) {
		return verdict{"ERROR", "no INVARIANT/AC target in test name"}
	}
	if p == nil {
		return verdict{"NOT_RUN", "package produced no events"}
	}
	// Rule 1 / 4: build failure. go test -json reports it as build-output on ImportPath "pkg [pkg.test]",
	// then a package-level fail with FailedBuild; there are no test events at all.
	if p.buildFailed {
		var adv, helper, app []string
		for _, l := range p.buildOutput {
			m := buildLoc.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			f := repoRel(m[1])
			switch {
			case isAdversary(f):
				adv = append(adv, f)
			case strings.HasSuffix(f, "_test.go"):
				helper = append(helper, f)
			default:
				app = append(app, f)
			}
		}
		switch {
		case len(app) > 0:
			return verdict{"CANDIDATE", "build failure in application code: " + strings.Join(uniq(app), ",")}
		case len(adv)+len(helper) > 0:
			return verdict{"ERROR", "build/vet failure in test code: " + strings.Join(uniq(append(adv, helper...)), ",")}
		default:
			return verdict{"ERROR", "build failure with no parseable location"}
		}
	}
	t := p.tests[a.name]
	if t == nil || !t.ran {
		return verdict{"NOT_RUN", "no run event"}
	}
	out := strings.Join(t.output, "")
	// Rule 2: timeout (the test binary panics; the running test gets the output but no fail event).
	if strings.Contains(out, "panic: test timed out after") {
		return verdict{"ERROR", "timeout"}
	}
	if t.passed {
		return verdict{"PASS", ""}
	}
	crashed := !t.failed && p.failed // ran, no terminal event, package failed: binary died under this test
	if !t.failed && !crashed {
		return verdict{"NOT_RUN", "ran but no result and package passed?"}
	}
	// Rule 3 / 4: panic → classify by top in-repo frame.
	if i := strings.Index(out, "\npanic: "); i >= 0 || strings.HasPrefix(out, "panic: ") {
		top := topInRepoFrame(t.output)
		switch {
		case top == "":
			return verdict{"ERROR", "panic with no in-repo frame"}
		case strings.HasSuffix(top, "_test.go"):
			return verdict{"ERROR", "panic thrown in test code at " + top}
		default:
			how := "panic"
			if crashed {
				how = "panic (binary crashed, no test fail event)"
			}
			return verdict{"CANDIDATE", how + " thrown in application code at " + top}
		}
	}
	if crashed {
		return verdict{"ERROR", "test binary died without a panic or timeout marker"}
	}
	// Rule 4: a plain failure is an assertion (testify or t.Error/t.Fatal).
	lib := "t.Error/t.Fatal"
	if strings.Contains(out, "Error Trace:") {
		lib = "testify"
	}
	return verdict{"CANDIDATE", "assertion failure (" + lib + ")"}
}

// topInRepoFrame returns the file of the first stack frame inside the repo (not GOROOT or the module cache).
func topInRepoFrame(lines []string) string {
	for _, l := range lines {
		m := frameFile.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		f := filepath.ToSlash(m[1])
		if strings.HasPrefix(strings.ToLower(f), strings.ToLower(goroot)) || strings.Contains(f, "/pkg/mod/") {
			continue
		}
		if r := repoRel(f); !strings.HasPrefix(r, "../") && !filepath.IsAbs(r) {
			return r
		}
	}
	return ""
}

func runTests(pkgPattern string, extra ...string) map[string]*pkgState {
	args := append([]string{"test", "-json", "-count=1", "-timeout", "5s"}, extra...)
	args = append(args, pkgPattern)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	_ = cmd.Run() // non-zero on any failure; the events carry the detail
	fmt.Printf("ran: go %s\n", strings.Join(args, " "))

	pkgs := map[string]*pkgState{}
	get := func(p string) *pkgState {
		if pkgs[p] == nil {
			pkgs[p] = &pkgState{tests: map[string]*testState{}}
		}
		return pkgs[p]
	}
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		switch e.Action {
		case "build-output":
			p := get(strings.SplitN(e.ImportPath, " ", 2)[0])
			p.buildOutput = append(p.buildOutput, e.Output)
		case "build-fail":
			get(strings.SplitN(e.ImportPath, " ", 2)[0]).buildFailed = true
		}
		if e.Package == "" {
			continue
		}
		p := get(e.Package)
		if e.Test == "" {
			if e.Action == "fail" {
				p.failed = true
				if e.FailedBuild != "" {
					p.buildFailed = true
				}
			}
			continue
		}
		name := strings.SplitN(e.Test, "/", 2)[0] // subtests roll up to the top-level test
		t := p.tests[name]
		if t == nil {
			t = &testState{}
			p.tests[name] = t
		}
		switch e.Action {
		case "run":
			t.ran = true
		case "pass":
			if e.Test == name {
				t.passed = true
			}
		case "fail":
			t.failed = true
		case "output":
			t.output = append(t.output, e.Output)
		}
	}
	return pkgs
}

func findAttacks() []attack {
	var as []attack
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isAdversary(repoRel(p)) {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if err != nil { // a file that doesn't parse still gets classified via the build output
			fmt.Printf("  parse error in %s: %v\n", repoRel(p), err)
			return nil
		}
		rel := repoRel(p)
		pkg := path.Join(module, path.Dir(rel))
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Test") {
				as = append(as, attack{pkg: pkg, name: fd.Name.Name, file: rel})
			}
		}
		return nil
	})
	sort.Slice(as, func(i, j int) bool { return as[i].pkg+as[i].name < as[j].pkg+as[j].name })
	return as
}

func isAdversary(rel string) bool { return strings.HasSuffix(rel, "_adversary_test.go") }

// repoRel normalizes a compiler path (relative, OS separators) or a stack path (absolute,
// forward slashes) to a repo-relative forward-slash path.
func repoRel(p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	r, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(r)
}

func readModule(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		panic(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(l, "module "))
		}
	}
	panic("no module line")
}

func uniq(s []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range s {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}
