// Spike: drive `claude -p --output-format stream-json --verbose` from Go with the
// prompt on stdin. Throwaway code; see FINDINGS.md.
//
//	go run . <case>     cases: basic, resume, tools, big, all
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const model = "claude-haiku-4-5-20251001"

type runResult struct {
	Events    []map[string]any
	Result    map[string]any
	Stderr    string
	ExitCode  int
	FirstByte time.Duration
	Total     time.Duration
}

// run launches claude in dir with prompt on stdin and extra args, logging every
// stdout event with its arrival time. Raw lines go to out/<name>.jsonl.
func run(name, dir, prompt string, extra ...string) runResult {
	args := append([]string{"-p", "--model", model, "--output-format", "stream-json", "--verbose"}, extra...)
	cmd := exec.Command("claude", args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(prompt)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	must(err)

	os.MkdirAll("out", 0o755)
	raw, err := os.Create(filepath.Join("out", name+".jsonl"))
	must(err)
	defer raw.Close()

	fmt.Printf("\n=== %s: claude %s (prompt %d chars on stdin)\n", name, strings.Join(args, " "), len(prompt))
	start := time.Now()
	must(cmd.Start())

	var rr runResult
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		el := time.Since(start)
		if rr.FirstByte == 0 {
			rr.FirstByte = el
		}
		raw.Write(line)
		raw.Write([]byte("\n"))
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Printf("  %6.2fs  NON-JSON: %.120s\n", el.Seconds(), line)
			continue
		}
		rr.Events = append(rr.Events, ev)
		fmt.Printf("  %6.2fs  %s\n", el.Seconds(), describe(ev))
		if ev["type"] == "result" {
			rr.Result = ev
		}
	}
	err = cmd.Wait()
	rr.Total = time.Since(start)
	rr.Stderr = stderr.String()
	if ee, ok := err.(*exec.ExitError); ok {
		rr.ExitCode = ee.ExitCode()
	} else if err != nil {
		panic(err)
	}
	fmt.Printf("  exit=%d total=%.2fs first_event=%.2fs stderr=%q\n",
		rr.ExitCode, rr.Total.Seconds(), rr.FirstByte.Seconds(), trunc(rr.Stderr, 300))
	if rr.Result != nil {
		fmt.Printf("  result: subtype=%v is_error=%v session_id=%v total_cost_usd=%v num_turns=%v\n",
			rr.Result["subtype"], rr.Result["is_error"], rr.Result["session_id"], rr.Result["total_cost_usd"], rr.Result["num_turns"])
		fmt.Printf("  result.result=%q\n", trunc(fmt.Sprint(rr.Result["result"]), 300))
		fmt.Printf("  result keys: %v\n", keys(rr.Result))
		if d, ok := rr.Result["permission_denials"]; ok {
			b, _ := json.Marshal(d)
			fmt.Printf("  permission_denials=%s\n", trunc(string(b), 600))
		}
	}
	return rr
}

// describe prints one line per event: type/subtype plus what's inside.
func describe(ev map[string]any) string {
	t, _ := ev["type"].(string)
	s := t
	if st, ok := ev["subtype"].(string); ok {
		s += "/" + st
	}
	switch t {
	case "system":
		if ev["subtype"] == "init" {
			tools, _ := ev["tools"].([]any)
			s += fmt.Sprintf(" session_id=%v model=%v permissionMode=%v cwd=%v tools(%d)=%v keys=%v",
				ev["session_id"], ev["model"], ev["permissionMode"], ev["cwd"], len(tools), trunc(fmt.Sprint(tools), 200), keys(ev))
		} else {
			s += fmt.Sprintf(" keys=%v", keys(ev))
		}
	case "assistant", "user":
		msg, _ := ev["message"].(map[string]any)
		content, _ := msg["content"].([]any)
		var parts []string
		for _, c := range content {
			cm, _ := c.(map[string]any)
			switch cm["type"] {
			case "text":
				parts = append(parts, fmt.Sprintf("text(%q)", trunc(fmt.Sprint(cm["text"]), 80)))
			case "tool_use":
				in, _ := json.Marshal(cm["input"])
				parts = append(parts, fmt.Sprintf("tool_use(%v %s)", cm["name"], trunc(string(in), 120)))
			case "tool_result":
				parts = append(parts, fmt.Sprintf("tool_result(is_error=%v %q)", cm["is_error"], trunc(fmt.Sprint(cm["content"]), 160)))
			default:
				parts = append(parts, fmt.Sprint(cm["type"]))
			}
		}
		s += " " + strings.Join(parts, " ")
	case "result":
		s += fmt.Sprintf(" is_error=%v", ev["is_error"])
	}
	return s
}

func main() {
	which := "all"
	if len(os.Args) > 1 {
		which = os.Args[1]
	}
	if which == "basic" || which == "all" {
		caseBasic()
	}
	if which == "resume" || which == "all" {
		caseResume()
	}
	if which == "tools" || which == "all" {
		caseTools()
	}
	if which == "big" || which == "all" {
		caseBig()
	}
	if which == "isolated" || which == "all" {
		caseIsolated()
	}
}

// caseIsolated tests the candidate isolation recipe: no user/project settings, no
// plugins/hooks, no MCP servers, and an explicit built-in tool list.
func caseIsolated() {
	iso := []string{"--restricted", "--strict-mcp-config", "--disable-slash-commands", "--permission-prompts", "none"}

	// Read-only profile (Ringleader/Judge).
	d := scratch("iso-ro")
	os.WriteFile(filepath.Join(d, "README.txt"), []byte("the answer is 41\n"), 0o644)
	run("iso-readonly", d,
		"Read README.txt, then create a file named pwned.txt containing hi using any tool you have "+
			"(Write, Edit, shell, anything). Reply with the number from README.txt plus one, then DONE or BLOCKED.",
		append(iso, "--tools", "Read,Grep,Glob")...)
	_, err := os.Stat(filepath.Join(d, "pwned.txt"))
	fmt.Printf("  >>> iso-readonly: pwned.txt exists=%v\n", err == nil)

	// Worker profile: edits allowed, shell limited to the test command.
	d = scratch("iso-worker")
	run("iso-worker", d,
		"1) Create hello.txt containing hi. 2) Run the shell command `go version` and report its output. "+
			"3) Run the shell command `curl -s https://example.com` and report whether it ran. Reply briefly.",
		append(iso, "--tools", "Read,Grep,Glob,Edit,Write,Bash,PowerShell",
			"--permission-mode", "acceptEdits",
			"--allowedTools", "Bash(go version),Bash(go test *),PowerShell(go version),PowerShell(go test *)")...)
	_, err = os.Stat(filepath.Join(d, "hello.txt"))
	fmt.Printf("  >>> iso-worker: hello.txt exists=%v\n", err == nil)
}

func scratch(name string) string {
	d, err := os.MkdirTemp("", "arbiter-harness-"+name+"-")
	must(err)
	return d
}

func caseBasic() {
	run("basic", scratch("basic"), "Reply with exactly the word PONG and nothing else.")
}

func caseResume() {
	d := scratch("resume")
	r1 := run("resume-1", d, "Remember this code word: ZEBRA-42. Reply only with OK.")
	sid := fmt.Sprint(r1.Result["session_id"])
	r2 := run("resume-2", d, "What was the code word I gave you? Reply with only the code word.", "--resume", sid)
	fmt.Printf("  resume: first session=%s second session=%v; context kept=%v\n",
		sid, r2.Result["session_id"], strings.Contains(fmt.Sprint(r2.Result["result"]), "ZEBRA-42"))
}

// caseTools checks whether read-only profiles really block writes (Write tool and shell).
func caseTools() {
	prompt := "Create a file named pwned.txt in the current directory containing the text hi. " +
		"Try the Write tool first; if that is unavailable or denied, try a shell command. " +
		"Then reply DONE or BLOCKED."
	profiles := []struct {
		name string
		args []string
	}{
		{"tools-allowedTools", []string{"--allowedTools", "Read,Grep,Glob"}},
		{"tools-allowedTools-acceptEdits", []string{"--allowedTools", "Read,Grep,Glob", "--permission-mode", "acceptEdits"}},
		{"tools-tools", []string{"--tools", "Read,Grep,Glob"}},
		{"tools-control-acceptEdits", []string{"--permission-mode", "acceptEdits"}},
	}
	for _, p := range profiles {
		d := scratch(p.name)
		run(p.name, d, prompt, p.args...)
		_, err := os.Stat(filepath.Join(d, "pwned.txt"))
		fmt.Printf("  >>> %s: pwned.txt exists=%v\n", p.name, err == nil)
	}
}

// caseBig sends a >40k character prompt with a needle at the end.
func caseBig() {
	filler := strings.Repeat("This is filler text for a large prompt used to test the stdin path; ignore it.\n", 570)

	// Variant 1: the question comes after the data (how a naive prompt builder would do it).
	r := run("big", scratch("big"), filler+"\nThe secret code is ORCHID-7. What is the secret code? Reply with only the code.\n")
	fmt.Printf("  big: needle found=%v\n", strings.Contains(fmt.Sprint(r.Result["result"]), "ORCHID-7"))

	// Variant 2: instruction first, data fenced in a tagged block (how Arbiter should build prompts).
	p := "You are testing a data pipeline. Below, inside <data>, is a large document. " +
		"Reply with only the value that follows 'marker:' on the last line of the document.\n<data>\n" +
		filler + "marker: ORCHID-7\n</data>\n"
	r = run("big-framed", scratch("big"), p)
	fmt.Printf("  big-framed: prompt=%d chars needle found=%v\n", len(p), strings.Contains(fmt.Sprint(r.Result["result"]), "ORCHID-7"))
}

func keys(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sortStrings(ks)
	return ks
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
