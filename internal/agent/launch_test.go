package agent

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

func TestProfileForReadOnlyRoles(t *testing.T) {
	for _, role := range []seat.Role{seat.RoleRingleader, seat.RoleJudge} {
		p, err := ProfileFor(role, []string{"Bash(go test *)"})
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if got, want := p.Args(), []string{"--tools", "Read,Grep,Glob"}; !slices.Equal(got, want) {
			t.Errorf("%s: Args() = %q, want %q (shell_allow must not leak into read-only roles)", role, got, want)
		}
	}
}

func TestProfileForEditRoles(t *testing.T) {
	allow := []string{"Bash(go test *)", "PowerShell(go test *)"}
	for _, role := range []seat.Role{seat.RoleWorker, seat.RoleAdversary} {
		p, err := ProfileFor(role, allow)
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		want := []string{
			"--tools", "Read,Grep,Glob,Edit,Write,Bash,PowerShell",
			"--permission-mode", "acceptEdits",
			"--allowedTools", "Bash(go test *),PowerShell(go test *)",
		}
		if got := p.Args(); !slices.Equal(got, want) {
			t.Errorf("%s: Args() = %q, want %q", role, got, want)
		}
	}
}

func TestProfileForEditRoleWithNoShellAllowOmitsAllowedTools(t *testing.T) {
	p, err := ProfileFor(seat.RoleWorker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.Args(), "--allowedTools") {
		t.Errorf("Args() = %q: an empty --allowedTools value would be parsed as the next flag", p.Args())
	}
}

func TestProfileForRejectsUnknownRole(t *testing.T) {
	if _, err := ProfileFor("overlord", nil); err == nil {
		t.Fatal("ProfileFor(unknown role) succeeded")
	}
}

func TestProfileForRejectsShellAllowWithComma(t *testing.T) {
	// --allowedTools takes one comma-joined value; a rule containing a comma
	// would split into two rules, one of them broader than the author meant.
	if _, err := ProfileFor(seat.RoleWorker, []string{"Bash(go test ./a,./b)"}); err == nil {
		t.Fatal("ProfileFor accepted a shell_allow rule containing a comma")
	}
}

func baseLaunch() Launch {
	return Launch{
		Command:   "claude",
		Model:     "claude-opus-5-5",
		Role:      seat.RoleJudge,
		BudgetUSD: 4.25,
	}
}

func TestLaunchArgsCarriesBaselineEveryRole(t *testing.T) {
	args, err := baseLaunch().Args()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-p", "--model", "claude-opus-5-5", "--output-format", "stream-json", "--verbose",
		"--restricted", "--strict-mcp-config", "--disable-slash-commands", "--permission-prompts", "none",
		"--max-budget-usd", "4.25",
		"--tools", "Read,Grep,Glob",
	}
	if !slices.Equal(args, want) {
		t.Errorf("Args() =\n %q\nwant\n %q", args, want)
	}
}

func TestLaunchArgsResume(t *testing.T) {
	l := baseLaunch()
	l.ResumeSessionID = "577b6ab1-0000-0000-0000-000000000000"
	args, err := l.Args()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(args, "--resume")
	if i < 0 || i+1 >= len(args) || args[i+1] != l.ResumeSessionID {
		t.Errorf("Args() = %q, want --resume %s", args, l.ResumeSessionID)
	}
}

func TestLaunchArgsBudgetRoundsDown(t *testing.T) {
	l := baseLaunch()
	l.BudgetUSD = 1.23456789
	args, err := l.Args()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(args, "--max-budget-usd")
	if got := args[i+1]; got != "1.2345" {
		t.Errorf("--max-budget-usd %s, want 1.2345 (rounded down to 1/10000 USD, never up)", got)
	}
}

func TestLaunchArgsRefusesExhaustedBudget(t *testing.T) {
	for _, b := range []float64{0, -1, 0.00009} {
		l := baseLaunch()
		l.BudgetUSD = b
		if _, err := l.Args(); !errors.Is(err, ErrBudgetExhausted) {
			t.Errorf("BudgetUSD %v: err = %v, want ErrBudgetExhausted", b, err)
		}
	}
}

func TestLaunchArgsRequiresModel(t *testing.T) {
	l := baseLaunch()
	l.Model = ""
	if _, err := l.Args(); err == nil {
		t.Fatal("Args() with no model succeeded")
	}
}

func TestLaunchArgsNeverCarriesPrompt(t *testing.T) {
	args, err := baseLaunch().Args()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range args {
		if strings.Contains(a, "\n") {
			t.Errorf("argv element %q looks like prompt text; the prompt goes on stdin", a)
		}
	}
}

func TestLaunchArgsRejectsFlagLikeValues(t *testing.T) {
	for name, mutate := range map[string]func(*Launch){
		"model flag":       func(l *Launch) { l.Model = "--dangerously-skip-permissions" },
		"model space":      func(l *Launch) { l.Model = "opus --verbose" },
		"resume flag":      func(l *Launch) { l.ResumeSessionID = "--continue" },
		"resume non-uuid":  func(l *Launch) { l.ResumeSessionID = "../../x" },
		"shell_allow flag": func(l *Launch) { l.Role = seat.RoleWorker; l.ShellAllow = []string{"--dangerously-skip-permissions"} },
	} {
		l := baseLaunch()
		mutate(&l)
		if args, err := l.Args(); err == nil {
			t.Errorf("%s: Args() = %q, want an error", name, args)
		}
	}
}
