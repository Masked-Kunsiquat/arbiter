// Package agent launches a headless Claude Code invocation and reads what it
// returns (spec §9.A, the v0.1 agent I/O contract).
//
// An agent talks to Arbiter only through its process, its working tree and
// one JSON result: Launch builds the argv (isolation baseline + role tool
// profile), GitEnv the per-process git overrides, Prompt the stdin text
// (instruction first, untrusted data fenced), ReadStream parses the
// stream-json output, and Runner ties them to a supervised process.
package agent

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Masked-Kunsiquat/arbiter/internal/seat"
)

// ErrBudgetExhausted is returned by Launch.Args when less than the smallest
// amount --max-budget-usd can express is left (§5.8: nothing new launches).
var ErrBudgetExhausted = errors.New("agent: PRD budget exhausted")

// budgetStep is the granularity of --max-budget-usd: 1/10000 USD.
const budgetStep = 1e4

// Tool lists for the two §9.A role profiles. The harness drops names it
// doesn't have (PowerShell on Linux), so one list serves every platform.
var (
	readOnlyTools = []string{"Read", "Grep", "Glob"}
	editTools     = []string{"Read", "Grep", "Glob", "Edit", "Write", "Bash", "PowerShell"}
)

// Profile is a role's tool profile (§9.A table): which tools exist, the
// permission mode, and the shell allow rules.
type Profile struct {
	Tools          []string
	PermissionMode string   // "" leaves the harness default
	AllowedTools   []string // shell allow rules (harness.shell_allow)
}

// ProfileFor returns role's profile. shellAllow applies only to the edit
// roles (Worker, Adversary).
func ProfileFor(role seat.Role, shellAllow []string) (Profile, error) {
	switch role {
	case seat.RoleRingleader, seat.RoleJudge:
		return Profile{Tools: readOnlyTools}, nil
	case seat.RoleWorker, seat.RoleAdversary:
		for _, rule := range shellAllow {
			// --allowedTools takes one comma-joined value, so a comma inside
			// a rule would split it into two, one broader than intended.
			if strings.Contains(rule, ",") {
				return Profile{}, fmt.Errorf("agent: shell_allow rule %q contains a comma", rule)
			}
		}
		return Profile{Tools: editTools, PermissionMode: "acceptEdits", AllowedTools: shellAllow}, nil
	}
	return Profile{}, fmt.Errorf("agent: no tool profile for role %q", role)
}

// Args returns the profile's flags.
func (p Profile) Args() []string {
	args := []string{"--tools", strings.Join(p.Tools, ",")}
	if p.PermissionMode != "" {
		args = append(args, "--permission-mode", p.PermissionMode)
	}
	if len(p.AllowedTools) > 0 {
		args = append(args, "--allowedTools", strings.Join(p.AllowedTools, ","))
	}
	return args
}

// Launch describes one harness invocation.
type Launch struct {
	Command         string    // resolved harness executable (config.ResolveHarnessCommand)
	Model           string    // harness.<role>_model
	Role            seat.Role // selects the tool profile
	ShellAllow      []string  // harness.shell_allow; edit roles only
	BudgetUSD       float64   // max_budget_usd − prds.spent_usd (§5.8)
	ResumeSessionID string    // seats.harness_session_id; "" starts a new session

	Dir      string   // working directory: the slot (§7)
	Env      []string // base environment; nil means the current process's
	SeatID   string   // git identity (GitEnv)
	HooksDir string   // empty hooks dir for core.hooksPath (worktree.EmptyHooksDir)
}

// Args returns the harness arguments (§9.A launch recipe), not including the
// program itself. The prompt is never among them: it goes on stdin.
func (l Launch) Args() ([]string, error) {
	if l.Model == "" {
		return nil, errors.New("agent: launch needs a model")
	}
	profile, err := ProfileFor(l.Role, l.ShellAllow)
	if err != nil {
		return nil, err
	}
	// Round down: the harness must never be allowed more than is left.
	budget := math.Floor(l.BudgetUSD*budgetStep) / budgetStep
	if budget <= 0 {
		return nil, fmt.Errorf("%w: %.4f USD left", ErrBudgetExhausted, l.BudgetUSD)
	}
	args := []string{
		"-p", "--model", l.Model, "--output-format", "stream-json", "--verbose",
		// Isolation baseline: no user/project settings, MCP servers or skills,
		// and anything that would prompt is denied.
		"--restricted", "--strict-mcp-config", "--disable-slash-commands", "--permission-prompts", "none",
		"--max-budget-usd", strconv.FormatFloat(budget, 'f', -1, 64),
	}
	if l.ResumeSessionID != "" {
		args = append(args, "--resume", l.ResumeSessionID)
	}
	return append(args, profile.Args()...), nil
}
