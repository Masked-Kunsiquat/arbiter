package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Masked-Kunsiquat/arbiter/internal/gittest"
)

func TestSeatEmail(t *testing.T) {
	got := SeatEmail("PRD-004/TASK-101/worker.2~7f3a")
	if want := "PRD-004.TASK-101.worker.2.7f3a@arbiter.invalid"; got != want {
		t.Errorf("SeatEmail = %q, want %q", got, want)
	}
}

// gitConfigGet runs `git config --get key` with env and returns the value.
func gitConfigGet(t *testing.T, env []string, key string) string {
	t.Helper()
	cmd := exec.Command("git", "config", "--get", key)
	cmd.Dir = t.TempDir()
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git config --get %s: %v", key, err)
	}
	return strings.TrimSpace(string(out))
}

func TestGitEnvOverridesReachGit(t *testing.T) {
	gittest.Isolate(t)
	hooks := t.TempDir()
	env := GitEnv(os.Environ(), "PRD-004/TASK-101/worker.2~7f3a", hooks)

	for key, want := range map[string]string{
		"commit.gpgsign": "false",
		"tag.gpgsign":    "false",
		"core.hooksPath": filepath.ToSlash(hooks),
		"core.fsmonitor": "false",
		"user.name":      "PRD-004/TASK-101/worker.2~7f3a",
		"user.email":     "PRD-004.TASK-101.worker.2.7f3a@arbiter.invalid",
	} {
		if got := gitConfigGet(t, env, key); got != want {
			t.Errorf("git sees %s = %q, want %q", key, got, want)
		}
	}
	if !slices.Contains(env, "GIT_TERMINAL_PROMPT=0") {
		t.Error("GIT_TERMINAL_PROMPT=0 missing")
	}
}

func TestGitEnvDropsInheritedGitConfigVariables(t *testing.T) {
	gittest.Isolate(t)
	// A parent environment that already uses the GIT_CONFIG_* mechanism (or
	// `git -c`, which travels as GIT_CONFIG_PARAMETERS) must not survive:
	// leftover KEY_n/VALUE_n pairs past our count, or a parameter setting a
	// hooks path, would otherwise apply to the agent's git.
	base := append(os.Environ(),
		"GIT_CONFIG_COUNT=3",
		"GIT_CONFIG_KEY_0=user.name", "GIT_CONFIG_VALUE_0=intruder",
		"GIT_CONFIG_KEY_2=core.sshCommand", "GIT_CONFIG_VALUE_2=evil",
		"GIT_CONFIG_PARAMETERS='alias.st'='!evil'",
		"GIT_DIR=/elsewhere/.git",
		"GIT_TERMINAL_PROMPT=1",
	)
	env := GitEnv(base, "seat", t.TempDir())

	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "GIT_CONFIG_PARAMETERS", name == "GIT_DIR":
			t.Errorf("inherited %s survived", kv)
		case kv == "GIT_CONFIG_VALUE_2=evil", kv == "GIT_CONFIG_VALUE_0=intruder", kv == "GIT_TERMINAL_PROMPT=1":
			t.Errorf("inherited %s survived", kv)
		}
	}
	if got := gitConfigGet(t, env, "user.name"); got != "seat" {
		t.Errorf("user.name = %q, want seat", got)
	}
}
