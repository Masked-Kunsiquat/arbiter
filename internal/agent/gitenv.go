package agent

import (
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// SeatEmail is the seat's git user.email (§9.A): the seat id with "/" and
// "~" replaced by ".", at the RFC 2606 reserved domain arbiter.invalid, so
// nothing an agent commits can ever be attributed to a deliverable address.
func SeatEmail(seatID string) string {
	return strings.NewReplacer("/", ".", "~", ".").Replace(seatID) + "@arbiter.invalid"
}

// GitEnv returns base with the §9.A per-process git overrides applied: no
// signing prompts, no hooks, no fsmonitor, the seat as the git identity, and
// no terminal prompts. It first drops whatever base carries in the same
// mechanism (GIT_CONFIG_COUNT/KEY_n/VALUE_n, and GIT_CONFIG_PARAMETERS from
// `git -c`) and any GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE pointing the
// agent's git somewhere other than its working directory.
func GitEnv(base []string, seatID, hooksDir string) []string {
	pairs := [][2]string{
		{"commit.gpgsign", "false"},
		{"tag.gpgsign", "false"},
		{"core.hooksPath", filepath.ToSlash(hooksDir)},
		{"core.fsmonitor", "false"},
		{"user.name", seatID},
		{"user.email", SeatEmail(seatID)},
	}
	env := make([]string, 0, len(base)+2*len(pairs)+2)
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if !droppedGitVar(name) {
			env = append(env, kv)
		}
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(pairs)))
	for i, p := range pairs {
		n := strconv.Itoa(i)
		env = append(env, "GIT_CONFIG_KEY_"+n+"="+p[0], "GIT_CONFIG_VALUE_"+n+"="+p[1])
	}
	return append(env, "GIT_TERMINAL_PROMPT=0")
}

func droppedGitVar(name string) bool {
	if runtime.GOOS == "windows" {
		name = strings.ToUpper(name) // environment names are case-insensitive there
	}
	switch name {
	case "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_TERMINAL_PROMPT",
		"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE":
		return true
	}
	return strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_")
}
