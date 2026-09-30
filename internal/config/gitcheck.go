package config

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// MinGitVersion is the minimum git version required (spec §9.A): the
// GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n environment
// mechanism Arbiter uses to override per-process git config was added in
// git 2.31.
var MinGitVersion = GitVersion{2, 31, 0}

// GitVersion is a parsed "git version X.Y.Z" triple.
type GitVersion struct {
	Major, Minor, Patch int
}

// Less reports whether v is older than other, comparing major, then minor,
// then patch.
func (v GitVersion) Less(other GitVersion) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

func (v GitVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

var gitVersionRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// CheckGitVersion runs `git --version` and fails if it's older than
// MinGitVersion or if git isn't on PATH at all.
func CheckGitVersion() (GitVersion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "git", "--version").Output()
	if err != nil {
		return GitVersion{}, fmt.Errorf("config: running git --version: %w", err)
	}

	m := gitVersionRe.FindSubmatch(out)
	if m == nil {
		return GitVersion{}, fmt.Errorf("config: could not parse git version from %q", out)
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	patch := 0
	if len(m[3]) > 0 {
		patch, _ = strconv.Atoi(string(m[3]))
	}
	got := GitVersion{major, minor, patch}

	if got.Less(MinGitVersion) {
		return got, fmt.Errorf("config: git %s found, but arbiter requires git >= %s (GIT_CONFIG_COUNT support, spec §9.A)",
			got, MinGitVersion)
	}
	return got, nil
}
