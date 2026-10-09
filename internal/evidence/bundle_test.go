package evidence

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// sample is a bundle of about 12,700 characters: 4,000 of passing output,
// 4,000 of attack diff, a 4,000-character and a 400-character worker diff.
func sample() Bundle {
	return Bundle{
		Spec:               "Rotate refresh tokens on /auth/refresh.",
		Invariants:         "INV-1: tokens are single-use.",
		AcceptanceCriteria: "AC-1: a reused token returns 401.",
		BlastRadius:        "medium: internal/auth/** (touches token storage)",
		Attacks:            "TestReuse_adversary: targets AC-1, ASSERTION_FAIL, claim upheld",
		WorkerDiff: []FileDiff{
			{Path: "internal/auth/small.go", Patch: "+small\n" + strings.Repeat("s", 393) + "\n", Stat: " internal/auth/small.go | 2 +"},
			{Path: "internal/auth/big.go", Patch: "+big\n" + strings.Repeat("b", 3995) + "\n", Stat: " internal/auth/big.go | 80 ++++----"},
		},
		AttackDiff:    []FileDiff{{Path: "internal/auth/reuse_adversary_test.go", Patch: strings.Repeat("a", 4000) + "\n", Stat: " internal/auth/reuse_adversary_test.go | 40 +"}},
		PassingOutput: strings.Repeat("p", 4000),
	}
}

func TestRenderUnderCapKeepsEverythingInOrder(t *testing.T) {
	b := sample()
	text, rep := b.Render(60000)
	if rep.PassingOutputDropped || rep.AttackDiffStat || len(rep.WorkerStatPaths) > 0 || rep.OverCap {
		t.Errorf("Report = %+v, want no cuts", rep)
	}
	var last int
	for _, part := range []string{
		b.Spec, b.Invariants, b.AcceptanceCriteria, b.BlastRadius, b.Attacks,
		b.WorkerDiff[1].Patch, b.AttackDiff[0].Patch, b.PassingOutput,
	} {
		i := strings.Index(text, part)
		if i < 0 {
			t.Fatalf("missing %.40q", part)
		}
		if i < last {
			t.Errorf("%.40q is out of the §9.A order", part)
		}
		last = i
	}
	if rep.Chars != utf8.RuneCountInString(text) {
		t.Errorf("Report.Chars = %d, text has %d", rep.Chars, utf8.RuneCountInString(text))
	}
}

func TestRenderDropsPassingOutputFirst(t *testing.T) {
	text, rep := sample().Render(2500) // 10,000 characters
	if !rep.PassingOutputDropped || rep.AttackDiffStat || len(rep.WorkerStatPaths) > 0 || rep.OverCap {
		t.Errorf("Report = %+v, want only the passing output dropped", rep)
	}
	if strings.Contains(text, strings.Repeat("p", 100)) || !strings.Contains(text, "passing-test output") {
		t.Error("passing output not replaced by a note")
	}
	if rep.Chars > rep.CapChars {
		t.Errorf("Chars %d over CapChars %d", rep.Chars, rep.CapChars)
	}
}

func TestRenderThenAttackDiffBecomesStat(t *testing.T) {
	b := sample()
	text, rep := b.Render(1500) // 6,000 characters
	if !rep.PassingOutputDropped || !rep.AttackDiffStat || len(rep.WorkerStatPaths) > 0 || rep.OverCap {
		t.Errorf("Report = %+v, want passing output dropped and attack diff as stat", rep)
	}
	if strings.Contains(text, b.AttackDiff[0].Patch) || !strings.Contains(text, b.AttackDiff[0].Stat) {
		t.Error("attack diff not replaced by its stat line")
	}
}

func TestRenderThenLargestWorkerFileFirst(t *testing.T) {
	b := sample()
	text, rep := b.Render(500) // 2,000 characters
	if !slices.Equal(rep.WorkerStatPaths, []string{"internal/auth/big.go"}) || rep.OverCap {
		t.Errorf("Report = %+v, want only big.go cut to a stat line", rep)
	}
	if !strings.Contains(text, b.WorkerDiff[0].Patch) {
		t.Error("the small file's diff was cut although cutting big.go was enough")
	}
	if !strings.Contains(text, b.WorkerDiff[1].Stat) {
		t.Error("big.go's stat line missing")
	}
}

func TestRenderNeverCutsSpecThroughLessons(t *testing.T) {
	b := sample()
	b.Spec = strings.Repeat("x", 10000)
	b.Lessons = "LESSON-12: check token reuse"
	text, rep := b.Render(100)
	if !rep.OverCap || len(rep.WorkerStatPaths) != 2 || !rep.AttackDiffStat || !rep.PassingOutputDropped {
		t.Errorf("Report = %+v, want every cut made and OverCap", rep)
	}
	for _, kept := range []string{b.Spec, b.Invariants, b.AcceptanceCriteria, b.BlastRadius, b.Attacks, b.Lessons} {
		if !strings.Contains(text, kept) {
			t.Errorf("never-cut item %.40q was cut", kept)
		}
	}
}

func TestRenderOmitsLessonsSectionWhenEmpty(t *testing.T) {
	text, _ := sample().Render(60000)
	if strings.Contains(text, "lessons") {
		t.Error("v0.1 bundle (no lessons) has a lessons section")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, _ := sample().Render(500)
	b, _ := sample().Render(500)
	if a != b {
		t.Error("same bundle rendered differently")
	}
}

func TestRenderDefaultCap(t *testing.T) {
	_, rep := sample().Render(0)
	if rep.CapChars != DefaultCapTokens*CharsPerToken {
		t.Errorf("CapChars = %d, want the 60k-token default", rep.CapChars)
	}
}

func TestHash(t *testing.T) {
	h := Hash("bundle")
	if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Errorf("Hash = %q, want 64 lowercase hex digits", h)
	}
	if h != Hash("bundle") || h == Hash("bundle ") {
		t.Error("Hash is not a function of the exact text")
	}
}
