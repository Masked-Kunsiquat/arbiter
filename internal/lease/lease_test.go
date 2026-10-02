package lease

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestConfigFromLimits(t *testing.T) {
	c := ConfigFromLimits(config.Limits{})
	if c.Lease != DefaultLease || c.Ceiling != DefaultCeiling || c.Idle != DefaultIdle {
		t.Fatalf("zero limits: got %+v, want spec defaults", c)
	}
	c = ConfigFromLimits(config.Limits{LeaseMinutes: 90, LeaseCeilingMinutes: 30})
	if c.Lease != 30*time.Minute {
		t.Fatalf("lease above ceiling: got %v, want capped at 30m", c.Lease)
	}
}

func TestLease_ExpiresWithoutActivity(t *testing.T) {
	l := New(Config{}, t0)
	if _, expired := l.Check(t0.Add(14 * time.Minute)); expired {
		t.Fatal("expired before 15m")
	}
	if _, expired := l.Check(t0.Add(15 * time.Minute)); !expired {
		t.Fatal("not expired at 15m with no activity after start")
	}
}

func TestLease_RenewsWhileLive(t *testing.T) {
	l := New(Config{}, t0)
	at := t0.Add(10 * time.Minute)
	l.Activity(at)
	renewed, expired := l.Check(at.Add(time.Minute))
	if !renewed || expired {
		t.Fatalf("live check: renewed=%v expired=%v", renewed, expired)
	}
	if want := at.Add(16 * time.Minute); !l.ExpiresAt().Equal(want) {
		t.Fatalf("expiry %v, want %v", l.ExpiresAt(), want)
	}
}

func TestLease_IdleStopsRenewal(t *testing.T) {
	l := New(Config{}, t0)
	l.Activity(t0.Add(time.Minute))
	// 121s after the last activity: not live, so no renewal.
	if renewed, _ := l.Check(t0.Add(time.Minute + 121*time.Second)); renewed {
		t.Fatal("renewed although idle past 120s")
	}
	if l.Live(t0.Add(time.Minute + 121*time.Second)) {
		t.Fatal("live although idle past 120s")
	}
}

func TestLease_CeilingCapsRenewal(t *testing.T) {
	l := New(Config{}, t0)
	var expiredAt time.Time
	for m := 1; m <= 120; m++ {
		now := t0.Add(time.Duration(m) * time.Minute)
		l.Activity(now)
		if _, expired := l.Check(now); expired {
			expiredAt = now
			break
		}
	}
	if want := t0.Add(DefaultCeiling); !expiredAt.Equal(want) {
		t.Fatalf("continuously live lease expired at %v, want ceiling %v", expiredAt, want)
	}
}

func TestLease_PauseFreezesTimers(t *testing.T) {
	l := New(Config{}, t0)
	l.PauseAll(t0.Add(5 * time.Minute))
	l.PauseAll(t0.Add(6 * time.Minute)) // nested
	if _, expired := l.Check(t0.Add(3 * time.Hour)); expired {
		t.Fatal("paused lease expired")
	}
	if !l.Live(t0.Add(3 * time.Hour)) {
		t.Fatal("paused lease not live")
	}
	l.ResumeAll(t0.Add(2 * time.Hour))
	if !l.Paused() {
		t.Fatal("unpaused before every Pause was matched")
	}
	resume := t0.Add(5*time.Minute + 2*time.Hour)
	l.ResumeAll(resume)
	// 5m elapsed before the pause, so 10m remain; the idle clock also
	// resumes where it stopped (5m since start activity -> idle).
	if want := t0.Add(15*time.Minute + 2*time.Hour); !l.ExpiresAt().Equal(want) {
		t.Fatalf("expiry after resume %v, want %v", l.ExpiresAt(), want)
	}
	if _, expired := l.Check(resume.Add(10 * time.Minute)); !expired {
		t.Fatal("not expired 10m after resume")
	}
	// The ceiling shifted too: 60m of unpaused time from start.
	l2 := New(Config{}, t0)
	l2.PauseAll(t0)
	l2.ResumeAll(t0.Add(time.Hour))
	for m := 1; m < 60; m++ {
		now := t0.Add(time.Hour + time.Duration(m)*time.Minute)
		l2.Activity(now)
		if _, expired := l2.Check(now); expired {
			t.Fatalf("expired at %d unpaused minutes, before the ceiling", m)
		}
	}
}

func TestLease_ActivityIgnoredWhilePaused(t *testing.T) {
	l := New(Config{}, t0)
	l.PauseAll(t0)
	l.Activity(t0.Add(time.Minute))
	if !l.LastActivity().Equal(t0) {
		t.Fatalf("activity recorded while paused: %v", l.LastActivity())
	}
}

// fakeClock is a settable clock for Watcher tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func waitDone(t *testing.T, w *Watcher) Result {
	t.Helper()
	select {
	case <-w.Done():
		return w.Wait()
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not finish")
		return Result{}
	}
}

func TestWatch_RequiresOptions(t *testing.T) {
	if _, err := Watch(context.Background(), Options{Terminate: func() error { return nil }}); err == nil {
		t.Fatal("missing Exited accepted")
	}
	if _, err := Watch(context.Background(), Options{Exited: make(chan struct{})}); err == nil {
		t.Fatal("missing Terminate accepted")
	}
}

func TestWatch_ExpiryTerminates(t *testing.T) {
	clk := &fakeClock{now: t0}
	exited := make(chan struct{})
	termErr := errors.New("boom")
	var terminated int
	var mu sync.Mutex
	var persisted []time.Time
	w, err := Watch(context.Background(), Options{
		Exited: exited,
		Terminate: func() error {
			terminated++
			close(exited)
			return termErr
		},
		Persist: func(_ context.Context, at time.Time) error {
			mu.Lock()
			persisted = append(persisted, at)
			mu.Unlock()
			return nil
		},
		Tick: time.Millisecond,
		Now:  clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(15 * time.Minute)
	res := waitDone(t, w)
	if res.Outcome != OutcomeExpired {
		t.Fatalf("outcome %v, want expired", res.Outcome)
	}
	if terminated != 1 || !errors.Is(res.TerminateErr, termErr) {
		t.Fatalf("terminated %d times, err %v", terminated, res.TerminateErr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(persisted) == 0 || !persisted[0].Equal(t0.Add(DefaultLease)) {
		t.Fatalf("initial lease not persisted: %v", persisted)
	}
}

func TestWatch_WriterKeepsAlive(t *testing.T) {
	clk := &fakeClock{now: t0}
	exited := make(chan struct{})
	w, err := Watch(context.Background(), Options{
		Exited:    exited,
		Terminate: func() error { t.Error("terminated a live process"); return nil },
		Tick:      time.Millisecond,
		Now:       clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	wr := w.Writer(&out)
	for range 40 { // 40 minutes, one event a minute
		clk.Advance(time.Minute)
		if _, err := wr.Write([]byte("event\n")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Millisecond)
	}
	if got := w.ExpiresAt(); !got.After(t0.Add(DefaultLease)) {
		t.Fatalf("lease not renewed: %v", got)
	}
	close(exited)
	if res := waitDone(t, w); res.Outcome != OutcomeExited {
		t.Fatalf("outcome %v, want exited", res.Outcome)
	}
	if out.Len() != 40*len("event\n") {
		t.Fatalf("writer did not pass output through: %d bytes", out.Len())
	}
}

// tick delivers n ticks and returns once the run loop has processed them
// (the extra send can only complete after the loop finished the last one),
// or once the watch has ended.
func tick(w *Watcher, ticks chan time.Time, n int) {
	for range n + 1 {
		select {
		case ticks <- time.Time{}:
		case <-w.Done():
			return
		}
	}
}

func TestWatch_PauseHoldsExpiryAndPersistsNull(t *testing.T) {
	clk := &fakeClock{now: t0}
	exited := make(chan struct{})
	ticks := make(chan time.Time)
	var mu sync.Mutex
	var persisted []time.Time
	w, err := Watch(context.Background(), Options{
		Exited:    exited,
		Terminate: func() error { return nil }, // expiry is asserted via Done/Outcome
		Persist: func(_ context.Context, at time.Time) error {
			mu.Lock()
			persisted = append(persisted, at)
			mu.Unlock()
			return nil
		},
		Now:   clk.Now,
		ticks: ticks,
	})
	if err != nil {
		t.Fatal(err)
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(persisted)
	}
	waitPersisted := func(n int) {
		deadline := time.Now().Add(5 * time.Second)
		for count() < n {
			if time.Now().After(deadline) {
				t.Fatalf("persisted %d times, want %d", count(), n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitPersisted(1)
	clk.Advance(5 * time.Minute)
	w.Pause()
	waitPersisted(2)
	clk.Advance(3 * time.Hour)
	tick(w, ticks, 3)
	w.Resume()
	waitPersisted(3)
	tick(w, ticks, 1)
	select {
	case <-w.Done():
		t.Fatal("watch ended across a pause")
	default:
	}
	// 10 minutes of lease were left at the pause.
	if want := t0.Add(15*time.Minute + 3*time.Hour); !w.ExpiresAt().Equal(want) {
		t.Fatalf("expiry after resume %v, want %v", w.ExpiresAt(), want)
	}
	clk.Advance(10 * time.Minute)
	tick(w, ticks, 1)
	if res := waitDone(t, w); res.Outcome != OutcomeExpired {
		t.Fatalf("outcome %v, want expired 10m after resume", res.Outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(persisted) != 3 || !persisted[1].IsZero() || !persisted[2].Equal(t0.Add(15*time.Minute+3*time.Hour)) {
		t.Fatalf("persisted %v, want [start lease, NULL on pause, shifted expiry on resume]", persisted)
	}
}

func TestLease_PauseLeaseKeepsCeiling(t *testing.T) {
	l := New(Config{}, t0)
	l.PauseLease(t0.Add(50 * time.Minute))
	l.ResumeLease(t0.Add(2 * time.Hour))
	// The test run froze the lease clock but not the absolute ceiling, so
	// the expiry is capped at start+60m, which is already past.
	if !l.ExpiresAt().Equal(t0.Add(DefaultCeiling)) {
		t.Fatalf("expiry %v, want capped at ceiling %v", l.ExpiresAt(), t0.Add(DefaultCeiling))
	}
	if _, expired := l.Check(t0.Add(2 * time.Hour)); !expired {
		t.Fatal("test-run pause extended the absolute ceiling")
	}
	// A short test run does extend the lease itself.
	l2 := New(Config{}, t0)
	l2.PauseLease(t0.Add(10 * time.Minute))
	l2.ResumeLease(t0.Add(20 * time.Minute))
	if want := t0.Add(25 * time.Minute); !l2.ExpiresAt().Equal(want) {
		t.Fatalf("expiry %v, want %v", l2.ExpiresAt(), want)
	}
}

func TestLease_MixedPausesNest(t *testing.T) {
	l := New(Config{}, t0)
	l.PauseLease(t0)
	l.PauseAll(t0.Add(time.Minute))
	l.ResumeLease(t0.Add(time.Hour)) // unmatched by kind order, still frozen
	if !l.Paused() {
		t.Fatal("resumed while awaiting_human still open")
	}
	l.ResumeAll(t0.Add(2 * time.Hour))
	if l.Paused() {
		t.Fatal("still paused after every pause was matched")
	}
	// Ceiling moved by the awaiting_human span only (1m -> 2h).
	ceiling := t0.Add(DefaultCeiling + 2*time.Hour - time.Minute)
	l.Activity(ceiling.Add(-time.Second))
	if _, expired := l.Check(ceiling.Add(-time.Second)); expired {
		t.Fatal("expired before the shifted ceiling")
	}
	if _, expired := l.Check(ceiling); !expired {
		t.Fatal("not expired at the shifted ceiling")
	}
	l.ResumeLease(t0.Add(3 * time.Hour)) // extra resume is a no-op
	if l.Paused() {
		t.Fatal("extra ResumeLease re-froze the lease")
	}
}

func TestLease_IgnoresActivityStampedDuringPause(t *testing.T) {
	l := New(Config{}, t0)
	l.PauseLease(t0.Add(time.Minute))
	resume := t0.Add(time.Hour)
	l.ResumeLease(resume)
	before := l.LastActivity()
	l.Activity(resume.Add(-time.Second)) // a test artifact seen by a later probe
	if !l.LastActivity().Equal(before) {
		t.Fatal("pause-era write counted as activity")
	}
	l.Activity(resume.Add(time.Second))
	if !l.LastActivity().Equal(resume.Add(time.Second)) {
		t.Fatal("post-resume activity ignored")
	}
}

func TestWatch_FSProbeKeepsAlive(t *testing.T) {
	clk := &fakeClock{now: t0}
	exited := make(chan struct{})
	w, err := Watch(context.Background(), Options{
		Exited:    exited,
		Terminate: func() error { t.Error("terminated a process writing files"); return nil },
		FSProbe:   func() (time.Time, error) { return clk.Now(), nil },
		Tick:      time.Millisecond,
		FSPoll:    time.Nanosecond,
		Now:       clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		clk.Advance(time.Minute)
		time.Sleep(3 * time.Millisecond)
	}
	close(exited)
	if res := waitDone(t, w); res.Outcome != OutcomeExited {
		t.Fatalf("outcome %v, want exited", res.Outcome)
	}
}

func TestWatch_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w, err := Watch(ctx, Options{
		Exited:    make(chan struct{}),
		Terminate: func() error { t.Error("terminated on cancel"); return nil },
		Tick:      time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if res := waitDone(t, w); res.Outcome != OutcomeCanceled {
		t.Fatalf("outcome %v, want canceled", res.Outcome)
	}
}

func TestWatch_PersistErrorsReported(t *testing.T) {
	exited := make(chan struct{})
	perr := errors.New("db down")
	w, err := Watch(context.Background(), Options{
		Exited:    exited,
		Terminate: func() error { return nil },
		Persist:   func(context.Context, time.Time) error { return perr },
		Tick:      time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	close(exited)
	if res := waitDone(t, w); !errors.Is(res.PersistErr, perr) {
		t.Fatalf("persist error not reported: %v", res.PersistErr)
	}
}

func TestLatestWrite_SkipsGitAndKeepList(t *testing.T) {
	root := t.TempDir()
	old := t0.Add(-time.Hour)
	newer := t0
	for _, dir := range []string{".git", "node_modules", "src"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]time.Time{
		"src/a.go":          newer,
		".git/index":        t0.Add(time.Hour),
		"node_modules/x.js": t0.Add(time.Hour),
	}
	for name, mt := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{".", ".git", "node_modules", "src"} {
		if err := os.Chtimes(filepath.Join(root, dir), old, old); err != nil {
			t.Fatal(err)
		}
	}
	got, err := LatestWrite(root, []string{"node_modules"})()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(newer) {
		t.Fatalf("latest write %v, want %v (skipped dirs leaked in?)", got, newer)
	}
}
