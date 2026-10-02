// Package lease implements invocation liveness and leases (spec §7
// "Liveness & Leases").
//
// Liveness is "process alive and activity within the last 120s", where
// activity is a stdout event or a worktree fs write. A lease belongs to an
// invocation: it starts at 15 minutes, is renewed while the process is live,
// and never runs past an absolute ceiling (60 minutes by default). Paused
// time (awaiting_human, Runner test runs) does not count against any timer.
//
// Expiry kills, it doesn't error: the Watcher terminates the process and
// reports OutcomeExpired, and the caller runs the autopsy. The model never
// sees an "expired" error.
package lease

import (
	"time"

	"github.com/Masked-Kunsiquat/arbiter/internal/config"
)

// Spec §7 defaults.
const (
	DefaultLease   = 15 * time.Minute
	DefaultCeiling = 60 * time.Minute
	DefaultIdle    = 120 * time.Second
)

// Config holds the lease timings.
type Config struct {
	Lease   time.Duration // renewal window; 0 means DefaultLease
	Ceiling time.Duration // absolute cap from start; 0 means DefaultCeiling
	Idle    time.Duration // liveness window; 0 means DefaultIdle
}

// ConfigFromLimits builds a Config from [limits] in config.toml. Zero
// values fall back to the spec defaults.
func ConfigFromLimits(l config.Limits) Config {
	return Config{
		Lease:   time.Duration(l.LeaseMinutes) * time.Minute,
		Ceiling: time.Duration(l.LeaseCeilingMinutes) * time.Minute,
	}.withDefaults()
}

func (c Config) withDefaults() Config {
	if c.Lease <= 0 {
		c.Lease = DefaultLease
	}
	if c.Ceiling <= 0 {
		c.Ceiling = DefaultCeiling
	}
	if c.Idle <= 0 {
		c.Idle = DefaultIdle
	}
	if c.Lease > c.Ceiling {
		c.Lease = c.Ceiling
	}
	return c
}

// Lease is the timer state of one invocation's lease. It is a pure state
// machine driven by explicit timestamps, so it has no goroutines and no
// clock of its own; Watcher drives it. Not safe for concurrent use.
//
// There are two kinds of pause (§7). awaiting_human "freezes all timers":
// expiry, idle window and the absolute ceiling. A Runner test run "pauses
// the lease clock": expiry and idle window only, so the ceiling stays an
// absolute cap on wall time spent outside human waits.
type Lease struct {
	cfg          Config
	expires      time.Time
	ceiling      time.Time
	lastActivity time.Time
	notBefore    time.Time // activity stamped earlier than this is ignored

	frozen      int       // open pauses of either kind
	frozenSince time.Time // when frozen went 0 -> 1
	all         int       // open PauseAll calls
	allSince    time.Time // when all went 0 -> 1
}

// New starts a lease at start. The start counts as activity.
func New(cfg Config, start time.Time) *Lease {
	cfg = cfg.withDefaults()
	return &Lease{
		cfg:          cfg,
		expires:      start.Add(cfg.Lease),
		ceiling:      start.Add(cfg.Ceiling),
		lastActivity: start,
	}
}

// ExpiresAt is the current lease expiry.
func (l *Lease) ExpiresAt() time.Time { return l.expires }

// LastActivity is the time of the latest recorded activity.
func (l *Lease) LastActivity() time.Time { return l.lastActivity }

// Paused reports whether the lease clock is frozen (either kind of pause).
func (l *Lease) Paused() bool { return l.frozen > 0 }

// Activity records a stdout event or worktree write stamped t. Activity
// while paused, or stamped before the last resume (a file written during a
// test run, seen by a later probe), is ignored.
func (l *Lease) Activity(t time.Time) {
	if l.frozen == 0 && !t.Before(l.notBefore) && t.After(l.lastActivity) {
		l.lastActivity = t
	}
}

// Live reports whether there was activity within the idle window before t.
// A paused lease is live.
func (l *Lease) Live(t time.Time) bool {
	return l.frozen > 0 || t.Sub(l.lastActivity) <= l.cfg.Idle
}

// PauseAll freezes every timer, ceiling included (awaiting_human). Pauses
// nest; each needs a ResumeAll.
func (l *Lease) PauseAll(t time.Time) {
	if l.all == 0 {
		l.allSince = t
	}
	l.all++
	l.freeze(t)
}

// ResumeAll matches one PauseAll. The span since the outermost PauseAll is
// added to the ceiling.
func (l *Lease) ResumeAll(t time.Time) {
	if l.all == 0 {
		return
	}
	l.all--
	if l.all == 0 {
		if d := t.Sub(l.allSince); d > 0 {
			l.ceiling = l.ceiling.Add(d)
		}
	}
	l.unfreeze(t)
}

// PauseLease freezes the expiry and idle window but not the ceiling (a
// Runner test run). Pauses nest; each needs a ResumeLease.
func (l *Lease) PauseLease(t time.Time) { l.freeze(t) }

// ResumeLease matches one PauseLease.
func (l *Lease) ResumeLease(t time.Time) {
	if l.frozen > l.all {
		l.unfreeze(t)
	}
}

func (l *Lease) freeze(t time.Time) {
	if l.frozen == 0 {
		l.frozenSince = t
	}
	l.frozen++
}

// unfreeze closes one pause. When the last closes, the frozen span is added
// to the expiry and the last activity, so the lease resumes exactly where
// it stopped, never past the ceiling.
func (l *Lease) unfreeze(t time.Time) {
	l.frozen--
	if l.frozen > 0 {
		return
	}
	if d := t.Sub(l.frozenSince); d > 0 {
		l.expires = l.expires.Add(d)
		l.lastActivity = l.lastActivity.Add(d)
	}
	if l.expires.After(l.ceiling) {
		l.expires = l.ceiling
	}
	l.notBefore = t
}

// Check evaluates the lease at t. A live process has its lease renewed to
// t+Lease, capped at the ceiling; renewed reports whether the expiry moved.
// expired reports whether t has reached the expiry. A paused lease never
// renews or expires.
func (l *Lease) Check(t time.Time) (renewed, expired bool) {
	if l.frozen > 0 {
		return false, false
	}
	if l.Live(t) {
		next := t.Add(l.cfg.Lease)
		if next.After(l.ceiling) {
			next = l.ceiling
		}
		if next.After(l.expires) {
			l.expires = next
			renewed = true
		}
	}
	return renewed, !t.Before(l.expires)
}
