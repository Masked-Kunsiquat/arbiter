package lease

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// Outcome is how a watched invocation ended.
type Outcome int

const (
	// OutcomeExited: the process exited on its own. Whether that was a
	// crash is for the caller to decide from the exit status and output.
	OutcomeExited Outcome = iota + 1
	// OutcomeExpired: the lease ran out and the Watcher terminated the
	// process. The caller runs the autopsy with the seat marked expired.
	// A harness that finished in the instant before Terminate is still
	// reported here; the caller can tell from a result event in its output.
	OutcomeExpired
	// OutcomeCanceled: the Watcher's context was canceled. The process is
	// left running for the caller to terminate.
	OutcomeCanceled
)

func (o Outcome) String() string {
	switch o {
	case OutcomeExited:
		return "exited"
	case OutcomeExpired:
		return "expired"
	case OutcomeCanceled:
		return "canceled"
	}
	return "unknown"
}

// Result is the final state of a Watcher.
type Result struct {
	Outcome   Outcome
	ExpiresAt time.Time // lease expiry when the watch ended
	// TerminateErr is set when Terminate failed after expiry.
	TerminateErr error
	// PersistErr joins every Persist failure. Persisting is best-effort:
	// the lease in memory is authoritative, the row is for observers.
	PersistErr error
}

// Defaults for the Watcher's polling.
const (
	DefaultTick         = time.Second
	DefaultFSPoll       = 15 * time.Second
	DefaultPersistEvery = time.Minute
)

// Options configures Watch.
type Options struct {
	Config

	// Exited is closed when the process exits (supervisor.Handle.Exited).
	Exited <-chan struct{}
	// Terminate kills the process's whole container. It is called at most
	// once, on expiry.
	Terminate func() error
	// Persist stores the lease expiry (invocations.lease_expires_at). It is
	// called on start, on every pause and resume, and whenever a renewal has
	// moved the expiry by at least PersistEvery. A zero time means the lease
	// is frozen (seat.RenewLease stores NULL). Optional.
	Persist func(ctx context.Context, expiresAt time.Time) error
	// FSProbe returns the latest write time in the worktree. It is polled
	// only while stdout has been quiet for half the idle window, at most
	// once per FSPoll. Optional; see LatestWrite.
	FSProbe func() (time.Time, error)

	Tick         time.Duration    // 0 means DefaultTick
	FSPoll       time.Duration    // 0 means DefaultFSPoll
	PersistEvery time.Duration    // 0 means DefaultPersistEvery
	Now          func() time.Time // nil means time.Now

	ticks <-chan time.Time // tests: replaces the Tick ticker
}

// Watcher supervises one invocation's lease. Its methods are safe for
// concurrent use.
type Watcher struct {
	opts Options

	mu    sync.Mutex
	lease *Lease

	nudge  chan struct{} // a pause or resume wants an immediate persist
	done   chan struct{}
	result Result
}

// Watch starts watching an invocation that started now. It returns an
// error only for missing required options.
func Watch(ctx context.Context, opts Options) (*Watcher, error) {
	if opts.Exited == nil {
		return nil, errors.New("lease: Watch requires Exited")
	}
	if opts.Terminate == nil {
		return nil, errors.New("lease: Watch requires Terminate")
	}
	if opts.Tick <= 0 {
		opts.Tick = DefaultTick
	}
	if opts.FSPoll <= 0 {
		opts.FSPoll = DefaultFSPoll
	}
	if opts.PersistEvery <= 0 {
		opts.PersistEvery = DefaultPersistEvery
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	w := &Watcher{
		opts:  opts,
		lease: New(opts.Config, opts.Now()),
		nudge: make(chan struct{}, 1),
		done:  make(chan struct{}),
	}
	go w.run(ctx)
	return w, nil
}

// Touch records activity now (a stdout event).
func (w *Watcher) Touch() {
	now := w.opts.Now()
	w.mu.Lock()
	w.lease.Activity(now)
	w.mu.Unlock()
}

// Writer wraps dst so every write counts as activity. Use it for the
// harness's stdout (and stderr) in supervisor.Cmd. A nil dst discards.
func (w *Watcher) Writer(dst io.Writer) io.Writer {
	if dst == nil {
		dst = io.Discard
	}
	return activityWriter{w: w, dst: dst}
}

// Pause freezes all timers, the absolute ceiling included: the task
// entered awaiting_human (§7). Pauses nest; each needs a Resume.
func (w *Watcher) Pause() { w.update((*Lease).PauseAll) }

// Resume matches one Pause.
func (w *Watcher) Resume() { w.update((*Lease).ResumeAll) }

// PauseLease freezes the lease clock but not the ceiling: the Runner
// launched a test run (§7). Pauses nest; each needs a ResumeLease.
func (w *Watcher) PauseLease() { w.update((*Lease).PauseLease) }

// ResumeLease matches one PauseLease.
func (w *Watcher) ResumeLease() { w.update((*Lease).ResumeLease) }

func (w *Watcher) update(f func(*Lease, time.Time)) {
	now := w.opts.Now()
	w.mu.Lock()
	f(w.lease, now)
	w.mu.Unlock()
	select {
	case w.nudge <- struct{}{}:
	default:
	}
}

// ExpiresAt is the current lease expiry.
func (w *Watcher) ExpiresAt() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lease.ExpiresAt()
}

// Done is closed when the watch has ended.
func (w *Watcher) Done() <-chan struct{} { return w.done }

// Wait blocks until the watch ends and returns its result.
func (w *Watcher) Wait() Result {
	<-w.done
	return w.result
}

func (w *Watcher) run(ctx context.Context) {
	defer close(w.done)

	var persistErrs []error
	persisted := w.ExpiresAt()
	persist := func(at time.Time) {
		if w.opts.Persist == nil {
			return
		}
		if err := w.opts.Persist(ctx, at); err != nil {
			persistErrs = append(persistErrs, err)
			return
		}
		persisted = at
	}
	finish := func(o Outcome, termErr error) {
		w.result = Result{
			Outcome:      o,
			ExpiresAt:    w.ExpiresAt(),
			TerminateErr: termErr,
			PersistErr:   errors.Join(persistErrs...),
		}
	}

	persist(persisted)

	ticks := w.opts.ticks
	if ticks == nil {
		ticker := time.NewTicker(w.opts.Tick)
		defer ticker.Stop()
		ticks = ticker.C
	}
	var lastProbe time.Time

	for {
		select {
		case <-w.opts.Exited:
			finish(OutcomeExited, nil)
			return
		case <-ctx.Done():
			finish(OutcomeCanceled, nil)
			return
		case <-w.nudge:
			w.mu.Lock()
			at := w.lease.ExpiresAt()
			if w.lease.Paused() {
				at = time.Time{}
			}
			w.mu.Unlock()
			persist(at)
			continue
		case <-ticks:
		}

		now := w.opts.Now()
		if w.opts.FSProbe != nil && w.wantProbe(now) && now.Sub(lastProbe) >= w.opts.FSPoll {
			lastProbe = now
			if at, err := w.opts.FSProbe(); err == nil && !at.IsZero() {
				if at.After(now) {
					at = now
				}
				w.mu.Lock()
				w.lease.Activity(at)
				w.mu.Unlock()
			}
		}

		w.mu.Lock()
		_, expired := w.lease.Check(now)
		expires := w.lease.ExpiresAt()
		paused := w.lease.Paused()
		w.mu.Unlock()

		if expired {
			// The process may have exited in the same instant; an exit
			// wins, since there is nothing left to kill.
			select {
			case <-w.opts.Exited:
				finish(OutcomeExited, nil)
				return
			default:
			}
			finish(OutcomeExpired, w.opts.Terminate())
			return
		}
		if !paused && expires.Sub(persisted) >= w.opts.PersistEvery {
			persist(expires)
		}
	}
}

// wantProbe reports whether stdout has been quiet long enough that a
// worktree write is the only thing that could keep the process live.
func (w *Watcher) wantProbe(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.lease.Paused() && now.Sub(w.lease.LastActivity()) >= w.lease.cfg.Idle/2
}

type activityWriter struct {
	w   *Watcher
	dst io.Writer
}

func (a activityWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		a.w.Touch()
	}
	return a.dst.Write(p)
}
