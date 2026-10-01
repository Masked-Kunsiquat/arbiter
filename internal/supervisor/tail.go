package supervisor

import (
	"bytes"
	"io"
	"strings"
	"sync"
)

// DefaultTailLines is how much output the crash autopsy keeps (§7 step 2:
// "Capture the last 50 lines of stdout/stderr").
const DefaultTailLines = 50

// maxTailLine caps one buffered line, so a process that never prints a
// newline cannot grow the buffer without bound.
const maxTailLine = 64 << 10

// TailBuffer is an io.Writer that keeps the last N lines written to it.
// To capture stdout and stderr interleaved, give each its own Stream so a
// line one stream has not finished is not glued to the other's. Safe for
// concurrent use.
type TailBuffer struct {
	mu      sync.Mutex
	max     int
	lines   []string // ring of complete lines
	next    int      // ring write position once full
	streams []*tailStream
	self    *tailStream // partial line for writes to the TailBuffer itself
}

// NewTailBuffer keeps the last n lines; n <= 0 means DefaultTailLines.
func NewTailBuffer(n int) *TailBuffer {
	if n <= 0 {
		n = DefaultTailLines
	}
	t := &TailBuffer{max: n}
	t.self = t.newStream()
	return t
}

// Stream returns a writer into the same ring with its own partial line.
func (t *TailBuffer) Stream() io.Writer {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.newStream()
}

func (t *TailBuffer) newStream() *tailStream {
	st := &tailStream{t: t}
	t.streams = append(t.streams, st)
	return st
}

// Write never fails.
func (t *TailBuffer) Write(p []byte) (int, error) { return t.self.Write(p) }

type tailStream struct {
	t       *TailBuffer
	partial []byte // trailing line with no newline yet
}

func (st *tailStream) Write(p []byte) (int, error) {
	t := st.t
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			st.add(p)
			break
		}
		st.add(p[:i])
		t.push(strings.TrimSuffix(string(st.partial), "\r"))
		st.partial = st.partial[:0]
		p = p[i+1:]
	}
	return n, nil
}

func (st *tailStream) add(p []byte) {
	st.partial = append(st.partial, p...)
	if len(st.partial) > maxTailLine {
		st.partial = st.partial[len(st.partial)-maxTailLine:]
	}
}

func (t *TailBuffer) push(line string) {
	if len(t.lines) < t.max {
		t.lines = append(t.lines, line)
		return
	}
	t.lines[t.next] = line
	t.next = (t.next + 1) % t.max
}

// Lines returns the kept lines, oldest first. Unterminated last lines (one
// per stream) are included and count toward the limit.
func (t *TailBuffer) Lines() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.lines)+len(t.streams))
	out = append(out, t.lines[t.next:]...)
	out = append(out, t.lines[:t.next]...)
	for _, st := range t.streams {
		if len(st.partial) > 0 {
			out = append(out, string(st.partial))
		}
	}
	if len(out) > t.max {
		out = out[len(out)-t.max:]
	}
	return out
}

// String returns the kept lines joined with newlines.
func (t *TailBuffer) String() string {
	return strings.Join(t.Lines(), "\n")
}
