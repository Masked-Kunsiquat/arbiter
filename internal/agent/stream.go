package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxLineBytes caps one stream-json line. A longer line (a huge tool result)
// is dropped and counted as malformed rather than buffered without bound.
var maxLineBytes = 16 << 20

// Event is one stream-json line, passed to the observer as it arrives
// (liveness §7, the TUI feed). Raw is the line itself; observers may keep it.
type Event struct {
	Type    string
	Subtype string
	Raw     []byte
}

// InitEvent is the system/init event: what the harness actually loaded.
type InitEvent struct {
	SessionID      string            `json:"session_id"`
	Model          string            `json:"model"`
	Tools          []string          `json:"tools"`
	MCPServers     []json.RawMessage `json:"mcp_servers"`
	PermissionMode string            `json:"permissionMode"`
}

// ResultEvent is the final result event (§9.A). Success is IsError == false,
// never Subtype: an API error arrives as subtype "success" with is_error.
type ResultEvent struct {
	Subtype        string   `json:"subtype"`
	IsError        bool     `json:"is_error"`
	Text           *string  `json:"result"` // the model's final message; null on some errors
	SessionID      string   `json:"session_id"`
	TotalCostUSD   *float64 `json:"total_cost_usd"`
	TerminalReason string   `json:"terminal_reason"`
	APIErrorStatus *int     `json:"api_error_status"`
	Errors         []string `json:"errors"`
	NumTurns       int      `json:"num_turns"`
}

// RateLimit is a rate_limit_event's rate_limit_info: subscription headroom.
type RateLimit struct {
	Status        string   `json:"status"`
	RateLimitType string   `json:"rateLimitType"`
	Utilization   *float64 `json:"utilization"`
	ResetsAt      int64    `json:"resetsAt"`
}

// Usage is an assistant message's token usage.
type Usage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

// MessageUsage is the last usage reported for one assistant message, with
// the model that produced it (for the §5.8 cost estimate).
type MessageUsage struct {
	Model string
	Usage Usage
}

// Stream is what ReadStream collected.
type Stream struct {
	Init      *InitEvent   // nil if the harness never initialised (e.g. a bad --resume)
	Result    *ResultEvent // the first one; nil if none arrived: killed or crashed (§9.A)
	Results   int          // result events seen; more than one means something forged one
	RateLimit *RateLimit   // the last one seen
	// Usage maps assistant message id to its usage. The harness repeats a
	// message once per content block, so each id is counted once.
	Usage     map[string]MessageUsage
	Malformed int // lines that weren't a JSON object with a type, or were too long
}

// ReadStream reads stream-json from r to EOF (the result event is not always
// last: hook events can follow it) and calls onEvent, if non-nil, for every
// parsed event. Malformed lines are counted and skipped. The error reports a
// failed read, never the stream's content.
func ReadStream(r io.Reader, onEvent func(Event)) (*Stream, error) {
	s := &Stream{Usage: map[string]MessageUsage{}}
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, err := readLine(br)
		if tooLong {
			s.Malformed++
		} else if len(bytes.TrimSpace(line)) > 0 {
			s.handle(line, onEvent)
		}
		if errors.Is(err, io.EOF) {
			return s, nil
		}
		if err != nil {
			return s, fmt.Errorf("agent: reading harness output: %w", err)
		}
	}
}

// readLine returns the next line without its newline. A line longer than
// maxLineBytes is consumed and discarded (tooLong).
func readLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > maxLineBytes+1 { // +1: the newline
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimRight(line, "\r\n"), tooLong, err
	}
}

func (s *Stream) handle(line []byte, onEvent func(Event)) {
	var head struct {
		Type    string `json:"type"`
		Subtype string `json:"subtype"`
	}
	if err := json.Unmarshal(line, &head); err != nil || head.Type == "" {
		s.Malformed++
		return
	}
	switch {
	case head.Type == "system" && head.Subtype == "init":
		var init InitEvent
		if json.Unmarshal(line, &init) == nil {
			s.Init = &init
		}
	case head.Type == "result":
		var res ResultEvent
		if json.Unmarshal(line, &res) == nil {
			// Keep the first: a process the agent started can write to the
			// harness's stdout, and must not replace the real outcome.
			s.Results++
			if s.Result == nil {
				s.Result = &res
			}
		}
	case head.Type == "rate_limit_event":
		var ev struct {
			Info RateLimit `json:"rate_limit_info"`
		}
		if json.Unmarshal(line, &ev) == nil {
			s.RateLimit = &ev.Info
		}
	case head.Type == "assistant":
		var ev struct {
			Message struct {
				ID    string `json:"id"`
				Model string `json:"model"`
				Usage *Usage `json:"usage"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &ev) == nil && ev.Message.ID != "" && ev.Message.Usage != nil {
			s.Usage[ev.Message.ID] = MessageUsage{Model: ev.Message.Model, Usage: *ev.Message.Usage}
		}
	}
	if onEvent != nil {
		onEvent(Event{Type: head.Type, Subtype: head.Subtype, Raw: bytes.Clone(line)})
	}
}
