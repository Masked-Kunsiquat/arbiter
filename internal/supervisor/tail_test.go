package supervisor

import (
	"fmt"
	"strings"
	"testing"
)

func TestTailBuffer_KeepsLastLines(t *testing.T) {
	tb := NewTailBuffer(3)
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(tb, "line %d\r\n", i)
	}
	if got, want := tb.String(), "line 3\nline 4\nline 5"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTailBuffer_SplitWritesAndPartialLine(t *testing.T) {
	tb := NewTailBuffer(2)
	for _, chunk := range []string{"a", "b\nc", "d\ne", "f"} {
		if _, err := tb.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	// "ab", "cd" complete; "ef" unterminated; limit 2 keeps "cd", "ef".
	if got, want := tb.String(), "cd\nef"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTailBuffer_DefaultAndLongLine(t *testing.T) {
	tb := NewTailBuffer(0)
	if tb.max != DefaultTailLines {
		t.Fatalf("default lines %d", tb.max)
	}
	if _, err := tb.Write([]byte(strings.Repeat("x", 3*maxTailLine))); err != nil {
		t.Fatal(err)
	}
	if got := len(tb.String()); got != maxTailLine {
		t.Fatalf("unterminated line kept %d bytes, want cap %d", got, maxTailLine)
	}
}

func TestTailBuffer_StreamsKeepSeparatePartials(t *testing.T) {
	tb := NewTailBuffer(5)
	out, errw := tb.Stream(), tb.Stream()
	fmt.Fprint(out, "abc")
	fmt.Fprint(errw, "ERR\n")
	fmt.Fprint(out, "def\n")
	if got, want := tb.String(), "ERR\nabcdef"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
