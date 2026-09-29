// Package app is the "worker's code" the attacks target.
package app

import "strings"

type Token struct{ Subject string }

// ParseToken returns nil for malformed input (a latent defect: callers deref it).
func ParseToken(s string) *Token {
	if !strings.HasPrefix(s, "tok:") {
		return nil
	}
	return &Token{Subject: s[4:]}
}

// Subject derefs the token without a nil check: a defect in application code.
func Subject(s string) string {
	return ParseToken(s).Subject
}

// Add is wrong on purpose for negatives.
func Add(a, b int) int {
	if a < 0 {
		return b - a
	}
	return a + b
}

// Background panics on a goroutine the test never sees.
func Background(done chan struct{}) {
	go func() {
		var m map[string]int
		m["x"] = 1 // panic: assignment to entry in nil map
		close(done)
	}()
}
