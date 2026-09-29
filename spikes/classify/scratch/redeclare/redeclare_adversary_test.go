package redeclare

import "testing"

// The adversary defines a helper whose name collides with application code.
func Normalize(s string) string { return s + "!" }

func TestAttack_INVARIANT_8_Collides(t *testing.T) {
	if Normalize("a") != "a!" {
		t.Fatal("x")
	}
}
