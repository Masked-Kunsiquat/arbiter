package testpanic

import (
	"testing"

	"scratch/app"
)

func TestAttack_INVARIANT_2_NilInTestBody(t *testing.T) {
	var tok *app.Token
	if tok.Subject == "" { // the test itself derefs nil
		t.Fatal("empty")
	}
}

func TestAttack_INVARIANT_2_ZPassingSibling(t *testing.T) {
	if app.Add(1, 2) != 3 {
		t.Fatal("bad add")
	}
}
