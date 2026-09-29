package apppanic

import (
	"testing"

	"scratch/app"
)

func TestAttack_INVARIANT_3_MalformedTokenCrashes(t *testing.T) {
	_ = app.Subject("garbage") // app derefs nil
}

func TestAttack_INVARIANT_3_ZPassingSibling(t *testing.T) {
	if app.Add(1, 2) != 3 {
		t.Fatal("bad add")
	}
}
