package testcompile

import (
	"testing"

	"scratch/app"
)

func TestAttack_INVARIANT_1_HallucinatedAPI(t *testing.T) {
	if app.RevokeFamily("u1") != nil {
		t.Fatal("expected nil")
	}
}
