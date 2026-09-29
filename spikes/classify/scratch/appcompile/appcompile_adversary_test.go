package appcompile

import "testing"

func TestAttack_AC_1_RefreshReturnsNew(t *testing.T) {
	if Refresh("a") == "a" {
		t.Fatal("refresh returned the old token")
	}
}
