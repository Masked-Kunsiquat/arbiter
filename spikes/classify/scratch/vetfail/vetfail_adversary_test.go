package vetfail

import (
	"fmt"
	"testing"
)

func TestAttack_INVARIANT_5_VetBroken(t *testing.T) {
	t.Log(fmt.Sprintf("%d", "not a number"))
}
