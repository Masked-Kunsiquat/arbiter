package timeout

import (
	"testing"
	"time"
)

func TestAttack_AC_3_Hangs(t *testing.T) {
	time.Sleep(time.Hour)
}

func TestAttack_AC_3_ZPassingSibling(t *testing.T) {}
