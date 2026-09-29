package assertfail

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"scratch/app"
)

func TestAttack_AC_2_AddNegative(t *testing.T) {
	assert.Equal(t, 1, app.Add(-1, 2), "Add(-1, 2)")
}

func TestAttack_AC_2_RequireNegative(t *testing.T) {
	require.Equal(t, -3, app.Add(-1, -2))
}

func TestAttack_AC_2_StdlibFatal(t *testing.T) {
	if got := app.Add(-5, 5); got != 0 {
		t.Fatalf("Add(-5,5) = %d, want 0", got)
	}
}
