package flaky

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttack_INVARIANT_4_Flaky(t *testing.T) {
	marker := filepath.Join(os.TempDir(), "arbiter-classify-flaky.marker")
	if _, err := os.Stat(marker); err != nil {
		os.WriteFile(marker, nil, 0o644)
		assert.Fail(t, "first run fails")
	}
}
