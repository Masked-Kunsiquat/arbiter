package goroutinepanic

import (
	"testing"
	"time"

	"scratch/app"
)

func TestAttack_INVARIANT_7_BackgroundCrash(t *testing.T) {
	done := make(chan struct{})
	app.Background(done)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}
