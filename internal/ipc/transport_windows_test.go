//go:build windows

package ipc

import (
	"testing"
)

// TestListen_PipeNameIsExclusive: a second listener on a live pipe name
// must fail rather than share it (FILE_FLAG_FIRST_PIPE_INSTANCE), so a
// squatter can't pre-create the core's pipe and a second core can't join
// the first's.
func TestListen_PipeNameIsExclusive(t *testing.T) {
	ep, err := Endpoint(newArbiterDir(t))
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	ln, err := Listen(ep)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	if ln2, err := Listen(ep); err == nil {
		_ = ln2.Close()
		t.Fatal("second Listen on the same pipe name succeeded")
	}
}
