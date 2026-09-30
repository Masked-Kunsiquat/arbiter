//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// listen creates the named pipe with a DACL granting full access to the
// current user only (protected, so nothing is inherited). go-winio opens
// the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE, so if another
// process already owns the name — a live core we somehow raced, or a
// squatter — listen fails instead of silently sharing the name.
func listen(name string) (net.Listener, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")",
	})
}

func dial(ctx context.Context, name string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, name)
}

// isNotListening reports a pipe name that doesn't exist. Named pipes vanish
// with the process that created them, so there is no stale-pipe case.
func isNotListening(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

func currentUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("reading current user SID: %w", err)
	}
	return u.User.Sid.String(), nil
}
