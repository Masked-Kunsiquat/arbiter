// Package ipc is the local transport between the core and its clients
// (spec §10.A, §10.B): a Windows named pipe at \\.\pipe\arbiter-<repo-hash>
// or a Unix domain socket at .arbiter/core.sock, carrying newline-delimited
// JSON.
//
// Every connection opens with a handshake that pins the protocol version
// and the repo, so a client can never end up talking to the core of a
// different repository (e.g. two checkouts whose pipe names collide, or a
// socket path reused across a move). After the handshake the client issues
// request/response calls one at a time.
//
// Access control is the OS's: the socket file is mode 0600 inside the
// user's repo, and the named pipe's DACL grants access only to the user
// that created it.
package ipc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// SocketName is the Unix domain socket's name inside the .arbiter
// directory (POSIX only).
const SocketName = "core.sock"

// pipePrefix is the Windows named pipe namespace prefix for core pipes.
const pipePrefix = `\\.\pipe\arbiter-`

// RepoHash returns a stable identifier for the repository whose .arbiter
// directory is arbiterDir: the first 16 hex characters of the SHA-256 of
// the repo root's canonical absolute path. Paths are case-folded on
// Windows, where the filesystem is case-insensitive, so C:\Repo and c:\repo
// map to the same core.
func RepoHash(arbiterDir string) (string, error) {
	root, err := canonicalRepoRoot(arbiterDir)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])[:16], nil
}

// Endpoint returns the address the core for arbiterDir listens on:
// \\.\pipe\arbiter-<repo-hash> on Windows, <arbiterDir>/core.sock elsewhere.
func Endpoint(arbiterDir string) (string, error) {
	if runtime.GOOS == "windows" {
		h, err := RepoHash(arbiterDir)
		if err != nil {
			return "", err
		}
		return pipePrefix + h, nil
	}
	abs, err := filepath.Abs(arbiterDir)
	if err != nil {
		return "", fmt.Errorf("ipc: resolving %s: %w", arbiterDir, err)
	}
	return filepath.Join(abs, SocketName), nil
}

func canonicalRepoRoot(arbiterDir string) (string, error) {
	abs, err := filepath.Abs(arbiterDir)
	if err != nil {
		return "", fmt.Errorf("ipc: resolving %s: %w", arbiterDir, err)
	}
	// Resolve symlinks so two spellings of the same directory (e.g. macOS
	// /tmp vs /private/tmp) agree. The directory must exist; a core is
	// never started for a repo that hasn't been initialized.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("ipc: resolving %s: %w", abs, err)
	}
	root := filepath.Dir(filepath.Clean(resolved))
	if runtime.GOOS == "windows" {
		root = strings.ToLower(root)
	}
	return root, nil
}
