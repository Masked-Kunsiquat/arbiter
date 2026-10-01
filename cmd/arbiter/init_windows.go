//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// isReFS reports whether the volume containing path is formatted with ReFS.
func isReFS(path string) bool {
	if path == "" {
		return false
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var volPathBuf [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumePathName(pathPtr, &volPathBuf[0], uint32(len(volPathBuf))); err != nil {
		return false
	}

	var fsNameBuf [256]uint16
	err = windows.GetVolumeInformation(
		&volPathBuf[0],
		nil,
		0,
		nil,
		nil,
		nil,
		&fsNameBuf[0],
		uint32(len(fsNameBuf)),
	)
	if err != nil {
		return false
	}
	fsName := windows.UTF16ToString(fsNameBuf[:])
	return strings.EqualFold(fsName, "ReFS")
}

// printDevDriveRecommendation prints a recommendation to place the repo on
// a Dev Drive (ReFS) when running on Windows (spec §7: "Windows: recommend
// placing the repo on a Dev Drive (ReFS) for faster I/O and copy-on-write").
func printDevDriveRecommendation(repoRoot string) {
	if isReFS(repoRoot) {
		fmt.Println("arbiter init: Dev Drive (ReFS) detected")
	} else {
		fmt.Println("tip: on Windows, recommend placing the repo on a Dev Drive (ReFS) for faster I/O and copy-on-write")
	}
}
