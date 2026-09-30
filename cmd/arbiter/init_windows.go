//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// isReFS reports whether the volume containing path is formatted with ReFS.
func isReFS(path string) bool {
	vol := filepath.VolumeName(path)
	if vol == "" {
		return false
	}
	volRoot := vol + `\`
	volPtr, err := windows.UTF16PtrFromString(volRoot)
	if err != nil {
		return false
	}

	var fsNameBuf [256]uint16
	err = windows.GetVolumeInformation(
		volPtr,
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
