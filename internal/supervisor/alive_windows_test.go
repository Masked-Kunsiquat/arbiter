package supervisor

import "golang.org/x/sys/windows"

// stillActive is STILL_ACTIVE, GetExitCodeProcess's code for a running process.
const stillActive = 259

// processAlive reports whether pid is running.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == stillActive
}
