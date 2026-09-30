package supervisor

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listProcesses snapshots every process and reads each one's command line
// and working directory from its PEB. Processes that can't be opened for
// reading (protected, elevated, another user's) are listed without them.
func listProcesses() ([]procInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var out []procInfo
	pe := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == 0 || pe.ProcessID == 4 { // System Idle, System
			continue
		}
		p := procInfo{pid: int(pe.ProcessID), image: windows.UTF16ToString(pe.ExeFile[:])}
		p.cmdline, p.cwd, p.started = readProcessDetails(pe.ProcessID)
		out = append(out, p)
	}
	return out, nil
}

// readProcessDetails returns the process's creation time and the command
// line and current directory from its RTL_USER_PROCESS_PARAMETERS, or zero
// values for what it can't read.
func readProcessDetails(pid uint32) (cmdline, cwd string, started time.Time) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", "", time.Time{}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) == nil {
		started = time.Unix(0, created.Nanoseconds())
	}
	cmdline, cwd = readProcessParams(h)
	return cmdline, cwd, started
}

// readProcessParams reads the command line and current directory of the
// process open as h, or empty strings.
func readProcessParams(h windows.Handle) (cmdline, cwd string) {
	var pbi windows.PROCESS_BASIC_INFORMATION
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil || pbi.PebBaseAddress == nil {
		return "", ""
	}
	// The PEB and parameter block live in the target's address space; the
	// pointers below are remote addresses, only ever passed to ReadProcessMemory.
	var peb windows.PEB
	if !readRemote(h, uintptr(unsafe.Pointer(pbi.PebBaseAddress)), unsafe.Pointer(&peb), unsafe.Sizeof(peb)) {
		return "", ""
	}
	var params windows.RTL_USER_PROCESS_PARAMETERS
	if !readRemote(h, uintptr(unsafe.Pointer(peb.ProcessParameters)), unsafe.Pointer(&params), unsafe.Sizeof(params)) {
		return "", ""
	}
	return readRemoteString(h, params.CommandLine), readRemoteString(h, params.CurrentDirectory.DosPath)
}

func readRemote(h windows.Handle, addr uintptr, dst unsafe.Pointer, size uintptr) bool {
	if addr == 0 {
		return false
	}
	var n uintptr
	err := windows.ReadProcessMemory(h, addr, (*byte)(dst), size, &n)
	return err == nil && n == size
}

// readRemoteString reads a UNICODE_STRING whose buffer is in process h.
func readRemoteString(h windows.Handle, s windows.NTUnicodeString) string {
	if s.Length == 0 || s.Buffer == nil {
		return ""
	}
	buf := make([]uint16, s.Length/2)
	if !readRemote(h, uintptr(unsafe.Pointer(s.Buffer)), unsafe.Pointer(&buf[0]), uintptr(s.Length)) {
		return ""
	}
	return windows.UTF16ToString(buf)
}
