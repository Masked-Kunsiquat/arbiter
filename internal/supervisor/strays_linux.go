package supervisor

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat's starttime. It is
// 100 on every Linux ABI Go supports; reading it properly needs
// sysconf(_SC_CLK_TCK), i.e. cgo.
const clockTicks = 100

// listProcesses reads every process from /proc. Processes that vanish
// mid-scan or belong to another user keep whatever fields were readable.
func listProcesses() ([]procInfo, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	boot := bootTime()
	var out []procInfo
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		p := procInfo{pid: pid}
		if b, err := os.ReadFile(dir + "/comm"); err == nil {
			p.image = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
			p.cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		}
		if cwd, err := os.Readlink(dir + "/cwd"); err == nil {
			p.cwd = cwd
		}
		p.started = startTime(pid, boot)
		out = append(out, p)
	}
	return out, nil
}

// startTime is pid's start time from its stat starttime (field 22), or
// zero if unknown.
func startTime(pid int, boot time.Time) time.Time {
	f, ok := statFields(pid)
	if boot.IsZero() || !ok || len(f) < 20 {
		return time.Time{}
	}
	ticks, err := strconv.ParseInt(string(f[19]), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return boot.Add(time.Duration(ticks) * time.Second / clockTicks)
}

// bootTime reads btime from /proc/stat, or returns zero.
func bootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			if secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(secs, 0)
			}
		}
	}
	return time.Time{}
}
