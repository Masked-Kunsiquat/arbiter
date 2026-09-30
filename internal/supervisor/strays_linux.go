package supervisor

import (
	"os"
	"strconv"
	"strings"
)

// listProcesses reads every process from /proc. Processes that vanish
// mid-scan or belong to another user keep whatever fields were readable.
func listProcesses() ([]procInfo, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
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
		out = append(out, p)
	}
	return out, nil
}
