package supervisor

// processAlive reports whether pid is running. A zombie counts as dead: a
// killed orphan stays a zombie until its new parent reaps it, and in a
// container whose PID 1 doesn't reap (Alpine CI's sh) that may be never.
func processAlive(pid int) bool {
	state, _, ok := procStat(pid)
	return ok && state != 'Z' && state != 'X'
}
