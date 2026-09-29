# Spike 2: Job Object containment on Windows

Environment: Windows 11 Home 10.0.26200, Go 1.27.1, golang.org/x/sys v0.48.0, Claude Code 2.1.284.
Code: `main.go` (`go build -o jobspike.exe . && ./jobspike.exe [scenario…]`).
The Go child (`jobspike child`) spawns a grandchild with plain `os/exec`; both install
`signal.Notify(os.Interrupt, SIGTERM)` and write a `.sig` file when signalled.

## Summary

| Spec assumption (§7) | Result |
|---|---|
| `CREATE_SUSPENDED` → assign to job → resume closes the spawn race | ✅ works, but `os/exec` discards the thread handle, so resuming needs a Toolhelp thread snapshot (or skip the dance, see below) |
| `TerminateJobObject` kills the whole tree | ✅ Go child + grandchild; claude + powershell + cmd + ping + conhost |
| `KILL_ON_JOB_CLOSE` kills the tree when the supervisor dies | ✅ supervisor hard-killed with `TerminateProcess`; everything gone within 1 s |
| `CTRL_BREAK_EVENT` to the new process group stops it gracefully | ⚠️ **only if the supervisor and child share a console.** Detached supervisor: the call fails. Child with `CREATE_NO_WINDOW`: the call **returns success and delivers nothing** |
| Children can't leave the job | ⚠️ `CREATE_BREAKAWAY_FROM_JOB` is denied ✅, but a process created **through WMI** lands outside the job and survives `TerminateJobObject` ❌ |
| "claude's node process tree" | `claude.exe` is a single native binary (no node). Its tree for a shell tool call: `claude.exe → powershell.exe → cmd.exe → PING.EXE`, plus `conhost.exe` |
| (§5.8) every invocation reports `total_cost_usd` | ❌ **not when stopped.** After `CTRL_BREAK`, claude exits with no `result` event |

## Real output

Supervisor run from a terminal (has a console):

```
driver pid=146744 consoleWindow=false consoleProcesses=3

=== terminate
  before TerminateJobObject: jobspike.exe(118012)=ALIVE jobspike.exe(74764)=ALIVE
  after  TerminateJobObject: ?(118012)=dead ?(74764)=dead
  RESULT all dead=true

=== parentdeath
  supervisor pid=20240; job tree: jobspike.exe(70228)=ALIVE jobspike.exe(83956)=ALIVE
  after killing supervisor: ?(70228)=dead ?(83956)=dead
  RESULT all dead=true

=== ctrlbreak
  tree: jobspike.exe(134872)=ALIVE jobspike.exe(136456)=ALIVE
  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 134872) err=<nil>
  after 15s grace: ?(134872)=dead ?(136456)=dead
  child.sig: child got interrupt at 2026-09-28T23:05:07.6832494-04:00
  grandchild.sig: grandchild got interrupt at 2026-09-28T23:05:07.6832494-04:00
  RESULT graceful (all exited without TerminateJobObject)=true

=== escape
  CREATE_BREAKAWAY_FROM_JOB from inside the job: err=fork/exec …\jobspike.exe: Access is denied.
  WMI-created grandchild pid=132380 inJob=false
  after TerminateJobObject: WMI grandchild jobspike.exe(132380)=ALIVE
  RESULT escaped=true
```

Supervisor started as `DETACHED_PROCESS` (no console, like a background `arbiter serve`):

```
driver pid=93028 consoleWindow=false consoleProcesses=0
=== ctrlbreak
  tree: jobspike.exe(134224)=ALIVE conhost.exe(142832)=ALIVE jobspike.exe(72956)=ALIVE
  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 134224) err=The handle is invalid.
  fallback AttachConsole+GenerateConsoleCtrlEvent err=<nil>
  after 15s grace: ?(134224)=dead ?(142832)=dead ?(72956)=dead
  child.console: consoleWindow=true consoleProcesses=1        <- a visible console window popped up
  child.sig: child got interrupt …
  grandchild.sig: grandchild got interrupt …
  RESULT graceful (all exited without TerminateJobObject)=true
```

Child created with `CREATE_NO_WINDOW` (no window pop-up):

```
--- detached supervisor + CREATE_NO_WINDOW
  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 14708) err=The handle is invalid.
  fallback AttachConsole+GenerateConsoleCtrlEvent err=<nil>
  child.console: consoleWindow=false consoleProcesses=1
  RESULT graceful (all exited without TerminateJobObject)=true

--- supervisor WITH a console + CREATE_NO_WINDOW
  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 135596) err=<nil>                  <- reports success
  after 15s grace: jobspike.exe(135596)=ALIVE conhost.exe(144308)=ALIVE jobspike.exe(30172)=ALIVE
  RESULT graceful (all exited without TerminateJobObject)=false                 <- nothing was delivered
```

`CTRL_BREAK_EVENT` only reaches a process group on the **caller's** console. A child without the
caller's console (the caller has none, or the child got its own hidden console via
`CREATE_NO_WINDOW`) needs the caller to `FreeConsole` → `AttachConsole(childPid)` → send → `FreeConsole`.
That detaches the supervisor from its own console and is process-global, so it must not run
inside the long-lived supervisor.

With `claude` as the child (isolated worker profile, prompt: run `ping -n 120 127.0.0.1`):

```
=== claude-terminate
  before TerminateJobObject: conhost.exe(100284)=ALIVE powershell.exe(139072)=ALIVE PING.EXE(141436)=ALIVE claude.exe(140456)=ALIVE cmd.exe(140480)=ALIVE
  after  TerminateJobObject: ?(100284)=dead ?(139072)=dead ?(141436)=dead ?(140456)=dead ?(140480)=dead
  RESULT all dead=true

=== claude-ctrlbreak
  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 140168) err=<nil>
  after 15s grace: all dead
  last stdout lines:
  | {"type":"assistant", … "content":[{"type":"tool_use", … "name":"Power…
  | {"type":"user", … "content":[{"type":"tool_result","content":"Exit code 137\nPinging 127.0.0.1 …","is_error":true …
  (no "result" event)
  RESULT graceful (all exited without TerminateJobObject)=true

=== claude-parentdeath
  supervisor pid=145700; job tree: conhost.exe(69436)=ALIVE powershell.exe(140496)=ALIVE PING.EXE(55292)=ALIVE claude.exe(145724)=ALIVE cmd.exe(85284)=ALIVE
  after killing supervisor: all dead
  RESULT all dead=true
```

## Notes on the spawn path

- Go 1.27's `syscall.SysProcAttr` has no job field, and `os/exec` closes the main thread handle
  from `CreateProcess`. The spike resumes via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` +
  `OpenThread` + `ResumeThread` (exactly one thread found every time).
- Cleaner alternative (not tested here): call `windows.CreateProcess` directly with
  `PROC_THREAD_ATTRIBUTE_JOB_LIST` in a `STARTUPINFOEX`. The process is created *inside* the job,
  so there's no suspended window and no thread hunt, at the cost of wiring stdio pipes by hand.
- `Supervisor.Terminate` should be: send CTRL_BREAK → wait for grace → `TerminateJobObject`
  → `CloseHandle(job)`. Never rely on the break alone: it can silently not arrive.

## What the spec should say instead (§7)

1. **Graceful stop on Windows:** always create children with
   `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW` (so a console-less `arbiter serve` doesn't pop
   up windows, and behaviour is the same with or without a console). Deliver CTRL_BREAK through a
   tiny helper (`arbiter _ctrlbreak <pid>`: `FreeConsole`, `AttachConsole(pid)`,
   `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)`), never from the supervisor process itself.
   Treat the graceful stop as best effort: `TerminateJobObject` after the grace period regardless.
2. **Spawn race:** keep "suspended → assign → resume", and note that Go needs the Toolhelp thread
   resume; or specify `PROC_THREAD_ATTRIBUTE_JOB_LIST` as the preferred path.
3. **Threat model (§8.A):** add "a process can leave the Job Object through WMI
   (`Win32_Process.Create`), the Task Scheduler, or services" to *Not defended against*. Containment
   is for cleaning up cooperative trees, not a sandbox. Optional cheap detection: after every
   invocation, scan for live processes whose command line or cwd contains the slot path and log
   them as a violation against the seat.
4. **Budget (§5.8) and autopsy (§7):** a killed or interrupted invocation produces **no `result`
   event and no `total_cost_usd`**. Either sum `message.usage` from the streamed `assistant`
   events against a price table as the fallback, or record `cost_usd = NULL` and count it as
   "unknown" against the budget. Pass `--max-budget-usd` (spike 1) so the harness caps spend itself.
5. **Wording:** replace "claude's node process tree" assumptions with: `claude.exe` is a
   single native binary; the tree is whatever its shell tools spawn (powershell/cmd/bash + commands), plus conhost.
