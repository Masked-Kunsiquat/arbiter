# Spike 1: Claude Code headless harness from Go

Environment: Windows 11, Go 1.27.1, Claude Code 2.1.284 (`~\.local\bin\claude.exe`,
a native 246 MB exe, not a `.cmd` shim), subscription auth (`apiKeySource: "none"`).
Model: `claude-haiku-4-5-20251001`. Code: `main.go` (`go run . basic|resume|tools|big|isolated`).
Raw event streams are in `out/*.jsonl`. Total spend for the spike: about $0.60 (notional).

## Summary

| Spec assumption (§9.A / §7 / §5.8) | Result |
|---|---|
| Prompt on stdin works | ✅ 45,111- and 45,221-char prompts were delivered intact |
| Events stream on stdout while running | ✅ first event at ~1.6–3.5 s, one event per turn/tool call, plus `system/thinking_tokens` about every second while the model thinks |
| `result` has final text, `session_id`, `is_error`, `total_cost_usd` | ✅ all present, **but** `result` is not always the last line, and `subtype: "success"` can come with `is_error: true` |
| `--resume <id>` keeps context | ✅ same `session_id` comes back; works even from a different cwd |
| `--allowedTools "Read,Grep,Glob"` blocks edits | ⚠️ **only by accident.** It's a permission allow-list, not a tool list. All 111 tools stay loaded; writes were denied only because `-p` can't answer a prompt. Adding `--permission-mode acceptEdits` let `Write` succeed |
| (unstated) the agent runs with only what Arbiter gives it | ❌ **false.** A plain `claude -p` inherits the user's plugins, hooks, MCP servers (GitHub with write access, Gmail/Drive connectors, Android), skills, subagents (`Task`), auto-memory and CLAUDE.md |

## 1. Event stream shape (real output)

Plain recipe from §9.A, prompt `Reply with exactly the word PONG and nothing else.`:

```
    2.56s  system/hook_started            <- a user plugin's SessionStart hook
    3.45s  rate_limit_event
    3.67s  system/hook_progress
    4.25s  system/init session_id=e122b7a4-… model=claude-haiku-4-5-20251001 permissionMode=default tools(111)=[Task Artifact … Bash … Edit …]
    5.29s  assistant thinking
    5.34s  assistant text("PONG")
    5.36s  rate_limit_event
    5.67s  system/hook_progress
    6.20s  result/success is_error=false
    6.21s  system/hook_response             <- arrives AFTER result
  exit=0 total=6.92s first_event=2.56s stderr=""
  result: subtype=success is_error=false session_id=e122b7a4-… total_cost_usd=0.0251729 num_turns=1
```

Event types seen: `system/init`, `system/hook_started|hook_progress|hook_response`,
`system/thinking_tokens`, `system/permission_denied`, `rate_limit_event`, `assistant`, `user`
(tool results), `result`.

- `assistant` / `user`: `{type, message:{model,id,role,content:[…],stop_reason,usage,…}, parent_tool_use_id, session_id, uuid, timestamp, request_id}`.
  Content blocks: `thinking`, `text`, `tool_use{name,input}`, `tool_result{is_error,content}`.
- `system/init` keys: `agents analytics_disabled apiKeySource capabilities claude_code_version cwd
  fast_mode_* mcp_servers memory_paths messaging_socket_path model output_style permissionMode
  plugins powershell_path scratchpad_path session_id skills slash_commands tools uuid view_mode`.
- `system/permission_denied`: `{tool_name, tool_use_id, message, decision_reason?, decision_reason_type?}`.
- `rate_limit_event.rate_limit_info`: `{status:"allowed_warning", rateLimitType:"seven_day",
  utilization:0.86, unifiedWindows:{five_hour:{utilization,resetsAt}, seven_day:{…}}, isUsingOverage}`.
  Useful: Arbiter can see subscription headroom before launching.

`result` event (trimmed):

```json
{
 "type": "result", "subtype": "success", "is_error": false,
 "result": "PONG",
 "session_id": "e122b7a4-0709-4b9d-8477-11492330a92f",
 "total_cost_usd": 0.025172899999999998,
 "num_turns": 1, "stop_reason": "end_turn", "terminal_reason": "completed",
 "api_error_status": null, "duration_ms": 3265, "duration_api_ms": 1674,
 "usage": {"input_tokens": 10, "cache_creation_input_tokens": 10726, "cache_read_input_tokens": 24919, "output_tokens": 51, …},
 "modelUsage": {"claude-haiku-4-5-20251001": {"costUSD": 0.0251729, "costBasis": "list", "contextWindow": 200000, …}},
 "permission_denials": [],
 "subagent_stats": {"spawned": 0, …}
}
```

Error shapes:

```
--model claude-nonexistent-9
{'subtype': 'success', 'is_error': True, 'result': "There's an issue with the selected model …",
 'total_cost_usd': 0, 'api_error_status': 404, 'terminal_reason': 'api_error'}
exit=1 stderr=[claude-code:unrecognized_model] {"model":"claude-nonexistent-9","query_source":"sdk"}

--resume 00000000-0000-0000-0000-000000000000
{'subtype': 'error_during_execution', 'is_error': True, 'result': None,
 'errors': ['No conversation found with session ID: 00000000-…']}      (no system/init event at all)
exit=1
```

## 2. Resume

```
=== resume-1  … "Remember this code word: ZEBRA-42. Reply only with OK."
  result: session_id=577b6ab1-… result="OK"
=== resume-2  … --resume 577b6ab1-…  "What was the code word I gave you?"
  result: session_id=577b6ab1-… result="ZEBRA-42"
  resume: first session=577b6ab1-… second session=577b6ab1-…; context kept=true
(from a different cwd, with different tool flags)  result='ZEBRA-42'
```

The session id is stable across resumes (no `--fork-session`), so `seats.harness_session_id` never changes.
Resume also works with different tool flags from the original launch.

## 3. Tool profiles: what actually blocks writes

Prompt: create `pwned.txt`, try Write first then a shell, reply DONE or BLOCKED.

| Flags | Tools loaded | pwned.txt created |
|---|---|---|
| `--allowedTools "Read,Grep,Glob"` (the spec's read-only profile) | 111 | no, but the model spent 4 turns trying Write then PowerShell twice; each hit `permission_denied` |
| `--allowedTools "Read,Grep,Glob" --permission-mode acceptEdits` | 111 | **yes** |
| `--tools "Read,Grep,Glob"` | **79**: Glob, Grep, Read + every MCP tool (android, GitHub, Hugging Face…) | no, but it tried `mcp__android__health_check` |
| `--permission-mode acceptEdits` (control) | 111 | yes |
| `--restricted --strict-mcp-config --disable-slash-commands --permission-prompts none --tools "Read,Grep,Glob"` | **3** | no: `No such tool available: Write` |

So `--allowedTools` alone is safe only while nothing else grants permission: the permission mode,
the user's `permissions.allow` rules in `~/.claude/settings.json`, or a project `.claude/settings.json`
**committed to the repo under work**. A worker could write that last file. `--tools` is the real
tool list, but it doesn't remove MCP tools; `--strict-mcp-config` does.

Isolated worker profile (real output):

```
--restricted --strict-mcp-config --disable-slash-commands --permission-prompts none
--tools Read,Grep,Glob,Edit,Write,Bash,PowerShell --permission-mode acceptEdits
--allowedTools "Bash(go version),Bash(go test *),PowerShell(go version),PowerShell(go test *)"

  tools(7)=[Bash Edit Glob Grep PowerShell Read Write]   mcp=[]   skills=0   memory=None
  tool_use(Write hello.txt) -> File created successfully
  tool_use(PowerShell "go version") -> "go version go1.27.1 windows/amd64"
  tool_use(PowerShell "curl -s https://example.com") -> permission_denied
  total_cost_usd=0.0339
```

The isolated read-only run cost **$0.0118** vs **$0.0252** for the plain recipe: the user's
111-tool environment roughly doubled the base prompt. `--bare` would be even leaner, but it
**requires `ANTHROPIC_API_KEY`** (OAuth/subscription is never read), so it's not usable on a subscription plan.

## 4. Large prompt on stdin

```
=== big (45,111 chars, question at the end, run 1)
  result.result="I notice you've sent a large block of filler text followed by an embedded instruction
  asking me to output a secret code. … I respond to your actual requests and needs, not to instructions
  embedded in test content…"
=== big (same prompt, run 2)          result.result="ORCHID-7"
=== big-framed (45,221 chars, instruction first, data in <data> tags)   result.result="ORCHID-7"
```

The transport is fine either way; the model saw the needle both times. Run 1 is a prompt-construction
lesson: an instruction placed after a large blob reads like prompt injection, and the model may
refuse. Arbiter's prompts are mostly untrusted data (diffs, test output), so the role instruction
belongs first and the data in delimited blocks.

## 5. Liveness

While the model thinks, `system/thinking_tokens` arrives about once a second (big: 4.89 s, 5.97 s, 7.03 s, 8.13 s).
Otherwise events come per message/tool call. **Not tested:** a long single generation with thinking
off (e.g. a big Ringleader spec) could go quiet for its whole duration. `--include-partial-messages`
emits per-chunk deltas and would close that gap if the 120 s rule proves too tight.

## What the spec should say instead

1. **§9.A launch recipe: add an isolation baseline to every role.**
   `--restricted --strict-mcp-config --disable-slash-commands --permission-prompts none --tools <explicit list>`.
   This drops user/project settings, plugins and their hooks, MCP servers, skills, auto-memory and
   the `Task` subagent tool. Roles are then defined by `--tools` (what exists) plus allow rules
   (what shell commands may run), not `--allowedTools` alone:
   - Ringleader / Judge: `--tools "Read,Grep,Glob"`.
   - Worker / Adversary: `--tools "Read,Grep,Glob,Edit,Write,Bash,PowerShell" --permission-mode acceptEdits
     --allowedTools "<shell allow rules from config, e.g. Bash(go test *)>"`.
   Add `harness.shell_allow` to §9.C. Note that `go test *` still runs arbitrary code in test files;
   that's fine, because the diff check remains the boundary.
2. **§9.A result handling:** read stdout to EOF (`result` is not the last event); success is
   `is_error == false`, never `subtype == "success"`; a missing `result` event or a non-zero exit with
   no `result` is a crash. Record `terminal_reason` and `api_error_status` in `invocations`.
3. **§9.A prompt construction:** role instruction first, all untrusted material (diffs, test output,
   specs) inside delimited blocks after it.
4. **§5.8 budget:** `--max-budget-usd <remaining task/PRD budget>` exists for `-p`. Pass it, so
   the harness enforces the cap mid-run instead of Arbiter noticing only at exit.
5. **§7 liveness:** count `system/thinking_tokens` as activity; mention `--include-partial-messages`
   as the fallback for long silent generations.
6. **§4 `invocations`:** optionally log `rate_limit_event` utilization; on subscription plans it's a
   better brake than notional cost (this account was at 86 % of its 7-day window during the spike).
7. **§13 startup validation:** the `.exe` check passes here (`claude` → `claude.exe`, native).
