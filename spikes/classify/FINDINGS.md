# Spike 3: classifying attack tests from `go test -json` (§5.4)

Environment: Go 1.27.1 on Windows, testify v1.12.1. Scratch module: `scratch/` (one package per
case, because in Go one compile error or panic takes down the whole package). Classifier: `main.go`
(`go run . scratch`). Full run: `go test -json -count=1 -timeout 5s ./...`; reruns add
`-run '^Name$'` on the one package.

## Result

```
appcompile      TestAttack_AC_1_RefreshReturnsNew             ASSERTION_FAIL  build failure in application code: appcompile/appcompile.go; reproduced on isolated rerun
apppanic        TestAttack_INVARIANT_3_MalformedTokenCrashes  ASSERTION_FAIL  panic thrown in application code at app/app.go; reproduced on isolated rerun
apppanic        TestAttack_INVARIANT_3_ZPassingSibling        PASS            never ran in the full run (a sibling killed the test binary); isolated run:
assertfail      TestAttack_AC_2_AddNegative                   ASSERTION_FAIL  assertion failure (testify); reproduced on isolated rerun
assertfail      TestAttack_AC_2_RequireNegative               ASSERTION_FAIL  assertion failure (testify); reproduced on isolated rerun
assertfail      TestAttack_AC_2_StdlibFatal                   ASSERTION_FAIL  assertion failure (t.Error/t.Fatal); reproduced on isolated rerun
flaky           TestAttack_INVARIANT_4_Flaky                  ERROR           flaky: assertion failure (testify); passed on isolated rerun
goroutinepanic  TestAttack_INVARIANT_7_BackgroundCrash        ASSERTION_FAIL  panic (binary crashed, no test fail event) thrown in application code at app/app.go; reproduced on isolated rerun
helperpanic     TestAttack_INVARIANT_6_UsesHelper             ERROR           panic thrown in test code at helperpanic/helpers_test.go
notarget        TestAttackRandomThing                         ERROR           no INVARIANT/AC target in test name
redeclare       TestAttack_INVARIANT_8_Collides               ERROR           build/vet failure in test code: redeclare/redeclare_adversary_test.go
testcompile     TestAttack_INVARIANT_1_HallucinatedAPI        ERROR           build/vet failure in test code: testcompile/testcompile_adversary_test.go
testpanic       TestAttack_INVARIANT_2_NilInTestBody          ERROR           panic thrown in test code at testpanic/testpanic_adversary_test.go
testpanic       TestAttack_INVARIANT_2_ZPassingSibling        PASS            never ran in the full run (a sibling killed the test binary); isolated run:
timeout         TestAttack_AC_3_Hangs                         ERROR           timeout
timeout         TestAttack_AC_3_ZPassingSibling               PASS            never ran in the full run (a sibling killed the test binary); isolated run:
vetfail         TestAttack_INVARIANT_5_VetBroken              ERROR           build/vet failure in test code: vetfail/vetfail_adversary_test.go
```

| Case (requested + extras) | Classified | Right? | What it took |
|---|---|---|---|
| Compile error in test file (hallucinated `app.RevokeFamily`) | ERROR | ✅ | build-output parsing; no test events exist |
| Compile error in application code | ASSERTION_FAIL | ⚠️ matches rule 4, but wrong in substance | no attack ran, so there's nothing for the claim check to check |
| Nil-pointer panic in the test body | ERROR | ✅ | top in-repo stack frame |
| Panic in application code | ASSERTION_FAIL | ✅ | top in-repo stack frame + rerun |
| testify `assert` / `require` failure | ASSERTION_FAIL | ✅ | `Error Trace:` marker |
| stdlib `t.Fatalf` failure | ASSERTION_FAIL | ✅ | `OutputType:"error"` |
| Timeout | ERROR | ✅ | output text match; **no test-level fail event** |
| Flaky | ERROR (flaky) | ✅ | isolated rerun |
| *extra:* `go vet` failure in the attack file | ERROR | ✅ | arrives as build-output, same shape as a compile error |
| *extra:* panic in a non-adversary `_test.go` helper | ERROR | ✅ per rule 3 | that helper may be worker-written |
| *extra:* panic on an application goroutine | ASSERTION_FAIL | ✅ | **no test-level fail event**, so it's inferred from "ran + package failed" |
| *extra:* adversary redeclares an app function | ERROR | ✅ only because tab-indented "other declaration" lines are ignored | see trap below |
| *extra:* no target in the name | ERROR | ✅ | regex |
| *extra:* passing sibling after a panic/timeout | PASS | ✅ only because of the rerun | **never ran** in the full run: no events at all |

## What `go test -json` gives you, and what it doesn't

**Build failures are not test events.** Real output:

```json
{"ImportPath":"scratch/testcompile [scratch/testcompile.test]","Action":"build-output","Output":"# scratch/testcompile [scratch/testcompile.test]\n"}
{"ImportPath":"scratch/testcompile [scratch/testcompile.test]","Action":"build-output","Output":"testcompile\\testcompile_adversary_test.go:10:9: undefined: app.RevokeFamily\n"}
{"ImportPath":"scratch/testcompile [scratch/testcompile.test]","Action":"build-fail"}
{"Action":"output","Package":"scratch/testcompile","Output":"FAIL\tscratch/testcompile [build failed]\n","OutputType":"frame"}
{"Action":"fail","Package":"scratch/testcompile","Elapsed":0,"FailedBuild":"scratch/testcompile [scratch/testcompile.test]"}
```

- Keyed by `ImportPath` (`"pkg [pkg.test]"`), not `Package`. The package `fail` event carries `FailedBuild`.
- **No test ids at all.** `go test -list` fails the same way. The unit you can classify is the
  *file* (and so every attack in the package), not the test.
- `go vet` failures (on by default in `go test`) come through the same channel:
  `"# [scratch/vetfail]"` then `vetfail\\vetfail_adversary_test.go:9:21: fmt.Sprintf format %d has arg …`.
- Paths are **cwd-relative with OS separators** (`testcompile\\…`).

**Trap in rule 1 ("errors also in application files").** A same-package name collision reports:

```
redeclare\\redeclare_adversary_test.go:6:6: Normalize redeclared in this block
\tredeclare\\redeclare.go:3:6: other declaration of Normalize
```

Only the first line is an error; the tab-indented line is a note pointing at app code. Counting it
would route a broken attack file to the worker. Only unindented `file:line:col:` lines count.

**Panics.** The test's output contains the stack, with absolute forward-slash paths:

```
panic: runtime error: invalid memory address or nil pointer dereference [recovered, repanicked]
[signal 0xc0000005 code=0x0 addr=0x0 pc=0x7ff603387603]
…
panic({0x7ff6034fe850?, 0x7ff603536320?})
	~/sdk/go1.27.1/src/runtime/panic.go:…
scratch/app.Subject(...)
	…/arbiter/spikes/classify/scratch/app/app.go:18
scratch/apppanic.TestAttack_INVARIANT_3_MalformedTokenCrashes(0x29b1a306a400?)
	C:/…/scratch/apppanic/apppanic_adversary_test.go:11 +0x…
```

"Top in-repo frame" = first `\t<file>:<line>` not under GOROOT or `pkg/mod`. That works as long as
paths are absolute; under `-trimpath` they become `scratch/app/app.go` and need a module-path mapping.

**A panic or timeout kills the whole test binary.** Every later test in that package never runs
and produces **no events**. Here: `testpanic`, `apppanic` and `timeout` each hid a passing sibling.
One bad attack blinds every attack after it in the same package.

**Goroutine panics and timeouts have no test-level `fail` event:**

```json
{"Action":"run","Package":"scratch/goroutinepanic","Test":"TestAttack_INVARIANT_7_BackgroundCrash"}
{"Action":"output",…,"Test":"TestAttack_INVARIANT_7_BackgroundCrash","Output":"panic: assignment to entry in nil map\n"}
{"Action":"output",…,"Test":"TestAttack_INVARIANT_7_BackgroundCrash","Output":"scratch/app.Background.func1()\n"}
{"Action":"fail","Package":"scratch/goroutinepanic","Elapsed":0.443}          <- package only

{"Action":"output","Package":"scratch/timeout","Test":"TestAttack_AC_3_Hangs","Output":"panic: test timed out after 5s\n"}
{"Action":"fail","Package":"scratch/timeout","Elapsed":5.442}                  <- package only
```

The output is attributed to "whichever test was running". With `t.Parallel()` that could be any of
several tests (not tested). `-timeout` is per package binary, not per test.

**Which tests are attacks?** `-json` events carry no file name, so the adversary path glob can't be
applied to a test id. The spike parses `*_adversary_test.go` with `go/parser` (stdlib, no cgo) to
list the `Test*` funcs per package. That list is also what reveals tests that never ran.

**Assertion markers:** testify prints `Error Trace:` / `Error:` lines; stdlib `t.Error`/`t.Fatal`
lines carry `"OutputType":"error"` (new in recent Go), and continuation lines carry `"error-continue"`.

## What the spec should say instead (§5.4, §5.3, §9.C)

1. **Build the worker's code before the adversary runs.** Add to step 3 (after the diff check):
   `go build ./... && go vet ./...` plus compiling tests without running them
   (`go test -run '^$' ./...`). A failure is a deterministic worker rejection (it counts as an
   attempt, with no claim check). Then drop "or a build failure located in application code" from
   rule 4: once app code is known to build, any attack-run build failure belongs to the attack
   files. (Otherwise that case becomes an ASSERTION_FAIL with no attack for the Judge to rule on.)
2. **Rule 1 wording:** "compiler/vet errors" means primary error lines only, not indented notes.
   Build failures are classified per **file**. Every attack in an affected package gets the same
   ERROR, and "dropped after 2 regenerations" drops files, not tests.
3. **Run attacks per test, not per package.** A panic or timeout in one attack hides its siblings.
   Build each package's test binary once (`go test -c -o <pkg>.test`), then run it per attack
   (`<pkg>.test -test.run '^Name$' -test.timeout <per-attack> -test.v=test2json | go tool test2json -p <pkg>`).
   That gives per-test timeouts, no collateral, and one compile per package. Rule 5's rerun becomes
   the same command. Verified on Windows (cwd must be the package dir, as `go test` does):

   ```
   --- TestAttack_AC_3_Hangs            (-test.timeout 2s)
   {'Action': 'start', 'Package': 'scratch/timeout'}
   {'Action': 'run', …, 'Test': 'TestAttack_AC_3_Hangs'}
   {'Action': 'output', …, 'Test': 'TestAttack_AC_3_Hangs', 'Output': 'panic: test timed out after 2s\n'}
                                        <- no test OR package terminal event: use the exit code
   --- TestAttack_AC_3_ZPassingSibling
   {'Action': 'run', …}  {'Action': 'pass', …, 'Test': 'TestAttack_AC_3_ZPassingSibling'}  {'Action': 'pass', 'Package': 'scratch/timeout'}
   ```
4. **Attack discovery for go-json:** attack tests are the `Test*` funcs declared in files matching
   the adversary pattern, found by parsing the source (`go/parser`). The runner report supplies
   results, not the list (for build failures it supplies neither).
5. **A crash with no test result counts as a result:** "ran, no pass/fail, binary failed" is a
   crash of that test. Classify by the panic's top frame (goroutine panics land here), or timeout.
6. **Rule 3 edge:** a panic in a non-adversary `_test.go` helper counts against the Adversary even if
   the worker wrote the helper. Acceptable, but say so. The claim check won't see it, because it's an ERROR.
7. **Rule 5 caveat:** an isolated rerun that passes may be an *order-dependent* real defect
   (shared global state), not flakiness. With per-test runs (item 3) there is no order to depend
   on, so the original run and the rerun are the same experiment and the ambiguity goes away.
8. **Always `-count=1`** for attack and gate runs. The Go test cache would otherwise replay a
   cached PASS without executing, even after the unseen-state check reinstalled dependencies.
9. **Path normalization** belongs in the §6.D normalizer: compiler paths are cwd-relative with `\`;
   stack paths are absolute with `/` (or module paths with `-trimpath`); compare case-insensitively on Windows.
