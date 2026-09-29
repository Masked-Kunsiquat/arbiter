Viewed spec.md:1-412

Here is a rigorous architectural teardown of `spec.md`. 

You’ve built an ambitious design that aims to take:
1. **The Visual/DAG Task Engine** (decoupling monolithic goals into verified, parallelizable sub-graphs),
2. **The Terminal-Native Git Pairing Engine** (tight worktree management, AST-aware diffs, test-driven feedback loops), and
3. **The Self-Distilling Epistemic Memory Layer** (dynamic extraction, outcome verification, and hierarchical rule promotion without context bloat).

The architectural ambition is great, but `spec.md` currently has several **critical operational traps, missing schema primitives, security theater assumptions, and OS portability bugs**.

Here is the grill.

---

### 1. The Coordination & DAG Problem
*You want parallel subtask execution without prompt-level chaos, but the execution model has structural bottlenecks.*

* **Where is the DAG actually stored?**
  In Section 4.A (`state.db`), your `tasks` table (lines 140–159) has `id`, `prd_id`, `status`, etc., but **zero relational fields for task dependencies** (no `parent_task_id`, `depends_on`, or `task_edges` table). If the Ringleader compiles a DAG, how does the daemon topologically sort it, resolve blockers, or identify independent tasks ready for parallel dispatch?
* **Cascading DAG Invalidation**:
  Software tasks are rarely decoupled waterfalls. If Task 1 (Database Migration) finishes, but during implementation changes an index name or column type that downstream Task 3 (Repository Queries) relied on, Task 3's locked spec is immediately out of sync. Since child workers have "Zero Unilateral Drift" and cannot alter contracts, does downstream failure force a full PRD halt and human SSH re-signing? How does a DAG react to intermediate API contract revisions without human fatigue?
* **File Reservations & Concurrency Deadlocks**:
  Your `file_reservations` table (line 162) locks by `file_path`.
  * What prevents classical circular deadlocks (Task A holds file 1, waits for file 2; Task B holds file 2, waits for file 1)?
  * Are reservations static and declared upfront during Ringleader decomposition, or acquired dynamically? If static, LLMs are notoriously bad at predicting every file they'll touch (e.g., realizing they need an extra shared type or utility). If dynamic, how do you handle lock acquisition rejections mid-flight?

---

### 2. The Isolation & Pair-Programming Feedback Loop
*You want isolated worktree execution with test-driven gates, but the testing gate has a fatal assumption.*

* **Who tests the Adversary's Attack Tests?**
  Section 5.3 states:
  > *"Attack test fails $\rightarrow$ Defect mathematically proven. Bounces task back to Worker."*
  
  This is a dangerous trap. LLM-generated tests fail **all the time** for bogus reasons: bad import syntax, hallucinated APIs, mocking nonexistent modules, or testing unpromised invariants. If the Adversary writes a broken test that fails with `SyntaxError` or an import crash, your daemon interprets that as a "mathematically proven defect" and forces the Worker into a 3-retry death spiral. What validates that an adversarial test failure is an application defect and not an adversarial hallucination?
* **The Cost of Git Worktree Hygiene**:
  A single-process pair programmer is fast because it works in-place. If Arbiter spins up separate worktrees for 4 concurrent tasks, what happens in heavy runtimes? In Node, Rust, or Go, a clean worktree means either running `npm install`/`cargo build` (eating 5 minutes and gigabytes of disk per task) or managing complex symlinks (`node_modules`, `target/`, `.venv`). How does Arbiter handle build artifact caching and dependency isolation across sibling worktrees?
* **Semantic Merge Conflicts & Tree-sitter Blast Radius**:
  The Judge auto-merges low-risk tasks to the feature branch. But if Task A and Task B run in parallel in separate worktrees without touching the exact same files (no file lock collision), Task A might change a function signature in `src/auth/utils.ts` that Task B calls in `src/auth/session.ts`. Both pass their isolated tests. When both auto-merge into `feature/auth-rotation`, the feature branch is broken. Does the Judge re-test the integrated feature branch against the full suite upon merge?

---

### 3. The Epistemic Memory & Distillation Problem
*You want self-improving memory that prevents repeating past mistakes, but your ledger has an attribution and human bottleneck.*

* **The Missing Formula & Attribution Problem**:
  In Section 6 (lines 322–324), you introduce the Utility Formula ($U$), but **the formula itself is literally blank in the markdown**. Furthermore:
  * Section 3 states: *Catches (+), Misses (-1.5), Contradictions (-3.0)*.
  * **Who logs a `miss`?** If an agent writes code with a bug that slips past the Adversary and hits production two weeks later, who attributes that miss to `LESSON-12`? If attributing misses requires developers to run `arbiter lesson outcome LESSON-12 --miss`, developers will simply stop doing it.
* **Context Injection Dilution**:
  Project lessons are triggered by `file_pattern` (e.g., `src/db/**/*.ts`). Over a 6-month project, you might have 60 active lessons matching `src/**/*.ts`.
  * Do all 60 get injected into every Worker's system prompt?
  * How do you handle contradictory active lessons that both match the same file pattern?
* **Stack Trace Semantic Clustering**:
  Gate 1 triggers when the Synthesizer clusters autopsies with embedding similarity $> 0.82$. But embedding models (like `bge-small`) struggle with raw stack traces and crash logs: virtually all TypeScript `TypeError: Cannot read properties of undefined` or Python `KeyError` look semantically identical in vector space, even if the root causes are completely unrelated. How are you sanitizing traces before embedding so you don't cluster false positives?

---

### 4. Security & Runtime Reality Check
*The spec has cryptographic elegance, but some parts are local security theater, and others won't boot on Windows.*

* **The OS Portability Hole**:
  Section 7 (lines 340–342) specifies:
  > *"Every sub-process is spawned with a dedicated Process Group (-PGID)... kill -TERM -<PGID> followed by kill -KILL -<PGID>... On Linux hosts, sub-processes configure PR_SET_PDEATHSIG..."*
  
  **Windows does not have Unix Process Groups, does not support negative PIDs for `kill`, and has no `PR_SET_PDEATHSIG`.**
  On Windows, you must use **Windows Job Objects** via Win32 APIs (`CreateJobObject`, `AssignProcessToJobObject`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`). If Arbiter is a single static Go/TypeScript binary running locally on Windows, this entire process-cleanup architecture will fail unless native Win32 Job Object handling is explicitly designed.
* **Local Ed25519 Keys: Threat Model vs. Security Theater**:
  Section 8 details ephemeral Ed25519 keypairs generated in RAM with 15-minute capability leases to sign Git commits and attestations.
  * *What is the actual threat model here?* Everything runs locally under the same OS user. The daemon holds the private key in memory and acts as a local signing proxy over IPC.
  * If a Worker suffers prompt injection, it controls the commands sent to the signing proxy during its 15-minute lease. The signature proves which ephemeral key signed it, but it does *not* prove the code is uncorrupted.
  * Isn't local cryptographic signing just adding IPC overhead and state complexity without providing true sandboxing (e.g., containerization or seccomp/seatbelt)?
* **Human SSH Key Fatigue**:
  Requiring a human SSH signature (`~/.ssh/id_ed25519`) for:
  1. Every PRD lock,
  2. Every PRD amendment,
  3. Every root merge, and
  4. Every Org Lesson promotion.
  If a developer uses a YubiKey or password-protected SSH key, they could be prompted for their passphrase 15–20 times across a couple of features. How do you prevent developer friction from turning into `ssh-agent` approval fatigue?

---

### Summary Challenge

If you want this engine to truly supersede its inspirations, you need answers to these core operational questions:

1. **Graph Layer**: How are DAG edges persisted in SQLite, and how do you handle dynamic replanning when a parent task changes an interface?
2. **Testing Layer**: How do you verify the Adversary's tests before punishing the Worker?
3. **Memory Layer**: What is the mathematical formulation of $U$, and how are misses attributed without manual accounting burden?
4. **Runtime Layer**: How do you bridge the Windows Job Object vs. POSIX PGID gap for true local-first isolation?

Which of these four cracks do you want to tackle first?