# rsansible — project conventions

This file captures rsansible-specific conventions that should outlive
any one session. If you're a future Claude session: read this before
touching code that crosses the controller/agent boundary or adds
user-facing names.

## Companion docs

- **`ANSIBLE_COMPAT.md`** — the canonical list of every place
  rsansible's behavior **differs** from Ansible's given identical
  input. Reach for this when a playbook ported from Ansible
  misbehaves under rsansible — the entry will tell you whether the
  difference is deliberate and what the rsansible-side semantics
  are. **Every deliberate divergence MUST be recorded there in the
  same commit that introduces it.** See the rule at the bottom of
  this file.

- **`RSANSIBLE_IDIOMS.md`** — the list of places where rsansible
  offers a **canonical spelling** alongside a thin compat shim that
  keeps the Ansible spelling working. Behavior matches Ansible (the
  shim makes it so), but new playbooks should reach for the
  canonical form. Reach for this when authoring fresh, or when
  you're about to add a second "god function with a string-dispatch
  selector" and need to remember to split it into canonical +
  shim. The two docs are mutually exclusive: if a shim makes
  behavior match, it goes in `RSANSIBLE_IDIOMS.md`; if behavior
  genuinely differs, it goes in `ANSIBLE_COMPAT.md`.

## Naming: `controller_` / `target_` prefix for side-aware operations

Any operation whose *location of execution* is a meaningful part of
its contract MUST be prefixed with either `controller_` or `target_`.

- **`controller_*`** — runs on the machine invoking `rsansible`
  (Bart's laptop, CI runner, whatever). This is the side that has the
  playbook source tree, the inventory, the user's SSH agent, the
  user's secret-manager, etc. Reading a file here means reading the
  playbook author's local filesystem.

- **`target_*`** — runs on the remote host being managed, inside the
  pushed musl agent. Reading a file here means reading the managed
  host's filesystem (post-SSH, post-`become:`).

Examples (current and prospective):

| Where it runs | Canonical name | Notes |
|---|---|---|
| Controller | `controller_read_file(path)` | Replacement for `lookup('file', ...)`. |
| Controller | `controller_shell_stdout(cmd)` | Replacement for `lookup('pipe', ...)`. |
| Controller | `controller_env(name)` | Replacement for `lookup('env', ...)`. |
| Target | `target_read_file(path)` | When/if we add it. |
| Target | `target_shell_stdout(cmd)` | When/if we add it; same idea as agent-side `shell:` but used for templating. |

### Why the prefix is non-negotiable

The whole class of confusing Ansible bugs in this area — `lookup('file',
'/etc/foo')` silently reading from the controller when the author meant
the target — exists *because* the language has no location marker.
A prefix at the call site means the answer is in the source, not in
the docs.

### Why this specific prefix pair

- `host_` is ambiguous (which side is "the host"?). Ansible's own
  vocabulary makes it mean the target, but plain English doesn't.
- `client_` is wrong for our architecture (the SSH client is the
  controller, but "client" elsewhere often means "the thing being
  managed").
- `controller_` is the term Ansible's own docs already use for "the
  machine running the playbook." We borrow the term without borrowing
  the bad design.
- `target_` matches our own internal vocabulary throughout the
  codebase ("target host", "target filesystem"). It's already what we
  call it.
- The pair is symmetric: same verb, one word changes, and the word
  that changes is the one that matters.

## Controller-side I/O: cache only when it's safe to

Per-run memoization is on the `Environment` (one per `run()`), keyed
by call args, dies when the run ends. But **not every `controller_*`
function caches** — the rule is per-function and depends on whether
caching would change observable semantics.

| Function | Cache? | Why |
|---|---|---|
| `controller_read_file` | yes | Files referenced from a playbook are inputs to the run, not state that mutates during the run. The "snapshot at first read" mental model is what users have. |
| `controller_env` | yes | Process env is stable mid-run absent something pathological. |
| `controller_shell_stdout` | **no** | Commands can be intentionally non-deterministic (`uuidgen`, `date +%s%N`, `openssl rand`, `mktemp`). Caching silently breaks those use cases. Match Ansible — let users hoist into `set_fact:` if they want one-shot. |

The asymmetry is the point. Don't reach for "cache everything for
consistency" — the cost of silently caching a deliberately
non-deterministic call is much higher than the cost of an extra fs
read.

Rules:

- Cache only successful results. Errors re-run — caching a stale
  error is more confusing than the redundant work.
- Cache per-`Environment` (i.e. per `run()`), never globally. The
  `Arc<Mutex<HashMap>>` gets cloned into each minijinja function
  closure at `make_env` time.
- When adding a new `controller_*` function, decide up front whether
  the operation is "stable input to the run" (cache) or "potentially
  fresh each call" (don't). Add a `CacheKey` variant only if you're
  caching. Document the choice and the rationale in the function's
  doc comment.
- Tests for caching behavior must observe a side effect — read a
  file before/after mutation, or count append-only writes. Tests
  for non-caching must do the same in reverse (e.g. counter
  command must produce `1-2-3` across three calls, not `1-1-1`).

For caching choices: the file-read and env-var caches are
intentional divergence from Ansible (Ansible's `lookup` plugins
don't cache). The semantics rsansible users want from a file or env
lookup is "what is the value at the start of this run," not "what
is the value at this exact render moment." Shell pipe matches
Ansible exactly (no cache) because non-determinism is a feature
there.

## Ansible-compat layer: thin shims, never god functions

Where Ansible exposes one symbol with dispatch-by-string (the
canonical example being `lookup(name, ...)`), rsansible follows a
two-layer pattern:

1. **N small, single-purpose canonical functions** carry the actual
   behavior. Each has its own real signature, its own error messages,
   its own tests. These are what playbooks authored fresh against
   rsansible reach for.

2. **A thin compatibility shim** with the Ansible spelling matches
   the plugin name and forwards to the canonical function. The shim
   is pure translation — no business logic. Unknown plugin names
   error loudly at render time with the supported-plugin list, not
   silently undefined.

Concretely for `lookup`:

```rust
// canonical, one per behavior:
fn controller_read_file(path: &str) -> Result<String> { ... }
fn controller_shell_stdout(cmd: &str) -> Result<String> { ... }

// compat shim, registered as the global `lookup`:
fn lookup_shim(plugin: &str, args: &[MjValue]) -> Result<MjValue> {
    match plugin {
        "file" => controller_read_file(args[0].as_str()?),
        "pipe" => controller_shell_stdout(args[0].as_str()?),
        other  => err!("lookup: unknown plugin {other:?}, \
                        supported: file, pipe, env"),
    }
}
```

Same logic applies if/when we mirror other Ansible god functions
(`query`, future plugin dispatchers): canonical names are the source
of truth, Ansible spelling is the compat layer.

## Documenting Ansible divergences

rsansible is "run real Ansible playbooks with minimal fuss" by
default, so matching Ansible's behavior is the baseline assumption
everywhere. That makes deliberate divergence the interesting case —
and the case future sessions will most often get wrong if it isn't
written down.

**The rule:** every place rsansible deliberately differs from Ansible
in user-visible behavior gets an entry in `ANSIBLE_COMPAT.md` in the
**same commit** that introduces the difference. If you find yourself
thinking "the Ansible way is silly here, I'll do X instead" — stop,
write the entry, then commit code + doc together.

What counts as a deliberate divergence:

- A playbook author would observe a difference (different result,
  different error, different validation outcome) for the same input.
- The difference is on purpose, not an unimplemented-yet gap.
- The decision was discussed and a direction chosen.

What does NOT go in `ANSIBLE_COMPAT.md`:

- Internal naming conventions (those go here, in CLAUDE.md).
- "Will match Ansible once we implement X" — that's a TODO.
- Performance differences with identical user-visible behavior.
- **Canonical-vs-compat-shim pairs where behavior matches.** A
  preferred rsansible spelling that has a thin compat shim
  forwarding to it (so the Ansible spelling still works) is not a
  divergence — it's an idiom preference. Those go in
  `RSANSIBLE_IDIOMS.md` instead. The litmus test: if a playbook
  using the Ansible spelling produces identical observable results,
  it's an idiom, not a divergence.

When you add a divergence: the function's own doc comment should
say `see ANSIBLE_COMPAT.md §N` so a developer reading the code
knows the choice was deliberate and where to find the rationale.
For canonical/shim pairs, the canonical function's doc comment
should say `see RSANSIBLE_IDIOMS.md §N` for the same reason.

## Recursive task lists: the executor pattern for grouped ops

`block:` / `rescue:` / `always:` introduced the first task-op whose
body contains *other tasks*. The pattern it established applies to
every future "ops that group tasks" feature — `include_tasks:` with
conditional logic, `import_tasks:` if it ever needs runtime
behavior, anything else that recurses.

The rules:

1. **The task list is recursive at the type level**, not flattened
   at load time. `TaskBody::Block(BlockSpec)` carries
   `Vec<Task>` for each arm; the executor walks them on the fly. We
   considered flattening into a synthetic linear sequence with
   marker tasks ("BlockStart"/"BlockEnd") and rejected it — it
   makes per-host state (registers, `ansible_failed_*`, loop scope)
   much harder to reason about than just recursing.

2. **Inheritance is a load-time push-down pass**, mirroring
   `inherit_become_defaults`. By the time the executor sees inner
   tasks they already carry the merged metadata (`when:`, `become:`,
   `tags:`, `ignore_errors:`, `check_mode:`, `delegate_to:`).
   `when:` joins with `({parent}) and ({child})`; `tags:` is union;
   everything else is "child's explicit Some wins, else parent's."
   See `inherit_block_metadata` in
   `crates/ctl/src/playbook/mod.rs`.

3. **The executor exposes two layered helpers**:
   - `run_task_list_on_host(tasks, ...) -> TaskListResult` walks
     a `&[Task]` sequentially on one host, stops at first failure,
     returns `(failed_task_name, reason, register_snapshot)` plus
     the mutated `HostCtx`.
   - `run_task_on_one_host(task, ...)` dispatches a single task,
     including `TaskBody::Block` which `Box::pin`s into
     `run_block_on_one_host`. The recursion goes
     `run_task_on_one_host` → `run_block_on_one_host` →
     `run_task_list_on_host` → `run_task_on_one_host`, so async
     recursion requires `Box::pin` at the dispatch point.

4. **Per-host state survives the recursion**. `HostCtx` flows in
   and out of every level; registers set inside a block are visible
   after it, `ansible_failed_*` is set on rescue entry and cleared
   on exit (and nested blocks save/restore around their own rescue
   so the outer block's failed-task info is preserved).

5. **`HostTaskOutcome::Failed` carries `register: Option<RegisterValue>`**
   so the failing task's register-shape result can flow up to
   wherever `ansible_failed_result` needs to be populated. Don't
   strip this — future ops with retry/recovery semantics will need
   it too.

6. **Per-strategy integration is transparent**. Both
   `run_play_per_task` and `run_play_per_play` call
   `run_task_on_one_host` per top-level task and per host — they
   don't need to know a block recurses internally. The recursion
   happens behind `Box::pin`, so the strategy code stays flat.

7. **Reject what we can't model yet at parse time, loudly.**
   `retries:` / `until:` / `delay:` on a block, `register:` and
   `notify:` on a block, `run_once:` on a block — all rejected
   in `Task::deserialize` with a message that points to the
   inner-task workaround. Better a clear parse error than a
   silently-wrong semantic. Future ops should inherit this
   discipline.

## `run_once:` on tasks nested inside a `block:`

`run_once: true` is honored at *any* depth in the task tree — including
on tasks inside `block:` / `rescue:` / `always:`. Implementation pattern:

1. **Pre-walk the task tree once** at strategy entry and allocate a
   shared `RunOnceCoord`: a pre-order DFS visits every task in the
   subtree, assigning slot `i` to the `i`th visited task. Coord
   carries one `Arc<OnceCell<RunOnceResult>>` per slot plus a
   `subtree_sizes[i]` field (size of the subtree rooted at slot `i`,
   inclusive). Per-strategy allocation point:
   - **`per_play`** → one coord covering all of `play.tasks` at play
     start, shared across every per-host walker (line ~1147 of
     `orchestrator.rs`, `RunOnceCoord::allocate(&play.tasks)`).
   - **`per_task` fanout** → one coord per fanned-out task at the
     spawn site (sized to `count_tasks_in_tree(&[task.clone()])`).
     Cheap (typical playbook tasks are leaves; only block-tasks
     produce a non-trivial subtree).

2. **Per-host walkers each carry a local `slot_counter: u32`**. They
   walk the task tree in the same pre-order as the coord allocation,
   incrementing the counter as they visit each task. Two walkers
   that visit the same task therefore see the same slot index. The
   coord is `Arc<...>` shared; the counter is per-host.

3. **`dispatch_one_task` is the SOLE entry point** for dispatching a
   task that owns a coord slot. It increments the counter past the
   task's own slot **before** calling `run_task_on_one_host`, so that
   when a block recurses internally the inner walker starts at the
   first inner slot (not the block's own slot). The body of
   `run_task_on_one_host` does NOT touch the counter — only
   `dispatch_one_task` does. **Every call site that dispatches a
   task at the entry of a recursion (per_task fanout, test drive
   helpers, future strategy implementations) MUST go through
   `dispatch_one_task`, never `run_task_on_one_host` directly.**
   Calling `run_task_on_one_host` with a fresh `slot_counter=0` on a
   block task means the inner walker treats slot 0 as the first
   inner task — exactly the wrong cell. (gather_facts /
   `run_task_once_per_task` / handler dispatch are exceptions: their
   tasks are always leaves with no inner subtree to recurse into.
   They take the empty-coord path and the counter is unused.)

4. **Runner identity is per-host, picked at spawn time.** `is_runner
   = (host_name == live_hosts[0])` — the first live host in the
   target set. Same host is the runner for every `run_once` task it
   encounters during its walk; non-runners await each cell in turn
   and apply the broadcast (`register` / `set_facts` / `notify`)
   without re-executing the body.

5. **The counter MUST stay synchronized across hosts.** The trap is
   tasks that short-circuit (`when: false`, `vars:`/`when:`/render
   error, loop-spec error) — they return from `run_task_on_one_host`
   without recursing into a block subtree, so the counter only
   advances by 1 (the task itself) rather than by `subtree_size`.
   Hosts that DID recurse fully would be ahead. The fix lives at
   the END of `dispatch_one_task`: `if *slot_counter < slot +
   subtree_size { *slot_counter = slot + subtree_size; }`. Belt
   and suspenders: `run_task_list_on_host` also advances the
   counter past any tasks it didn't visit due to early-exit on
   first-failure, using `coord.subtree_size(slot)` per skipped task.

6. **Looped blocks don't coordinate run_once internally.** A block
   with a `loop:` re-walks its arms on every iteration; the
   OnceCells filled on iteration 1 would deadlock iteration 2's
   non-runner hosts. For now `run_block_on_one_host` swaps to
   `RunOnceCoord::empty()` for the inner walks when `loop_spec` is
   set, so `run_once` on tasks inside a looped block silently falls
   back to "execute on every host every iteration." If a real
   playbook needs run_once inside a looped block, the right fix is
   per-iteration fresh OnceCells (allocate inside the loop body) —
   not yet implemented.

7. **`HostTaskOutcome` is broadcast verbatim to non-runners.** A
   non-runner reads the runner's `outcome` from the cell and uses
   it as its own outcome. If the runner's body failed, every
   non-runner reports Failed too, and the block-rescue arm fires
   symmetrically on all hosts. That's the right semantics: a
   `run_once` failure isn't "a failure on one host" — it's a
   failure of the only attempt that was supposed to happen, so
   every host that depended on it is in the same broken state.

## Retry loop: `retries:` / `until:` / `delay:`

`run_body_with_retries` in `orchestrator.rs` wraps every body-once
call inside `run_task_on_one_host` (both the single-shot path and
each loop iteration — retries are per-iteration, not per-loop, which
matches Ansible). The rules that proved non-obvious during
implementation:

1. **Ansible's `+1` semantic is sticky.** `retries: N` means N
   retries on top of the initial attempt → N+1 total attempts. Default
   when only `until:` is set: 4 total (3 retries). When neither is
   set: 1 attempt, no retry loop entered at all.

2. **`until:` controls termination, not classification.** A truthy
   `until` exits the retry loop even when the underlying body
   failed; an exhausted loop without `until` ever becoming truthy
   flags the task `Failed` even when the body succeeded on every
   attempt. The latter is the part everyone forgets — "if your
   `until:` never converges, the task failed by definition." Catch:
   we surface it as `"did not satisfy `until:` after N attempts"`
   on the BodyResult::Failed.

3. **The per-attempt register is recorded mid-loop on `HostCtx`** so
   `until:` can reference it as `{{ register_name.rc }}`. Each
   attempt overwrites; the natural single-shot record-after also
   runs, so the final value lands in `ctx.registers` correctly.
   Pair this with the parse-time rule that `until:` requires
   `register:` (ANSIBLE_COMPAT §4) — the divergence isn't accidental,
   it makes the rendering target self-documenting.

4. **`RegisterValue.attempts` is only surfaced when nonzero.**
   Single-attempt tasks (no retry semantics) keep `attempts: 0`
   which `to_json` hides — playbooks can safely guard with
   `{% if r.attempts is defined %}` or `{% if r.attempts > 1 %}`
   without false hits on tasks that didn't retry.

5. **`retries:` / `delay:` are int-or-Jinja-string at parse time.**
   Render-and-parse helpers (`render_int_field`, `render_float_field`)
   short-circuit literal numerics and only spin a template up when
   the source contains Jinja. Render errors bubble as a single
   `BodyResult::Failed` for the task — no attempts dispatch.

6. **Block tasks reject `retries:` / `until:` / `delay:` at parse
   time.** Users put them on inner tasks instead. Already enforced
   in `Task::deserialize`. The same applies to future grouped ops
   (`include_tasks:` etc.) — see the recursive-task-lists section
   above for the discipline.

7. **`failed_when:` is NOT yet implemented.** When it lands, the
   integration point is right after each `run_body_once` returns —
   apply `failed_when` to convert Ok→Failed (or leave alone),
   THEN run the `until:` check. Documented in
   `run_body_with_retries`'s doc comment.

## Agent-pool become routing: one process per `(host, become-config)`

`become:` is honored at the **transport** layer, not by wrapping argv
inside a single shared agent. Every host has an [`AgentPool`] keyed
by [`BecomeKey`], with slots lazily populated on first reference:

- `BecomeKey::None` — the agent spawned at connect time, running as
  the SSH user (or controller user, for `connection: local`).
- `BecomeKey::As(user)` — an agent process spawned under
  `sudo -n -u <user> -- <agent_path>` the first time a task with
  effective `become: true` hits this user on this host.

Once a task's `EffectiveBecome` is computed, its wire ops dispatch
against the matching pool slot — so `systemd`, `copy`, `file`,
`lineinfile`, … all run with the correct EUID by virtue of *which
agent process is on the other end of the pipe*. No per-op argv
wrapping, no double-sudo, no "this op happens to honor become and
this one silently doesn't."

### The rules

1. **`become_::effective` resolves precedence and renders
   `become_user`.** Task `become:` → inventory `ansible_become` →
   default `false`. `become_user` is rendered as a Jinja template
   against the per-host context — so `become_user: "{{ db_user }}"`
   works. This happens *before* the key is constructed; the pool
   never sees an unrendered Jinja expression.

2. **`BecomeKey` is `Hash + Eq + Ord` and used as the pool's map
   key.** Two tasks with the same effective become share a long-lived
   agent process; tasks with different keys get independent processes.

3. **One SSH session per host carries N channels** — one per pool
   slot. Channels are opened lazily via `spawn_agent_channel`.
   `connection: local` mirrors the pattern: one `LocalSession` per
   host, N `Command::spawn` children.

4. **Pool resolution is per-body-call inside `run_task_on_one_host`,
   not pre-hoisted at the dispatcher level.** Loop iterations
   re-resolve become per item, so `become_user: "{{ item }}"` routes
   each iteration to its matching slot. The `resolve_target!` macro
   in `run_task_on_one_host` does the lookup in three steps:
   compute `BecomeKey`, pick target pool (own or delegate_to'd),
   `get_or_spawn` on the pool to get the `ConnHandle`. The pool
   mutex is held only across `get_or_spawn` — released before the
   body dispatches.

5. **Pool growth is monotonic per run.** No eviction policy in v1.
   A host with three distinct become users peaks at 4 agents
   (None + 3); each is ~3.7 MiB. Acceptable for run-scoped pools;
   reopen the discussion if a long-lived multi-tenant controller
   emerges.

6. **`PoolTransport::Mock`** is the controller-only test pool. It
   vends a dead handle (`Arc<Mutex<None>>`) on every `get_or_spawn`,
   so unit tests for controller-side bodies (set_fact, fail, assert,
   debug, block dispatch) never need to construct a real agent.
   Tests that *should* dispatch a wire op surface "agent conn is
   dead" cleanly instead of needing fixtures.

### What `ANSIBLE_COMPAT.md §7` covers vs. what's here

- `ANSIBLE_COMPAT.md §7` documents the user-facing divergence
  (sudo-only `become_method`, NOPASSWD requirement, ignored
  `become_flags` / `become_exe`).
- This section documents the **internal pattern** — the type names,
  the lazy-spawn discipline, where in the dispatch flow resolution
  happens. Future work that adds a second pool dimension (e.g. an
  `--ask-become-pass` mode, a `become_method: doas` alt-transport)
  should slot in here without breaking the existing keys.

[`AgentPool`]: ./crates/ctl/src/pool.rs
[`BecomeKey`]: ./crates/ctl/src/become_.rs

## Every bug fix ships with a regression test

If you fix a bug, you write a test that **fails against the old code
and passes against the new code** in the same commit. No exceptions —
"the live drill passed" is not a substitute. The live exercise tells
us the symptom is gone today; the regression test is what keeps it
gone six months from now when someone refactors the area without
remembering the original failure mode.

The test has to actually exercise the broken codepath. Two ways
this goes wrong in practice:

1. **Testing the post-fix shape instead of the failure sequence.**
   The deadlock that motivated this rule was that
   `OnceCell::get_or_init(|| pending().await)` locked the cell so
   `cell.set(...)` from another task silently failed and the waiter
   hung forever. The existing tests pre-`set` the cell BEFORE the
   non-runner enters `get_or_init`, so they hit the "cell already
   initialized → return immediately" fast path. The bug only
   manifested in the wait-first / publish-later sequence, which no
   test covered until we wrote one. When you fix a concurrency or
   ordering bug, write down "what's the timing that broke this?"
   and reproduce that exact timing in the test (spawn the waiter
   first, sleep, then publish — not the other way around).

2. **Letting a hang look like a pass.** A regression test for a
   deadlock fix must use `tokio::time::timeout` (or equivalent) with
   a short bound and a clear failure message ("deadlock regressed?").
   Without the timeout, a re-introduced deadlock just hangs the test
   process — CI eventually kills it but the operator-facing failure
   is "test runner timed out," not "deadlock came back." With the
   timeout the test fails in 2 seconds with a message that points
   at the original bug.

The rule applies to controller bugs, agent bugs, and parse-time
validation gaps alike. If the bug surfaced because something user-
visible misbehaved, there's a unit-level shape that demonstrates it
— find that shape and lock it down. The fix isn't done until both
the production symptom AND the unit-level reproduction are green.

## When you add a new convention here

Keep entries short and rationale-first. The point of this file isn't
to be exhaustive documentation — it's to catch future sessions before
they reinvent a decision Bart already made. If a convention has been
discussed and a direction chosen, write it down here the same turn
so the next session inherits it.
