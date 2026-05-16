# rsansible — project conventions

This file captures rsansible-specific conventions that should outlive
any one session. If you're a future Claude session: read this before
touching code that crosses the controller/agent boundary or adds
user-facing names.

## Companion docs

- **`ANSIBLE_COMPAT.md`** — the canonical list of every place
  rsansible deliberately differs from Ansible. **Every deliberate
  divergence MUST be recorded there in the same commit that
  introduces it.** See the rule at the bottom of this file.

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

When you add a divergence: the function's own doc comment should
say `see ANSIBLE_COMPAT.md §N` so a developer reading the code
knows the choice was deliberate and where to find the rationale.

## When you add a new convention here

Keep entries short and rationale-first. The point of this file isn't
to be exhaustive documentation — it's to catch future sessions before
they reinvent a decision Bart already made. If a convention has been
discussed and a direction chosen, write it down here the same turn
so the next session inherits it.
