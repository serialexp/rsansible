# rsansible — project conventions

This file captures rsansible-specific conventions that should outlive
any one session. If you're a future Claude session: read this before
touching code that crosses the controller/agent boundary or adds
user-facing names.

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

## When you add a new convention here

Keep entries short and rationale-first. The point of this file isn't
to be exhaustive documentation — it's to catch future sessions before
they reinvent a decision Bart already made. If a convention has been
discussed and a direction chosen, write it down here the same turn
so the next session inherits it.
