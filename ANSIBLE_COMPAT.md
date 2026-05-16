# Ansible compatibility — where rsansible deliberately differs

rsansible is meant to run real-world Ansible playbooks with minimal
fuss, so the default is: match Ansible's behavior, even when Ansible's
behavior is questionable. But there are cases where matching exactly
would either (a) hide a footgun that we can surface without breaking
useful playbooks, or (b) leave performance/UX wins on the table at no
real cost.

This file is the canonical, exhaustive list of those cases. **Every
deliberate divergence from Ansible MUST be recorded here in the same
commit that introduces it.** If you find yourself thinking "I'll do
it the rsansible way because the Ansible way is silly" — write it
down. Future-you, and future readers of vendored playbooks, will need
to know.

The list is ordered loosely by user-visible surface area: things a
playbook author would notice first come first.

---

## 1. Controller-side lookups: `file` and `env` cache per-run

| Aspect | Ansible | rsansible |
|---|---|---|
| `lookup('file', path)` | Re-reads the file on every call | Reads once per `run()`, caches result |
| `lookup('env', name)` | Re-reads the env var on every call | Reads once per `run()`, caches result |
| `lookup('pipe', cmd)` | Re-runs the command every call | **Same — no cache** |

**Why diverge for `file` / `env`.** Templates render many times per
playbook (once per host, once per `loop:` iteration, once per `when:`
eval). Caching turns a 50-host inventory's identical
`controller_read_file('/etc/ssh/host.pub')` from 50 disk reads into
one. Files referenced from a playbook are inputs to the run, not
state that mutates during the run — the "snapshot at first read"
mental model is what users have.

**Why NOT diverge for `pipe`.** Shell commands can be intentionally
non-deterministic (`uuidgen`, `date +%s%N`, `openssl rand`, `mktemp`).
Silently caching would break those use cases subtly. Users who want
one-shot semantics use `set_fact:` at the top of the play, same as
Ansible.

**User escape hatch.** If you actually want `file`/`env` to re-read,
you currently can't — but realistically you don't. If this ever
becomes necessary, the answer is a per-call `nocache=True` flag, not
disabling the cache wholesale.

**Code:** `crates/ctl/src/template.rs::LookupCache` and the
`controller_*_impl` functions.

---

## 2. `command:` rejects `executable:` instead of ignoring it

| Aspect | Ansible | rsansible |
|---|---|---|
| `command:` with `executable: /bin/sh` | Silently ignores the field | Errors at parse time |

**Ansible behavior.** `command:` doesn't go through a shell, so
`executable:` has no meaning there. Ansible accepts it anyway and
discards it — playbook authors who want a specific interpreter are
supposed to know they should use `shell:` instead, but the silent
acceptance hides that.

**Why diverge.** A silent accept means the playbook reads as if a
specific interpreter is being used and actually isn't. The footgun
cost (debugging "why isn't my zsh-only syntax working") is high; the
compat cost (one extra parse error message that explains the fix) is
low. rsansible errors with:

> `command.executable: not supported — use 'shell:' to pick a
> different interpreter`

**Other `command:` fields rsansible accepts-and-discards.** `warn:`
and `strip_empty_ends:` — these are *also* fields Ansible silently
ignores in this context, but they don't change the meaning of the
command, so we don't gain anything by being loud. Discarded silently.

**Code:** `crates/ctl/src/playbook/task_op.rs::CommandOp`.

---

## 3. `lookup(plugin, ...)` errors loudly on unknown plugins

| Aspect | Ansible | rsansible |
|---|---|---|
| `lookup('nonexistent', ...)` | Plugin not found → undefined (often silently) | Errors at render time with the supported-plugin list |

**Why diverge.** The combination of "lenient undefined" templating
and a plugin-namespace dispatcher means Ansible can render
`lookup('vauilt', ...)` (typo) to empty string and ship the result
into a `template:` body without anyone noticing. rsansible's shim
errors with:

> `lookup("vauilt"): unknown plugin (supported plugins: file, pipe, env)`

at template-render time, so the typo surfaces immediately.

**Implication for vendored playbooks.** A playbook that relied on
silent-undefined for an unimplemented plugin (e.g. `lookup('vault',
...)` against an upstream we haven't shimmed yet) will start erroring
under rsansible. The fix is to implement the plugin, not to weaken
the error.

**Code:** `crates/ctl/src/template.rs::lookup_shim_impl`.

---

## 4. `until:` requires `register:`

| Aspect | Ansible | rsansible |
|---|---|---|
| `until: <expr>` without `register:` | Binds an implicit `result` var the expression can reference | Parse error: "`until:` requires `register:` to also be set" |

**Ansible behavior.** Even without `register:`, Ansible exposes the
task's result envelope under a synthetic name (effectively `result`)
that the `until:` expression can evaluate against. Authors writing
`until: result.rc == 0` get the implicit binding "for free."

**Why diverge.** The implicit binding is a magic-name surface that
makes the `until:` expression's meaning depend on hidden state. In
real-world usage (verified across the entire gothab playbook tree —
4 playbooks, 9 `until:` sites) **every single `until:` references a
named registered variable** — `wait_new_primary.rc`,
`drill_state.stdout`, `writer_status.finished`, etc. Nobody actually
relies on the implicit binding.

Requiring `register:` makes the expression self-documenting at
the call site: the reader can see which variable is being polled
without having to know rsansible's binding conventions.

**Fix when porting an Ansible playbook.** Add `register: result` (or
some other name) to the task. The expression continues to work
unchanged.

**Code:** `crates/ctl/src/playbook/task_op.rs::Task::deserialize`
— the check happens at parse time, surfacing immediately rather than
mid-run.

---

## When you add a new divergence

1. **Document it here first.** Add a `## N. <one-line summary>`
   section. The table-then-rationale-then-code-pointer shape is
   what every entry should follow.
2. **Same commit, not a follow-up.** If the doc and the code split
   across commits, the doc never lands. Ship them together.
3. **Be honest about scope.** "Matches Ansible" doesn't go here.
   "Will match Ansible once we implement X" doesn't go here either
   (that's a TODO). This file is *only* for deliberate, permanent
   semantic differences a playbook author would notice.
4. **Cross-link.** The function's own doc comment should say "see
   ANSIBLE_COMPAT.md §N" so a developer reading the code knows the
   choice was deliberate and where to find the rationale.
