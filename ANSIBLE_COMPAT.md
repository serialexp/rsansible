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
real-world usage (verified across the entire acme playbook tree —
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

## 5. `tempfile:` is controller-side in v1

**rsansible's behavior.** `tempfile:` (Ansible's
`ansible.builtin.tempfile`) creates the temp file or directory on the
**controller** filesystem, regardless of the play's `connection:` or
which host the task is targeting. The register's `.path` is a
controller path.

**Ansible's behavior.** `tempfile:` runs on the target host: a play
against `hosts: db01 connection: ssh` creates `/tmp/<…>` on `db01`,
and `register.path` is `db01`'s path.

**Why we diverge.** The only Phase 1 consumer (acme's
`bootstrap-etcd-ca.yml`) runs `connection: local` against `localhost`,
so the controller IS the target. Growing a target-side wire op
(`OpTempfile` + agent handler + integration tests) is work we don't
need yet. The parser-level shape stays identical for the future
target-side variant, so playbooks don't need to know about the split.

**When this bites you.** Using `tempfile:` against a remote SSH target
today silently creates the path on the controller instead of the
remote host — wrong, and surprising in a vendored playbook. Safe for
`connection: local` / `hosts: localhost` / `delegate_to: localhost`.
The restriction lifts the first time a Phase 1+ playbook needs
target-side tempfiles; until then, the controller-side branch is the
only path.

**Code:** `crates/ctl/src/orchestrator.rs::synth_tempfile` — lives
next to `synth_cert_pipe` because both share the "controller-side, no
wire dispatch, synthesize register entry" shape. Parser is
`crates/ctl/src/playbook/task_op/tempfile.rs::TempfileOp`; the parsed
shape carries no connection-aware fields, so a future split adds an
orchestrator dispatch arm without touching YAML semantics.

---

## 6. `openssl_csr_pipe` / `x509_certificate_pipe` quirks

### 6a. KeyUsage / BasicConstraints are always critical

**rsansible's behavior.** When `openssl_csr_pipe` emits a `KeyUsage`
or `BasicConstraints` extension, it's always marked **critical**.
Setting `key_usage_critical: false` while `key_usage:` is non-empty
(or the equivalent BC pair) is rejected at parse time.

**Ansible's behavior.** `community.crypto.openssl_csr` defaults
`key_usage_critical` / `basic_constraints_critical` to `false` and
emits the extensions non-critical unless you opt in.

**Why we diverge.** rcgen 0.13 doesn't expose the critical bit per
extension at this layer — KeyUsage and BasicConstraints are written
critical by default when present, with no toggle. Silently accepting
`critical: false` and producing a critical extension anyway would be
worse than a parse-time error: a downstream peer that ignores
non-critical extensions would behave differently against rsansible's
output vs Ansible's. We surface the limitation up front.

**Fix when porting an Ansible playbook.** Set
`key_usage_critical: true` (and `basic_constraints_critical: true`
when supplying BC). For the only Phase 1 consumer (acme's etcd CA)
this matches what the playbook already wants — a CA's KeyUsage *must*
be critical for openssl's chain validator to accept it.

### 6b. `selfsigned_digest` is parsed but advisory

**rsansible's behavior.** `x509_certificate_pipe.selfsigned_digest:`
is parsed and stored, but the actual signature digest is picked by
rcgen based on the signing key (RSA → SHA-256, Ed25519 → its built-in,
ECDSA P-256 → SHA-256). Asking for a non-default digest doesn't
change the output.

**Ansible's behavior.** `community.crypto.x509_certificate_pipe`
honors `selfsigned_digest:` and rejects keys it can't sign with the
requested digest.

**Why we diverge.** For the keys we generate (RSA / Ed25519) the
defaults rcgen picks line up with the Ansible defaults that any
sane modern playbook would specify. Plumbing per-extension digest
selection through rcgen is work we'd do when a playbook needs SHA-512
or SHA-384, which acme doesn't.

**Fix when porting an Ansible playbook.** If the playbook depends on
a non-default digest, this won't yet do what you want — file an issue
with the failing case. Otherwise it's a no-op divergence.

### 6c. CSR / cert registers carry both Ansible spellings

**rsansible's behavior.** `openssl_csr_pipe` emits both
`register.content` and `register.csr` with the CSR PEM;
`x509_certificate_pipe` emits both `register.content` and
`register.certificate`.

**Ansible's behavior.** `openssl_csr_pipe` uses `.csr`,
`x509_certificate_pipe` uses `.certificate`. `.content` is rsansible's
own spelling.

**Why we diverge.** v0 of rsansible only emitted `.content` (the spelling
shared with `slurp` and other `_pipe` ops). Adding the Ansible spelling
in parallel lets vendored playbooks reach `ca_csr.csr` or
`ca_cert.certificate` without rewrites, while not breaking older
rsansible-native playbooks that already used `.content`. Both keys
point at the same string.

**Fix when porting an Ansible playbook.** Nothing to fix — both work.
When writing new rsansible-native code, prefer the Ansible spelling
(`.csr` / `.certificate`) since it'll port back if you ever need to.

---

## 7. `become:` is honored only via `sudo -n`, and `become_method` is sudo-only

| Setting               | rsansible                                         |
|-----------------------|---------------------------------------------------|
| `become_method:`      | Only `sudo` (default). Any other value is rejected at parse time. |
| `become_flags:`       | Ignored. Sudo is always invoked as `sudo -n -u <user> --`. |
| `become_exe:`         | Ignored. We always shell out to the system `sudo`. |
| Password prompts      | Never. `-n` is non-interactive — sudo fails fast rather than prompt. NOPASSWD entries in `/etc/sudoers` are required. |

### Rationale

Ansible's privilege-escalation layer is a pluggable shim with seven
methods (`sudo`, `su`, `doas`, `runas`, `pbrun`, `pmrun`, `dzdo`,
`ksu`, `machinectl`, `sesu`). Each carries its own argv shape, its
own password-prompt protocol, and its own quirks; the matrix between
that and `become_user` × `become_flags` × `become_exe` is large and
mostly load-bearing for nobody.

rsansible picks the path that ~every modern Ansible deployment
already uses: `sudo` with `NOPASSWD` entries. The choice has knock-on
benefits: the agent process for a given `(host, become_user)` tuple
runs under the right EUID from spawn time, so every wire op
(systemd, copy, file, package, …) gets the right privileges
*automatically* — see CLAUDE.md's "Agent-pool become routing"
section for the architectural shape.

### Per-host agent pool: how `become:` is actually routed

For a given host, rsansible holds one persistent agent process per
distinct `(BecomeKey)`:

- `BecomeKey::None` — the agent we spawned at connect time, running
  as the SSH user.
- `BecomeKey::As(user)` — an agent spawned lazily under
  `sudo -n -u <user> -- <agent_path>`.

Each task computes its effective become (precedence: task `become:`
→ inventory `ansible_become` → default `false`) and routes its wire
ops to the pool slot matching that key. A play with
`become: true, become_user: root` plus some unbecomed tasks ends up
with two agents per host: one under the SSH user, one under root.

`become_user:` is rendered as a Jinja template against the per-host
context before keying — so `become_user: "{{ db_user }}"` works.

### Fix when porting an Ansible playbook

- **`become_method: sudo`** — works (no-op, that's the default).
- **`become_method:` anything else** — rejected at parse time. If
  your fleet has a real reason to need `doas` or `pbrun` here,
  surface it: file an issue with the use case.
- **`become_flags:`** — dropped on the floor with a warning. If your
  flags were just `-H` or `-i` (preserve / login shell) you can
  usually delete the directive. If they were carrying password input
  via a non-NOPASSWD sudo, switch to NOPASSWD; rsansible will never
  send a password down the wire.
- **Password prompts (`--ask-become-pass`, `ansible_become_pass`)** —
  ignored. NOPASSWD is required.

Code pointers:
- `crates/ctl/src/become_.rs` — `BecomeKey` + `effective()` + Jinja
  templating of `become_user`.
- `crates/ctl/src/pool.rs` — `AgentPool` with lazy `get_or_spawn`
  per `BecomeKey`.
- `crates/ctl/src/ssh.rs` — `spawn_agent_channel` builds the
  `sudo -n -u <user> --` exec line for `BecomeKey::As(user)`.

---

## 8. `pause:` rejects the interactive (no-duration / `prompt:`) path

| Ansible spelling | rsansible behavior |
|---|---|
| `pause:` (no args) | **Parse error** — rejects with a pointer to this section. |
| `pause: { prompt: "..." }` | **Parse error.** |
| `pause: { echo: ... }` | **Parse error** (the `echo:` knob only applies to `prompt:`). |
| `pause: { seconds: N }` / `{ minutes: N }` | Honored. Accepts int or Jinja string. |
| `pause: { seconds: N, minutes: M }` | **Parse error** — mutually exclusive. |

### Why

Ansible's `pause:` has two unrelated modes folded under one module
name:

1. **Timed pause.** Sleep for `seconds:` or `minutes:` and continue.
   This is what almost every production playbook means by `pause:`.
2. **Interactive pause.** With no duration (or with `prompt:` set),
   block forever waiting for a human to press Enter or answer a
   prompt at the controller's terminal. The result of the prompt is
   bound to a register.

The second mode is fundamentally incompatible with how rsansible is
used. We're a non-interactive runner — typical invocation paths
include CI, cron, deploy scripts, and remote agents. There's no
terminal to read from in any of those, and pretending there is would
mean the play hangs forever the first time it's run in automation.

We could have silently treated a no-duration pause as a no-op, but
that masks the real intent ("wait for human confirmation"); the
playbook would behave differently in the runner than the author
expected. Rejecting at parse time means the author sees the
divergence the first time they load the playbook, not the first
time a drill hangs in CI.

The `seconds:` / `minutes:` knobs accept both literal ints and
Jinja-templated strings — same shape as `async:` / `poll:` /
`retries:` / `delay:`. The runtime renders + parses at dispatch.

### Code pointers

- `crates/ctl/src/playbook/task_op/mod.rs` — `PauseTask` and its
  `Deserialize` impl reject `prompt:` / `echo:` / no-args.
- `crates/ctl/src/orchestrator.rs` — `run_pause_body` renders the
  duration via `render_int_field` and `tokio::time::sleep`s.

---

## 9. `iptables:` covers a subset, rejects extension knobs loudly

| Ansible knob | rsansible behavior |
|---|---|
| `chain`, `protocol`/`proto`, `source`/`src`, `destination`/`dest`, `source_port`, `destination_port`, `in_interface`, `out_interface`, `jump`, `comment`, `ctstate`, `table`, `ip_version`, `action`, `state` | **Honored.** |
| `match`, `tcp_flags`, `syn`, `to_destination`, `to_source`, `to_ports`, `reject_with`, `icmp_type`, `uid_owner`, `gid_owner`, `log_prefix`, `log_level`, `limit`, `limit_burst`, `flush`, `policy`, `rule_num`, `gateway`, `numeric`, `wait` | **Parse error** — "not yet supported" with a pointer to file an issue. |

### Why

Ansible's `iptables` module has ~30 knobs spanning filter, NAT,
LOG/REJECT targets, conntrack, owner-match, rate-limiting, and
whole-chain operations (`flush:` / `policy:`). The full surface is a
substantial agent module.

The subset above covers what acme and similar production playbooks
actually use: insert/remove DROP rules with a comment tag for
idempotency, optionally scoped to a single interface, address, and
port. The unsupported knobs are rejected **at parse time, loudly**,
with their name in the error message and a pointer to file an issue.
A silent skip would let a NAT or LOG playbook run end-to-end without
its rules ever firing, which is a much worse failure mode than "we
told you up front this isn't ready yet."

### Idempotency model

We use `iptables -C` (the kernel's own "would this rule match an
existing entry?" check) rather than parsing `iptables-save` output.
This is what the upstream Ansible module also does and it's robust
against tab/space/order differences that `iptables-save` parsers
trip on. Exit code 0 = present, 1 = absent; any other exit is
treated as a real error.

### `become_method` is still sudo-only

The agent does NOT run `iptables` via internal escalation — it
inherits the EUID of the agent process. With `become: true,
become_user: root` (the typical case), the agent itself is already
running as root via the per-host pool's `BecomeKey::As("root")`
slot (see §7), so `iptables` just works. Without `become:` it'll
fail with iptables's "Permission denied" exit, surfaced as
`TaskError IO`.

### Code pointers

- `schema/wire.schema.json5` — `OpIptables` (kind=20). 15 string
  fields plus `ip_version`, `action`, `rule_state` bytes.
- `crates/ctl/src/playbook/task_op/iptables.rs` — controller parser
  with the unsupported-knob allowlist and per-field validation.
- `crates/agent/src/modules/iptables.rs` — `-C` probe → `-A`/`-I`/`-D`
  with argv construction respecting iptables's flag ordering rules.

---

## 10. `command:` shlex-splits its `cmd:` **after** Jinja renders, not before

Ansible's `command:` module renders the full command string against the
play context, then shlex-splits the result into argv. We do the same.
The natural Rust port — split at parse time, render each argv element
at task time — broke any `cmd:` that embedded `{{ var }}`, because the
splitter saw `{{`, `var`, and `}}` as three separate tokens and the
template engine then failed to compile `{{` as an expression.

| Input | Parse-time argv | Render-time argv |
|---|---|---|
| `command: "/usr/bin/echo hi"` (no Jinja) | `[]` (deferred) | `["/usr/bin/echo", "hi"]` |
| `command: { cmd: "/bin/x --id {{ drill_id }}" }` | `[]` (deferred) | `["/bin/x", "--id", "drill-1234"]` |
| `command: { argv: ["/bin/x", "{{ id }}"] }` | `["/bin/x", "{{ id }}"]` | `["/bin/x", "drill-1234"]` |

The argv-list form keeps the per-element render path — the user
explicitly told us how to slice, so we don't second-guess it.

### What still happens at parse time

- **Unterminated quotes** in `cmd:` strings that contain no Jinja are
  surfaced immediately (a literal command string with no `{{ }}` has
  no reason to wait until render to fail).
- **Empty** `cmd:` / shorthand strings.
- **Mutual exclusion** of `cmd:` and `argv:`.
- **Template syntax errors** in the raw `cmd:` string (caught by
  `template.rs` precompile, which now compiles the whole string
  instead of each token).

### What only happens at render time

- The actual shlex-split of `cmd:` into argv.
- Render-time variable substitution.
- Render-time shlex parse errors (e.g. a variable expanded into an
  unterminated quoted string).

### Code pointers

- `crates/ctl/src/playbook/task_op/command.rs` — `CommandOp.raw_cmd`
  holds the unsplit string; the deserializer leaves `argv` empty for
  the `cmd:`/shorthand paths.
- `crates/ctl/src/template.rs` (TaskOp::Command branch) — compiles
  `raw_cmd` as one template instead of per-argv-element.
- `crates/ctl/src/orchestrator.rs` `render_op` — renders `raw_cmd`,
  then `shlex::split`s the result into the final argv before
  dispatch.

---

## 11. `internal_ansible_host` / `internal_ansible_port` — per-host dial-from-inside addresses

| Aspect | Ansible | rsansible |
|---|---|---|
| Magic var for "dial address when inside the target network" | none | `internal_ansible_host` (string), `internal_ansible_port` (int) |
| Applied | n/a | Forward mode only (`rsansible run --forward …`). Non-forward runs ignore the var. |
| Resolution scope | n/a | Per-host `inline_vars` (highest), then on-disk `host_vars/<name>.yml`. Group_vars not yet honored — extend if a real use case shows up. |
| Failure mode | n/a | Non-string `internal_ansible_host` or non-integer / out-of-range `internal_ansible_port` errors loudly at run start, before any SSH dial. |

### Why

Forward mode relocates the controller from the operator's laptop to a
forwarder *inside* the target network. The laptop reaches each host
over one address (typically a public IP); the forwarder reaches the
same hosts over a different address (typically a private vnet IP).
Ansible has no native way to express both addresses on the same
inventory entry — operators normally maintain two parallel inventory
files or jump-host configs. rsansible models them as paired per-host
vars so a single inventory carries both facts about the same host.

### How it interacts with the rest of the pipeline

- **Forwarder selection** runs on the laptop *before* the override,
  using `ansible_host` (public). The forwarder we SSH into must be
  reachable from the laptop, so this ordering is mandatory.
- **Inventory shipping**: the laptop mutates each host's `host` /
  `port` to the internal value *after* selection, *before* the
  Inventory is serialized into the WorkflowPayload. The forwarder
  receives an Inventory that already uses internal addresses and
  never sees the public ones.
- **The forwarder host itself** can have an `internal_ansible_host`
  set and it'll be overwritten like any other; harmless, since the
  forwarder uses a `Local` pool to dispatch to itself (no SSH to
  itself ever happens).

### Where this lives

- `crates/ctl/src/forward.rs` — `INTERNAL_HOST_VAR` /
  `INTERNAL_HOST_PORT_VAR` constants and
  `apply_internal_host_overrides()`, called once at the top of
  `run_forwarded`.

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
