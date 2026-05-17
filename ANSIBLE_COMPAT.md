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

## 5. `tempfile:` is controller-side in v1

**rsansible's behavior.** `tempfile:` (Ansible's
`ansible.builtin.tempfile`) creates the temp file or directory on the
**controller** filesystem, regardless of the play's `connection:` or
which host the task is targeting. The register's `.path` is a
controller path.

**Ansible's behavior.** `tempfile:` runs on the target host: a play
against `hosts: db01 connection: ssh` creates `/tmp/<…>` on `db01`,
and `register.path` is `db01`'s path.

**Why we diverge.** The only Phase 1 consumer (gothab's
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
when supplying BC). For the only Phase 1 consumer (gothab's etcd CA)
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
or SHA-384, which gothab doesn't.

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
