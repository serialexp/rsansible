# rsansible

An Ansible-shaped configuration tool that avoids Ansible's per-task SSH cost.

The model: push a single static binary to each host over SSH, talk a framed
binary RPC protocol to it for the duration of the run, then delete it.
Modules (exec, shell, file ops, templating, service control, …) are inline
in the agent binary, not separate scripts. Hosts execute in lockstep — per-
task barrier by default — so it feels like Ansible's linear strategy,
just fast.

Status: **pre-v0**, but already runs real Ansible playbooks. A
production homelab (postgres + Patroni + pgbackrest + valkey + monitoring)
is the working reference workload — steady-state drills match
`ansible-playbook`'s PLAY RECAP shape `ok=N changed=M failed=0` exactly.

## Install

```
curl -fsSL https://raw.githubusercontent.com/serialexp/rsansible/main/install.sh | sh
```

Detects your OS/arch, downloads the matching release tarball, verifies
its checksum, and drops the `rsansible` controller plus the
`rsansible-agent` binary into `~/.local/bin` (override with
`RSANSIBLE_INSTALL_DIR`). Pin a version with `RSANSIBLE_VERSION=v0.1.0`.

Prebuilt for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
and `aarch64-apple-darwin`. Other platforms (Intel macOS, Windows):
build from source — see [Building](#building).

The agent shipped in the tarball is x86_64 musl — it's the binary
pushed to your (x86_64 Linux) targets via `-a`, regardless of the
controller's own arch.

## What's in the box

### Playbook surface

Plays load from the same YAML shape as Ansible. The parser accepts:

- **Tasks** with `name:` / body / `when:` / `tags:` / `register:` /
  `vars:` / `environment:` / `notify:` / `delegate_to:` / `run_once:` /
  `loop:` (+ `loop_control:` with `label:` / `loop_var:`) /
  `ignore_errors:` / `check_mode:` / `changed_when:` / `failed_when:` /
  `retries:` + `until:` + `delay:` / `async:` + `poll:` /
  `become:` + `become_user:` / `no_log:`.
- **`block:` / `rescue:` / `always:`** with block-level metadata
  pushed down into children at load time. `ansible_failed_*` is
  populated on rescue entry.
- **Handlers**, notified by name, deduped across the play, drained at
  the end of the play or on `meta: flush_handlers`.
- **Roles** via `roles:` in a play and `include_role:` / `import_role:`
  in tasks. `defaults/main.yml`, `vars/main.yml`, `tasks/main.yml`,
  `handlers/main.yml`, `templates/`, `files/` resolve as expected.
  Role `tasks_from:` for picking a sibling task file works.
- **`import_tasks:`** to splice another file inline at load time.
- **Inventory** YAML files / directories (group_vars, host_vars,
  vaulted files). Groups, group-of-groups, `children:`, `hosts:`.
- **Vault** files (`ANSIBLE_VAULT;1.1;AES256` envelopes) decrypted
  with a password file or `ANSIBLE_VAULT_PASSWORD_FILE` env var.
- **`--limit`** with names, globs (`web*`), regex (`~^web\d$`),
  intersection / exclusion / group slicing.
- **`--tags` / `--skip-tags`** with the magic `always` / `all` /
  `untagged` selectors.
- **`-e key=val` / `-e @vars.yml` / `-e '{json}'`** for extra-vars,
  highest precedence.
- **`--check`** for dry-run: modules report what they would change;
  mutating ops are skipped; per-task `check_mode: false` opts back in.

### Templating

minijinja with the Ansible compatibility shims people actually use
day-to-day:

- `hostvars[<peer>]` resolves to a peer host's live state — registers
  + set_facts + facts + inventory vars — with a per-task barrier in
  the default strategy and eventually-consistent peer views in
  `strategy: free`.
- `groups['name']`, `inventory_hostname`, `ansible_*` facts.
- Implicit register exposure inside `changed_when:` / `failed_when:`
  / `until:` so you can write `rc != 0` without the register prefix.
- `lookup('file', ...)` / `lookup('pipe', ...)` / `lookup('env', ...)`
  shims; the canonical spelling is `controller_read_file(...)` /
  `controller_shell_stdout(...)` / `controller_env(...)`. See
  `RSANSIBLE_IDIOMS.md §1`.
- Ansible-idiomatic numeric attribute subscripting (`item.0.name`
  rewrites to `item[0].name` at template-prepare time).
- Jinja2 `include` for chunking templates (e.g. `patroni.yml.j2`'s
  shared snippets).

### Modules

**File / content:** `file:`, `copy:`, `template:`, `write_file:`,
`lineinfile:`, `blockinfile:`, `stat:`, `slurp:`, `unarchive:`
(`remote_src: yes`), `get_url:`, `tempfile:` (controller-side).

**Process / shell:** `command:` (with `creates:` / `removes:`
short-circuit, post-Jinja shlex split), `shell:`, `exec:`,
`wait_for:` (TCP port / path appear / path disappear).

**System state:** `systemd:` / `service:`, `package:` (`apt:`,
`pip:`), `repository:` / `apt_repository:`, `group:`, `user:`,
`authorized_key:`, `getent:`, `hostname:`, `timezone:`.

**Networking:** `ufw:`, `iptables:` (subset; see ANSIBLE_COMPAT.md
§9 for the rejected knobs), `uri:` (HTTP client).

**TLS / crypto:** `openssl_privatekey:` (controller-side, ships
PEM), `openssl_csr_pipe:` (controller-side, no wire dispatch),
`x509_certificate_pipe:` (controller-side, self-signed in v1).

**PostgreSQL:** `postgresql_query:`, `postgresql_ext:`,
`postgresql_user:`, `postgresql_db:`, `postgresql_membership:`.

**Async:** `async:` + `poll: 0` for fire-and-forget,
`async_status:` to poll later.

**Control-flow ops (controller-side):** `assert:`, `fail:`,
`debug:`, `set_fact:`, `pause:` (non-interactive), `meta:
flush_handlers`.

### Connection / become

- **SSH** via the operator's `ssh-agent`, one session per host with
  N channels — one channel per `(host, become-config)` pair. No
  argv-wrapping shenanigans: an agent under `sudo -n -u <user>`
  IS the agent the orchestrator dispatches against.
- **`become:`** is sudo-only (`sudo -n`); `become_method:` defaults
  to sudo and other methods are rejected loudly. NOPASSWD is
  required.
- **`connection: local`** runs the agent as a subprocess on the
  controller, same protocol over a pipe pair.
- **Per-host facts gathering** when `gather_facts: true` (or by
  default at play start). Faster than Ansible's setup module —
  the agent reads `/etc/os-release`, `/proc/*`, `getent`,
  `hostname -A`, etc. directly.

### Forward mode

`rsansible run --forward [--forward-host <name>]` pushes the
controller binary to a host near the targets (default: first
targeted host) and drives the run from there. Collapses per-op
SSH RTT on long-haul links — a Tokyo→Falkenstein drill that took
~110s in normal mode runs in ~15-20s in forward mode without
changing the playbook. `connection: local` still means "the
operator's laptop" via a back-channel SSH session. Linux x86_64
required for the forwarder in v1.

### Performance discipline

- **Wire-time accounting** built in. Every run prints a summary
  attributing wall time to `agent=` (work the agent actually did)
  vs `rtt=` (bits in flight, skew-corrected). `--timing` adds a
  phase-by-phase orchestrator breakdown (template render, when-
  eval, become resolution, body dispatch, …).
- **Composite ops** for `openssl_privatekey:`, the `postgresql_*`
  family, and `command: creates:/removes:` to keep wire RTT down
  on idempotent re-runs.
- **`WireStrategy`** (`auto` / `blind` / `probe`) decides per-host
  whether modules that ship file content should stat-probe first
  or send blind based on RTT × bandwidth.

## Compatibility scope

Two companion docs spell out the boundaries:

- **`ANSIBLE_COMPAT.md`** — every place rsansible deliberately
  *differs* from Ansible given the same input. Reach here when a
  ported playbook behaves differently. Examples: `become:` is
  sudo-only, `command:` rejects `executable:` instead of silently
  ignoring it, controller-side `lookup('file', ...)` caches
  per-run.
- **`RSANSIBLE_IDIOMS.md`** — preferred *spellings* for fresh
  playbooks, alongside compat shims that keep Ansible's spelling
  working. Behavior matches via the shim — these are
  ergonomics/naming preferences, not divergences. Example:
  `controller_read_file(...)` over `lookup('file', ...)`.

Anything not in those two files is intended to behave like
Ansible. If you find a divergence not listed, that's a bug —
file it.

## Layout

- `crates/wire/` — wire types (generated from
  `schema/wire.schema.json5` via binschema) plus length-prefix
  framing helpers.
- `crates/agent/` — the pushed binary. Reads framed messages from
  stdin, writes to stdout, dispatches to module handlers under
  `crates/agent/src/modules/`.
- `crates/ctl/` — the controller CLI. Parses playbooks, opens SSH
  sessions, pushes agents, drives the barrier loop.
  - `playbook/` — YAML parser, task-op deserializers, inheritance
    passes (block metadata, role metadata).
  - `orchestrator.rs` — per-task / per-play strategy drivers,
    handlers, run_once coordination, hostvars snapshotting.
  - `forward.rs`, `remote.rs`, `back_channel.rs` — forward-mode
    machinery.
- `schema/wire.schema.json5` — protocol source of truth.
- `examples/` — sample playbooks.

## Building

```
just gen-wire           # regenerate crates/wire/src/generated.rs from schema
cargo build             # workspace
just build-agent-musl   # static stripped agent for Linux x86_64
just build-ctl-musl     # static ctl binary (required for forward mode)
```

`just gen-wire` requires `bun` and a checkout of binschema at
`$BINSCHEMA_ROOT` (default `~/Projects/binschema`).

## Running

```
rsansible run \
  -i inventory \
  -a target/x86_64-unknown-linux-musl/release/rsansible-agent \
  --limit web \
  --tags deploy \
  playbook.yml
```

Add `--forward` to push the controller next to the targets for
long-haul runs. Add `--check` for a dry run. Add `--timing` to
see where wall time went.

## Contributing

Read `CLAUDE.md` first. It documents the project's non-obvious
conventions: the `controller_*` / `target_*` naming rule for any
operation whose side-of-execution is part of its contract; how
controller-side I/O caching is decided per-function; the
recursive-task-list executor pattern for `block:` and future
grouped ops; per-host run_once coordination and the runner-
identity discipline; the agent-pool keying by `(host, become-
config)`; dynamic `hostvars[<peer>]` snapshotting; and the rule
that every bug fix ships with a regression test.

Every deliberate Ansible divergence belongs in
`ANSIBLE_COMPAT.md` in the same commit. Every preferred-spelling
shim belongs in `RSANSIBLE_IDIOMS.md`. The litmus test:
observable behavior change → COMPAT, no-op behavior shim → IDIOMS.

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this
crate by you, as defined in the Apache-2.0 license, shall be dual-licensed
as above, without any additional terms or conditions.
