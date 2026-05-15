# rsansible — roadmap to running gothab

The v0 shipped (`shell`/`exec`/`write_file` over a pushed-agent framed
protocol). To run the real Ansible flows in `~/Projects/gothab/ansible/`
(4 playbooks, 8 roles, ~400 tasks, 17 Jinja templates), the controller
needs a real programming model and the agent needs a wider module set.

Phasing is deliberate: each phase unlocks the next, and Phase 1 alone
should be enough to run `bootstrap-etcd-ca.yml`. Sizing is rough.

---

## Phase 1 — Programming model (controller-only; no wire change)

This is the biggest architectural step. Today the orchestrator is "barrier
loop over a flat task list". Gothab needs a per-host data-flow graph:
registers feed conditions feed set_facts feed delegate_to feed handlers.

**Estimated:** ~1500 LoC controller-side. Most of it lives in
`crates/ctl/src/orchestrator.rs` and a new `crates/ctl/src/exec_ctx.rs`.

### Phase 1a — foundation (landed)

- [x] **Per-host execution context** (`HostCtx`)
  - holds register dict, set_fact dict, the host's facts, the host's
    variables (from inventory + group_vars + host_vars). Threaded through
    every task execution. Replaces the current "just an `AgentConn`".
- [x] **`register:`**
  - capture `TaskDone.exit_code`, `changed`, `took_ms`, plus stdout/stderr
    aggregated from streamed `TaskProgress` chunks (1 MiB cap, truncation
    marker), plus a parsed `.json` field when stdout is valid JSON. Lives
    in `HostCtx.registers[name]`.
- [x] **`when:` clause**
  - minijinja `Environment::compile_expression(s)` evaluated against the
    host context. False → task skipped on that host (Skipped outcome,
    doesn't fail the barrier; register if set gets a skipped marker).
- [x] **`set_fact:`**
  - YAML values pass through; scalar strings are jinja-rendered. Output
    that looks JSON-ish auto-parses so `count: "{{ x + 1 }}"` yields a
    number. Persists across plays for the same host (Ansible-faithful).
- [x] **`loop:` (runtime expansion + `loop_control.loop_var`)**
  - Runtime, not parse-time (loop expressions reference registers).
  - Literal list (`loop: [a,b,c]`) or jinja string (`loop: "{{ xs }}"`).
  - Per-iteration register aggregated into `results: [...]` under the
    task's `register:`. `subelements` filter ships in template env.
  - `include_tasks:` (runtime include) deferred — gothab uses
    `import_tasks` exclusively, per the survey.
- [x] **`import_tasks:` (parse-time flattening)**
  - Recursive with cycle detection and 16-deep cap. Imports flatten
    away during `playbook::load()` so the orchestrator never sees them.
- [x] **`assert:` / `fail:`**
  - Controller-side terminal task kinds; no agent involvement. Honor
    `when:` and respect the play's `on_failure` policy.
- [x] **Drop "exactly-one-op" Task invariant**
  - `Task { name, body: TaskBody, when, register, loop_spec,
    loop_control, tags }`. Hand-written `Deserialize` enforces exactly
    one of 7 body keys plus any of the metadata keys; rejects unknown
    top-level keys.

**Phase 1a acceptance (met):** `examples/programming_model.yaml` runs
against a 3-container fleet end-to-end (`tests/programming_model.rs`):
import flattens, register flows into a when-gated follow-up, a literal
loop produces N templated files, an assert validates set_fact state. A
second test forces an assert failure and verifies `on_failure: stop`
halts the playbook.

### Phase 1b — landed

- [x] **`delegate_to:`**
  - Per-task host override; resolved as a Jinja-templated hostname
    against the originating host's view. The op runs against the
    target host's `AgentConn`; register/set_fact/notify side effects
    land on the originating host's `HostCtx`. Implemented via shared
    `Arc<Mutex<Option<AgentConn>>>` handles in
    `crates/ctl/src/orchestrator.rs::ConnHandle` so any task future
    can borrow any host's conn.
- [x] **`run_once:`**
  - Under per_task: the first live host (inventory order) runs;
    register / set_fact / notify are broadcast to every other live
    host's ctx after the runner returns.
  - Under per_play: per-task `OnceCell<RunOnceResult>` lets the
    runner publish its result and non-runner hosts inherit it
    without re-executing the body.
- [x] **Handlers + `notify:` + `meta: flush_handlers`**
  - `Play.handlers` is a parallel task list. Tasks carry a
    `notify: [names]` list; changed-and-successful tasks insert the
    handler names into `HostCtx.pending_handlers` (BTreeSet → free
    dedup). `meta: flush_handlers` drains mid-play; end-of-play also
    flushes implicitly. Each handler runs at most once per play per
    host. Handlers iterated in declaration order.

**Phase 1b acceptance (met):**
`examples/handlers_and_delegation.yaml` runs against the 3-container
fleet via `tests/handlers_delegation.rs`. Three async e2e tests
cover: notify dedup + mid-play flush + end-of-play flush + run_once
broadcast (the happy-path test), unknown-delegate failure path, and
handler failure under `on_failure: stop` halting the play.

The originally-named acceptance — running a hand-translated
`bootstrap-etcd-ca.yml.port` from gothab — is deferred to a
follow-up: the per-feature e2e is more diagnostic, and porting the
real gothab playbook is its own unit of work.

---

## Phase 2 — Variable scope + minimal facts

**Estimated:** ~800 LoC. Mostly a precedence-walker and a small protocol
change.

### Phase 2a — landed

- [x] **Inventory schema rewrite**
  - Ansible-shaped `all.children.<group>.{vars,hosts}`. Connection-coord
    keys (`ansible_host`, `ansible_port`, `ansible_user`,
    `ansible_ssh_private_key_file`) are lifted; other host-level keys
    become per-host inventory vars. Flat groups only (no nested
    `children:`); no boolean/exclusion selectors yet.
- [x] **`group_vars/` and `host_vars/` directories**
  - `<inv_dir>/group_vars/<group>/*.yml` (dir form, alphabetical merge)
    and `<group>.yml` (file form); same for host_vars. Loaded by
    `inventory::load_with_vars()` and folded into the connection-coord
    resolution AND the runtime template view.
- [x] **Ansible Vault decryption**
  - `crates/ctl/src/vault.rs` — `$ANSIBLE_VAULT;1.1` / `1.2;AES256`,
    PBKDF2-SHA256(10k, 80B) → AES-256-CTR + HMAC-SHA256. Detected on the
    first line of any group_vars/host_vars file; `--vault-password-file`
    CLI flag (or `ANSIBLE_VAULT_PASSWORD_FILE` env var). Files skipped
    with a warning when no password is supplied.
- [x] **Variable precedence chain (Phase 2a slice)**
  ```
  all_vars  <  group_vars (inline + on-disk; member_of order)
            <  host_vars (on-disk)  <  inline host vars
            <  play.vars  <  set_fact  <  register
  ```
  Lower layers resolved at startup into `HostCtx.inventory_vars`;
  `play.vars` rendered into `HostCtx.play_vars` at the start of each
  play. set_fact / register layer on top as before.
- [x] **`groups[]` / `hostvars[]` template globals**
  - Computed once per run as `Arc<WorldVars>`; every `build_template_ctx`
    call receives it. `{{ groups['web'][0] }}` and
    `{{ hostvars[...].region }}` work end-to-end.
- [x] **`Play.vars`**
  - Per-play layer, rendered against each host's inventory_vars-only
    view at play start (no chicken-and-egg with set_fact).
- [x] **Group selectors in `hosts:`**
  - `hosts: web` / `hosts: [web, host3]` / `hosts: all`. Group wins on
    name collision (Ansible's behavior). Unknown names error at validate
    time.

**Phase 2a acceptance (met):** `tests/groups_and_vars.rs`'s 3-container
e2e exercises group selector resolution, every precedence layer (all,
group, host, inline, play), `groups[]`/`hostvars[]` lookups, and vault
decryption, all against `examples/groups_and_vars.yaml` +
`examples/group_vars/{all,web}/` + `examples/host_vars/host1.yml` +
a vault-encrypted `examples/group_vars/web/secrets.yml`.

### Phase 2b — landed

- [x] **Roles** (`roles/<name>/{tasks,handlers,defaults,templates}/main.yml`
  discovery + `roles:` directive on plays). Role flatten pass in
  `crates/ctl/src/playbook/role.rs` runs after `import::flatten_playbook`;
  `defaults/main.yml` feeds `play.role_defaults` (lowest-precedence
  user-defined layer, below `inventory_vars`); role tasks/handlers are
  prepended to the play's own lists (Ansible's ordering). Bare-string
  and `{ role: name, tags: [...] }` invocation forms both accepted;
  `tags:` parsed-and-ignored for now.
- [x] **`template:` task module** — controller-side desugar to
  `OpWriteFile`. `src:` resolved at load time against
  `<role_dir>/templates/`, `<playbook_dir>/templates/`, then
  `<playbook_dir>/`; body inlined onto the parsed `TemplateOp` and
  rendered through the standard minijinja env at task time.
- [x] **`OpGatherFacts` agent op + `gather_facts:` directive**
  (default true, Ansible-faithful). Facts emitted: `ansible_hostname`,
  `ansible_distribution`, `ansible_distribution_release`,
  `ansible_date_time` (nested, with `iso8601`/`date`/`time`/`epoch`),
  `ansible_default_ipv4` (best-effort via UDP-connect trick). First
  wire-schema change since v0 (Op kind=3); facts ride back on
  `TaskProgress.stdout` as a JSON object and the orchestrator lifts
  them into per-host `HostCtx.facts` (persists across plays). Failures
  are best-effort — logged, don't halt the play.
- [ ] **Nested groups / boolean selectors** — defer; gothab doesn't
  use either. Add if/when something needs them.
- [x] **CLI `--extra-vars`** — top-of-stack precedence layer, ahead of
  registers. `rsansible run -e key=value` (always stringified, Ansible-
  faithful), `-e @file.yml` (top-level YAML map), `-e {json_literal}`
  (object literal). Repeatable; later occurrences override earlier on
  key collision. Parsed via `crates/ctl/src/extra_vars.rs` and threaded
  through `RunSpec.extra_vars` → `HostCtx.extra_vars`. Layered last in
  `build_template_ctx`; visible to `play.vars` rendering too.

### Phase 2c — in flight

- [x] **`copy:` task module** — controller-side desugar to `OpWriteFile`,
  parallel to `template:`. `src:` resolved at load time against
  `<role_dir>/files/`, `<playbook_dir>/files/`, then `<playbook_dir>/`;
  raw bytes inlined onto the parsed `CopyOp` and shipped verbatim
  (binary-safe — keeps the `TaskOp::Copy` variant through dispatch so
  `to_wire_op` emits `OpWriteFile` directly rather than round-tripping
  through `WriteFileOp.content: String`). 3-container e2e in
  `tests/roles_and_facts.rs` plus 9 unit tests across parse, resolver,
  and binary-bytes paths.
- [x] **Custom Jinja filters** — `b64encode` / `b64decode` (base64
  crate), `from_json` (serde_json), `to_json` (Ansible alias for
  minijinja's built-in `tojson`, compact output), `regex_replace`
  (regex crate, supports `$N` backrefs and inline `(?i)`/`(?m)`
  flags). All registered in `template::make_env`; precompile_all
  already exercises them whenever a template body references them.
  11 unit tests in `template::tests`. `mandatory` was already in.
- [x] **`include_role: tasks_from:`** — parse-time expansion (despite
  Ansible's nominally-runtime semantics, we don't need a runtime path
  yet — no `loop:` on the include site, no register feeding through to
  the include name). New `TaskBody::IncludeRole(IncludeRoleSpec{name,
  tasks_from, vars})` variant; `expand_include_roles` pass in
  `playbook::role` runs between role-flatten and template/copy resolution.
  Splices in `roles/<name>/tasks/<tasks_from>(.yml|.yaml)`, merges
  defaults/handlers into the play, tags spliced tasks with the role's
  dir so `template:`/`copy:` src lookups resolve correctly, pushes the
  include task's `when:` down onto each spliced task (AND-merged), and
  prepends a synthetic `set_fact:` for the include's `vars:` block.
  Recursive (16-deep cap) with (name, tasks_from) cycle detection. 14
  unit tests in `playbook::role`/`playbook::task_op` plus an e2e
  assertion in `tests/roles_and_facts.rs` that `/tmp/rsansible-include-role`
  contains the vars-supplied value on every container.

**Phase 2b acceptance (met):** `tests/roles_and_facts.rs`'s 3-container
e2e exercises role flatten, role defaults precedence, the `template:`
op resolving against the role's `templates/` dir, the implicit
`Gathering Facts` task populating `ansible_*` keys, and the role's
handler firing at end-of-play on template change. 118 ctl lib tests
green plus +5 agent tests for the gather_facts module (os-release
parsing, civil-from-days date decomposition, fact collection) and a
new wire framing roundtrip for `OpGatherFacts`.

---

## Phase 3 — Become + filesystem/service modules

**Estimated:** ~1200 LoC, mostly agent-side.

- [x] **`become:` / `become_user:` on every op** — controller-side
  argv wrapping. New `crates/ctl/src/become_.rs` module computes
  effective become per (task, ctx) and mutates the rendered `TaskOp`
  before `to_wire_op`: `Shell` gets `sudo -n -u <user> -- ` prepended
  to the command string, `Exec` gets the same as a structural argv
  prefix. Non-argv ops (`write_file:` / `template:` / `copy:` /
  `gather_facts`) pass through — the agent's own privilege level
  dictates whether they succeed; agent-side `become_user`-for-writes
  is deferred. Both `Task` and `Play` carry `become_: Option<bool>` +
  `become_user: Option<String>`; `playbook::inherit_become_defaults`
  push-down pass at load time folds play defaults into tasks that left
  the fields as `None` (an explicit `Some(false)` opts out of inherited
  `true`). Inventory `ansible_become` / `ansible_become_user` are
  consulted at runtime when task+play both leave `become_` as `None`.
  `become_user` is validated as a POSIX username — `[A-Za-z_][A-Za-z0-9_-]*`
  up to 32 chars — so shell metacharacters can't escape the wrap. 14
  unit tests in `become_` + 4 parser + 4 validator + 2 inheritance +
  one 1-container e2e (`tests/become_e2e.rs`) that proves play default
  → root, per-task `become_user: becometest` → flipped uid, per-task
  `become: false` → opted-out (ran as the SSH login user).
- [x] **`OpStat`** — read-only filesystem probe. New wire op kind=4
  (`{path, follow}`); agent emits a JSON object on stdout with
  `exists` / type bits (`isreg`/`isdir`/`islnk`/`isblk`/`ischr`/
  `isfifo`/`issock`) / 4-digit octal `mode` / `size` / `uid`+`gid` /
  `mtime`+`atime`+`ctime` (fractional seconds) / `checksum` (sha256
  hex for regular files) / `lnk_source` (when `follow: no` and the
  path is a symlink). Controller-side `TaskOp::Stat(StatOp)` with
  `follow:` defaulting to true and accepting Ansible booleans
  (`yes`/`no`/`on`/`off` plus `true`/`false`). After the op finishes,
  the orchestrator lifts the parsed stdout JSON into
  `register.stat.<field>`, matching Ansible's
  `foo_stat.stat.exists` contract — implemented via a generic
  `RegisterValue.extra: BTreeMap<String, JsonValue>` so other modules
  can opt in later without further core changes. `path` is Jinja-
  rendered at task time. 6 stat unit tests in the agent + 6
  parser/validator tests + 1 register-lifting unit test + a
  single-container e2e (`tests/stat_e2e.rs`) covering regular file
  (incl. exact sha256 of `"hello\n"`), directory, missing path, and
  `when: foo.stat.exists` gating both positive and negative paths.
- [x] **`OpFile`** — Ansible's `file:` task module. New wire op kind=5
  (`{path, state, has_mode, mode, owner, group, recurse}`); agent
  module supports the four states gothab uses: `directory` (mkdir -p
  + chmod/chown; recurse flag walks descendants), `absent` (rm -rf for
  dirs, unlink for files/symlinks; no-op when missing), `touch`
  (create-if-missing + bump atime/mtime, always-changed per Ansible's
  contract), and `file` (assert regular-file existence; apply
  mode/owner/group). Idempotency is real: `changed` is set iff the
  filesystem actually moved. Owner/group are resolved via a 30-line
  `/etc/passwd` + `/etc/group` parser (NSS-free; agent stays FFI-
  light and `forbid(unsafe_code)`). `chown` and the utime bump shell
  out to `/usr/bin/chown -h` and `/usr/bin/touch -a -m` for the same
  reason — keeps us off `rustix::fs::{Uid,Gid}::from_raw` which are
  unsafe in 0.38. Controller-side `TaskOp::File(FileOp)` with a
  `FileState` enum and a mode deserializer that accepts both YAML
  ints (`0o755`) and Ansible's stringly-typed octal (`"0755"`).
  `path`, `owner`, and `group` are Jinja-rendered at task time;
  template precompile checks them. `recurse: yes` is validated to
  reject any state other than `directory`. Caveat documented in
  `examples/file.yaml`: the file op is not argv-wrapped by `become:`
  (matches `write_file`/`template`/`copy`/`gather_facts`), so
  `owner:` only works when the agent itself runs with CAP_CHOWN —
  agent-side privilege escalation for non-argv ops is a separate
  Phase 3+ deferral. 10 agent unit tests (per state + idempotency +
  recurse + passwd parser) + 7 parser tests + 3 validator tests +
  one single-container e2e (`tests/file_e2e.rs`) running an 11-task
  playbook whose internal `assert:` chain validates every
  changed/no-op claim along the directory → idempotent → touch →
  chmod-changed → chmod-noop → recurse → absent → absent-noop path.
- [x] **`OpLineInFile`** — idempotent single-line text edit. Wire op
  kind=7 with path/regexp/line/state/has_mode+mode/create/insertbefore/
  insertafter/backrefs. `state=present` ensures the line is there
  (replace by regexp match, or by literal `line` equality); `state=absent`
  removes every matching line. `insertbefore`/`insertafter` (regex
  anchors) and the literal `EOF` for append-place new lines. `backrefs`
  substitutes regex captures into `line`; with no match the file is
  left untouched (Ansible's documented rule). `create=yes` seeds the
  file (with `mode`) when missing. Atomic write via sibling-tempfile +
  rename; preserves original mode unless `mode` is given. `changed=1`
  iff bytes actually moved on disk. e2e covers create / idempotent
  no-op / regex-replace / insertafter / backrefs / state=absent in
  one playbook.
- [x] **`OpBlockInFile`** — idempotent multi-line block edit. Wire op
  kind=8 with path/block/marker/marker_begin/marker_end/state/
  has_mode+mode/create/insertbefore/insertafter. The block body is
  delimited by two marker lines built from `marker` with the literal
  `{mark}` token substituted for `marker_begin` (top) and `marker_end`
  (bottom). Defaults follow Ansible: marker = "# {mark} ANSIBLE
  MANAGED BLOCK", begin/end = BEGIN/END. Replace-in-place when a
  block already exists; otherwise place via `insertbefore`/
  `insertafter` (last-match for after, like Ansible) or append. Empty
  `block` + state=present means "remove the block if it exists" —
  also matches Ansible. Atomic write via sibling-tempfile + rename;
  `changed=1` iff bytes actually moved on disk. e2e covers seed →
  no-op → body update → custom-marker block placement → state=absent
  with the custom block surviving.
- [x] **`OpSystemd`** — start / stop / restart / reload / enable /
  disable / mask / unmask with proper "did this actually change anything"
  reporting. Wire op kind=9 with name/state/enabled/masked/daemon_reload/
  no_block. Action order matches Ansible: `daemon-reload` (if requested)
  → mask/unmask transition → enable/disable transition → state transition
  (started/stopped/restarted/reloaded). Probes via `systemctl is-active`
  and `systemctl is-enabled` for idempotency: `started`/`stopped` only
  fire when current state disagrees; `restarted`/`reloaded` always
  report changed (Ansible contract). `--no-block` is inserted before
  the subcommand when set. `systemctl` binary path is overridable via
  `RSANSIBLE_SYSTEMCTL` env (used by tests with a stub). e2e plants a
  stub systemctl in /usr/local/bin (via `write_file:` + `become: true
  install`) on an Alpine sshd container and exercises start (changed)
  → re-start (no-op) → restart (changed) → enable (changed) →
  daemon_reload + start (daemon-reload precedes start in log) → mask
  (changed).
- [x] **`OpPackage`** — generic package-manager wrapper (one wire op
  per manager kept dying the moment a second manager landed, so the
  protocol carries a single op with a `manager` discriminator byte:
  0=auto, 1=apt, 2=dnf (reserved), 3=yum (reserved), 4=apk (reserved),
  5=pacman (reserved), 6=zypper (reserved)). Wire op kind=10 with
  manager + name(s) + state (present/absent/latest) + update_cache +
  cache_valid_time + purge + autoremove + default_release +
  allow_unauthenticated. The wire shape carries the *union* of all
  backends' knobs; each backend ignores fields it doesn't consume.
  Batched: one wire op carries the full list of package names; the
  apt backend probes each via `dpkg-query -W` and feeds only the
  missing/present subset to `apt-get install -y` / `apt-get remove -y`.
  For `state=latest` the agent captures pre- and post-versions to
  drive accurate `changed` reporting. `update_cache` honors
  `cache_valid_time` by checking `/var/cache/apt/pkgcache.bin` mtime.
  apt-get is invoked with `DEBIAN_FRONTEND=noninteractive`.
  `RSANSIBLE_APT_GET` / `RSANSIBLE_DPKG_QUERY` env overrides power the
  tests with stubs. YAML surface: `apt:` (pins manager=Apt, accepts
  the full apt-specific knob set), `package:` (manager=Auto; the
  agent picks the backend by probing PATH for known manager binaries —
  refuses apt-only knobs at parse time since we can't promise the
  auto-detected backend will honor them). Both keys accept `name:` as
  string or list and `state:` aliases (installed/removed). Agent layout:
  `modules/package/mod.rs` (dispatch + auto-detect) +
  `modules/package/apt.rs` (apt backend). e2e plants apt-get +
  dpkg-query stubs on an Alpine container and exercises install
  (changed) → re-install (no-op) → batch install (only-missing) →
  remove (changed) → second remove (no-op) → latest with version bump
  (changed) → latest stable (no-op) → update_cache + install (update
  precedes install) → `package:` (auto-detect picks apt backend via
  PATH probe, installs htop).
- [x] **`OpUfw`** — Uncomplicated Firewall control. Wire op kind=11
  with op (rule/enable/disable/reset/default/reload/logging) +
  rule/direction/proto/from_ip/from_port/to_ip/to_port/interface/
  comment/delete/insert. YAML dispatches op kind by inspecting `state:`
  (enabled/disabled/reloaded/reset) first, then `default:`, then
  `logging:`, then `rule:`; common aliases (`from`/`src`,
  `to`/`dest`, `if`/`interface`) accepted. Idempotency probes `ufw
  status verbose` and matches the requested rule against the
  normalized rule list (loose match on verb + port/proto + direction)
  before any mutation. enable/disable/reset use `--force`. e2e plants
  a stub ufw in /usr/local/bin on an Alpine container and exercises
  enable (changed) → enable (no-op) → allow ssh (no-op since stub
  status reports it) → allow https (changed) → default deny (no-op
  since current matches) → logging high (changed).
- [x] **`OpWaitFor`** — port-ready (host + port + timeout) or path-exists.
  Wire op kind=6 with host/port/path/state/timeout_ms/delay_ms/sleep_ms.
  Two modes: TCP probe (`host`+`port`) or path probe (`path`); mutual
  exclusion enforced at parse, validate, and agent. `state: present`
  (default; aliases `started`) waits for it to come up; `state: absent`
  (alias `stopped`) waits for it to go away. `timeout`/`delay`/`sleep`
  accept seconds (Ansible-style) and convert to ms. TCP probe uses
  `TcpStream::connect_timeout` with a 1s per-attempt deadline; the
  agent parks the sync wait loop on `spawn_blocking`. e2e via
  `examples/wait_for.yaml` covers path-appears, path-disappears, and
  TCP-already-listening.
- [x] **Idempotency reporting sweep** — audited every agent module
  against the `TaskDone.changed` contract handlers depend on. Findings
  per module:
  - `write_file`: bytes+mode diff against on-disk; `changed=1` iff
    bytes or mode bits actually moved. ✓ (smoke.rs validates both
    branches).
  - `file`: per-state (`directory`/`file`/`touch`/`absent`) returns
    accurate `changed` from `apply_*` helpers; `touch` is
    Ansible-faithfully always-changed. ✓
  - `lineinfile` / `blockinfile`: render new bytes, compare against
    existing, `changed=1` iff different. Mode-only delta on an
    otherwise-unchanged file is reported as `changed=1`. ✓
  - `stat` / `gather_facts` / `wait_for`: read-only modules, always
    `changed=0`. ✓
  - `systemd`: per-action flag accumulation; `started`/`stopped`/
    `enabled`/`masked` gated by `is-active`/`is-enabled` probes;
    `restarted`/`reloaded`/`daemon_reload` always-changed (matches
    Ansible). ✓
  - `ufw`: per-op `status verbose` probe; rules/defaults/logging only
    flip changed when state moves; `reset`/`reload` always-changed
    (matches Ansible). ✓
  - `package/apt`: pre/post `dpkg-query` version compare; `present`
    skips when installed, `latest` only reports changed on version
    move, `absent` skips when not installed. ✓
  - `exec` / `shell`: `changed = (exit_code == 0)`. Diverges in
    spirit from Ansible's "always-changed for command/shell" only on
    the failure branch — but the controller treats `exit_code != 0`
    as task failure (BodyResult::Failed) and `ignore_errors:` isn't
    supported yet, so the failure-branch `changed` value isn't
    observable. Comment in `modules/exec.rs:126` already documents
    the intent. Revisit when `ignore_errors:` ships.
  Controller side: `RegisterValue::from_exec` lifts `done.changed`
  into `register.changed`; `enqueue_notifies` gates on
  `!skipped && changed && !task.notify.is_empty()`. ✓ No drift; no
  source changes required.

**Acceptance:** `common` role applies end-to-end (users, packages, ssh
config, ufw rules, netplan, sshd handlers fire on change).

---

## Phase 4 — Templates + HTTP

**Estimated:** ~600 LoC.

- [ ] **`OpTemplate`** — render minijinja on the controller, ship the
  result as `OpWriteFile`. Avoids putting jinja state in the agent.
  16 template sites in gothab.
- [ ] **Custom filter set** in `crates/ctl/src/template.rs`:
  - [ ] `b64encode` / `b64decode` (etcd CA bundle)
  - [ ] `from_json` (REST response parsing in drills)
  - [ ] `to_json` (status payloads)
  - [ ] `regex_replace(pattern, replacement)` (drill endpoint mapping)
  - [ ] `mandatory` (assert var defined)
  - already built into minijinja: `default`, `bool`, `int`, `map`,
    `selectattr`, `split`, `join`, `length`, …
- [ ] **`OpUri`** — HTTP client (`reqwest` w/ rustls) — method, url,
  headers, body, expected status. Returns status + body + parsed JSON.
  8 uri sites; Patroni & Sentinel REST APIs in drills.
- [ ] Validation pass: precompile every `.j2` referenced by a `template:`
  task at validate-time. Already hooked into `template::precompile_all`.

**Acceptance:** `etcd` role applies (templated `etcd.conf.j2`,
templated systemd units, CA cert distribution).

---

## Phase 5 — Heavy modules for drill playbooks

**Estimated:** ~1500 LoC.

- [ ] **`OpPostgresql`** — query and extension management
  - 11 `postgresql_query` + 3 `postgresql_ext` sites in gothab.
  - `tokio-postgres` over UNIX socket (Patroni clusters listen there).
  - Returns rows as JSON-ish for `register:` consumption.
- [ ] **`OpOpenSslPrivkey` / `OpOpenSslCsr` / `OpX509Certificate`**
  - 4 `openssl_privatekey` + 4 `openssl_csr_pipe` + 4 `x509_certificate_pipe`
    sites — the etcd CA bootstrap.
  - `rcgen` is the obvious crate; or `aws-lc-rs` since we already pulled
    it in for russh, but rcgen is simpler.
  - Output keys/certs need to be returnable via `register` (they're
    consumed by later `copy:` tasks).
- [ ] **`OpAsync` / async polling**
  - 2 async sites in drill-failover (continuous-writer side-process).
  - Agent spawns a child, returns a job handle, later tasks poll it.
  - Implies a new op kind plus a tracking table inside the agent.
- [ ] **`OpGetUrl` / `OpUnarchive`** — optional, can be replaced with
  shell, but the modules are tiny and they show up 12 times total. Worth
  it if we want to advertise the module list.

**Acceptance:** both `drill-failover.yml` and `drill-valkey-failover.yml`
run against an existing cluster.

---

## Cross-cutting

These don't fit neatly into a phase but should happen alongside the work:

- [x] **Tags** (`tags:` + `--tags` / `--skip-tags`) — controller-side
  task-dispatch gate, no wire change. `tags:` accepted on tasks and on
  `roles:` invocations as either a bare string or a YAML list; empty
  entries rejected at parse. Role-flatten propagates `RoleSpec.tags`
  onto every task and handler pulled from that invocation (deduped +
  sorted); `include_role:` propagates the include task's own `tags:`
  onto the spliced tasks the same way. CLI exposes `--tags` and
  `--skip-tags` (both repeatable, comma-splitting via
  `value_delimiter`); they resolve to an `Arc<TagFilter>` consulted at
  dispatch time in both `run_play_per_task` and `run_play_per_play`
  (gated right after the `meta: flush_handlers` check). Magic tags
  honored: `always` (task runs unless `--skip-tags always`), `never`
  (task only runs when explicitly opted in via `--tags`), plus the
  `all` and `untagged` CLI selectors. The implicit `Gathering Facts`
  task ships with `tags: ["always"]` so `--tags foo` doesn't
  accidentally drop fact-gathering. Handlers aren't filtered in v1 —
  a notified handler fires if its trigger task fired, regardless of
  `--tags`. Tag-skipped tasks are dropped entirely (no register
  binding, no notify), matching Ansible. 22 `TagFilter` rule-table
  unit tests + 3 task-parse tests + 4 role-flatten tests + a
  5-scenario 1-container e2e (`tests/tags_e2e.rs`) covering no-flags
  / `--tags setup` / `--skip-tags teardown` / `--tags never` /
  `--skip-tags always`.
- [ ] **`--limit` flag** — restrict the run to a host pattern. Ansible
  convention; gothab's bin/ scripts call ansible-playbook with this.
- [ ] **`--check` mode** — dry-run; every op reports what it *would* do
  without changing state. Each new module needs a check-mode codepath.
- [ ] **Better progress output** — current `info!` stream is fine but a
  per-host status line ("[pg1] task 7/15: Configure patroni — changed
  (41ms)") would be a big quality bump.
- [x] **Vault** — landed in Phase 2a (`crates/ctl/src/vault.rs`).
  rustcrypto stack (`aes`+`ctr`+`pbkdf2`+`hmac`+`sha2`+`subtle`+`hex`).
  Used by group_vars/host_vars discovery; one example is
  vault-encrypted in `examples/group_vars/web/secrets.yml`.
- [ ] **Ansible compat shim** — at some point, decide whether we want
  `rsansible run playbook.yaml` to **accept Ansible's exact YAML** or
  diverge. Gothab is the test case. Aim for "accept what gothab uses"
  rather than "accept all of Ansible".

---

## Scope summary

| Phase | LoC est. | Wire changes | Unlocks |
|---|---|---|---|
| 1 | ~1500 | none | bootstrap-etcd-ca.yml |
| 2 | ~800  | +1 op (`OpGatherFacts`) | site.yml first play |
| 3 | ~1200 | +6 ops | site.yml `common` role |
| 4 | ~600  | +1 op (`OpUri`); templates rendered controller-side | site.yml etcd role |
| 5 | ~1500 | +3 ops (`OpPostgresql`, `OpAsync`, x509 family) | drill playbooks |
| **total** | **~5600 LoC** | **+11 ops** | full gothab |

For reference, v0 today is roughly 2000 LoC across all crates. So
running gothab is a ~3.5× larger codebase than what's there now. Not
absurd, but it's a real project, not a weekend.
