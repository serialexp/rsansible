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

- [ ] **Inventory groups**
  - groups + group membership; a host can be in multiple groups. Top-level
    `all`. Inventory file format extension:
    ```yaml
    groups:
      postgres:
        hosts: [pg1, pg2]
      etcd:
        hosts: [e1, e2, e3]
        children: [some_other_group]
    ```
  - resolve `hosts: [postgres, !pg1]` syntax (exclusions) — common in
    gothab.
- [ ] **`group_vars/` and `host_vars/` directories**
  - load `inventory_dir/group_vars/<group>.yml` and `host_vars/<host>.yml`
    for every host. Mirror Ansible's discovery rules.
- [ ] **Role `defaults/main.yml` and `vars/main.yml`**
  - lowest-priority defaults, slightly-higher-priority vars. 8 roles in
    gothab use these heavily.
- [ ] **Variable precedence chain** (matches Ansible's where reasonable):
  ```
  role defaults  <  inventory group_vars  <  inventory host_vars
                <  play vars  <  set_fact  <  register  <  CLI --extra-vars
  ```
- [ ] **Templated value resolution**
  - any string in any var, any op argument, any when/register/set_fact
    field can contain Jinja. Resolved against the current `HostCtx` at
    the moment the task starts. Single pass — no recursive lazy
    expansion (Ansible does this; keep it simple).
- [ ] **`OpGatherFacts` agent op + corresponding `gather_facts:` directive**
  - returns a flat string-keyed dict. Minimum keys for gothab:
    `ansible_hostname`, `ansible_fqdn`, `ansible_host`, `ansible_port`,
    `ansible_date_time` (ISO-8601), `ansible_distribution`,
    `ansible_distribution_release`, `ansible_default_ipv4` (best-effort).
  - implies one new op kind in the schema.

**Acceptance:** `site.yml`'s first play (common role) renders correctly
against gothab's inventory + group_vars.

---

## Phase 3 — Become + filesystem/service modules

**Estimated:** ~1200 LoC, mostly agent-side.

- [ ] **`become:` / `become_user:` on every op**
  - either: add to `Task` metadata (controller wraps argv in
    `sudo -n -u <user> --`), or: add a `become` field to every op in the
    schema (agent wraps). Pick controller-side wrapping for simplicity;
    only requires changes to argv/command construction.
  - 45 explicit sites in gothab plus play-level default; ansible.cfg
    already requires sudo.
- [ ] **`OpStat`** — returns existence, type, mode, owner/group, size,
  mtime, sha256. 10 stat sites in gothab.
- [ ] **`OpFile`** — proper file module: ensure absent/file/directory/link
  with mode/owner/group, atomic. Subsumes some uses of write_file's mode
  param plus chmod via shell. 26 file sites.
- [ ] **`OpLineInFile` / `OpBlockInFile`** — idempotent line/block edits
  using anchored regex; preserves file mode/ownership. 6 sites.
- [ ] **`OpSystemd`** — start / stop / restart / reload / enable /
  disable / mask / unmask with proper "did this actually change anything"
  reporting. 39 sites. Wraps `systemctl`.
- [ ] **`OpApt`** — name(s), state (present/absent/latest), update_cache.
  Wraps apt-get with DEBIAN_FRONTEND=noninteractive. 13 sites.
- [ ] **`OpUfw`** — allow/deny/limit + from/to/port/proto + reset/enable.
  14 sites. Wraps `ufw`.
- [ ] **`OpWaitFor`** — port-ready (host + port + timeout) or path-exists.
  5 sites. Tiny.
- [ ] Idempotency reporting: every module sets `TaskDone.changed`
  correctly so handlers fire only when state actually changed. This is
  the contract handlers depend on.

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

- [ ] **Tags** (`tags:` + `--tags` / `--skip-tags`). 36 sites. Skippable
  for v1 but obvious quality-of-life.
- [ ] **`--limit` flag** — restrict the run to a host pattern. Ansible
  convention; gothab's bin/ scripts call ansible-playbook with this.
- [ ] **`--check` mode** — dry-run; every op reports what it *would* do
  without changing state. Each new module needs a check-mode codepath.
- [ ] **Better progress output** — current `info!` stream is fine but a
  per-host status line ("[pg1] task 7/15: Configure patroni — changed
  (41ms)") would be a big quality bump.
- [ ] **Vault** — none used in gothab today (verified by survey), so
  defer. If it ever shows up, look at `age` or `aws-lc-rs` for symmetric
  decryption.
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
