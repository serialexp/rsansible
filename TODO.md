# rsansible — roadmap to running gothab

The v0 shipped (`shell`/`exec`/`write_file` over a pushed-agent framed
protocol). To run the real Ansible flows in `~/Projects/gothab/ansible/`
(4 playbooks, 8 roles, ~400 tasks, 17 Jinja templates), the controller
needs a real programming model and the agent needs a wider module set.

Phasing is deliberate: each phase unlocks the next, and Phase 1 alone
should be enough to run `bootstrap-etcd-ca.yml`. Sizing is rough.

**Phases 1, 2, and 3 are complete** (programming model, variable scope
+ facts, become + filesystem/service modules). Their full descriptions
and acceptance criteria live in `TODO_DONE.md`. What's left:

---

## Phase 2 — open follow-ups

- [ ] **Nested groups / boolean selectors** — defer; gothab doesn't
  use either. Add if/when something needs them.

---

## Phase 4 — Templates + HTTP

**Estimated:** ~600 LoC.

- [x] **`OpTemplate`** — render minijinja on the controller, ship the
  result as `OpWriteFile`. Avoids putting jinja state in the agent.
  Shipped in Phase 2b/2c.
- [x] **Custom filter set** in `crates/ctl/src/template.rs`:
  `b64encode` / `b64decode`, `from_json`, `to_json`, `regex_replace`,
  `mandatory`. Built-in minijinja filters cover `default`, `bool`,
  `int`, `map`, `selectattr`, `split`, `join`, `length`, … Shipped in
  Phase 2b/2c.
- [x] **`OpUri`** — HTTP client (`reqwest` w/ rustls) — method, url,
  headers, body, expected status. Returns status + body + parsed JSON.
  8 uri sites; Patroni & Sentinel REST APIs in drills.
- [x] Validation pass: precompile every `.j2` referenced by a `template:`
  task at validate-time. Hooked into `template::precompile_all`.

**Acceptance:** `etcd` role applies (templated `etcd.conf.j2`,
templated systemd units, CA cert distribution).

---

## Phase 5 — Heavy modules for drill playbooks

**Estimated:** ~1500 LoC.

- [x] **`OpPostgresqlQuery` + `OpPostgresqlExt`** — query + extension management. Shipped:
  - Two wire ops (kinds 13, 14). `OpPostgresqlQuery` carries a controller-classified `read_only` byte; `OpPostgresqlExt` carries name/state/version/schema/cascade.
  - Agent uses `tokio-postgres` over UNIX socket (Patroni / peer auth) or TCP. Pure Rust, musl-safe. `simple_query` for the no-args case (text values, real `statusmessage`); typed `query` path for parameterised SQL (common pg oids + String fallback).
  - SQL classifier on the controller (`classify_sql_readonly`) strips comments, splits on unquoted semicolons, and peeks the first keyword: SELECT/SHOW/VALUES/TABLE → read-only; EXPLAIN is read-only unless ANALYZE is on (then it recurses on the wrapped statement); WITH is read-only unless any CTE body or trailing statement contains a mutating keyword token (identifier-aware scanner skips string / dollar-quoted / quoted-identifier bodies). Everything else → mutating. Re-runs post-Jinja in case the rendered SQL differs from the literal source.
  - `--check` skip: mutating SQL is dropped on the controller (no dispatch) and a skipped register is synthesised; `postgresql_ext` still dispatches (the agent's probe-first idempotency is read-only by construction). Per-task `check_mode: false` overrides.
  - Register lifting matches Ansible: `register.query_result[0].col`, `register.rowcount`, `register.statusmessage`; for ext, `register.extension`, `register.state`, `register.prior_version`, `register.version`.
  - Extension version upgrades: when the extension is already present and `version:` differs from the installed version, agent issues `ALTER EXTENSION "<name>" UPDATE TO '<version>'` (`changed=true`); equal versions or unspecified `version:` are no-ops. Server enforces that an update script for the hop exists.
  - v1 caveats: no `named_args` (Ansible's `%(name)s` style) — positional only. The classifier doesn't follow `EXPLAIN ANALYZE EXECUTE <stmt>` into the prepared statement (it conservatively flags as mutating, which is the safe direction).
  - E2E: `crates/ctl/tests/postgresql_e2e.rs` (`#[ignore]`-gated) installs postgres in the sshd container and runs `examples/postgresql.yaml` end-to-end (SELECT + parameterised + INSERT + ext install + idempotent re-run).
- [x] **`openssl_privatekey` / `openssl_csr_pipe` / `x509_certificate_pipe`**
  - Shipped in the TLS chunk (commits `d6a38a9` + `2a49eee`).
  - Controller-side via rcgen + aws_lc_rs; agent unchanged for
    csr_pipe / cert_pipe (synthetic register.content), privkey
    rides on OpWriteFile + the new `only_if_missing` byte.
  - Composite dispatch in the orchestrator: privkey ships blind
    or probes-first based on the wire-cost heuristic.
  - mTLS for `uri:` (PEM bytes on OpUri) shipped alongside in
    `e5ad8a2`.
  - Cross-run signing now works: on `csr_pipe` cache miss the
    controller dispatches `OpReadFile` against the agent to fetch the
    on-disk PEM (1 MiB cap), caches it, and signs from there. So a
    play can call `openssl_csr_pipe:` directly against a key
    provisioned in a previous run; no need to chain through an
    `openssl_privatekey:` task each time.
- [x] **`OpAsync` / async polling** — shipped in `fecca35` (agent) +
  `147bac9` (ctl).
  - Wire: `OpAsyncStart` (kind=16) wraps any Op + carries timeout_ms;
    `OpAsyncStatus` (kind=17) polls by `job_id`. Recursive nesting of
    `Op` works through binschema's discriminated_union codec.
  - Agent: in-memory `JobTable` keyed by start-dispatch seq; the inner
    op runs against a capturing mpsc writer so its TaskProgress /
    TaskDone / TaskError bytes get stashed into the entry. Timeout
    enforced server-side. Recursive `dispatch` returns `Pin<Box<dyn
    Future + Send>>` to break the Send-inference cycle.
  - Ctl: `async:` + `poll:` task-level metadata. `async: N` wraps the
    inner op; `poll: M (M>0)` runs an inline status-poll loop on the
    same agent connection until the inner finishes or the deadline
    elapses. `poll: 0` is fire-and-forget — the register holds the
    start envelope.
  - v1 caveats: no `until:` / `retries:` yet, so the canonical
    `async_status:` polling task body is deferred (users wanting to
    wait on a fire-and-forget job have to poll manually via a loop
    or use `poll: M > 0` on the original task). The job table is
    in-memory only; the controller must finish polling before the
    agent disconnects.
- [x] **`OpGetUrl`** — shipped in `fecca35` (wire+agent) + `5dcf346` (ctl).
  - Wire kind=15. Stream download → atomic rename, sha256/sha1/md5
    checksum verification, stat-skip on existing dest, mTLS / CA-bundle
    wiring matching OpUri.
  - Envelope shape mirrors `ansible.builtin.get_url`: url/dest/
    checksum_src/checksum_dest/size/status_code/msg, lifted to the
    register's top level so vendored playbooks unchanged.
  - `checksum_dest` is always the actual sha256 of the on-disk file
    (even on the stat-skip path) — registers stay honest.
- [x] **`OpReadFile` + `slurp:`** — wire kind=18; reads a file on the
  agent and ships its contents back in a base64 `slurp`-shaped
  envelope (`content`/`source`/`encoding`). Lifted to the top level of
  the register so `register.content | b64decode` resolves the way
  vendored playbooks expect. Adds an optional `max_bytes:` safety cap
  (0 = unbounded). Also unlocks cross-run `openssl_csr_pipe:` by
  letting the controller fetch a previously-provisioned on-disk PEM
  on cache miss.
- [x] **`OpUnarchive` + `unarchive:`** — wire kind=19. Pure-Rust
  extractors (musl-safe): `flate2` (miniz_oxide) for gz, `bzip2-rs`
  for bz2, `lzma-rs` for xz, the `tar` crate for tar walking, and
  `zip = "2"` (deflate-only) for zip. Format inferred from the `src`
  extension when `format:` is omitted (auto/tar.gz/tgz/tar.bz2/tbz2/
  tar.xz/txz/tar/zip). Idempotency via `creates:` marker (the agent
  short-circuits without opening the archive when the marker
  exists). `keep_newer:` skips entries whose archive mtime is older
  than the on-disk file. `include:` / `exclude:` filter archive
  entry paths (exact match, no globbing). Owner/group/mode applied
  to all extracted entries post-walk. Envelope matches Ansible's
  `unarchive` return shape (`dest` / `src` / `handler` /
  `extract_results` / optional `files`); top-level lift so vendored
  playbooks resolve `register.files | length` and `register.handler`
  the way they expect. Safety: archive entries with absolute or
  `..`-bearing paths are rejected before any write (zip-slip /
  tar-slip protection); same for symlinks whose targets would
  escape `dest`. v1 caveats: `remote_src: yes` is required (no
  controller→agent archive push — combine with a prior `copy:` /
  `get_url:`); no `extra_opts:` (we don't shell out to `tar`); the
  xz path decompresses into memory before tar-walking (fine for
  the < 100 MiB archives we've seen, fragile beyond that).

**Acceptance:** both `drill-failover.yml` and `drill-valkey-failover.yml`
run against an existing cluster.

---

## Cross-cutting

These don't fit neatly into a phase but should happen alongside the work.
Done items live in `TODO_DONE.md` (Tags, `--limit`, `ignore_errors:`,
Vault).

- [x] **`--check` mode** — dry-run; every op reports what it *would* do
  without changing state. Shipped:
  - Wire envelope carries `TaskDispatch.check_mode` (1 byte) and `TaskDone.skipped` (1 byte).
  - CLI `--check` flag + per-task `check_mode: true/false` YAML override.
  - Per-module behavior: read-only modules pass through; probe-only modules
    (write_file/file/lineinfile/blockinfile/systemd/package/ufw) compute
    `changed` without mutating; exec/shell skip outright; uri is method-aware
    (GET/HEAD pass through, mutating verbs skip).
  - Composite privkey path: forces probe under check_mode, synthesizes a
    `changed=true, skipped=true` result, still caches the generated PEM so
    chained `csr_pipe`/`cert_pipe` produce meaningful register output.
  - Banner + per-task `[CHECK]`/`[WOULD CHANGE]`/`[CHECK OK]` markers + end-of-run summary.
  - Follow-ups: `--diff` (show actual diffs), apt `STATE_LATEST` proper
    `apt-cache policy` parsing under check mode (currently only flags
    missing packages as would-change).
- [ ] **Better progress output** — current `info!` stream is fine but a
  per-host status line ("[pg1] task 7/15: Configure patroni — changed
  (41ms)") would be a big quality bump.
- [ ] **Ansible compat shim** — at some point, decide whether we want
  `rsansible run playbook.yaml` to **accept Ansible's exact YAML** or
  diverge. Gothab is the test case. Aim for "accept what gothab uses"
  rather than "accept all of Ansible".

---

## Scope summary

| Phase | LoC est. | Wire changes | Unlocks | Status |
|---|---|---|---|---|
| 1 | ~1500 | none | bootstrap-etcd-ca.yml | ✅ done |
| 2 | ~800  | +1 op (`OpGatherFacts`) | site.yml first play | ✅ done |
| 3 | ~1200 | +6 ops | site.yml `common` role | ✅ done |
| 4 | ~600  | +1 op (`OpUri`); templates rendered controller-side | site.yml etcd role | ✅ done |
| 5 | ~1500 | +3 ops (`OpPostgresql`, `OpAsync`, x509 family) | drill playbooks | done — x509 ✅, postgresql ✅, async ✅, get_url ✅, read_file ✅, unarchive ✅ |
| **total** | **~5600 LoC** | **+13 ops** | full gothab | |

For reference, v0 today is roughly 2000 LoC across all crates. So
running gothab is a ~3.5× larger codebase than what's there now. Not
absurd, but it's a real project, not a weekend.

## drill-failover blockers surfaced 2026-05-18

Two `block:`-related orchestrator bugs found by running gothab's
drill-failover.yml live and fixed in the same session; one
playbook-level dependency surfaced after, NOT yet implemented:

1. **(FIXED)** `run_once:` on tasks nested inside a `block:` deadlocked
   in production. Root cause: non-runner hosts awaited
   `OnceCell::get_or_init(|| pending().await)`, which holds the cell's
   init slot — so the runner's later `cell.set(...)` returned Err
   (swallowed by `let _ =`) and the awaiter never woke. Replaced
   the bare `OnceCell` with a `RunOnceSlot { cell: OnceCell, notify:
   Notify }` so `publish()` actually wakes external `wait()`ers.
   Live drill now progresses through the entire block.

2. **(FIXED)** `register:` from an `async: N` task (with `poll: 0`)
   didn't surface `ansible_job_id` at the register top level, so the
   follow-up `async_status: jid: "{{ writer_async.ansible_job_id }}"`
   rendered to `""` and failed with "expected u32 after rendering,
   got ''". Added `lift_async_envelope` mirroring the existing
   per-module lift pattern (postgresql_query, slurp, etc.); called
   from the orchestrator when `async_wrap.is_some()` OR the inner op
   is `AsyncStatus`.

3. **(FIXED for both strategies)** Cross-host `hostvars[<peer>].…`
   access into the running play's per-host state (facts, set_facts,
   registers, plus `inventory_hostname`).
   - **per_task:** `merge_dynamic_hostvars` rebuilds `world.hostvars`
     from every host's current `HostCtx` before each task (and the
     implicit end-of-play flush). All ctxs are back in the map at
     task boundaries — the fanout owns them by-value mid-task and
     re-inserts via `apply_per_host_result` — so no locking is
     needed. Barrier-consistent peer visibility.
   - **per_play:** `merge_dynamic_hostvars_locked` reads from an
     `Arc<TokioRwLock<HostCtx>>` per host, written by each walker
     after every completed task. Peer views are
     eventually-consistent ("the peer's last committed task"),
     which matches per_play's no-barrier shape; documented in
     CLAUDE.md.

## Gothab live-fire results (2026-05-18, commit 14107b8)

Tried `rsansible validate` against every gothab playbook + one live run.

- [x] **bootstrap-etcd-ca.yml** parses AND runs end-to-end on localhost.
  Correctly bailed at the "refuse to overwrite" assert because the CA
  is already provisioned. Tasks exercised: slurp+loop, assert with
  fail_msg, b64decode in jinja, set_fact. Matches Ansible semantics.

- [x] **drill-failover.yml** (24 tasks) — parses cleanly. Not run
  (hits production).

- [x] **drill-restore.yml** (7 tasks) — parses cleanly. Not run
  (triggers a real drill on app-1).

- [ ] **drill-valkey-failover.yml** parse error: `when:` accepts a
  YAML sequence in Ansible (AND-joins entries), rsansible rejects
  it as "`when` must be a string." Fix at `Task::deserialize` —
  detect Sequence and join with `(a) and (b)`. Small.

- [ ] **pgbackrest.yml** parse error: `copy:` with the `content:`
  form (inline content rather than `src:`). Need to add a `content`
  field to `CopyOp` and let `src` be optional when `content` is
  set. Small.

- [ ] **site.yml** parse error: `community.general.timezone` module
  unsupported. The FQCN stripping works fine (it's the bare
  `timezone` that's unknown). Easiest path: implement a `timezone:`
  module that writes `/etc/timezone` + `timedatectl set-timezone`
  via the existing exec channel. Medium.

- [ ] **Doubled log output**: every tracing line prints twice when
  running `rsansible run` (e.g. "agent up host=…" appears 2×).
  `tracing_subscriber::fmt().init()` only happens once in main.rs;
  suspect a duplicate `set_global_default` somewhere or a fmt layer
  being added twice. Cosmetic, but distracting in real-world output.

- [ ] **Other unsupported FQCN modules surfaced by `grep -roE`** in
  gothab roles (not yet hit because site.yml fails earlier, but will
  block once we land timezone):
  - `community.docker.docker_image`
  - `community.general.counter`
  - `community.general.ufw` — we have `ufw` already; verify FQCN
    routes there
  - `community.postgresql.postgresql_db`
  - `community.postgresql.postgresql_membership`
  - `community.postgresql.postgresql_user`
  - `community.crypto.x` — likely truncated grep, probably
    `x509_certificate_pipe` which we already have

## Test-infrastructure flake (pre-existing)

- [ ] **ETXTBSY race in stub-script tests.** A handful of agent tests
  (`getent`, `hostname`, `pip`, possibly others) write a small shell
  script into a tempdir and then exec it. When several such tests
  run in parallel, Linux returns ETXTBSY for one of the execs:
  thread A finishes its `std::fs::write` (closes its fd in A's
  parent), but thread B forked between A's open and close — B's
  child inherited A's write fd and still holds it open until B's
  child execs. A's subsequent exec of its own script sees the
  inherited write fd from B's child and refuses with ETXTBSY.
  Rate: maybe 1 in 5 full-workspace runs. Re-running fixes it.
  Real fix: process-wide mutex around the write-then-exec window in
  the test helpers, OR a single shared write_script helper that
  serialises across the binary. Out of scope for now — flake is
  rare enough that it's noise, not a blocker.
