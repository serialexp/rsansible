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
- [ ] **`OpUnarchive`** — survey-elevated to next priority. Used by
  26/57 real-world repos (the #1 unshipped Ansible module by repo
  breadth). Wire op + agent should support `tar.gz` / `tar.bz2` /
  `tar.xz` / `zip` extraction with idempotency by mtime-stamp or by
  presence-of-marker-file. Owner/group/mode on extracted files. Not
  yet started.

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
| 5 | ~1500 | +3 ops (`OpPostgresql`, `OpAsync`, x509 family) | drill playbooks | done — x509 ✅, postgresql ✅, async ✅, get_url ✅, read_file ✅ |
| **total** | **~5600 LoC** | **+12 ops** | full gothab | |

For reference, v0 today is roughly 2000 LoC across all crates. So
running gothab is a ~3.5× larger codebase than what's there now. Not
absurd, but it's a real project, not a weekend.
