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

- [ ] **`OpPostgresql`** — query and extension management
  - 11 `postgresql_query` + 3 `postgresql_ext` sites in gothab.
  - `tokio-postgres` over UNIX socket (Patroni clusters listen there).
  - Returns rows as JSON-ish for `register:` consumption.
- [x] **`openssl_privatekey` / `openssl_csr_pipe` / `x509_certificate_pipe`**
  - Shipped in the TLS chunk (commits `d6a38a9` + `2a49eee`).
  - Controller-side via rcgen + aws_lc_rs; agent unchanged for
    csr_pipe / cert_pipe (synthetic register.content), privkey
    rides on OpWriteFile + the new `only_if_missing` byte.
  - Composite dispatch in the orchestrator: privkey ships blind
    or probes-first based on the wire-cost heuristic.
  - mTLS for `uri:` (PEM bytes on OpUri) shipped alongside in
    `e5ad8a2`.
  - v1 caveat: csr_pipe must run in the same play as its privkey
    task — cross-run signing of an existing on-disk key needs
    `OpReadFile`, which is deferred.
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
| 5 | ~1500 | +3 ops (`OpPostgresql`, `OpAsync`, x509 family) | drill playbooks | partial — x509 ✅, postgresql + async open |
| **total** | **~5600 LoC** | **+11 ops** | full gothab | |

For reference, v0 today is roughly 2000 LoC across all crates. So
running gothab is a ~3.5× larger codebase than what's there now. Not
absurd, but it's a real project, not a weekend.
