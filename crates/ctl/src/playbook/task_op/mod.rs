//! Task YAML types and conversion to wire `Op` messages.
//!
//! A task is `{ name: <str>, [metadata...], <body-kind>: <body-payload> }`.
//! The body kind is identified by a top-level key (Ansible-style): one of
//! `shell`, `exec`, `write_file`, `assert`, `fail`, `set_fact`,
//! `import_tasks`, `meta`. Metadata keys (`when`, `register`, `loop`,
//! `loop_control`, `tags`, `name`, `delegate_to`, `run_once`, `notify`)
//! sit alongside.
//!
//! Serde derives can't express "exactly one of N body keys, plus any of M
//! metadata keys, plus reject the rest" — `flatten` + an externally-tagged
//! enum silently picks the first body key and fights `deny_unknown_fields`.
//! So Task has a hand-written `Deserialize` that:
//!
//!   * requires `name: <str>`
//!   * extracts metadata fields if present (each strongly typed)
//!   * requires exactly one body key from the BODY_KEYS list
//!   * rejects everything else
//!
//! The body sub-types keep their derived `Deserialize` with
//! `deny_unknown_fields` to catch typos one level down.

use anyhow::{anyhow, Result};
use rsansible_wire::{
    msg::{
        op_async_status, op_authorized_key, op_blockinfile, op_exec, op_file, op_gather_facts,
        op_get_url, op_getent, op_group, op_hostname, op_iptables, op_lineinfile, op_package,
        op_postgresql_ext, op_postgresql_query, op_repository, op_shell, op_stat, op_systemd,
        op_ufw, op_uri, op_user, op_wait_for, op_write_file,
    },
    Op,
};
use serde::{de::Error as _, Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::path::PathBuf;

mod shared;
mod shell;
mod exec;
mod command;
mod write_file;
mod template;
mod copy;
mod stat;
mod file;
mod wait_for;
mod lineinfile;
mod blockinfile;
mod systemd;
mod authorized_key;
mod getent;
mod group;
mod hostname;
mod package;
mod repository;
mod user;
mod iptables;
mod ufw;
mod uri;
mod openssl;
mod postgresql;
mod get_url;
mod slurp;
mod unarchive;
mod tempfile;
mod block;

pub use block::BlockSpec;
pub use blockinfile::{BlockInFileOp, BlockInFileState};
pub use command::CommandOp;
pub use copy::CopyOp;
pub use exec::ExecOp;
pub use file::{FileOp, FileState};
pub use get_url::GetUrlOp;
pub use lineinfile::{LineInFileOp, LineInFileState};
pub use openssl::{OpenSslCsrPipeOp, OpenSslPrivkeyOp, X509CertificatePipeOp};
pub use authorized_key::{AuthorizedKeyOp, AuthorizedKeyState};
pub use getent::GetentOp;
pub use group::{GroupOp, GroupState};
pub use hostname::HostnameOp;
pub use package::{PackageManager, PackageOp, PackageState};
pub use repository::{RepositoryManager, RepositoryOp, RepositoryState};
pub use user::{UserOp, UserState};
pub use postgresql::{classify_sql_readonly, PostgresqlExtOp, PostgresqlQueryOp};
pub use shell::ShellOp;
pub use slurp::SlurpOp;
pub use stat::StatOp;
pub use systemd::{SystemdOp, SystemdState};
pub use template::TemplateOp;
pub use tempfile::{TempfileKind, TempfileOp};
pub use iptables::{IptablesAction, IptablesIpVersion, IptablesOp, IptablesRuleState};
pub use ufw::{UfwOp, UfwOpKind};
pub use unarchive::UnarchiveOp;
pub use uri::UriOp;
pub use wait_for::{WaitForOp, WaitForState};
pub use write_file::WriteFileOp;

use package::parse_package_body;
use shared::{read_pem_if_set, take_int_or_template_string, take_optional_string, take_string_or_bool, take_when_field};


#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub name: String,
    pub body: TaskBody,
    /// `when:` — a single Jinja expression; the task is skipped on a host
    /// where this evaluates to a falsy value.
    pub when: Option<String>,
    /// `register: my_result` — name to bind the result under in the host's
    /// register dict.
    pub register: Option<String>,
    /// `loop:` — iterate the task over a sequence. Two shapes: an inline
    /// YAML list (`loop: [a, b, c]`) or a Jinja expression string.
    pub loop_spec: Option<LoopSpec>,
    /// `loop_control:` — currently only `loop_var:` is supported (rename
    /// `item`). Any other key is rejected.
    pub loop_control: Option<LoopControl>,
    /// `tags:` — currently parsed and stored but not yet honored by the
    /// orchestrator (Phase 1a defers `--tags`/`--skip-tags` filtering).
    pub tags: Vec<String>,
    /// `delegate_to: somehost` — Jinja-templated hostname. The task body
    /// runs against this host's connection, but register/set_fact effects
    /// land in the *originating* host's context (Ansible semantics).
    pub delegate_to: Option<String>,
    /// `run_once: true` — exactly one host (the first targeted, or the
    /// `delegate_to` target) runs the task; the resulting register/set_fact
    /// is broadcast to every other targeted host.
    pub run_once: bool,
    /// `notify: [handler_a, handler_b]` (or a single string). Handler
    /// names are queued onto the host's pending-handlers set when the
    /// task changes; deduped and flushed at end-of-play (or on `meta:
    /// flush_handlers`). Names are Jinja-templated at enqueue time.
    pub notify: Vec<String>,
    /// Path of the role directory this task came from, if the task was
    /// pulled in by the role-flatten pass. `None` for tasks declared
    /// directly under a play. Used by `TaskOp::Template` to resolve
    /// `src:` relative to the role's `templates/` directory.
    ///
    /// Not Deserialize-able — populated at load time.
    pub role_dir: Option<PathBuf>,
    /// `become: true|false` — run this task with elevated privileges
    /// via `sudo`. `None` means "inherit from the play's become
    /// keyword" — a play-level default push-down pass at load time
    /// fills it in. `Some(false)` explicitly opts out of an inherited
    /// `become: true`. The orchestrator wraps `shell:` / `exec:` argv
    /// with `sudo -n -u <become_user> --` when this is true; non-argv
    /// ops (`write_file:` / `template:` / `copy:` / `gather_facts`)
    /// run with the agent's own privileges and rely on the agent
    /// having been pushed as a sufficiently privileged user.
    pub become_: Option<bool>,
    /// `become_user: <name>` — target user for `become: true`. None
    /// means "inherit from play, then default to root". Only meaningful
    /// when `become_` resolves to true at runtime.
    pub become_user: Option<String>,
    /// `ignore_errors: true` — when this task fails on a host, don't
    /// halt the play and don't mark the host failed. The register (if
    /// any) still reflects the failure (`.failed=true`, `.rc=...`) so
    /// downstream `when:` clauses can inspect it. Notifies are NOT
    /// enqueued for an ignored failure — handlers don't fire on
    /// errored tasks regardless. Default `None` (treated as false).
    pub ignore_errors: Option<bool>,
    /// `check_mode: true|false` — per-task override of the run-level
    /// `--check` flag. `None` means "inherit". `Some(true)` forces this
    /// task to dry-run even when the run is live; `Some(false)` forces
    /// this task to run for real even when the CLI passed `--check`
    /// (useful for fact-gathering shells that have no side effects).
    /// The orchestrator computes the effective flag at dispatch time:
    /// `task.check_mode.unwrap_or(ctx.check_mode)`.
    pub check_mode: Option<bool>,
    /// `async: <int|jinja>` — run the task body as a background job on
    /// the agent. Wraps the inner wire op in `OpAsyncStart(timeout_ms
    /// = async*1000, inner)`. `Some("0")` is interpreted as "synchronous"
    /// (matches Ansible: async: 0 disables async). `None` means absent.
    ///
    /// Stored as a String to support templated values like
    /// `async: "{{ (writer_duration_s | int) + 30 }}"`; the runtime
    /// renders + parses to u32 immediately before dispatch.
    pub async_seconds: Option<String>,
    /// `poll: <int|jinja>` — how often the orchestrator polls the job
    /// for completion. `Some("0")` is fire-and-forget: the orchestrator
    /// returns the start envelope (`ansible_job_id`, `started:1`,
    /// `finished:0`) and lets the user poll later via `async_status:`.
    /// `Some("n")` with n>0 makes the orchestrator block, polling every
    /// n seconds until the job finishes or the async deadline expires.
    /// `None` defaults to 10 when async is set (matches Ansible).
    ///
    /// Same templated-string storage as `async_seconds`.
    pub poll_seconds: Option<String>,
    /// `retries: <int|jinja>` — re-run the task up to N times on
    /// failure or until `until:` is satisfied. Stored as a String to
    /// support templated values like
    /// `retries: "{{ (duration_s | int) // 5 }}"`; the runtime
    /// renders + parses to u32 immediately before the retry loop.
    /// `None` = no retry semantics. See ANSIBLE_COMPAT.md §4 for the
    /// `register:`-required rule.
    pub retries: Option<String>,
    /// `delay: <int|jinja>` — seconds between retry attempts. Same
    /// templated-string storage as `retries`. Defaults to 5 seconds
    /// when retry semantics are active and `delay:` is unset
    /// (matches Ansible).
    pub delay: Option<String>,
    /// `until: <jinja expr>` — boolean expression evaluated against
    /// the registered task result after each attempt. Truthy stops
    /// the retry loop. Requires `register:` to also be set; see
    /// ANSIBLE_COMPAT.md §4.
    pub until: Option<String>,
    /// `changed_when: <jinja expr>` — overrides the module's natural
    /// "did this task change state" answer. The expression is
    /// evaluated against the task's register after the body runs; a
    /// truthy result marks the task `changed=true`, falsy `changed=false`.
    ///
    /// **Parsed but not yet honored** — the orchestrator does not
    /// currently consult this field. Storing it now so playbooks parse
    /// cleanly; the runtime hook is the same place `failed_when:` will
    /// land (see `run_body_with_retries` doc comment in orchestrator.rs).
    pub changed_when: Option<String>,
    /// `failed_when: <jinja expr>` — overrides the module's natural
    /// failure verdict. Same evaluation contract as `changed_when:`.
    ///
    /// **Parsed but not yet honored** — see CLAUDE.md "Retry loop"
    /// section, rule 7, for the integration point.
    pub failed_when: Option<String>,
    /// `no_log: true|false` — when true, the task's args and output
    /// must not be logged (used for secrets).
    ///
    /// **Parsed but not yet honored** — the orchestrator logs every
    /// task uniformly. A load-time warning fires if any task sets
    /// `no_log: true` so users running with secrets are not silently
    /// surprised. Tracked separately from changed_when/failed_when
    /// because the cost of getting it wrong is leaking secrets, not
    /// just an incorrect changed flag.
    pub no_log: Option<bool>,
    /// `vars:` — per-task variable scope. Rendered against the host's
    /// view immediately before the body dispatches; each rendered value
    /// lands in `ctx.task_vars` and is visible to `when:`, body fields,
    /// templates, etc. for the duration of this task only. Cleared
    /// after the task returns. Layered just below `extra_vars` in
    /// precedence (above registers/set_facts/play_vars).
    ///
    /// Empty for tasks that don't declare `vars:`. Note: for
    /// `include_role:` tasks the same YAML field instead populates
    /// `IncludeRoleSpec.vars` (Ansible's per-role-include override) and
    /// this field stays empty.
    pub vars: BTreeMap<String, serde_yaml::Value>,
    /// `environment:` — task-level env var overlay applied when the
    /// task body dispatches a `shell:` / `command:` / `exec:` op (or
    /// any op whose wire form carries env_keys/env_values today —
    /// currently OpExec and OpShell). Values are rendered through
    /// Jinja at dispatch against the host's view, then handed to the
    /// agent which overlays them on top of the agent's process env
    /// (Ansible-compatible: additive on top of the connection env,
    /// per-task scope).
    ///
    /// Empty for tasks that don't declare `environment:`. Keys are
    /// always strings; values must be string-compatible scalars
    /// (string / int / bool / float — coerced at parse time).
    ///
    /// Inheritance: `inherit_block_metadata` merges block-level env
    /// INTO each child task's env. Child key wins on collision.
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskBody {
    /// Existing v0 ops. Sent to the agent as a wire `Op`.
    Op(TaskOp),
    /// Controller-side: each `that:` expression must evaluate truthy.
    Assert(AssertTask),
    /// Controller-side: unconditional failure with `msg:`.
    Fail(FailTask),
    /// Controller-side: print a Jinja-rendered message or the value of
    /// a named variable. No state change.
    Debug(DebugTask),
    /// Controller-side: bind values into the host's set_facts dict.
    SetFact(SetFactMap),
    /// Controller-side: sleep for a fixed duration. Mirrors Ansible's
    /// `ansible.builtin.pause` with the interactive-prompt path
    /// rejected at parse time (see ANSIBLE_COMPAT.md §8).
    Pause(PauseTask),
    /// Parse-time directive: splice in tasks from `<file>`. After the
    /// import-flattening pass walks the playbook, no `ImportTasks` body
    /// should remain.
    ImportTasks(PathBuf),
    /// Parse-time directive: splice in tasks from another role's
    /// `tasks/<tasks_from>.yml`. The role's `defaults/main.yml` is
    /// merged into the play's role_defaults; the role's
    /// `handlers/main.yml` (if any) is appended to the play's handler
    /// list; the included tasks are tagged with the role's directory so
    /// `template:` / `copy:` lookups resolve relative to that role.
    /// `vars:` on the include site become a synthetic prepended
    /// `set_fact:` so they're visible to the spliced tasks. After the
    /// include-role expansion pass, no `IncludeRole` body should remain.
    IncludeRole(IncludeRoleSpec),
    /// Control-flow marker: e.g. `meta: flush_handlers` to force the
    /// pending-handler queue to drain mid-play.
    Meta(MetaAction),
    /// `block:` — controller-side task grouping with optional `rescue:`
    /// and `always:` arms. Block-level metadata on the outer Task
    /// (when, tags, become, become_user, ignore_errors, check_mode,
    /// delegate_to) is pushed down into every child task by the
    /// load-time `inherit_block_metadata` pass in
    /// `crates/ctl/src/playbook/mod.rs`. `loop:` stays on the outer
    /// Task and the executor iterates the whole block→rescue→always
    /// triple per item. `retries:` / `until:` / `delay:` are rejected
    /// at parse time on a block — push them onto individual inner
    /// tasks instead.
    Block(BlockSpec),
}

/// Parsed body of an `include_role:` task. The optional `vars:` sits
/// alongside `name:` / `tasks_from:` on the task; `vars:` at the task
/// level (sibling of `include_role:`) is folded in by the parser.
#[derive(Debug, Clone, PartialEq)]
pub struct IncludeRoleSpec {
    /// Name of the role to include (simple identifier — no path
    /// separators). Resolved to `<base_dir>/roles/<name>/` at load time.
    pub name: String,
    /// Which file in the role's `tasks/` directory to load. Defaults to
    /// `"main"`. The `.yml` (or `.yaml`) extension is added if missing.
    pub tasks_from: String,
    /// Per-include variable overrides. Spliced in as a synthetic
    /// `set_fact:` prepended to the included tasks. Values can be Jinja
    /// strings and will be rendered at runtime against the host's view.
    pub vars: BTreeMap<String, serde_yaml::Value>,
}

/// `meta:` task kinds. Currently only `flush_handlers`; the variant exists
/// so future controls (`clear_host_errors`, `end_play`, …) can be added
/// without another body-key churn.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaAction {
    FlushHandlers,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskOp {
    Shell(ShellOp),
    Exec(ExecOp),
    Command(CommandOp),
    WriteFile(WriteFileOp),
    /// `template:` — controller-side. The op declaration carries `src`
    /// (a file path resolved at load time against the invoking role's
    /// `templates/` dir, then the playbook dir) and a `dest` plus
    /// `mode`. At execution time the orchestrator looks up the
    /// pre-loaded template source from the playbook's `TemplateRegistry`,
    /// renders it against the host's view, and dispatches the result
    /// as an `OpWriteFile`. No new wire variant needed.
    Template(TemplateOp),
    /// `copy:` — controller-side. The op declaration carries `src` (a
    /// file path resolved at load time against the invoking role's
    /// `files/` dir, then the playbook dir) and a `dest` plus `mode`.
    /// At execution time the orchestrator looks up the pre-loaded raw
    /// bytes from the `CopyOp.body`, renders `dest` against the host's
    /// view, and dispatches the result as an `OpWriteFile`. No new wire
    /// variant needed. Unlike `template:`, the body is **not** Jinja-
    /// rendered — `copy:` ships bytes verbatim, including binary.
    Copy(CopyOp),
    /// Implicit op emitted by the orchestrator when `gather_facts: true`
    /// is set on a play. Not produced by parsing user YAML — there is
    /// no `gather_facts:` task-body key.
    GatherFacts,
    /// `stat:` — read-only filesystem inspection. The agent emits a JSON
    /// object on stdout describing the path; the orchestrator lifts it
    /// into `register.stat` (matching Ansible's `foo.stat.exists` shape).
    Stat(StatOp),
    /// `file:` — Ansible's `ansible.builtin.file` module. Ensures a
    /// filesystem path is in the requested state
    /// (directory/absent/touch/file) with optional mode/owner/group +
    /// recurse for directories.
    File(FileOp),
    /// `wait_for:` — block until a TCP port is reachable OR a path
    /// appears/disappears. No state change; `changed` is always 0.
    WaitFor(WaitForOp),
    /// `lineinfile:` — idempotent single-line edit. Ensures or removes
    /// a line in a text file; supports anchored-regex match,
    /// `insertbefore`/`insertafter` placement, and backref substitution.
    LineInFile(LineInFileOp),
    /// `blockinfile:` — idempotent multi-line block edit. Delimited by
    /// templated marker comments; replaces an existing block in place
    /// or inserts a fresh one via `insertbefore`/`insertafter`.
    BlockInFile(BlockInFileOp),
    /// `systemd:` / `service:` — manage a systemd unit's run-state and
    /// enable-state. Idempotent via `is-active` / `is-enabled` probes.
    Systemd(SystemdOp),
    /// `package:` / `apt:` / `dnf:` / `apk:` / ... — install/remove/upgrade
    /// OS packages. One TaskOp variant covers every per-manager YAML key
    /// (the YAML deserializer pins the `manager` field); `package:` uses
    /// `Auto` to let the agent pick at run time. Batched (one wire op
    /// carries multiple `name`s). Idempotency is per-backend.
    Package(PackageOp),
    /// `repository:` (canonical) / `apt_repository:` (compat shim) —
    /// add or remove a third-party package source. `manager:` selects the
    /// backend (default `Auto`; today only `apt` is implemented). See
    /// `RSANSIBLE_IDIOMS.md §2` for why `repository:` is the preferred
    /// spelling.
    Repository(RepositoryOp),
    /// `group:` — create/delete a unix group via `groupadd`/`groupdel`,
    /// idempotent via a `getent group` probe.
    Group(GroupOp),
    /// `user:` — create/update/delete a unix user via `useradd` /
    /// `usermod` / `userdel`, idempotent via a `getent passwd` probe.
    /// Only deltas are applied to an existing user (no churn on
    /// re-runs).
    User(UserOp),
    /// `authorized_key:` — idempotent line management for
    /// `~<user>/.ssh/authorized_keys`. The agent computes a key
    /// fingerprint (type + key body) to match existing entries so an
    /// updated comment doesn't double-add.
    AuthorizedKey(AuthorizedKeyOp),
    /// `getent:` — look up a single NSS database entry. Read-only;
    /// always reports `changed=0`. The envelope shape matches
    /// Ansible's `getent_<database>[<key>]` so vendored templates
    /// resolve unchanged after the orchestrator lifts the result.
    Getent(GetentOp),
    /// `hostname:` — set the system hostname. Idempotent: reads the
    /// running hostname before mutating.
    Hostname(HostnameOp),
    /// `ufw:` — Uncomplicated Firewall control. One op covers one of
    /// rule / enable / disable / reset / default / reload / logging.
    Ufw(UfwOp),
    /// `iptables:` — manage a single iptables/ip6tables rule.
    /// Idempotency comes from `iptables -C` on the agent before the
    /// `-A` / `-I` / `-D`. Subset of Ansible's
    /// `ansible.builtin.iptables` — extension knobs like
    /// `to_destination`, `tcp_flags`, `limit:`, `reject_with:`,
    /// `flush:`, `policy:` are rejected at parse time.
    Iptables(IptablesOp),
    /// `async_status:` — poll the status of an async job started with
    /// `async: N, poll: 0` (fire-and-forget). The `jid` is taken from
    /// the register of the start task as `{{ start_result.ansible_job_id }}`.
    /// The agent looks up the job in its in-process table and returns
    /// the latest status envelope (finished/started/elapsed/rc, plus
    /// the inner module's envelope once finished).
    AsyncStatus(AsyncStatusOp),
    /// `uri:` — HTTP client. Maps Ansible's `ansible.builtin.uri`
    /// (subset). The agent emits a JSON envelope on stdout describing
    /// the response; the orchestrator lifts the envelope fields to the
    /// top level of `register` so `register.status`, `register.content`,
    /// `register.json.<body-field>` etc. all resolve in templates,
    /// matching Ansible's contract.
    Uri(UriOp),
    /// `openssl_privatekey:` — controller-side. Generates a fresh RSA
    /// or Ed25519 private key on the controller via `rcgen`, then
    /// dispatches an `OpWriteFile` to ship the PEM. The dispatch is
    /// **composite**: depending on the per-host wire-cost heuristic
    /// (`WireStrategy` × `should_probe_first`) it either probes with
    /// `OpStat` first and conditionally writes, or ships blind with
    /// `OpWriteFile { only_if_missing: 1 }`. Matches Ansible's
    /// `community.crypto.openssl_privatekey` idempotency: an existing
    /// key on disk is never overwritten.
    OpenSslPrivkey(OpenSslPrivkeyOp),
    /// `openssl_csr_pipe:` — controller-side, no wire dispatch.
    /// Computes a CSR PEM on the controller (using the privkey PEM
    /// cached on `HostCtx` by an earlier `openssl_privatekey` task)
    /// and stashes the bytes into the synthetic register so
    /// downstream tasks reference `{{ csr.content }}`.
    OpenSslCsrPipe(OpenSslCsrPipeOp),
    /// `x509_certificate_pipe:` — controller-side, no wire dispatch.
    /// Self-signs a cert against the supplied CSR + private key
    /// (both fed in as PEM strings, typically via Jinja from earlier
    /// registers) and stashes the cert PEM into the synthetic
    /// register so downstream tasks reference `{{ cert.content }}`.
    /// v1 supports `provider: selfsigned` only.
    X509CertificatePipe(X509CertificatePipeOp),
    /// `postgresql_query:` — execute SQL against a PostgreSQL server.
    /// Maps Ansible's `community.postgresql.postgresql_query` (subset).
    /// The controller classifies the SQL at compile time (read-only vs
    /// mutating) and pins `read_only` here; the agent uses that byte to
    /// gate check-mode skip and `changed` reporting. Connection prefers
    /// `login_unix_socket` (Patroni clusters) and falls back to TCP at
    /// `login_host:login_port`. Empty `login_user` triggers peer auth
    /// against the agent process's effective uid — under `become:
    /// postgres` that's the postgres OS user.
    PostgresqlQuery(PostgresqlQueryOp),
    /// `postgresql_ext:` — manage a PostgreSQL extension's presence.
    /// Maps Ansible's `community.postgresql.postgresql_ext` (subset).
    /// Probe-then-DDL idempotency. Version updates not implemented in
    /// v1.
    PostgresqlExt(PostgresqlExtOp),
    /// `get_url:` — HTTP file downloader. Maps Ansible's
    /// `ansible.builtin.get_url` (subset). The agent does stat-skip on
    /// existing dest (with optional checksum match), atomic-renames a
    /// staged tmp file on success, and verifies any operator-supplied
    /// checksum post-download. The envelope shape matches Ansible
    /// (`url`, `dest`, `checksum_src`, `checksum_dest`, `size`,
    /// `status_code`, `msg`) so vendored playbooks register-lift
    /// unchanged.
    GetUrl(GetUrlOp),
    /// `slurp:` — Ansible's `ansible.builtin.slurp` module. Reads a
    /// file on the remote host and registers a base64-encoded copy of
    /// its contents (`register.content`, `register.source`,
    /// `register.encoding`). Dispatched via `OpReadFile`. Read-only;
    /// `changed` is always 0.
    Slurp(SlurpOp),
    /// `unarchive:` — Ansible's `ansible.builtin.unarchive` module
    /// (`remote_src: yes` flavour only). Extracts an archive that
    /// already lives on the agent host. Dispatched via `OpUnarchive`.
    Unarchive(UnarchiveOp),
    /// `tempfile:` — Ansible's `ansible.builtin.tempfile`.
    /// **Controller-side only** in v1; no wire dispatch. Creates a
    /// temp file or directory on the controller filesystem and binds
    /// `register.path` to the absolute path. See ANSIBLE_COMPAT.md for
    /// the controller-vs-target divergence.
    Tempfile(TempfileOp),
}

const BODY_KEYS: &[&str] = &[
    "shell",
    "exec",
    "command",
    "write_file",
    "template",
    "copy",
    "stat",
    "file",
    "wait_for",
    "lineinfile",
    "blockinfile",
    "systemd",
    "service",
    "apt",
    "pip",
    "package",
    "repository",
    "apt_repository",
    "user",
    "group",
    "authorized_key",
    "getent",
    "hostname",
    "async_status",
    "iptables",
    "ufw",
    "uri",
    "openssl_privatekey",
    "openssl_csr_pipe",
    "x509_certificate_pipe",
    "postgresql_query",
    "postgresql_ext",
    "get_url",
    "slurp",
    "unarchive",
    "tempfile",
    "assert",
    "fail",
    "debug",
    "pause",
    "set_fact",
    "import_tasks",
    "include_role",
    "meta",
    "block",
];

// Note: `rescue` and `always` are siblings of `block:` on the task
// mapping (not nested inside `block:`). The Task deserializer extracts
// them by direct `map.remove("rescue")`/`map.remove("always")` before
// the unknown-key check; the block body arm consumes them via
// `.take()`. Non-block bodies that leave them Some get a clear
// "rescue/always only valid alongside block" error.

/// Top-level keys that don't select a body but do carry per-task metadata.
const METADATA_KEYS: &[&str] = &[
    "name",
    "when",
    "register",
    "loop",
    "loop_control",
    "tags",
    "delegate_to",
    "run_once",
    "notify",
    "become",
    "become_user",
    "ignore_errors",
    "check_mode",
    "async",
    "poll",
    "retries",
    "delay",
    "until",
    "changed_when",
    "failed_when",
    "no_log",
    "environment",
];


/// FQCN prefixes we accept on task keys. Ansible playbooks routinely
/// spell modules as `ansible.builtin.<name>`, `community.crypto.<name>`,
/// etc. — we accept any of these prefixes and the key is treated as
/// its bare canonical name (e.g. `ansible.builtin.shell` ↔ `shell`).
///
/// The collection-name part is informational: we don't validate that
/// the FQCN's collection matches where the canonical module would live
/// in Ansible. If a user writes `community.crypto.shell` we strip and
/// accept it; the bare name carries the truth. This matches how Ansible
/// itself works for the modules we ship — the collection prefix is a
/// namespace hint, not a routing decision.
///
/// Unrecognized prefixes are left untouched and surface as unknown-field
/// errors with the original FQCN spelling preserved, so users see the
/// exact key they wrote in the error message.
const FQCN_PREFIXES: &[&str] = &[
    "ansible.builtin.",
    "ansible.posix.",
    "community.crypto.",
    "community.general.",
    "community.postgresql.",
    "community.docker.",
];

/// Strip a recognized FQCN prefix, returning the bare name if any
/// prefix matched. Returns None if no prefix applies — the caller
/// keeps the original key as-is in that case.
fn strip_fqcn(key: &str) -> Option<&str> {
    for prefix in FQCN_PREFIXES {
        if let Some(rest) = key.strip_prefix(prefix) {
            return Some(rest);
        }
    }
    None
}

impl<'de> Deserialize<'de> for Task {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        // FQCN normalization: rewrite any `ansible.builtin.shell` /
        // `community.crypto.openssl_privatekey` / etc. to its bare
        // canonical spelling so the rest of the deserializer (which
        // matches on bare names) works without per-call prefix-stripping.
        //
        // Collisions (both `shell:` and `ansible.builtin.shell:` set on
        // the same task) are rejected — the YAML is ambiguous and the
        // user should pick one spelling.
        let fqcn_rewrites: Vec<(serde_yaml::Value, String)> = map
            .iter()
            .filter_map(|(k, _)| {
                let s = k.as_str()?;
                let bare = strip_fqcn(s)?;
                Some((k.clone(), bare.to_string()))
            })
            .collect();
        for (old_key, bare) in fqcn_rewrites {
            let bare_yaml = serde_yaml::Value::String(bare.clone());
            if map.contains_key(&bare_yaml) {
                return Err(D::Error::custom(format!(
                    "task has both `{}` and the FQCN spelling `{}` set; \
                     pick one",
                    bare,
                    old_key.as_str().unwrap_or("<non-string-key>"),
                )));
            }
            let val = map.remove(&old_key).expect("key was just observed");
            map.insert(bare_yaml, val);
        }

        let name = match map.remove("name") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task `name` must be a string, got: {other:?}"
                )));
            }
            None => return Err(D::Error::missing_field("name")),
        };

        // Extract metadata fields.
        let when = take_when_field(&mut map, &name)?;
        let register = take_optional_string(&mut map, "register", &name)?;
        let loop_spec = match map.remove("loop") {
            None => None,
            Some(v) => Some(LoopSpec::from_yaml(v).map_err(|e| {
                D::Error::custom(format!("task {name:?}: loop: {e}"))
            })?),
        };
        let loop_control = match map.remove("loop_control") {
            None => None,
            Some(v) => Some(serde_yaml::from_value::<LoopControl>(v).map_err(|e| {
                D::Error::custom(format!("task {name:?}: loop_control: {e}"))
            })?),
        };
        let tags = match map.remove("tags") {
            None => Vec::new(),
            Some(v) => parse_tags_value::<D::Error>(v)
                .map_err(|e| D::Error::custom(format!("task {name:?}: tags: {e}")))?,
        };
        let delegate_to = take_optional_string(&mut map, "delegate_to", &name)?;
        let become_ = match map.remove("become") {
            None => None,
            Some(serde_yaml::Value::Bool(b)) => Some(b),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `become` must be a bool, got: {other:?}"
                )));
            }
        };
        let become_user = take_optional_string(&mut map, "become_user", &name)?;
        let ignore_errors = match map.remove("ignore_errors") {
            None => None,
            Some(serde_yaml::Value::Bool(b)) => Some(b),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `ignore_errors` must be a bool, got: {other:?}"
                )));
            }
        };
        let check_mode = match map.remove("check_mode") {
            None => None,
            Some(serde_yaml::Value::Bool(b)) => Some(b),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `check_mode` must be a bool, got: {other:?}"
                )));
            }
        };
        // async/poll accept either an integer (most common) or a
        // Jinja-templated string (e.g. `async: "{{ (n | int) + 30 }}"`).
        // Store both as String — the runtime renders + parses to u32.
        let async_seconds = take_int_or_template_string(&mut map, "async", &name)?;
        let poll_seconds = take_int_or_template_string(&mut map, "poll", &name)?;
        if poll_seconds.is_some() && async_seconds.is_none() {
            return Err(D::Error::custom(format!(
                "task {name:?}: `poll:` is only meaningful with `async:` set"
            )));
        }
        // retries/delay accept either an integer (most common) or a
        // Jinja-templated string (e.g. `retries: "{{ (n | int) // 5 }}"`).
        // Store both as String — the runtime renders + parses to u32.
        let retries = take_int_or_template_string(&mut map, "retries", &name)?;
        let delay = take_int_or_template_string(&mut map, "delay", &name)?;
        // `until:` accepts a single Jinja expression OR a list of
        // expressions (implicit AND between items — matches Ansible).
        // List form joins as `(item1) and (item2) and ...` so each
        // item's operator precedence stays self-contained.
        let until = match map.remove("until") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) => Some(s),
            Some(serde_yaml::Value::Sequence(seq)) => {
                let mut parts: Vec<String> = Vec::with_capacity(seq.len());
                for (i, item) in seq.into_iter().enumerate() {
                    match item {
                        serde_yaml::Value::String(s) => parts.push(format!("({s})")),
                        other => {
                            return Err(D::Error::custom(format!(
                                "task {name:?}: `until[{i}]` must be a string Jinja expression, got: {other:?}"
                            )));
                        }
                    }
                }
                if parts.is_empty() {
                    return Err(D::Error::custom(format!(
                        "task {name:?}: `until:` cannot be an empty list"
                    )));
                }
                Some(parts.join(" and "))
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `until:` must be a string or list of strings, got: {other:?}"
                )));
            }
        };
        // until: requires register: (we need the registered envelope
        // to evaluate the expression against). See ANSIBLE_COMPAT.md §4.
        if until.is_some() && register.is_none() {
            return Err(D::Error::custom(format!(
                "task {name:?}: `until:` requires `register:` to also be \
                 set — rsansible doesn't bind an implicit `result` var \
                 (see ANSIBLE_COMPAT.md §4)"
            )));
        }
        // delay: without retries: is meaningless. Surface it instead of
        // silently dropping the field, same shape as `poll:` without `async:`.
        if delay.is_some() && retries.is_none() {
            return Err(D::Error::custom(format!(
                "task {name:?}: `delay:` is only meaningful with `retries:` set"
            )));
        }
        // changed_when / failed_when both accept either a Jinja-expression
        // string OR a literal bool. The bool form is idiomatic shorthand
        // — `changed_when: false` on a shell command says "this is
        // idempotent, never flag changed." We canonicalize to a string:
        // `"true"` / `"false"`, which minijinja evaluates to the same
        // truthiness as the literal bool when the runtime hook lands.
        let changed_when = take_string_or_bool(&mut map, "changed_when", &name)?;
        let failed_when = take_string_or_bool(&mut map, "failed_when", &name)?;
        let no_log = match map.remove("no_log") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::Bool(b)) => Some(b),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `no_log` must be a bool, got: {other:?}"
                )));
            }
        };
        let run_once = match map.remove("run_once") {
            None => false,
            Some(serde_yaml::Value::Bool(b)) => b,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `run_once` must be a bool, got: {other:?}"
                )));
            }
        };
        // `vars:` only has meaning on `include_role:` today. We strip it
        // here so it doesn't trigger the unknown-key check, then enforce
        // the include_role-only restriction once the body kind is known.
        let task_vars: Option<BTreeMap<String, serde_yaml::Value>> = match map.remove("vars") {
            None => None,
            Some(serde_yaml::Value::Mapping(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    let key = k.as_str().ok_or_else(|| {
                        D::Error::custom(format!(
                            "task {name:?}: vars keys must be strings, got {k:?}"
                        ))
                    })?;
                    out.insert(key.to_string(), v);
                }
                Some(out)
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `vars` must be a mapping, got: {other:?}"
                )));
            }
        };

        // `environment:` — task-level env var map. Strings only; we
        // coerce a small set of scalar types (int / bool / float) to
        // their string form so playbooks can write `MY_PORT: 5432`
        // without surrounding quotes. Anything else (mapping, sequence,
        // null) is rejected at parse time — silently dropping a
        // structured value would produce a surprising "empty env".
        let environment: BTreeMap<String, String> = match map.remove("environment") {
            None => BTreeMap::new(),
            Some(serde_yaml::Value::Mapping(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    let key = k.as_str().ok_or_else(|| {
                        D::Error::custom(format!(
                            "task {name:?}: environment keys must be strings, got {k:?}"
                        ))
                    })?;
                    let val = match v {
                        serde_yaml::Value::String(s) => s,
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "task {name:?}: environment[{key:?}] must be a string/int/bool, got {other:?}"
                            )));
                        }
                    };
                    out.insert(key.to_string(), val);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `environment` must be a mapping, got: {other:?}"
                )));
            }
        };

        let notify = match map.remove("notify") {
            None => Vec::new(),
            Some(serde_yaml::Value::String(s)) => vec![s],
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .into_iter()
                .map(|item| match item {
                    serde_yaml::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!(
                        "task {name:?}: notify entries must be strings, got: {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `notify` must be a string or list of strings, got: {other:?}"
                )));
            }
        };

        // `rescue:` and `always:` are siblings of `block:` on the
        // task mapping (not nested inside `block:`). Extract them
        // here so the unknown-key check below doesn't trip; the
        // `block` body arm consumes them via `.take()`. Any non-block
        // body that leaves these Some after the arm runs is a hard
        // error (the sibling has no meaning without the block).
        let mut rescue_yaml: Option<serde_yaml::Value> = map.remove("rescue");
        let mut always_yaml: Option<serde_yaml::Value> = map.remove("always");

        // Find exactly one body key.
        let mut chosen: Option<(&'static str, serde_yaml::Value)> = None;
        for &k in BODY_KEYS {
            if let Some(v) = map.remove(k) {
                if let Some((prev, _)) = &chosen {
                    return Err(D::Error::custom(format!(
                        "task {name:?}: more than one body key set ({prev:?} and {k:?}); \
                         a task must have exactly one of {BODY_KEYS:?}"
                    )));
                }
                chosen = Some((k, v));
            }
        }

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "task {name:?}: unknown field(s): {unknown:?}; \
                 expected metadata in {METADATA_KEYS:?} plus one of {BODY_KEYS:?}"
            )));
        }

        let (kind, body_yaml) = chosen.ok_or_else(|| {
            D::Error::custom(format!(
                "task {name:?}: missing body — expected one of {BODY_KEYS:?}"
            ))
        })?;

        let body = match kind {
            "shell" => TaskBody::Op(TaskOp::Shell(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "exec" => TaskBody::Op(TaskOp::Exec(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "command" => TaskBody::Op(TaskOp::Command(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "write_file" => TaskBody::Op(TaskOp::WriteFile(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "template" => TaskBody::Op(TaskOp::Template(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "copy" => TaskBody::Op(TaskOp::Copy(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "stat" => TaskBody::Op(TaskOp::Stat(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "file" => TaskBody::Op(TaskOp::File(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "wait_for" => TaskBody::Op(TaskOp::WaitFor(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "lineinfile" => TaskBody::Op(TaskOp::LineInFile(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "blockinfile" => TaskBody::Op(TaskOp::BlockInFile(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            // `service:` is an alias for `systemd:` — Ansible treats
            // them as separate modules but for our subset they're the
            // same wrapper; we accept either spelling.
            "systemd" | "service" => TaskBody::Op(TaskOp::Systemd(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "apt" => {
                // Ansible-compat shim. Pins `manager: Apt`; body may not
                // contradict it. See `RSANSIBLE_IDIOMS.md §3`.
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Package(parse_package_body::<D::Error>(
                    Some(PackageManager::Apt),
                    map,
                )?))
            }
            "pip" => {
                // Ansible-compat shim. Pins `manager: Pip`; body may not
                // contradict it. See `RSANSIBLE_IDIOMS.md §3`.
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Package(parse_package_body::<D::Error>(
                    Some(PackageManager::Pip),
                    map,
                )?))
            }
            "package" => {
                // Canonical rsansible spelling. `manager:` is read from
                // the body; defaults to `Auto`. Per-manager knobs are
                // accepted only under the matching pin. See
                // `RSANSIBLE_IDIOMS.md §3`.
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Package(parse_package_body::<D::Error>(
                    None,
                    map,
                )?))
            }
            "repository" => {
                // Canonical rsansible spelling. `manager:` is read from
                // the body; defaults to `Auto`. See `RSANSIBLE_IDIOMS.md §2`.
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Repository(
                    repository::parse_repository_body::<D::Error>(None, map)?,
                ))
            }
            "apt_repository" => {
                // Ansible-compat shim. Pins `manager: Apt`; body may not
                // contradict it.
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Repository(
                    repository::parse_repository_body::<D::Error>(
                        Some(RepositoryManager::Apt),
                        map,
                    )?,
                ))
            }
            "group" => {
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Group(group::parse_group_body::<D::Error>(map)?))
            }
            "user" => {
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::User(user::parse_user_body::<D::Error>(map)?))
            }
            "authorized_key" => {
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::AuthorizedKey(
                    authorized_key::parse_authorized_key_body::<D::Error>(map)?,
                ))
            }
            "getent" => {
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Getent(getent::parse_getent_body::<D::Error>(map)?))
            }
            "hostname" => {
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Hostname(
                    hostname::parse_hostname_body::<D::Error>(map)?,
                ))
            }
            "iptables" => TaskBody::Op(TaskOp::Iptables(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "async_status" => TaskBody::Op(TaskOp::AsyncStatus(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "ufw" => TaskBody::Op(TaskOp::Ufw(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "uri" => TaskBody::Op(TaskOp::Uri(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "openssl_privatekey" => TaskBody::Op(TaskOp::OpenSslPrivkey(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "openssl_csr_pipe" => TaskBody::Op(TaskOp::OpenSslCsrPipe(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "x509_certificate_pipe" => TaskBody::Op(TaskOp::X509CertificatePipe(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "postgresql_query" => TaskBody::Op(TaskOp::PostgresqlQuery(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "postgresql_ext" => TaskBody::Op(TaskOp::PostgresqlExt(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "get_url" => TaskBody::Op(TaskOp::GetUrl(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "slurp" => TaskBody::Op(TaskOp::Slurp(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "unarchive" => TaskBody::Op(TaskOp::Unarchive(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "tempfile" => TaskBody::Op(TaskOp::Tempfile(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            )),
            "assert" => TaskBody::Assert(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            ),
            "fail" => TaskBody::Fail(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            ),
            "debug" => TaskBody::Debug(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            ),
            "pause" => TaskBody::Pause(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            ),
            "set_fact" => {
                let raw: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                let mut out = BTreeMap::new();
                for (k, v) in raw {
                    let key = k.as_str().ok_or_else(|| {
                        D::Error::custom(format!(
                            "task {name:?}: set_fact keys must be strings, got {k:?}"
                        ))
                    })?;
                    out.insert(key.to_string(), v);
                }
                TaskBody::SetFact(SetFactMap(out))
            }
            "import_tasks" => {
                let path: String =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::ImportTasks(PathBuf::from(path))
            }
            "include_role" => {
                // include_role body is itself a mapping: { name, tasks_from? }.
                let mut body_map = match body_yaml {
                    serde_yaml::Value::Mapping(m) => m,
                    other => {
                        return Err(D::Error::custom(format!(
                            "task {name:?}: include_role body must be a mapping, got: {other:?}"
                        )));
                    }
                };
                let role_name = match body_map.remove("name") {
                    Some(serde_yaml::Value::String(s)) => s,
                    Some(other) => {
                        return Err(D::Error::custom(format!(
                            "task {name:?}: include_role.name must be a string, got: {other:?}"
                        )));
                    }
                    None => {
                        return Err(D::Error::custom(format!(
                            "task {name:?}: include_role missing required `name`"
                        )));
                    }
                };
                let tasks_from = match body_map.remove("tasks_from") {
                    None => "main".to_string(),
                    Some(serde_yaml::Value::String(s)) => s,
                    Some(other) => {
                        return Err(D::Error::custom(format!(
                            "task {name:?}: include_role.tasks_from must be a string, got: {other:?}"
                        )));
                    }
                };
                if !body_map.is_empty() {
                    let unknown: Vec<String> = body_map
                        .keys()
                        .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                        .collect();
                    return Err(D::Error::custom(format!(
                        "task {name:?}: include_role: unknown field(s) {unknown:?}; \
                         expected [name, tasks_from]"
                    )));
                }
                let vars = task_vars.clone().unwrap_or_default();
                TaskBody::IncludeRole(IncludeRoleSpec {
                    name: role_name,
                    tasks_from,
                    vars,
                })
            }
            "meta" => {
                let action: MetaAction = serde_yaml::from_value(body_yaml).map_err(|e| {
                    D::Error::custom(format!(
                        "task {name:?}: meta: expected one of [flush_handlers], got: {e}"
                    ))
                })?;
                TaskBody::Meta(action)
            }
            "block" => {
                // `block:` must be a non-empty list of tasks.
                let tasks: Vec<Task> = match body_yaml {
                    v @ serde_yaml::Value::Sequence(_) => serde_yaml::from_value(v)
                        .map_err(|e| {
                            D::Error::custom(format!("task {name:?}: block: {e}"))
                        })?,
                    other => {
                        return Err(D::Error::custom(format!(
                            "task {name:?}: `block` must be a list of tasks, got: {other:?}"
                        )));
                    }
                };
                if tasks.is_empty() {
                    return Err(D::Error::custom(format!(
                        "task {name:?}: `block` must not be empty"
                    )));
                }
                let rescue: Vec<Task> = match rescue_yaml.take() {
                    None => Vec::new(),
                    Some(v @ serde_yaml::Value::Sequence(_)) => serde_yaml::from_value(v)
                        .map_err(|e| {
                            D::Error::custom(format!("task {name:?}: rescue: {e}"))
                        })?,
                    Some(other) => {
                        return Err(D::Error::custom(format!(
                            "task {name:?}: `rescue` must be a list of tasks, got: {other:?}"
                        )));
                    }
                };
                let always: Vec<Task> = match always_yaml.take() {
                    None => Vec::new(),
                    Some(v @ serde_yaml::Value::Sequence(_)) => serde_yaml::from_value(v)
                        .map_err(|e| {
                            D::Error::custom(format!("task {name:?}: always: {e}"))
                        })?,
                    Some(other) => {
                        return Err(D::Error::custom(format!(
                            "task {name:?}: `always` must be a list of tasks, got: {other:?}"
                        )));
                    }
                };
                TaskBody::Block(BlockSpec { tasks, rescue, always })
            }
            _ => unreachable!("body key not in BODY_KEYS dispatch"),
        };

        // `vars:` on an `include_role:` is consumed by the include_role
        // arm above (becomes `IncludeRoleSpec.vars`). For every other
        // body kind, it becomes the task-level scoped vars layered into
        // `ctx.task_vars` at dispatch time.
        let task_level_vars: BTreeMap<String, serde_yaml::Value> =
            if matches!(body, TaskBody::IncludeRole(_)) {
                BTreeMap::new()
            } else {
                task_vars.unwrap_or_default()
            };
        // `rescue:` and `always:` are consumed by the block body arm.
        // If they're set on any other body kind, surface the error.
        if rescue_yaml.is_some() {
            return Err(D::Error::custom(format!(
                "task {name:?}: `rescue:` is only valid alongside `block:`"
            )));
        }
        if always_yaml.is_some() {
            return Err(D::Error::custom(format!(
                "task {name:?}: `always:` is only valid alongside `block:`"
            )));
        }
        // Block-on-{retries,until,delay,register,notify,run_once}
        // rejections. These metadata fields don't have a defined
        // meaning on a block container in Ansible (or have semantics
        // that interact badly with rescue/always); push them onto
        // individual inner tasks instead.
        if matches!(body, TaskBody::Block(_)) {
            if retries.is_some() {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `retries:` is not supported on a `block:` — \
                     put `retries:` on the individual tasks inside the block instead"
                )));
            }
            if until.is_some() {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `until:` is not supported on a `block:` — \
                     put `until:` on the individual tasks inside the block instead"
                )));
            }
            if delay.is_some() {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `delay:` is not supported on a `block:` — \
                     put `delay:` on the individual tasks inside the block instead"
                )));
            }
            if register.is_some() {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `register:` has no defined meaning on a `block:` — \
                     put `register:` on the individual tasks inside the block instead"
                )));
            }
            if !notify.is_empty() {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `notify:` is not supported on a `block:` — \
                     put `notify:` on the individual tasks inside the block instead"
                )));
            }
            if run_once {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `run_once:` is not supported on a `block:` — \
                     put `run_once:` on the individual tasks inside the block instead"
                )));
            }
        }
        Ok(Task {
            name,
            body,
            when,
            register,
            loop_spec,
            loop_control,
            tags,
            delegate_to,
            run_once,
            notify,
            role_dir: None,
            become_,
            become_user,
            ignore_errors,
            check_mode,
            async_seconds,
            poll_seconds,
            retries,
            delay,
            until,
            changed_when,
            failed_when,
            no_log,
            vars: task_level_vars,
            environment,
        })
    }
}

/// Deserialize a `tags:` value into `Vec<String>`. Ansible accepts both
/// `tags: foo` and `tags: [foo, bar]`; we accept both shapes here. Empty
/// or whitespace-only tag strings are rejected — they almost always
/// indicate a typo (a trailing comma, an unquoted YAML null, etc.) and
/// silently dropping them would mask the bug.
pub(crate) fn parse_tags_value<E: serde::de::Error>(
    v: serde_yaml::Value,
) -> Result<Vec<String>, E> {
    let raw: Vec<String> = match v {
        serde_yaml::Value::String(s) => vec![s],
        serde_yaml::Value::Sequence(_) => serde_yaml::from_value::<Vec<String>>(v)
            .map_err(|e| E::custom(format!("expected a list of strings: {e}")))?,
        serde_yaml::Value::Null => Vec::new(),
        other => {
            return Err(E::custom(format!(
                "expected a string or list of strings, got: {other:?}"
            )))
        }
    };
    for s in &raw {
        if s.trim().is_empty() {
            return Err(E::custom(
                "tag entries must be non-empty (check for stray commas \
                 or unquoted YAML nulls)"
                    .to_string(),
            ));
        }
    }
    Ok(raw)
}

/// `serde::Deserialize` adapter for the standalone `tags:` field on
/// `RoleSpec`. The task-level parser does its own field-by-field
/// extraction (so it doesn't use this directly) but the role-spec
/// derive flow does.
pub(crate) fn deserialize_tags<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = serde_yaml::Value::deserialize(d)?;
    parse_tags_value(v)
}

/// `assert: { that: ["x == 1", "y > 0"], fail_msg: "..." }`
///
/// Ansible has two ways to spell the failure message: `fail_msg`
/// (preferred / modern) and `msg` (legacy alias). We accept both and
/// they map to the same field; we don't surface a "you used the old
/// spelling" warning because lots of real playbooks still use `msg:`
/// and it's not deprecated.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AssertTask {
    /// One or more Jinja expressions. Ansible accepts a single string in
    /// place of a list; honor that for ergonomics.
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    pub that: Vec<String>,
    /// Message printed when an assertion fails. Accepts `fail_msg:`
    /// (Ansible's preferred name) or `msg:` (legacy alias).
    #[serde(default, alias = "msg")]
    pub fail_msg: Option<String>,
}

/// `fail: { msg: "..." }`
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FailTask {
    #[serde(default = "default_fail_msg")]
    pub msg: String,
}

fn default_fail_msg() -> String {
    "Failed as requested".to_string()
}

/// `async_status:` parsed form. The wire op carries a u32 job id;
/// we store the raw input as a String so it can carry Jinja
/// (`jid: "{{ start_result.ansible_job_id }}"`) and render+parse at
/// dispatch time.
#[derive(Debug, Clone, PartialEq)]
pub struct AsyncStatusOp {
    /// Job id — int-or-jinja. Rendered at dispatch; the wire op then
    /// gets the parsed u32.
    pub jid: String,
}

impl<'de> Deserialize<'de> for AsyncStatusOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        // Accept either an int (`jid: 12`) or a string (the Jinja form
        // the playbook author uses 100% of the time in practice).
        let jid = match map.remove("jid") {
            None | Some(serde_yaml::Value::Null) => {
                return Err(D::Error::custom("async_status.jid: required"));
            }
            Some(serde_yaml::Value::String(s)) => s,
            Some(serde_yaml::Value::Number(n)) => n.to_string(),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "async_status.jid: expected int or string, got: {other:?}"
                )));
            }
        };
        // `mode:` (Ansible's `cleanup` / `status` selector) is rejected —
        // we only support the implicit `status` mode; the agent's job
        // table cleans itself up when the agent dies.
        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "async_status: unknown field {k:?}; only `jid` accepted"
            )));
        }
        Ok(AsyncStatusOp { jid })
    }
}

/// `pause:` — controller-side sleep. Blocks the orchestrator for the
/// rendered duration. `seconds:` and `minutes:` accept int-or-Jinja
/// (rendered at dispatch). Exactly one of `seconds:` / `minutes:` may
/// be set; setting both is rejected at parse time.
///
/// `prompt:` (interactive pause that waits for human input) is rejected
/// at parse time — see ANSIBLE_COMPAT.md §8. rsansible is a
/// non-interactive runner; an interactive prompt would deadlock under
/// any automated invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct PauseTask {
    /// Rendered to integer seconds at dispatch. Mutually exclusive with
    /// `minutes`. Stored as String to support templated values like
    /// `seconds: "{{ poll_interval * 2 }}"`.
    pub seconds: Option<String>,
    /// Rendered to integer minutes at dispatch. Mutually exclusive with
    /// `seconds`. Same templated-string storage.
    pub minutes: Option<String>,
}

impl<'de> Deserialize<'de> for PauseTask {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(d)?;
        // `pause:` with no args at all means "pause indefinitely until
        // a user hits Enter" in Ansible. For a non-interactive runner
        // that's a deadlock, not a wait — reject it the same way we
        // reject `prompt:`.
        let mut map = match v {
            serde_yaml::Value::Mapping(m) => m,
            serde_yaml::Value::Null => {
                return Err(D::Error::custom(
                    "pause: requires `seconds:` or `minutes:` — \
                     interactive (no-arg) pause is rejected by \
                     rsansible (see ANSIBLE_COMPAT.md §8)",
                ));
            }
            other => {
                return Err(D::Error::custom(format!(
                    "pause: expected a mapping with `seconds:` or `minutes:`, got: {other:?}"
                )));
            }
        };
        if map.remove("prompt").is_some() {
            return Err(D::Error::custom(
                "pause: `prompt:` (interactive wait) is not supported — \
                 rsansible is a non-interactive runner (see ANSIBLE_COMPAT.md §8)",
            ));
        }
        // `echo:` is an Ansible-specific knob for the interactive
        // prompt path. Since we've already rejected `prompt:`, accepting
        // a bare `echo:` would be confusing — surface it loudly.
        if map.remove("echo").is_some() {
            return Err(D::Error::custom(
                "pause: `echo:` only applies to interactive `prompt:` mode, \
                 which rsansible doesn't support (see ANSIBLE_COMPAT.md §8)",
            ));
        }
        let seconds = take_int_or_template_string::<D::Error>(&mut map, "seconds", "pause")?;
        let minutes = take_int_or_template_string::<D::Error>(&mut map, "minutes", "pause")?;
        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "pause: unknown field {k:?}; only seconds/minutes accepted"
            )));
        }
        if seconds.is_some() && minutes.is_some() {
            return Err(D::Error::custom(
                "pause: `seconds:` and `minutes:` are mutually exclusive",
            ));
        }
        if seconds.is_none() && minutes.is_none() {
            return Err(D::Error::custom(
                "pause: one of `seconds:` or `minutes:` is required \
                 (interactive pause without a duration is not supported; \
                 see ANSIBLE_COMPAT.md §8)",
            ));
        }
        Ok(PauseTask { seconds, minutes })
    }
}

/// `debug: { msg: "..." }` or `debug: { var: "name.path" }`. Controller-
/// side; emits an info-level log line and registers a no-change result.
/// Exactly one of `msg`/`var` must be set. `verbosity:` is parsed and
/// ignored — every debug task runs at info level for now.
#[derive(Debug, Clone, PartialEq)]
pub enum DebugMsg {
    /// `msg: "hello"` (or scalar coerced via YAML) — a single
    /// Jinja-templated string. Rendered as one unit.
    One(String),
    /// `msg:` is a YAML list — rendered line-by-line at runtime so
    /// per-item Jinja expressions stay independent. (YAML
    /// round-tripping a list of strings re-quotes them, which
    /// corrupts inline Jinja string literals like
    /// `{{ '' + foo if cond else '' }}`.)
    Many(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DebugTask {
    pub msg: Option<DebugMsg>,
    pub var: Option<String>,
}

impl<'de> Deserialize<'de> for DebugTask {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(d)?;
        // Shorthand: `debug: "string"` → msg=string.
        if let serde_yaml::Value::String(s) = &v {
            return Ok(DebugTask {
                msg: Some(DebugMsg::One(s.clone())),
                var: None,
            });
        }
        let mut map = match v {
            serde_yaml::Value::Mapping(m) => m,
            other => {
                return Err(D::Error::custom(format!(
                    "debug: expected a mapping (or a string shorthand), got: {other:?}"
                )))
            }
        };
        let msg = match map.remove("msg") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) => Some(DebugMsg::One(s)),
            // A list of strings becomes DebugMsg::Many; each entry is
            // rendered independently at runtime so embedded Jinja
            // string literals don't get YAML-escaped through a
            // round-trip.
            Some(serde_yaml::Value::Sequence(seq)) => {
                let mut lines = Vec::with_capacity(seq.len());
                for item in seq {
                    match item {
                        serde_yaml::Value::String(s) => lines.push(s),
                        other => {
                            // Non-string entries get YAML-stringified
                            // for fidelity with Ansible's repr-style
                            // output (numbers, nested maps, etc.).
                            lines.push(
                                serde_yaml::to_string(&other)
                                    .map_err(D::Error::custom)?
                                    .trim_end()
                                    .to_string(),
                            );
                        }
                    }
                }
                Some(DebugMsg::Many(lines))
            }
            // Ansible accepts non-string/non-list msg (dict/number)
            // and prints them via repr. Accept whatever it is and
            // stringify via YAML for fidelity.
            Some(other) => Some(DebugMsg::One(
                serde_yaml::to_string(&other)
                    .map_err(D::Error::custom)?
                    .trim_end()
                    .to_string(),
            )),
        };
        let var = match map.remove("var") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "debug.var: expected a non-empty string, got: {other:?}"
                )))
            }
        };
        // `verbosity:` parsed and discarded (we always print).
        let _ = map.remove("verbosity");
        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "debug: unknown field {k:?}; only msg/var/verbosity accepted"
            )));
        }
        if msg.is_some() && var.is_some() {
            return Err(D::Error::custom(
                "debug: msg and var are mutually exclusive",
            ));
        }
        if msg.is_none() && var.is_none() {
            // Ansible defaults to msg="Hello world!" when neither is given.
            return Ok(DebugTask {
                msg: Some(DebugMsg::One("Hello world!".into())),
                var: None,
            });
        }
        Ok(DebugTask { msg, var })
    }
}

fn deserialize_string_or_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = serde_yaml::Value::deserialize(d)?;
    match v {
        serde_yaml::Value::String(s) => Ok(vec![s]),
        serde_yaml::Value::Sequence(seq) => seq
            .into_iter()
            .map(|item| match item {
                serde_yaml::Value::String(s) => Ok(s),
                other => Err(D::Error::custom(format!(
                    "expected string, got: {other:?}"
                ))),
            })
            .collect(),
        other => Err(D::Error::custom(format!(
            "expected string or list of strings, got: {other:?}"
        ))),
    }
}

/// Values inside a `set_fact:` map. Stored as `serde_yaml::Value` so
/// scalar strings can be Jinja-rendered at runtime and structured values
/// (lists, maps, numbers, bools) pass through unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct SetFactMap(pub BTreeMap<String, serde_yaml::Value>);

#[derive(Debug, Clone, PartialEq)]
pub enum LoopSpec {
    /// `loop: [a, b, c]` — literal list.
    Items(Vec<serde_yaml::Value>),
    /// `loop: "{{ some_list }}"` — Jinja expression that yields a list.
    Expr(String),
}

impl LoopSpec {
    fn from_yaml(v: serde_yaml::Value) -> Result<Self, String> {
        match v {
            serde_yaml::Value::String(s) => Ok(LoopSpec::Expr(s)),
            serde_yaml::Value::Sequence(seq) => Ok(LoopSpec::Items(seq)),
            other => Err(format!(
                "expected list or Jinja string, got: {other:?}"
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LoopControl {
    /// Variable name to expose the current iteration's item under.
    /// Defaults to `item` when absent.
    #[serde(default)]
    pub loop_var: Option<String>,
    /// `label:` — a Jinja-templatable summary to print *instead of* the
    /// full item value in loop progress output. Used in Ansible to hide
    /// large or sensitive loop items from the run log (`loop_control:
    /// { label: "{{ item.name }}" }`).
    ///
    /// **Parsed but not yet honored** — our progress output doesn't
    /// print per-iteration item values at all yet, so there's nothing
    /// to substitute. Stored so playbooks parse cleanly.
    #[serde(default)]
    pub label: Option<String>,
}

impl TaskOp {
    /// Convert this playbook-level op into a wire `Op` message body.
    ///
    /// Caller is responsible for having rendered any Jinja in the op
    /// fields before calling this — `to_wire_op` itself is a pure
    /// structural conversion.
    pub fn to_wire_op(&self) -> Result<Op> {
        match self {
            TaskOp::Shell(s) => Ok(op_shell(
                s.command().to_string(),
                Vec::new(),
                Vec::new(),
                s.timeout_ms(),
            )),
            TaskOp::Exec(e) => {
                if e.argv.is_empty() {
                    return Err(anyhow!("exec.argv is empty"));
                }
                let (env_keys, env_values): (Vec<_>, Vec<_>) =
                    e.env.iter().map(|(k, v)| (k.clone(), v.clone())).unzip();
                Ok(op_exec(
                    e.argv.clone(),
                    env_keys,
                    env_values,
                    e.cwd.clone().unwrap_or_default(),
                    e.stdin.as_bytes().to_vec(),
                    e.timeout_ms,
                ))
            }
            TaskOp::Command(c) => {
                // `creates:` / `removes:` are honored via a composite
                // OpStat probe in the orchestrator, not here. Reject
                // them at to_wire_op so we fail loudly if the
                // composite path forgets to peel them off.
                if !c.creates.is_empty() || !c.removes.is_empty() {
                    return Err(anyhow!(
                        "internal: TaskOp::Command with creates/removes reached to_wire_op without composite probe"
                    ));
                }
                if c.argv.is_empty() {
                    return Err(anyhow!("command.argv is empty"));
                }
                Ok(op_exec(
                    c.argv.clone(),
                    Vec::new(),
                    Vec::new(),
                    c.chdir.clone(),
                    c.stdin.as_bytes().to_vec(),
                    c.timeout_ms,
                ))
            }
            TaskOp::WriteFile(w) => Ok(op_write_file(
                w.path.clone(),
                w.mode,
                false,
                w.content.as_bytes().to_vec(),
            )),
            // `template:` is desugared to `OpWriteFile` by the orchestrator
            // (after rendering the template body), so we should never see
            // a raw `TaskOp::Template` here.
            TaskOp::Template(_) => Err(anyhow!(
                "internal: TaskOp::Template reached to_wire_op without being desugared to TaskOp::WriteFile"
            )),
            TaskOp::Copy(c) => {
                // `copy:` keeps its variant through render_op (rather
                // than desugaring to WriteFile) so we can ship bytes
                // verbatim — WriteFileOp.content is String, which would
                // lossy-convert binary blobs.
                let body = c.body.as_ref().ok_or_else(|| {
                    anyhow!(
                        "internal: TaskOp::Copy src {:?} body not resolved at to_wire_op time",
                        c.src
                    )
                })?;
                Ok(op_write_file(c.dest.clone(), c.mode, false, body.clone()))
            }
            TaskOp::GatherFacts => Ok(op_gather_facts()),
            TaskOp::Stat(s) => Ok(op_stat(s.path.clone(), s.follow)),
            TaskOp::WaitFor(w) => Ok(op_wait_for(
                w.host.clone().unwrap_or_default(),
                w.port.unwrap_or(0),
                w.path.clone().unwrap_or_default(),
                w.state.wire_byte(),
                w.timeout_ms,
                w.delay_ms,
                w.sleep_ms,
            )),
            TaskOp::File(f) => Ok(op_file(
                f.path.clone(),
                f.state.wire_byte(),
                f.mode,
                f.owner.clone().unwrap_or_default(),
                f.group.clone().unwrap_or_default(),
                f.recurse,
            )),
            TaskOp::LineInFile(l) => Ok(op_lineinfile(
                l.path.clone(),
                l.regexp.clone(),
                l.line.clone(),
                l.state.wire_byte(),
                l.mode,
                l.create,
                l.insertbefore.clone(),
                l.insertafter.clone(),
                l.backrefs,
            )),
            TaskOp::BlockInFile(b) => Ok(op_blockinfile(
                b.path.clone(),
                b.block.clone(),
                b.marker.clone(),
                b.marker_begin.clone(),
                b.marker_end.clone(),
                b.state.wire_byte(),
                b.mode,
                b.create,
                b.insertbefore.clone(),
                b.insertafter.clone(),
            )),
            TaskOp::Systemd(s) => Ok(op_systemd(
                s.name.clone(),
                s.state.wire_byte(),
                s.enabled,
                s.masked,
                s.daemon_reload,
                s.no_block,
            )),
            TaskOp::Package(p) => Ok(op_package(
                p.manager.wire_byte(),
                p.names.clone(),
                p.state.wire_byte(),
                p.update_cache,
                p.cache_valid_time,
                p.purge,
                p.autoremove,
                p.default_release.clone(),
                p.allow_unauthenticated,
                p.virtualenv.clone(),
                p.virtualenv_command.clone(),
            )),
            TaskOp::Repository(r) => Ok(op_repository(
                r.manager.wire_byte(),
                r.repo.clone(),
                r.state.wire_byte(),
                r.filename.clone(),
                r.mode,
                r.update_cache,
            )),
            TaskOp::Group(g) => Ok(op_group(g.name.clone(), g.state.wire_byte(), g.system)),
            TaskOp::User(u) => Ok(op_user(
                u.name.clone(),
                u.state.wire_byte(),
                u.system,
                u.shell.clone(),
                u.home.clone(),
                u.create_home,
                u.primary_group.clone(),
                u.groups.clone(),
                u.append,
            )),
            TaskOp::AuthorizedKey(a) => Ok(op_authorized_key(
                a.user.clone(),
                a.key.clone(),
                a.state.wire_byte(),
                a.exclusive,
            )),
            TaskOp::Getent(g) => Ok(op_getent(
                g.database.clone(),
                g.key.clone(),
                g.fail_key,
                g.split.clone(),
            )),
            TaskOp::Hostname(h) => Ok(op_hostname(h.name.clone())),
            TaskOp::AsyncStatus(a) => {
                // `jid` has already been rendered to its final string
                // form by the orchestrator's render_op pass; we just
                // parse it to u32 here.
                let jid: u32 = a.jid.trim().parse().map_err(|e| {
                    anyhow!("async_status.jid: expected u32 after rendering, got {:?}: {e}", a.jid)
                })?;
                Ok(op_async_status(jid))
            }
            TaskOp::Iptables(i) => Ok(op_iptables(
                i.table.clone(),
                i.chain.clone(),
                i.protocol.clone(),
                i.source.clone(),
                i.destination.clone(),
                i.source_port.clone(),
                i.destination_port.clone(),
                i.in_interface.clone(),
                i.out_interface.clone(),
                i.jump.clone(),
                i.ctstate.clone(),
                i.comment.clone(),
                i.ip_version.wire_byte(),
                i.action.wire_byte(),
                i.rule_state.wire_byte(),
            )),
            TaskOp::Ufw(u) => Ok(op_ufw(
                u.op.wire_byte(),
                u.rule.clone(),
                u.direction.clone(),
                u.proto.clone(),
                u.from_ip.clone(),
                u.from_port.clone(),
                u.to_ip.clone(),
                u.to_port.clone(),
                u.interface.clone(),
                u.comment.clone(),
                u.delete,
                u.insert,
            )),
            TaskOp::Uri(u) => {
                // BTreeMap iteration is sorted → deterministic on the wire.
                let (header_keys, header_values): (Vec<_>, Vec<_>) =
                    u.headers.iter().map(|(k, v)| (k.clone(), v.clone())).unzip();
                // mTLS PEM material: read from the controller filesystem at
                // wire-emit time. Paths are already Jinja-rendered (the
                // orchestrator renders all UriOp string fields before
                // to_wire_op runs). Empty path → empty bytes (= absent on
                // the wire, agent skips the mTLS branch).
                let client_cert_pem = read_pem_if_set(&u.client_cert, "client_cert")?;
                let client_key_pem = read_pem_if_set(&u.client_key, "client_key")?;
                let ca_bundle_pem = read_pem_if_set(&u.ca_path, "ca_path")?;
                Ok(op_uri(
                    u.method,
                    u.url.clone(),
                    header_keys,
                    header_values,
                    u.body.as_bytes().to_vec(),
                    u.body_format,
                    u.status_codes.clone(),
                    u.timeout_ms,
                    u.return_content,
                    u.validate_certs,
                    u.follow_redirects,
                    client_cert_pem,
                    client_key_pem,
                    ca_bundle_pem,
                ))
            }
            // These three are dispatched through the orchestrator's
            // composite-dispatch path (see `dispatch_plan` /
            // `run_body_op`), not via to_wire_op:
            //
            //   - OpenSslPrivkey emits OpStat + maybe OpWriteFile.
            //   - OpenSslCsrPipe / X509CertificatePipe synthesize a
            //     register entry without any wire dispatch.
            //
            // Reaching to_wire_op for any of them is a routing bug.
            TaskOp::OpenSslPrivkey(_) => Err(anyhow!(
                "internal: TaskOp::OpenSslPrivkey reached to_wire_op without being routed through composite dispatch"
            )),
            TaskOp::OpenSslCsrPipe(_) => Err(anyhow!(
                "internal: TaskOp::OpenSslCsrPipe reached to_wire_op — this op is pure controller-side, should be intercepted earlier"
            )),
            TaskOp::X509CertificatePipe(_) => Err(anyhow!(
                "internal: TaskOp::X509CertificatePipe reached to_wire_op — this op is pure controller-side, should be intercepted earlier"
            )),
            TaskOp::Tempfile(_) => Err(anyhow!(
                "internal: TaskOp::Tempfile reached to_wire_op — this op is pure controller-side, should be intercepted earlier"
            )),
            TaskOp::PostgresqlQuery(p) => Ok(op_postgresql_query(
                p.query.clone(),
                p.db.clone(),
                p.login_user.clone(),
                p.login_password.clone(),
                p.login_unix_socket.clone(),
                p.login_host.clone(),
                p.login_port,
                p.autocommit,
                p.positional_args.clone(),
                p.read_only,
            )),
            TaskOp::PostgresqlExt(p) => Ok(op_postgresql_ext(
                p.name.clone(),
                p.state,
                p.version.clone(),
                p.ext_schema.clone(),
                p.cascade,
                p.db.clone(),
                p.login_user.clone(),
                p.login_password.clone(),
                p.login_unix_socket.clone(),
                p.login_host.clone(),
                p.login_port,
            )),
            TaskOp::GetUrl(g) => {
                let (header_keys, header_values): (Vec<_>, Vec<_>) =
                    g.headers.iter().map(|(k, v)| (k.clone(), v.clone())).unzip();
                let client_cert_pem = read_pem_if_set(&g.client_cert, "client_cert")?;
                let client_key_pem = read_pem_if_set(&g.client_key, "client_key")?;
                let ca_bundle_pem = read_pem_if_set(&g.ca_path, "ca_path")?;
                Ok(op_get_url(
                    g.url.clone(),
                    g.dest.clone(),
                    g.checksum.clone(),
                    g.mode,
                    g.owner.clone(),
                    g.group.clone(),
                    header_keys,
                    header_values,
                    g.timeout_ms,
                    g.force,
                    g.validate_certs,
                    g.follow_redirects,
                    client_cert_pem,
                    client_key_pem,
                    ca_bundle_pem,
                ))
            }
            TaskOp::Slurp(s) => Ok(rsansible_wire::msg::op_read_file(
                s.src.clone(),
                s.max_bytes,
            )),
            TaskOp::Unarchive(u) => {
                let (has_mode, mode_bits) = match u.mode {
                    Some(m) => (1u8, m),
                    None => (0u8, 0u32),
                };
                Ok(rsansible_wire::msg::op_unarchive(
                    u.src.clone(),
                    u.dest.clone(),
                    u.format,
                    u.creates.clone(),
                    has_mode,
                    mode_bits,
                    u.owner.clone(),
                    u.group.clone(),
                    if u.keep_newer { 1 } else { 0 },
                    if u.list_files { 1 } else { 0 },
                    u.include.clone(),
                    u.exclude.clone(),
                ))
            }
        }
    }
}

/// Test helper: parse a single Task from YAML, panicking on failure.
/// Lives at file level (rather than inside `mod tests`) so per-op submodule
/// tests can reuse it via `use crate::playbook::task_op::parse_task_for_test;`.
#[cfg(test)]
pub(crate) fn parse_task_for_test(yaml: &str) -> Task {
    serde_yaml::from_str(yaml).expect("parses")
}

/// Test helper: parse a Task from YAML, returning the serde error on failure.
#[cfg(test)]
pub(crate) fn try_parse_task_for_test(yaml: &str) -> Result<Task, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_task_for_test as parse_task, try_parse_task_for_test as try_parse_task, *,
    };

    #[test]
    fn retries_integer_form_parses() {
        let yaml = r#"
- name: wait
  shell: check.sh
  register: r
  retries: 5
  delay: 2
  until: r.rc == 0
"#;
        let tasks: Vec<Task> = serde_yaml::from_str(yaml).unwrap();
        let t = &tasks[0];
        assert_eq!(t.retries.as_deref(), Some("5"));
        assert_eq!(t.delay.as_deref(), Some("2"));
        assert_eq!(t.until.as_deref(), Some("r.rc == 0"));
        assert_eq!(t.register.as_deref(), Some("r"));
    }

    #[test]
    fn retries_jinja_string_form_parses() {
        // This is the actual shape gothab's drill playbooks use.
        let yaml = r#"
- name: wait
  shell: check.sh
  register: writer_status
  retries: "{{ (writer_duration_s | int) // 5 + 5 }}"
  delay: "{{ poll_interval }}"
  until: writer_status.finished
"#;
        let tasks: Vec<Task> = serde_yaml::from_str(yaml).unwrap();
        let t = &tasks[0];
        assert_eq!(
            t.retries.as_deref(),
            Some("{{ (writer_duration_s | int) // 5 + 5 }}")
        );
        assert_eq!(t.delay.as_deref(), Some("{{ poll_interval }}"));
    }

    #[test]
    fn retries_without_until_is_accepted() {
        // Ansible allows `retries:` without `until:` — retry on failure.
        let yaml = r#"
- name: try
  shell: flake.sh
  retries: 3
"#;
        let tasks: Vec<Task> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tasks[0].retries.as_deref(), Some("3"));
        assert!(tasks[0].until.is_none());
    }

    #[test]
    fn until_without_register_errors() {
        let yaml = r#"
- name: wait
  shell: check.sh
  retries: 3
  until: result.rc == 0
"#;
        let err = serde_yaml::from_str::<Vec<Task>>(yaml).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("until") && s.contains("register"),
            "unexpected error: {s}"
        );
    }

    #[test]
    fn delay_without_retries_errors() {
        let yaml = r#"
- name: foo
  shell: echo
  delay: 5
"#;
        let err = serde_yaml::from_str::<Vec<Task>>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("delay") && err.to_string().contains("retries"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn retries_bool_rejected() {
        let yaml = r#"
- name: x
  shell: e
  retries: true
"#;
        let err = serde_yaml::from_str::<Vec<Task>>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("retries"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn retries_negative_rejected() {
        let yaml = r#"
- name: x
  shell: e
  retries: -1
"#;
        let err = serde_yaml::from_str::<Vec<Task>>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("retries"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parses_task_with_metadata() {
        let t = parse_task(
            r#"
name: greet
when: "1 == 1"
register: greet_out
tags: [smoke, hello]
shell: "echo hi"
"#,
        );
        assert_eq!(t.name, "greet");
        assert_eq!(t.when.as_deref(), Some("1 == 1"));
        assert_eq!(t.register.as_deref(), Some("greet_out"));
        assert_eq!(t.tags, vec!["smoke", "hello"]);
        assert!(matches!(t.body, TaskBody::Op(TaskOp::Shell(_))));
    }

    #[test]
    fn parses_bare_string_tag() {
        // Ansible-style shorthand: `tags: foo` (no brackets).
        let t = parse_task(
            r#"
name: t
tags: smoke
shell: "echo hi"
"#,
        );
        assert_eq!(t.tags, vec!["smoke"]);
    }

    #[test]
    fn rejects_non_string_tag_scalar() {
        let err = serde_yaml::from_str::<Task>(
            r#"
name: t
tags: 42
shell: "echo hi"
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("tags"),
            "expected a tags-related error, got: {err}"
        );
    }

    #[test]
    fn rejects_empty_tag_in_list() {
        let err = serde_yaml::from_str::<Task>(
            r#"
name: t
tags: [smoke, ""]
shell: "echo hi"
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("non-empty"),
            "expected non-empty error, got: {err}"
        );
    }

    #[test]
    fn parses_assert_body() {
        let t = parse_task(
            r#"
name: check
assert:
  that:
    - "x == 1"
    - "y > 0"
  msg: not happy
"#,
        );
        match t.body {
            TaskBody::Assert(a) => {
                assert_eq!(a.that, vec!["x == 1", "y > 0"]);
                assert_eq!(a.fail_msg.as_deref(), Some("not happy"));
            }
            other => panic!("expected assert, got {other:?}"),
        }
    }

    #[test]
    fn assert_accepts_single_string_for_that() {
        let t = parse_task(
            r#"
name: check
assert:
  that: "x == 1"
"#,
        );
        match t.body {
            TaskBody::Assert(a) => assert_eq!(a.that, vec!["x == 1"]),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_fail_body() {
        let t = parse_task(
            r#"
name: bail
fail:
  msg: nope
"#,
        );
        match t.body {
            TaskBody::Fail(f) => assert_eq!(f.msg, "nope"),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_set_fact_body() {
        let t = parse_task(
            r#"
name: facts
set_fact:
  greeting: "{{ result.stdout }}"
  count: 3
  enabled: true
"#,
        );
        match t.body {
            TaskBody::SetFact(s) => {
                assert_eq!(s.0.len(), 3);
                assert!(s.0.contains_key("greeting"));
                assert!(s.0.contains_key("count"));
                assert!(s.0.contains_key("enabled"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_import_tasks_body() {
        let t = parse_task(
            r#"
name: include common
import_tasks: tasks/common.yml
"#,
        );
        match t.body {
            TaskBody::ImportTasks(p) => assert_eq!(p, PathBuf::from("tasks/common.yml")),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_become_metadata() {
        let t = parse_task(
            r#"
name: install pg
become: true
become_user: postgres
shell: "apt install -y postgresql"
"#,
        );
        assert_eq!(t.become_, Some(true));
        assert_eq!(t.become_user.as_deref(), Some("postgres"));
    }

    #[test]
    fn become_defaults_to_none_for_inheritance() {
        let t = parse_task(
            r#"
name: t
shell: hi
"#,
        );
        assert_eq!(t.become_, None, "None signals 'inherit from play'");
        assert_eq!(t.become_user, None);
    }

    #[test]
    fn become_false_distinguishes_from_unset() {
        let t = parse_task(
            r#"
name: t
become: false
shell: hi
"#,
        );
        assert_eq!(
            t.become_,
            Some(false),
            "Some(false) signals 'opt out of inherited become: true'"
        );
    }

    #[test]
    fn become_non_bool_rejected() {
        let err = try_parse_task(
            r#"
name: t
become: "yes"
shell: hi
"#,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("become") && msg.contains("bool"), "got: {msg}");
    }

    #[test]
    fn parses_include_role_minimal() {
        let t = parse_task(
            r#"
name: include role
include_role:
  name: web
"#,
        );
        match t.body {
            TaskBody::IncludeRole(ir) => {
                assert_eq!(ir.name, "web");
                assert_eq!(ir.tasks_from, "main");
                assert!(ir.vars.is_empty());
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_include_role_with_tasks_from_and_vars() {
        let t = parse_task(
            r#"
name: flip archive_command
include_role:
  name: postgres-node
  tasks_from: apply-cluster-config
vars:
  pg_archive_command: "/usr/bin/wrapper %p"
  retries: 3
"#,
        );
        match t.body {
            TaskBody::IncludeRole(ir) => {
                assert_eq!(ir.name, "postgres-node");
                assert_eq!(ir.tasks_from, "apply-cluster-config");
                assert_eq!(ir.vars.len(), 2);
                assert_eq!(
                    ir.vars.get("pg_archive_command").and_then(|v| v.as_str()),
                    Some("/usr/bin/wrapper %p")
                );
                assert_eq!(
                    ir.vars.get("retries").and_then(|v| v.as_u64()),
                    Some(3)
                );
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn include_role_rejects_missing_name() {
        let err = try_parse_task(
            r#"
name: t
include_role:
  tasks_from: setup
"#,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("name"), "got: {msg}");
    }

    #[test]
    fn include_role_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
include_role:
  name: web
  apply: { tags: [setup] }
"#,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("apply"), "got: {msg}");
    }

    #[test]
    fn vars_on_non_include_role_task_lands_in_task_vars() {
        let t = parse_task(
            r#"
name: t
shell: echo hi
vars:
  x: 1
  y: "{{ x }}"
"#,
        );
        assert!(matches!(t.body, TaskBody::Op(TaskOp::Shell(_))));
        assert_eq!(t.vars.len(), 2);
        assert_eq!(t.vars["x"], serde_yaml::Value::from(1));
        assert_eq!(
            t.vars["y"],
            serde_yaml::Value::String("{{ x }}".to_string())
        );
    }

    #[test]
    fn vars_on_include_role_still_routes_to_include_role_spec() {
        let t = parse_task(
            r#"
name: t
include_role:
  name: myrole
vars:
  x: 1
"#,
        );
        // Include-role consumes vars itself; the task-level slot stays empty.
        assert!(t.vars.is_empty());
        match t.body {
            TaskBody::IncludeRole(spec) => {
                assert_eq!(spec.vars["x"], serde_yaml::Value::from(1));
            }
            other => panic!("expected IncludeRole, got {other:?}"),
        }
    }

    #[test]
    fn parses_loop_as_literal_list() {
        let t = parse_task(
            r#"
name: greet each
loop: [alice, bob]
shell: "echo {{ item }}"
"#,
        );
        match t.loop_spec {
            Some(LoopSpec::Items(items)) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].as_str(), Some("alice"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_loop_as_expr() {
        let t = parse_task(
            r#"
name: greet each
loop: "{{ users }}"
shell: "echo {{ item }}"
"#,
        );
        match t.loop_spec {
            Some(LoopSpec::Expr(s)) => assert_eq!(s, "{{ users }}"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_loop_control_loop_var() {
        let t = parse_task(
            r#"
name: x
loop: [1, 2]
loop_control:
  loop_var: i
shell: "echo {{ i }}"
"#,
        );
        assert_eq!(
            t.loop_control.as_ref().and_then(|c| c.loop_var.as_deref()),
            Some("i")
        );
    }

    #[test]
    fn rejects_unknown_loop_control_key() {
        // `pause:` isn't a loop_control field we've implemented or
        // accepted as parse-only — verifies deny_unknown_fields still
        // catches genuinely unknown keys. (We deliberately accept
        // `label:` now, see `LoopControl::label` doc.)
        let err = try_parse_task(
            r#"
name: x
loop: [1]
loop_control:
  pause: 5
shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("pause") || msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn rejects_two_body_keys() {
        let err = try_parse_task(
            r#"
name: x
shell: "echo"
write_file:
  path: /tmp/x
  mode: 0o644
  content: ""
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("more than one") || msg.contains("body"), "got: {msg}");
    }

    #[test]
    fn rejects_missing_body() {
        let err = try_parse_task(
            r#"
name: x
when: "1 == 1"
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing body"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let err = try_parse_task(
            r#"
name: x
this_is_not_a_real_key: web1
shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("this_is_not_a_real_key") || msg.contains("unknown"),
            "got: {msg}"
        );
    }

    #[test]
    fn parses_delegate_to_literal() {
        let t = parse_task(
            r#"
name: t
delegate_to: web1
shell: echo
"#,
        );
        assert_eq!(t.delegate_to.as_deref(), Some("web1"));
    }

    #[test]
    fn parses_delegate_to_template() {
        let t = parse_task(
            r#"
name: t
delegate_to: "{{ groups['etcd'][0] }}"
shell: echo
"#,
        );
        assert_eq!(t.delegate_to.as_deref(), Some("{{ groups['etcd'][0] }}"));
    }

    #[test]
    fn parses_run_once() {
        let t = parse_task(
            r#"
name: t
run_once: true
shell: echo
"#,
        );
        assert!(t.run_once);

        let t = parse_task(
            r#"
name: t
shell: echo
"#,
        );
        assert!(!t.run_once);
    }

    #[test]
    fn parses_ignore_errors_true() {
        let t = parse_task(
            r#"
name: t
ignore_errors: true
shell: echo
"#,
        );
        assert_eq!(t.ignore_errors, Some(true));
    }

    #[test]
    fn parses_ignore_errors_false() {
        let t = parse_task(
            r#"
name: t
ignore_errors: false
shell: echo
"#,
        );
        assert_eq!(t.ignore_errors, Some(false));
    }

    #[test]
    fn ignore_errors_defaults_to_none() {
        let t = parse_task(
            r#"
name: t
shell: echo
"#,
        );
        assert_eq!(t.ignore_errors, None);
    }

    #[test]
    fn rejects_non_bool_ignore_errors() {
        let err = try_parse_task(
            r#"
name: t
ignore_errors: "yes"
shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ignore_errors"), "got: {msg}");
    }

    #[test]
    fn parses_check_mode_true() {
        let t = parse_task(
            r#"
name: t
check_mode: true
shell: echo
"#,
        );
        assert_eq!(t.check_mode, Some(true));
    }

    #[test]
    fn parses_check_mode_false() {
        let t = parse_task(
            r#"
name: t
check_mode: false
shell: echo
"#,
        );
        assert_eq!(t.check_mode, Some(false));
    }

    #[test]
    fn check_mode_defaults_to_none() {
        let t = parse_task(
            r#"
name: t
shell: echo
"#,
        );
        assert_eq!(t.check_mode, None);
    }

    #[test]
    fn rejects_non_bool_check_mode() {
        let err = try_parse_task(
            r#"
name: t
check_mode: "yes"
shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("check_mode"), "got: {msg}");
    }

    #[test]
    fn rejects_non_bool_run_once() {
        let err = try_parse_task(
            r#"
name: t
run_once: "yes"
shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("run_once"), "got: {msg}");
    }

    #[test]
    fn parses_notify_string() {
        let t = parse_task(
            r#"
name: t
notify: restart_sshd
shell: echo
"#,
        );
        assert_eq!(t.notify, vec!["restart_sshd".to_string()]);
    }

    #[test]
    fn parses_notify_list() {
        let t = parse_task(
            r#"
name: t
notify:
  - restart_sshd
  - log_change
shell: echo
"#,
        );
        assert_eq!(
            t.notify,
            vec!["restart_sshd".to_string(), "log_change".to_string()]
        );
    }

    #[test]
    fn parses_meta_flush_handlers() {
        let t = parse_task(
            r#"
name: drain
meta: flush_handlers
"#,
        );
        match t.body {
            TaskBody::Meta(MetaAction::FlushHandlers) => {}
            other => panic!("expected meta flush_handlers, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_meta_action() {
        let err = try_parse_task(
            r#"
name: t
meta: hammer_time
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("meta") || msg.contains("flush_handlers"), "got: {msg}");
    }

    #[test]
    fn rejects_non_string_when() {
        let err = try_parse_task(
            r#"
name: x
when: 1
shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("when"), "got: {msg}");
    }

    #[test]
    fn env_yaml_coerces_scalars() {
        let t = parse_task(
            r#"
name: x
exec:
  argv: [/bin/true]
  env:
    B: 2
    A: 1
    C: true
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Exec(e)) => {
                assert_eq!(e.env.get("A").map(String::as_str), Some("1"));
                assert_eq!(e.env.get("B").map(String::as_str), Some("2"));
                assert_eq!(e.env.get("C").map(String::as_str), Some("true"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_debug_msg() {
        let t = parse_task(
            r#"
name: t
debug:
  msg: "value is {{ foo }}"
"#,
        );
        let TaskBody::Debug(d) = t.body else { panic!() };
        assert_eq!(d.msg, Some(DebugMsg::One("value is {{ foo }}".into())));
        assert!(d.var.is_none());
    }

    #[test]
    fn parse_debug_var() {
        let t = parse_task(
            r#"
name: t
debug:
  var: my_register.stdout
"#,
        );
        let TaskBody::Debug(d) = t.body else { panic!() };
        assert!(d.msg.is_none());
        assert_eq!(d.var.as_deref(), Some("my_register.stdout"));
    }

    #[test]
    fn parse_debug_string_shorthand() {
        let t = parse_task(
            r#"
name: t
debug: hello world
"#,
        );
        let TaskBody::Debug(d) = t.body else { panic!() };
        assert_eq!(d.msg, Some(DebugMsg::One("hello world".into())));
    }

    #[test]
    fn parse_debug_empty_defaults_to_hello() {
        let t = parse_task(
            r#"
name: t
debug: {}
"#,
        );
        let TaskBody::Debug(d) = t.body else { panic!() };
        assert_eq!(d.msg, Some(DebugMsg::One("Hello world!".into())));
    }

    #[test]
    fn parse_debug_rejects_msg_and_var_together() {
        let yaml = r#"
name: t
debug:
  msg: x
  var: y
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn parse_debug_ignores_verbosity() {
        let t = parse_task(
            r#"
name: t
debug:
  msg: x
  verbosity: 3
"#,
        );
        let TaskBody::Debug(_) = t.body else { panic!() };
    }

    #[test]
    fn parse_debug_rejects_unknown_field() {
        let yaml = r#"
name: t
debug:
  msg: x
  bogus: 1
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_async_poll_metadata() {
        let t = parse_task(
            r#"
name: t
shell: sleep 5
async: 60
poll: 5
"#,
        );
        assert_eq!(t.async_seconds.as_deref(), Some("60"));
        assert_eq!(t.poll_seconds.as_deref(), Some("5"));
    }

    #[test]
    fn parse_async_without_poll_is_ok() {
        let t = parse_task(
            r#"
name: t
shell: sleep 5
async: 60
"#,
        );
        assert_eq!(t.async_seconds.as_deref(), Some("60"));
        assert_eq!(t.poll_seconds, None);
    }

    #[test]
    fn parse_poll_without_async_rejected() {
        let yaml = r#"
name: t
shell: sleep 5
poll: 5
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(r.is_err());
        assert!(format!("{:?}", r.err()).contains("poll"));
    }

    #[test]
    fn parse_async_zero_treated_as_value_but_orchestrator_skips() {
        // The parser accepts async: 0; the orchestrator treats `Some(0)`
        // the same as `None` (synchronous). Verifying just the parse here.
        let t = parse_task(
            r#"
name: t
shell: ok
async: 0
"#,
        );
        assert_eq!(t.async_seconds.as_deref(), Some("0"));
    }

    #[test]
    fn until_list_form_joins_with_and() {
        let t = parse_task(
            r#"
name: t
shell: probe
register: r
until:
  - r.status == 200
  - r.json.members | length == 1
retries: 3
"#,
        );
        // List form is flattened into a single Jinja expr at parse
        // time — each item wrapped in parens, joined with `and`.
        assert_eq!(
            t.until.as_deref(),
            Some("(r.status == 200) and (r.json.members | length == 1)")
        );
    }

    #[test]
    fn until_empty_list_rejected() {
        let yaml = r#"
name: t
shell: probe
register: r
until: []
retries: 3
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(err.contains("empty list"), "msg: {err}");
    }

    #[test]
    fn until_non_string_in_list_rejected() {
        let yaml = r#"
name: t
shell: probe
register: r
until:
  - 42
retries: 3
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(err.contains("until[0]"), "msg: {err}");
    }

    #[test]
    fn parse_pause_seconds_literal() {
        let t = parse_task(
            r#"
name: t
pause:
  seconds: 3
"#,
        );
        let TaskBody::Pause(p) = t.body else {
            panic!("expected Pause body, got {:?}", t.body);
        };
        assert_eq!(p.seconds.as_deref(), Some("3"));
        assert_eq!(p.minutes, None);
    }

    #[test]
    fn parse_pause_minutes_jinja() {
        let t = parse_task(
            r#"
name: t
pause:
  minutes: "{{ wait_minutes }}"
"#,
        );
        let TaskBody::Pause(p) = t.body else {
            panic!("expected Pause body, got {:?}", t.body);
        };
        assert_eq!(p.seconds, None);
        assert_eq!(p.minutes.as_deref(), Some("{{ wait_minutes }}"));
    }

    #[test]
    fn parse_pause_both_units_rejected() {
        let yaml = r#"
name: t
pause:
  seconds: 5
  minutes: 1
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(
            err.contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_pause_no_args_rejected() {
        // `pause:` with no args means interactive (wait for Enter) in
        // Ansible. We reject this — interactive wait is not supported.
        let yaml = r#"
name: t
pause:
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(
            err.contains("ANSIBLE_COMPAT.md") && err.contains("pause"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_pause_neither_unit_rejected() {
        // Map present but neither seconds nor minutes set. Same rule —
        // we need a duration.
        let yaml = r#"
name: t
pause: {}
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(
            err.contains("seconds") && err.contains("minutes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_pause_prompt_rejected() {
        let yaml = r#"
name: t
pause:
  prompt: "press enter"
  seconds: 5
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(
            err.contains("prompt") && err.contains("non-interactive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_pause_unknown_field_rejected() {
        let yaml = r#"
name: t
pause:
  seconds: 5
  bogus: 1
"#;
        let r: Result<Task, _> = serde_yaml::from_str(yaml);
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(err.contains("bogus"), "unexpected error: {err}");
    }

    #[test]
    fn parse_pause_fqcn_spelling_works() {
        // Ansible's namespaced spelling normalizes to the bare token at
        // the FQCN-rewrite stage. The pause body itself is unchanged.
        let t = parse_task(
            r#"
name: t
ansible.builtin.pause:
  seconds: 2
"#,
        );
        let TaskBody::Pause(p) = t.body else {
            panic!("expected Pause body");
        };
        assert_eq!(p.seconds.as_deref(), Some("2"));
    }

    #[test]
    fn parse_async_jinja_string_form_parses() {
        // Mirror of retries_jinja_string_form_parses: `async:` / `poll:`
        // accept templated values that render to ints at dispatch.
        let t = parse_task(
            r#"
name: t
shell: sleep 5
async: "{{ (writer_duration_s | int) + 30 }}"
poll: "{{ poll_interval }}"
"#,
        );
        assert_eq!(
            t.async_seconds.as_deref(),
            Some("{{ (writer_duration_s | int) + 30 }}")
        );
        assert_eq!(t.poll_seconds.as_deref(), Some("{{ poll_interval }}"));
    }

    #[test]
    fn parses_environment_string_int_bool_values() {
        let t = parse_task(
            r#"
name: t
shell: env
environment:
  PIPX_HOME: /opt/patroni
  MAX_RETRIES: 3
  VERBOSE: true
"#,
        );
        assert_eq!(t.environment.get("PIPX_HOME").map(String::as_str), Some("/opt/patroni"));
        assert_eq!(t.environment.get("MAX_RETRIES").map(String::as_str), Some("3"));
        assert_eq!(t.environment.get("VERBOSE").map(String::as_str), Some("true"));
    }

    #[test]
    fn rejects_environment_mapping_value() {
        let yaml = r#"
name: t
shell: env
environment:
  NESTED: { not: "allowed" }
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err().to_string();
        assert!(
            err.contains("environment[\"NESTED\"]"),
            "expected complaint about NESTED env value; got: {err}"
        );
    }

    #[test]
    fn rejects_environment_non_mapping_root() {
        let yaml = r#"
name: t
shell: env
environment: "FOO=bar"
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err().to_string();
        assert!(
            err.contains("`environment` must be a mapping"),
            "expected complaint about non-mapping env root; got: {err}"
        );
    }

    /// `when:` as a YAML sequence is Ansible-idiomatic for "AND
    /// all of these." We canonicalize at parse time so the runtime
    /// evaluates a single Jinja expression instead of N.
    #[test]
    fn parses_when_sequence_as_and_joined_string() {
        let yaml = r#"
name: t
shell: echo
when:
  - not (skip_failback | bool)
  - drill_mode != 'graceful'
"#;
        let task: Task = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(
            task.when.as_deref(),
            Some("(not (skip_failback | bool)) and (drill_mode != 'graceful')"),
            "got: {:?}",
            task.when
        );
    }

    /// Empty sequence → no condition (matches Ansible: `when: []`
    /// runs unconditionally).
    #[test]
    fn parses_empty_when_sequence_as_none() {
        let yaml = r#"
name: t
shell: echo
when: []
"#;
        let task: Task = serde_yaml::from_str(yaml).expect("parses");
        assert!(task.when.is_none(), "got: {:?}", task.when);
    }

    /// Sequence with a non-string entry surfaces a clear error.
    #[test]
    fn rejects_when_sequence_with_non_string_entry() {
        let yaml = r#"
name: t
shell: echo
when:
  - "x == 1"
  - 42
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err().to_string();
        assert!(
            err.contains("`when[1]` must be a string"),
            "got: {err}"
        );
    }
}
