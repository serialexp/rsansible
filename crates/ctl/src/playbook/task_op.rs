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

use anyhow::{anyhow, Context as _, Result};
use rsansible_wire::{
    msg::{
        op_blockinfile, op_exec, op_file, op_gather_facts, op_get_url, op_lineinfile, op_package,
        op_postgresql_ext, op_postgresql_query, op_shell, op_stat, op_systemd, op_ufw, op_uri,
        op_wait_for, op_write_file, postgresql_ext_state, uri_body_format, uri_follow, uri_method,
    },
    Op,
};
use serde::{de::Error as _, Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::path::PathBuf;

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
    /// `async: <seconds>` — run the task body as a background job on
    /// the agent. Wraps the inner wire op in `OpAsyncStart(timeout_ms
    /// = async*1000, inner)`. `Some(0)` is interpreted as "synchronous"
    /// (matches Ansible: async: 0 disables async). `None` means absent.
    pub async_seconds: Option<u32>,
    /// `poll: <seconds>` — how often the orchestrator polls the job
    /// for completion. `Some(0)` is fire-and-forget: the orchestrator
    /// returns the start envelope (`ansible_job_id`, `started:1`,
    /// `finished:0`) and lets the user poll later via `async_status:`.
    /// `Some(n)` with n>0 makes the orchestrator block, polling every
    /// n seconds until the job finishes or the async deadline expires.
    /// `None` defaults to 10 when async is set (matches Ansible).
    pub poll_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskBody {
    /// Existing v0 ops. Sent to the agent as a wire `Op`.
    Op(TaskOp),
    /// Controller-side: each `that:` expression must evaluate truthy.
    Assert(AssertTask),
    /// Controller-side: unconditional failure with `msg:`.
    Fail(FailTask),
    /// Controller-side: bind values into the host's set_facts dict.
    SetFact(SetFactMap),
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
    /// `ufw:` — Uncomplicated Firewall control. One op covers one of
    /// rule / enable / disable / reset / default / reload / logging.
    Ufw(UfwOp),
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
}

/// `slurp:` parsed form. The YAML accepts `src:` (the file path on the
/// remote host) and an optional `max_bytes:` safety cap (extension; the
/// vanilla Ansible slurp has no cap and will happily read multi-GB
/// files). Zero means no cap.
#[derive(Debug, Clone, PartialEq)]
pub struct SlurpOp {
    pub src: String,
    pub max_bytes: u32,
}

/// `unarchive:` parsed form. v1 requires `remote_src: yes` (the
/// archive lives on the agent — controller-pushed archives must come
/// via a prior `copy:` or `get_url:` task). YAML surface:
///
/// ```yaml
/// - unarchive:
///     src: /srv/cache/etcd.tar.gz
///     dest: /usr/local/bin
///     remote_src: yes              # required for v1
///     creates: /usr/local/bin/etcd
///     keep_newer: yes
///     list_files: yes
///     include: [etcd, etcdctl]
///     exclude: [README.md]
///     owner: root
///     group: root
///     mode: "0755"
/// ```
///
/// `format` accepts `auto` (default) or one of `tar.gz`/`tgz`,
/// `tar.bz2`/`tbz2`, `tar.xz`/`txz`, `tar`, `zip`. When omitted, the
/// agent infers from `src`'s extension.
#[derive(Debug, Clone, PartialEq)]
pub struct UnarchiveOp {
    pub src: String,
    pub dest: String,
    pub format: u8,
    pub creates: String,
    pub mode: Option<u32>,
    pub owner: String,
    pub group: String,
    pub keep_newer: bool,
    pub list_files: bool,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

/// `ufw:` parsed form. Mirrors `community.general.ufw` (subset). The
/// YAML surface accepts one set of fields per op kind; everything not
/// applicable to a given kind must be unset (validated at parse).
#[derive(Debug, Clone, PartialEq)]
pub struct UfwOp {
    pub op: UfwOpKind,
    /// rule body (allow/deny/limit/reject for op=rule; allow/deny/reject
    /// for op=default; on/off/low/medium/high/full for op=logging).
    pub rule: String,
    pub direction: String,
    pub proto: String,
    pub from_ip: String,
    pub from_port: String,
    pub to_ip: String,
    pub to_port: String,
    pub interface: String,
    pub comment: String,
    pub delete: bool,
    pub insert: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfwOpKind {
    Rule,
    Enable,
    Disable,
    Reset,
    Default,
    Reload,
    Logging,
}

impl UfwOpKind {
    pub fn wire_byte(self) -> u8 {
        match self {
            UfwOpKind::Rule => 0,
            UfwOpKind::Enable => 1,
            UfwOpKind::Disable => 2,
            UfwOpKind::Reset => 3,
            UfwOpKind::Default => 4,
            UfwOpKind::Reload => 5,
            UfwOpKind::Logging => 6,
        }
    }
}

/// `package:` / `apt:` / `dnf:` / ... parsed form. The wire shape
/// carries the union of all backends' knobs (some are apt-only); the
/// agent ignores fields its backend doesn't consume. `names` is the
/// list of packages — Ansible's `name:` accepts either a single string
/// or a list; we normalize to a Vec at parse time.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageOp {
    /// Which backend to dispatch to. The YAML keys `apt:`, `dnf:`,
    /// `apk:`, etc. pin this at parse time. The generic `package:` key
    /// sets it to `Auto` and lets the agent choose at run time.
    pub manager: PackageManager,
    pub names: Vec<String>,
    pub state: PackageState,
    pub update_cache: bool,
    /// Seconds; only meaningful with `update_cache=true`. 0 = always
    /// update. Apt-only on the agent side (other backends ignore).
    pub cache_valid_time: u32,
    /// Apt-only: switches `remove` for `purge` on absent.
    pub purge: bool,
    /// Apt/dnf: run an autoremove pass after the main op.
    pub autoremove: bool,
    /// Apt-only: maps to `apt-get -t <release>`. Empty = unused.
    pub default_release: String,
    /// Apt-only: adds `--allow-unauthenticated`.
    pub allow_unauthenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageState {
    Present,
    Absent,
    Latest,
}

impl PackageState {
    pub fn wire_byte(self) -> u8 {
        match self {
            PackageState::Present => 0,
            PackageState::Absent => 1,
            PackageState::Latest => 2,
        }
    }
}

/// Which package-manager backend to dispatch the wire op to. The YAML
/// per-manager keys (`apt:`, `dnf:`, ...) pin this to a specific value;
/// the generic `package:` key uses `Auto` so the agent detects what's
/// available on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Auto,
    Apt,
    // Reserved for future backends — wire bytes already allocated in
    // rsansible_wire::msg::package_manager. Uncomment + add to wire_byte
    // when the agent gains a backend for them.
    // Dnf,
    // Yum,
    // Apk,
    // Pacman,
    // Zypper,
}

impl PackageManager {
    pub fn wire_byte(self) -> u8 {
        match self {
            PackageManager::Auto => 0,
            PackageManager::Apt => 1,
        }
    }

    /// Human-readable label for error messages. Used by the validator
    /// and the per-manager YAML parsers so a rejection message names
    /// the module surface (`apt`) rather than the wire byte.
    pub fn label(self) -> &'static str {
        match self {
            PackageManager::Auto => "package",
            PackageManager::Apt => "apt",
        }
    }

    /// Which apt-specific knobs the backend actually consumes. Used by
    /// the YAML parser to reject e.g. `default_release:` under
    /// `package:` (generic dispatch) since we can't promise the chosen
    /// backend will honor it.
    fn accepts_apt_knobs(self) -> bool {
        matches!(self, PackageManager::Apt)
    }
}

/// `systemd:` parsed form. Mirrors Ansible's `ansible.builtin.systemd_service`
/// (subset). Either `state` or `enabled` or `masked` (or `daemon_reload`)
/// must be specified — a task with none of those is a no-op and rejected
/// at validate.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemdOp {
    pub name: String,
    pub state: SystemdState,
    pub enabled: Option<bool>,
    pub masked: Option<bool>,
    pub daemon_reload: bool,
    pub no_block: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdState {
    /// No run-state change — `enabled`/`masked` only.
    None,
    Started,
    Stopped,
    Restarted,
    Reloaded,
}

impl SystemdState {
    pub fn wire_byte(self) -> u8 {
        match self {
            SystemdState::None => 0,
            SystemdState::Started => 1,
            SystemdState::Stopped => 2,
            SystemdState::Restarted => 3,
            SystemdState::Reloaded => 4,
        }
    }
}

/// `blockinfile:` parsed form. `block` is the body (typically multi-line)
/// to ensure or remove; the `marker` template builds the BEGIN/END
/// marker lines via literal-token `{mark}` substitution. `insertbefore`
/// / `insertafter` are mutually exclusive; `EOF` for `insertafter`
/// means "append" (Ansible's default).
#[derive(Debug, Clone, PartialEq)]
pub struct BlockInFileOp {
    pub path: String,
    pub block: String,
    pub marker: String,
    pub marker_begin: String,
    pub marker_end: String,
    pub state: BlockInFileState,
    pub mode: Option<u32>,
    pub create: bool,
    pub insertbefore: String,
    pub insertafter: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockInFileState {
    Present,
    Absent,
}

impl BlockInFileState {
    pub fn wire_byte(self) -> u8 {
        match self {
            BlockInFileState::Present => 0,
            BlockInFileState::Absent => 1,
        }
    }
}

/// `lineinfile:` parsed form. Mirrors Ansible's `ansible.builtin.lineinfile`
/// args (subset). `regexp` empty means match by literal equality with
/// `line`. `insertbefore` / `insertafter` are mutually exclusive; the
/// literal `EOF` for `insertafter` means "append".
#[derive(Debug, Clone, PartialEq)]
pub struct LineInFileOp {
    pub path: String,
    pub regexp: String,
    pub line: String,
    pub state: LineInFileState,
    pub mode: Option<u32>,
    pub create: bool,
    pub insertbefore: String,
    pub insertafter: String,
    pub backrefs: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineInFileState {
    Present,
    Absent,
}

impl LineInFileState {
    pub fn wire_byte(self) -> u8 {
        match self {
            LineInFileState::Present => 0,
            LineInFileState::Absent => 1,
        }
    }
}

/// `wait_for:` parsed form. Either (host + port) OR path must be set;
/// validated at parse + validate time. Timing fields are in
/// **seconds** in YAML (Ansible's spec) but stored as millis here.
#[derive(Debug, Clone, PartialEq)]
pub struct WaitForOp {
    pub host: Option<String>,
    pub port: Option<u32>,
    pub path: Option<String>,
    pub state: WaitForState,
    pub timeout_ms: u32,
    pub delay_ms: u32,
    pub sleep_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitForState {
    Present,
    Absent,
}

impl WaitForState {
    pub fn wire_byte(self) -> u8 {
        match self {
            WaitForState::Present => 0,
            WaitForState::Absent => 1,
        }
    }
}

/// Hand-written deserializer so we can:
///   - reject host+port mixed with path
///   - accept Ansible's aliases for `state` (`started`/`present` →
///     Present; `stopped`/`absent` → Absent)
///   - parse seconds (int or string) → millis for the wire
///   - default timeout=300s, sleep=1s, delay=0s
impl<'de> Deserialize<'de> for WaitForOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let host = match map.remove("host") {
            None => None,
            Some(serde_yaml::Value::String(s)) => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.host must be a string, got: {other:?}"
                )))
            }
        };
        let port = match map.remove("port") {
            None => None,
            Some(serde_yaml::Value::Number(n)) => Some(n.as_u64().ok_or_else(|| {
                D::Error::custom(format!("wait_for.port must be a non-negative int, got: {n}"))
            })? as u32),
            Some(serde_yaml::Value::String(s)) => Some(s.parse::<u32>().map_err(|e| {
                D::Error::custom(format!("wait_for.port: invalid int {s:?}: {e}"))
            })?),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.port must be an int or numeric string, got: {other:?}"
                )))
            }
        };
        let path = match map.remove("path") {
            None => None,
            Some(serde_yaml::Value::String(s)) => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.path must be a string, got: {other:?}"
                )))
            }
        };

        let state = match map.remove("state") {
            None => WaitForState::Present,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" | "started" => WaitForState::Present,
                "absent" | "stopped" => WaitForState::Absent,
                other => {
                    return Err(D::Error::custom(format!(
                        "wait_for.state: expected one of [present, started, absent, stopped], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.state must be a string, got: {other:?}"
                )))
            }
        };

        let timeout_ms = take_seconds_ms(&mut map, "timeout", 300_000)?;
        let delay_ms = take_seconds_ms(&mut map, "delay", 0)?;
        let sleep_ms = take_seconds_ms(&mut map, "sleep", 1_000)?;
        // `msg:` is the Ansible-style custom message on timeout. We
        // accept and discard it for now — gothab sets it but the
        // agent-side error already names the resource. Drop it from
        // the map so the unknown-field check doesn't trip.
        let _ = map.remove("msg");

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "wait_for: unknown field(s): {unknown:?}; \
                 expected one of [host, port, path, state, timeout, delay, sleep, msg]"
            )));
        }

        // Mode mutual exclusion (defensive; agent re-checks).
        let has_tcp = port.is_some();
        let has_path = path.is_some();
        if has_tcp && has_path {
            return Err(D::Error::custom(
                "wait_for: host+port and path are mutually exclusive",
            ));
        }
        if !has_tcp && !has_path {
            return Err(D::Error::custom(
                "wait_for: must specify either host+port (TCP probe) or path (file probe)",
            ));
        }
        if has_tcp && port == Some(0) {
            return Err(D::Error::custom("wait_for: port must be non-zero"));
        }

        Ok(WaitForOp {
            host,
            port,
            path,
            state,
            timeout_ms,
            delay_ms,
            sleep_ms,
        })
    }
}

/// Accept `<key>: <seconds>` as int or numeric string; convert to ms.
/// Returns `default_ms` if absent.
fn take_seconds_ms<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
    default_ms: u32,
) -> Result<u32, E> {
    match map.remove(key) {
        None => Ok(default_ms),
        Some(serde_yaml::Value::Number(n)) => {
            let s = n.as_f64().ok_or_else(|| {
                E::custom(format!("wait_for.{key}: invalid number {n}"))
            })?;
            if !s.is_finite() || s < 0.0 {
                return Err(E::custom(format!(
                    "wait_for.{key}: expected non-negative seconds, got {s}"
                )));
            }
            Ok((s * 1000.0) as u32)
        }
        Some(serde_yaml::Value::String(s)) => {
            let f = s.parse::<f64>().map_err(|e| {
                E::custom(format!("wait_for.{key}: invalid number {s:?}: {e}"))
            })?;
            if !f.is_finite() || f < 0.0 {
                return Err(E::custom(format!(
                    "wait_for.{key}: expected non-negative seconds, got {f}"
                )));
            }
            Ok((f * 1000.0) as u32)
        }
        Some(other) => Err(E::custom(format!(
            "wait_for.{key} must be a number or numeric string, got: {other:?}"
        ))),
    }
}

/// `file: { path: …, state: directory, mode: "0755", owner: root,
/// group: root, recurse: yes }`
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileOp {
    pub path: String,
    pub state: FileState,
    /// `mode: "0755"` (string), `mode: 0o755` (int) — Ansible playbooks
    /// use both. Parsed by `deserialize_file_mode` into a 12-bit perm
    /// value. Absent → don't chmod.
    #[serde(default, deserialize_with = "deserialize_file_mode")]
    pub mode: Option<u32>,
    /// Owner / group as user-resolvable names. Empty → don't chown.
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    /// Only meaningful for `state: directory`. When true, recursively
    /// apply mode/owner/group to all descendants (Ansible behavior).
    #[serde(default, deserialize_with = "deserialize_ansible_bool")]
    pub recurse: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    Directory,
    Absent,
    Touch,
    /// Regular file — ensure it exists; doesn't create. Used to chmod /
    /// chown an existing file.
    File,
}

impl FileState {
    /// Wire byte matching `schema/wire.schema.json5` OpFile.state.
    pub fn wire_byte(self) -> u8 {
        match self {
            FileState::Directory => 0,
            FileState::Absent => 1,
            FileState::Touch => 2,
            FileState::File => 3,
        }
    }
}

/// Parse `mode:` from either a string (`"0755"`, `"755"`, `"0o755"`)
/// or an int (e.g. `0o755` literal in YAML). Strings with a leading `0`
/// are treated as octal — Ansible's behavior. Returns the parsed value
/// or an error; `None` means the field was absent.
fn deserialize_file_mode<'de, D>(d: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = match Option::<serde_yaml::Value>::deserialize(d)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let n = match v {
        serde_yaml::Value::Null => return Ok(None),
        serde_yaml::Value::Number(n) => {
            n.as_u64().ok_or_else(|| {
                D::Error::custom(format!("mode: expected non-negative integer, got: {n}"))
            })? as u32
        }
        serde_yaml::Value::String(s) => parse_mode_str(&s).map_err(D::Error::custom)?,
        other => {
            return Err(D::Error::custom(format!(
                "mode: expected string or int, got: {other:?}"
            )))
        }
    };
    if n & !0o7777 != 0 {
        return Err(D::Error::custom(format!(
            "mode: only the low 12 bits are meaningful (got 0o{n:o})"
        )));
    }
    Ok(Some(n))
}

/// Strings like `"0755"` and `"755"` → 0o755. `"0o755"` and `"0755"`
/// also accepted. No symbolic modes (`u=rwx,g=rx`) — gothab doesn't use
/// them.
fn parse_mode_str(s: &str) -> Result<u32, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("mode: empty string".to_string());
    }
    let (body, radix) = if let Some(rest) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        (rest, 8u32)
    } else if t.starts_with('0') && t.len() > 1 {
        (t, 8u32)
    } else {
        (t, 8u32)
    };
    u32::from_str_radix(body, radix)
        .map_err(|e| format!("mode: invalid octal {s:?}: {e}"))
}

/// `stat: { path: /etc/foo, follow: yes }`. `follow` selects stat() vs
/// lstat() — defaults to true (Ansible's default). Currently always
/// computes a sha256 for regular files (agent-side); a `get_checksum:
/// no` knob can be added if the size becomes a problem.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatOp {
    pub path: String,
    /// Defaults to true (Ansible's default). Accepts `yes`/`no`/`true`/
    /// `false` in YAML — Ansible playbooks commonly spell booleans as
    /// `yes`/`no`, which serde_yaml otherwise refuses.
    #[serde(default = "default_stat_follow", deserialize_with = "deserialize_ansible_bool")]
    pub follow: bool,
}

fn default_stat_follow() -> bool {
    true
}

/// Accept Ansible-flavored booleans: `true`, `false`, `yes`, `no`, `on`,
/// `off` (case-insensitive). YAML 1.2 only accepts `true`/`false`, but
/// every gothab playbook uses `yes`/`no` so we widen.
fn deserialize_ansible_bool<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let v = serde_yaml::Value::deserialize(d)?;
    match v {
        serde_yaml::Value::Bool(b) => Ok(b),
        serde_yaml::Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" => Ok(true),
            "no" | "false" | "off" => Ok(false),
            other => Err(D::Error::custom(format!(
                "expected bool (true/false/yes/no/on/off), got: {other:?}"
            ))),
        },
        other => Err(D::Error::custom(format!(
            "expected bool, got: {other:?}"
        ))),
    }
}

/// Hand-written so we can:
///   - default `state: present`
///   - default `regexp`/`insertbefore`/`insertafter`/`line` to empty
///   - accept Ansible-style `mode` (octal int or string)
///   - accept Ansible-style booleans for `create` / `backrefs`
///   - enforce insertbefore/insertafter mutual exclusion
///   - enforce backrefs requires regexp
impl<'de> Deserialize<'de> for LineInFileOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let path = match map.remove("path") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "lineinfile.path must be a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::custom("lineinfile: missing required field `path`")),
        };

        let line = match map.remove("line") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            // Accept numeric/bool lines by stringifying — Ansible allows
            // `line: 1234`.
            Some(serde_yaml::Value::Number(n)) => n.to_string(),
            Some(serde_yaml::Value::Bool(b)) => b.to_string(),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "lineinfile.line must be a scalar string, got: {other:?}"
                )))
            }
        };

        let regexp = take_optional_field_string(&mut map, "regexp")?;
        let regexp = regexp.unwrap_or_default();
        let insertbefore = take_optional_field_string(&mut map, "insertbefore")?.unwrap_or_default();
        let insertafter = take_optional_field_string(&mut map, "insertafter")?.unwrap_or_default();

        let state = match map.remove("state") {
            None => LineInFileState::Present,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => LineInFileState::Present,
                "absent" => LineInFileState::Absent,
                other => {
                    return Err(D::Error::custom(format!(
                        "lineinfile.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "lineinfile.state must be a string, got: {other:?}"
                )))
            }
        };

        let mode = take_optional_mode(&mut map, "mode")?;
        let create = take_optional_ansible_bool(&mut map, "create")?.unwrap_or(false);
        let backrefs = take_optional_ansible_bool(&mut map, "backrefs")?.unwrap_or(false);

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "lineinfile: unknown field(s): {unknown:?}; expected one of \
                 [path, line, regexp, state, mode, create, insertbefore, insertafter, backrefs]"
            )));
        }

        if !insertbefore.is_empty() && !insertafter.is_empty() {
            return Err(D::Error::custom(
                "lineinfile: insertbefore and insertafter are mutually exclusive",
            ));
        }
        if backrefs && regexp.is_empty() {
            return Err(D::Error::custom(
                "lineinfile: backrefs requires regexp to be set",
            ));
        }
        if matches!(state, LineInFileState::Present) && line.is_empty() && !backrefs {
            return Err(D::Error::custom(
                "lineinfile: state=present requires a non-empty `line` (unless using backrefs)",
            ));
        }

        Ok(LineInFileOp {
            path,
            regexp,
            line,
            state,
            mode,
            create,
            insertbefore,
            insertafter,
            backrefs,
        })
    }
}

/// Hand-written so we can accept Ansible-flavored booleans (yes/no) for
/// enabled/masked/daemon_reload/no_block, map Ansible state strings
/// (started/stopped/restarted/reloaded) to the byte enum, default
/// state to `None`, and validate that at least one knob is being
/// asked for.
impl<'de> Deserialize<'de> for SystemdOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let name = match map.remove("name") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "systemd.name must be a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::custom("systemd: missing required field `name`")),
        };

        let state = match map.remove("state") {
            None => SystemdState::None,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "started" => SystemdState::Started,
                "stopped" => SystemdState::Stopped,
                "restarted" => SystemdState::Restarted,
                "reloaded" => SystemdState::Reloaded,
                other => {
                    return Err(D::Error::custom(format!(
                        "systemd.state: expected one of [started, stopped, restarted, reloaded], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "systemd.state must be a string, got: {other:?}"
                )))
            }
        };

        let enabled = take_optional_ansible_bool(&mut map, "enabled")?;
        let masked = take_optional_ansible_bool(&mut map, "masked")?;
        let daemon_reload = take_optional_ansible_bool(&mut map, "daemon_reload")?.unwrap_or(false);
        let no_block = take_optional_ansible_bool(&mut map, "no_block")?.unwrap_or(false);
        // Ansible's `scope:` accepts user/system; we silently drop
        // user-scope as out of charter for now (gothab doesn't use it).
        // Reject explicitly so the user knows.
        if let Some(scope) = map.remove("scope") {
            if let serde_yaml::Value::String(s) = &scope {
                if s != "system" {
                    return Err(D::Error::custom(format!(
                        "systemd.scope: only `system` is supported, got: {s:?}"
                    )));
                }
            }
        }

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "systemd: unknown field(s): {unknown:?}; expected one of \
                 [name, state, enabled, masked, daemon_reload, no_block, scope]"
            )));
        }

        if matches!(state, SystemdState::None)
            && enabled.is_none()
            && masked.is_none()
            && !daemon_reload
        {
            return Err(D::Error::custom(
                "systemd: must specify at least one of [state, enabled, masked, daemon_reload]",
            ));
        }

        Ok(SystemdOp {
            name,
            state,
            enabled,
            masked,
            daemon_reload,
            no_block,
        })
    }
}

/// Parse a `PackageOp` from a YAML body under a per-manager YAML key
/// (`apt:`, `package:`, ...). `manager` is pinned by the caller — the
/// YAML key, not the body, determines which backend will run, so each
/// per-manager key reuses this function with its own fixed value.
///
/// Per-manager surface differences:
///   * `apt:` accepts apt-specific knobs (`cache_valid_time`, `purge`,
///     `default_release`, `allow_unauthenticated`)
///   * `package:` (manager=Auto) rejects those knobs — we can't
///     promise the auto-detected backend will honor them
///
/// `force_apt_get` and `install_recommends` are accepted-and-discarded
/// under apt for Ansible compatibility (we always use apt-get; we keep
/// recommends ON which matches Ansible's default).
fn parse_package_body<E: serde::de::Error>(
    manager: PackageManager,
    mut map: serde_yaml::Mapping,
) -> Result<PackageOp, E> {
    let label = manager.label();

    // `name:` is required and may be a string or a list of strings.
    // Ansible also accepts `pkg:` as an alias under `apt:` / `package:`.
    let names = match map.remove("name").or_else(|| map.remove("pkg")) {
        None => {
            return Err(E::custom(format!(
                "{label}: missing required field `name`"
            )))
        }
        Some(serde_yaml::Value::String(s)) => vec![s],
        Some(serde_yaml::Value::Sequence(seq)) => {
            let mut out = Vec::with_capacity(seq.len());
            for v in seq {
                match v {
                    serde_yaml::Value::String(s) => out.push(s),
                    other => {
                        return Err(E::custom(format!(
                            "{label}.name list items must be strings, got: {other:?}"
                        )))
                    }
                }
            }
            out
        }
        Some(other) => {
            return Err(E::custom(format!(
                "{label}.name must be a string or list of strings, got: {other:?}"
            )))
        }
    };

    let state = match map.remove("state") {
        None => PackageState::Present,
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "present" | "installed" => PackageState::Present,
            "absent" | "removed" => PackageState::Absent,
            "latest" => PackageState::Latest,
            other => {
                return Err(E::custom(format!(
                    "{label}.state: expected one of [present, installed, absent, removed, latest], got: {other:?}"
                )))
            }
        },
        Some(other) => {
            return Err(E::custom(format!(
                "{label}.state must be a string, got: {other:?}"
            )))
        }
    };

    let update_cache =
        take_optional_ansible_bool::<E>(&mut map, "update_cache")?.unwrap_or(false);
    let autoremove =
        take_optional_ansible_bool::<E>(&mut map, "autoremove")?.unwrap_or(false);

    // Apt-specific knobs: only consumed when manager pins an apt-aware
    // backend. Under `package:` (auto), we refuse them at parse time so
    // users don't silently lose configuration when the auto-detected
    // backend ignores them.
    let (cache_valid_time, purge, default_release, allow_unauthenticated) =
        if manager.accepts_apt_knobs() {
            let cache_valid_time = match map.remove("cache_valid_time") {
                None | Some(serde_yaml::Value::Null) => 0u32,
                Some(serde_yaml::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    E::custom(format!(
                        "{label}.cache_valid_time must be a non-negative integer, got: {n}"
                    ))
                })? as u32,
                Some(serde_yaml::Value::String(s)) => s.parse::<u32>().map_err(|e| {
                    E::custom(format!(
                        "{label}.cache_valid_time: invalid int {s:?}: {e}"
                    ))
                })?,
                Some(other) => {
                    return Err(E::custom(format!(
                        "{label}.cache_valid_time must be a number, got: {other:?}"
                    )))
                }
            };
            let purge =
                take_optional_ansible_bool::<E>(&mut map, "purge")?.unwrap_or(false);
            let default_release =
                take_optional_field_string::<E>(&mut map, "default_release")?
                    .unwrap_or_default();
            let allow_unauthenticated =
                take_optional_ansible_bool::<E>(&mut map, "allow_unauthenticated")?
                    .unwrap_or(false);
            // Accept and discard `force_apt_get` — we always use apt-get.
            let _ = map.remove("force_apt_get");
            // Accept and discard `install_recommends` for now; gothab
            // doesn't set it. (Ansible's default ON matches apt-get's
            // default ON.)
            let _ = map.remove("install_recommends");
            (cache_valid_time, purge, default_release, allow_unauthenticated)
        } else {
            // `package:` (auto): refuse apt-only knobs explicitly rather
            // than silently dropping them. If a user wants apt-specific
            // behavior, they should use `apt:`.
            for k in [
                "cache_valid_time",
                "purge",
                "default_release",
                "allow_unauthenticated",
                "force_apt_get",
                "install_recommends",
            ] {
                if map.contains_key(serde_yaml::Value::String(k.to_string())) {
                    return Err(E::custom(format!(
                        "{label}: field `{k}` is only valid under `apt:` (manager-specific). \
                         Use `apt:` instead of `package:` to set it."
                    )));
                }
            }
            (0, false, String::new(), false)
        };

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        let allowed = if manager.accepts_apt_knobs() {
            "[name, pkg, state, update_cache, cache_valid_time, purge, autoremove, default_release, allow_unauthenticated, install_recommends, force_apt_get]"
        } else {
            "[name, pkg, state, update_cache, autoremove]"
        };
        return Err(E::custom(format!(
            "{label}: unknown field(s): {unknown:?}; expected one of {allowed}"
        )));
    }

    if names.is_empty() {
        return Err(E::custom(format!(
            "{label}.name: must specify at least one package"
        )));
    }
    for n in &names {
        if n.trim().is_empty() {
            return Err(E::custom(format!("{label}.name: empty package name")));
        }
    }
    if !update_cache && cache_valid_time != 0 {
        return Err(E::custom(format!(
            "{label}: `cache_valid_time` requires `update_cache: true`"
        )));
    }

    Ok(PackageOp {
        manager,
        names,
        state,
        update_cache,
        cache_valid_time,
        purge,
        autoremove,
        default_release,
        allow_unauthenticated,
    })
}

/// Hand-written so we can:
///   - dispatch on `state:` (Ansible's surface) to pick an op kind,
///     since Ansible folds rule/enable/disable/reset/etc. under one
///     module argument set
///   - flatten port/proto/from/to/iface/comment into a single record
///   - default direction to empty (the agent expands defaults)
impl<'de> Deserialize<'de> for UfwOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let state = take_optional_field_string(&mut map, "state")?;
        let rule_field = take_optional_field_string(&mut map, "rule")?;
        let default_field = take_optional_field_string(&mut map, "default")?;
        let logging_field = take_optional_field_string(&mut map, "logging")?;
        let direction = take_optional_field_string(&mut map, "direction")?.unwrap_or_default();
        let proto = take_optional_field_string(&mut map, "proto")?.unwrap_or_default();
        let comment = take_optional_field_string(&mut map, "comment")?.unwrap_or_default();
        let interface = take_optional_field_string(&mut map, "interface")?
            .or(take_optional_field_string(&mut map, "if")?)
            .unwrap_or_default();
        let from_ip = take_optional_field_string(&mut map, "from_ip")?
            .or(take_optional_field_string(&mut map, "src")?)
            .or(take_optional_field_string(&mut map, "from")?)
            .unwrap_or_default();
        let to_ip = take_optional_field_string(&mut map, "to_ip")?
            .or(take_optional_field_string(&mut map, "dest")?)
            .or(take_optional_field_string(&mut map, "to")?)
            .unwrap_or_default();
        // Port fields accept either int (`port: 22`) or string (`port:
        // "22:25"` for ranges). Coerce int → string.
        let from_port = take_optional_port(&mut map, "from_port")?.unwrap_or_default();
        // `port:` is the common Ansible spelling for "destination port".
        let to_port = take_optional_port(&mut map, "to_port")?
            .or(take_optional_port(&mut map, "port")?)
            .unwrap_or_default();
        let delete = take_optional_ansible_bool(&mut map, "delete")?.unwrap_or(false);
        let insert = match map.remove("insert") {
            None | Some(serde_yaml::Value::Null) => 0u32,
            Some(serde_yaml::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                D::Error::custom(format!(
                    "ufw.insert must be a non-negative integer, got: {n}"
                ))
            })? as u32,
            Some(serde_yaml::Value::String(s)) => s.parse::<u32>().map_err(|e| {
                D::Error::custom(format!("ufw.insert: invalid int {s:?}: {e}"))
            })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "ufw.insert must be a number, got: {other:?}"
                )))
            }
        };

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "ufw: unknown field(s): {unknown:?}; expected one of \
                 [state, rule, default, logging, direction, proto, from, from_ip, src, from_port, to, to_ip, dest, to_port, port, interface, if, comment, delete, insert]"
            )));
        }

        // Determine the op kind. Priority:
        //   * state: enabled/disabled/reloaded/reset → those ops
        //   * default: → default-policy op
        //   * logging: → logging op
        //   * rule + state default → rule op (default state)
        let state_lc = state.as_deref().map(|s| s.to_ascii_lowercase());
        let (op_kind, rule) = match state_lc.as_deref() {
            Some("enabled") => (UfwOpKind::Enable, String::new()),
            Some("disabled") => (UfwOpKind::Disable, String::new()),
            Some("reloaded") => (UfwOpKind::Reload, String::new()),
            Some("reset") => (UfwOpKind::Reset, String::new()),
            _ => {
                if let Some(d) = default_field {
                    (UfwOpKind::Default, d)
                } else if let Some(l) = logging_field {
                    (UfwOpKind::Logging, l)
                } else if let Some(r) = rule_field {
                    (UfwOpKind::Rule, r)
                } else {
                    return Err(D::Error::custom(
                        "ufw: must specify one of [rule, default, logging] or state=enabled/disabled/reloaded/reset",
                    ));
                }
            }
        };

        // Validation per kind.
        match op_kind {
            UfwOpKind::Rule => {
                let r = rule.to_ascii_lowercase();
                if !matches!(r.as_str(), "allow" | "deny" | "limit" | "reject") {
                    return Err(D::Error::custom(format!(
                        "ufw.rule: expected one of [allow, deny, limit, reject], got: {rule:?}"
                    )));
                }
            }
            UfwOpKind::Default => {
                let r = rule.to_ascii_lowercase();
                if !matches!(r.as_str(), "allow" | "deny" | "reject") {
                    return Err(D::Error::custom(format!(
                        "ufw.default: expected one of [allow, deny, reject], got: {rule:?}"
                    )));
                }
            }
            UfwOpKind::Logging => {
                let r = rule.to_ascii_lowercase();
                if !matches!(
                    r.as_str(),
                    "on" | "off" | "low" | "medium" | "high" | "full"
                ) {
                    return Err(D::Error::custom(format!(
                        "ufw.logging: expected one of [on, off, low, medium, high, full], got: {rule:?}"
                    )));
                }
            }
            _ => {}
        }

        if !direction.is_empty() {
            let d = direction.to_ascii_lowercase();
            if !matches!(
                d.as_str(),
                "in" | "out" | "routed" | "incoming" | "outgoing"
            ) {
                return Err(D::Error::custom(format!(
                    "ufw.direction: expected one of [in, out, routed, incoming, outgoing], got: {direction:?}"
                )));
            }
        }
        if !proto.is_empty() {
            let p = proto.to_ascii_lowercase();
            if !matches!(p.as_str(), "any" | "tcp" | "udp" | "esp" | "ah" | "ipv6" | "igmp") {
                return Err(D::Error::custom(format!(
                    "ufw.proto: expected one of [any, tcp, udp, esp, ah, ipv6, igmp], got: {proto:?}"
                )));
            }
        }

        Ok(UfwOp {
            op: op_kind,
            rule,
            direction,
            proto,
            from_ip,
            from_port,
            to_ip,
            to_port,
            interface,
            comment,
            delete,
            insert,
        })
    }
}

/// `uri:` parsed form. Mirrors Ansible's `ansible.builtin.uri` (subset).
/// Fields documented at the module-level for `OpUri` in `wire.schema.json5`.
///
/// `body` here is always a string at this layer — for `body_format: json`
/// with a YAML mapping/list source, the deserializer serializes to JSON
/// at parse time so the wire transport stays a single bytes field.
#[derive(Debug, Clone, PartialEq)]
pub struct UriOp {
    /// Jinja-templated URL. Required.
    pub url: String,
    /// `uri_method::*` byte: GET/POST/PUT/PATCH/DELETE/HEAD.
    pub method: u8,
    /// Request headers. Values are Jinja-templated at run time.
    /// BTreeMap so iteration order is deterministic on the wire.
    pub headers: BTreeMap<String, String>,
    /// Possibly Jinja-templated. For `body_format: json` with a YAML
    /// map/list source, this is the pre-serialized JSON string.
    pub body: String,
    /// `uri_body_format::*` byte: RAW/JSON/FORM.
    pub body_format: u8,
    /// Accepted HTTP statuses. Non-empty; default `[200]`.
    pub status_codes: Vec<u16>,
    /// Total request timeout in milliseconds. Default 30_000.
    pub timeout_ms: u32,
    /// If true, include the response body (UTF-8) in the envelope.
    pub return_content: bool,
    /// If false, disable TLS cert / hostname verification. Default true.
    pub validate_certs: bool,
    /// `uri_follow::*` byte: NONE/SAFE/ALL. Default SAFE.
    pub follow_redirects: u8,
    /// Path on the controller to a PEM-encoded client certificate.
    /// Empty = absent. Jinja-templatable. Read into bytes at render
    /// time (so a per-host path templated from `inventory_hostname`
    /// works). Matches Ansible's `uri.client_cert`.
    pub client_cert: String,
    /// Path on the controller to the PEM-encoded private key paired
    /// with `client_cert`. Required if `client_cert` is set. Empty =
    /// absent. Jinja-templatable. Matches Ansible's `uri.client_key`.
    pub client_key: String,
    /// Path on the controller to a PEM-encoded CA bundle used to
    /// verify the server certificate (added on top of the system
    /// roots, not replacing them). Empty = absent. Jinja-templatable.
    /// Matches Ansible's `uri.ca_path`.
    pub ca_path: String,
}

/// Hand-written so we can:
///   - accept method case-insensitively (`get`/`Get`/`GET`)
///   - accept `status_code` as a single int OR a list of ints
///   - accept `body` as string OR mapping/list (with `body_format: json`
///     a non-string body is serialized to JSON at parse time)
///   - accept `headers` as a mapping of string→string
///   - accept `timeout` as seconds (int or float) and convert to ms
///   - accept `follow_redirects` as `none`/`safe`/`all` (case-insensitive)
impl<'de> Deserialize<'de> for UriOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        // url — required, must be a non-empty string here (Jinja can
        // render to empty at runtime; that's validate-time's job).
        let url = match map.remove("url") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.url: expected a string, got: {other:?}"
                )));
            }
            None => return Err(D::Error::missing_field("url")),
        };

        // method — case-insensitive verb, default GET.
        let method = match map.remove("method") {
            None | Some(serde_yaml::Value::Null) => uri_method::GET,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_uppercase().as_str() {
                "GET" => uri_method::GET,
                "POST" => uri_method::POST,
                "PUT" => uri_method::PUT,
                "PATCH" => uri_method::PATCH,
                "DELETE" => uri_method::DELETE,
                "HEAD" => uri_method::HEAD,
                other => {
                    return Err(D::Error::custom(format!(
                        "uri.method: expected one of [GET, POST, PUT, PATCH, DELETE, HEAD], got: {other:?}"
                    )));
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.method: expected a string, got: {other:?}"
                )));
            }
        };

        // headers — a YAML mapping with string keys + string values.
        let headers: BTreeMap<String, String> = match map.remove("headers") {
            None | Some(serde_yaml::Value::Null) => BTreeMap::new(),
            Some(serde_yaml::Value::Mapping(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    let key = match k {
                        serde_yaml::Value::String(s) => s,
                        other => {
                            return Err(D::Error::custom(format!(
                                "uri.headers: keys must be strings, got: {other:?}"
                            )));
                        }
                    };
                    let val = match v {
                        serde_yaml::Value::String(s) => s,
                        // Ansible accepts numeric header values; coerce.
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "uri.headers[{key:?}]: expected a string or scalar, got: {other:?}"
                            )));
                        }
                    };
                    out.insert(key, val);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.headers: expected a mapping, got: {other:?}"
                )));
            }
        };

        // body_format — default raw.
        let body_format = match map.remove("body_format") {
            None | Some(serde_yaml::Value::Null) => uri_body_format::RAW,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "raw" => uri_body_format::RAW,
                "json" => uri_body_format::JSON,
                "form" | "form-urlencoded" => uri_body_format::FORM,
                other => {
                    return Err(D::Error::custom(format!(
                        "uri.body_format: expected one of [raw, json, form], got: {other:?}"
                    )));
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.body_format: expected a string, got: {other:?}"
                )));
            }
        };

        // body — accept string verbatim; or, for body_format=json, accept
        // YAML mapping/list and serialize to JSON at parse time.
        let body = match map.remove("body") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(v @ serde_yaml::Value::Mapping(_)) | Some(v @ serde_yaml::Value::Sequence(_)) => {
                if body_format != uri_body_format::JSON {
                    return Err(D::Error::custom(
                        "uri.body: non-string body requires `body_format: json` \
                         (a YAML mapping/list is only auto-serialized as JSON)",
                    ));
                }
                serde_json::to_string(&v).map_err(|e| {
                    D::Error::custom(format!("uri.body: failed to JSON-encode: {e}"))
                })?
            }
            Some(serde_yaml::Value::Number(n)) => n.to_string(),
            Some(serde_yaml::Value::Bool(b)) => b.to_string(),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.body: expected a string or (with body_format=json) a mapping/list, got: {other:?}"
                )));
            }
        };

        // status_code — single int or list of ints; default [200].
        let status_codes = match map.remove("status_code") {
            None | Some(serde_yaml::Value::Null) => vec![200u16],
            Some(serde_yaml::Value::Number(n)) => {
                let v = n.as_u64().ok_or_else(|| {
                    D::Error::custom(format!("uri.status_code: expected a non-negative int, got: {n}"))
                })?;
                if !(100..=599).contains(&v) {
                    return Err(D::Error::custom(format!(
                        "uri.status_code: {v} out of range [100, 599]"
                    )));
                }
                vec![v as u16]
            }
            Some(serde_yaml::Value::Sequence(seq)) => {
                if seq.is_empty() {
                    return Err(D::Error::custom("uri.status_code: list must be non-empty"));
                }
                let mut out = Vec::with_capacity(seq.len());
                for item in seq {
                    let n = match item {
                        serde_yaml::Value::Number(n) => n,
                        other => {
                            return Err(D::Error::custom(format!(
                                "uri.status_code: list entries must be ints, got: {other:?}"
                            )));
                        }
                    };
                    let v = n.as_u64().ok_or_else(|| {
                        D::Error::custom(format!("uri.status_code: expected a non-negative int, got: {n}"))
                    })?;
                    if !(100..=599).contains(&v) {
                        return Err(D::Error::custom(format!(
                            "uri.status_code: {v} out of range [100, 599]"
                        )));
                    }
                    out.push(v as u16);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.status_code: expected an int or list of ints, got: {other:?}"
                )));
            }
        };

        // timeout — seconds (int or float) → ms. Default 30s.
        let timeout_ms = match map.remove("timeout") {
            None | Some(serde_yaml::Value::Null) => 30_000u32,
            Some(serde_yaml::Value::Number(n)) => {
                let s = n.as_f64().ok_or_else(|| {
                    D::Error::custom(format!("uri.timeout: invalid number {n}"))
                })?;
                if !s.is_finite() || s < 0.0 {
                    return Err(D::Error::custom(format!(
                        "uri.timeout: expected non-negative seconds, got {s}"
                    )));
                }
                (s * 1000.0) as u32
            }
            Some(serde_yaml::Value::String(s)) => {
                let f = s.parse::<f64>().map_err(|e| {
                    D::Error::custom(format!("uri.timeout: invalid number {s:?}: {e}"))
                })?;
                if !f.is_finite() || f < 0.0 {
                    return Err(D::Error::custom(format!(
                        "uri.timeout: expected non-negative seconds, got {f}"
                    )));
                }
                (f * 1000.0) as u32
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.timeout: expected a number or numeric string, got: {other:?}"
                )));
            }
        };

        // return_content / validate_certs — Ansible-flavored bools.
        let return_content = take_optional_ansible_bool::<D::Error>(&mut map, "return_content")?
            .unwrap_or(false);
        let validate_certs = take_optional_ansible_bool::<D::Error>(&mut map, "validate_certs")?
            .unwrap_or(true);

        // follow_redirects — none/safe/all. Default safe.
        let follow_redirects = match map.remove("follow_redirects") {
            None | Some(serde_yaml::Value::Null) => uri_follow::SAFE,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "none" | "no" | "false" => uri_follow::NONE,
                "safe" => uri_follow::SAFE,
                "all" | "yes" | "true" => uri_follow::ALL,
                other => {
                    return Err(D::Error::custom(format!(
                        "uri.follow_redirects: expected one of [none, safe, all], got: {other:?}"
                    )));
                }
            },
            // Ansible historically accepts a bool here too (no/yes).
            Some(serde_yaml::Value::Bool(b)) => {
                if b {
                    uri_follow::ALL
                } else {
                    uri_follow::NONE
                }
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.follow_redirects: expected a string, got: {other:?}"
                )));
            }
        };

        // mTLS / custom-CA paths. Strings (paths on the controller),
        // Jinja-templatable, optional. Empty string = absent. Bytes are
        // read at render time so per-host paths work.
        let client_cert = take_optional_string::<D::Error>(&mut map, "client_cert", "uri")?
            .unwrap_or_default();
        let client_key = take_optional_string::<D::Error>(&mut map, "client_key", "uri")?
            .unwrap_or_default();
        let ca_path = take_optional_string::<D::Error>(&mut map, "ca_path", "uri")?
            .unwrap_or_default();
        if !client_cert.is_empty() && client_key.is_empty() {
            return Err(D::Error::custom(
                "uri.client_cert is set but uri.client_key is missing — \
                 a client cert without its key cannot complete the mTLS handshake",
            ));
        }
        if client_cert.is_empty() && !client_key.is_empty() {
            return Err(D::Error::custom(
                "uri.client_key is set but uri.client_cert is missing — \
                 a client key on its own is useless",
            ));
        }

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "uri: unknown field(s): {unknown:?}; expected one of \
                 [url, method, headers, body, body_format, status_code, \
                 timeout, return_content, validate_certs, follow_redirects, \
                 client_cert, client_key, ca_path]"
            )));
        }

        Ok(UriOp {
            url,
            method,
            headers,
            body,
            body_format,
            status_codes,
            timeout_ms,
            return_content,
            validate_certs,
            follow_redirects,
            client_cert,
            client_key,
            ca_path,
        })
    }
}

/// Hand-written so we can apply Ansible-flavored defaults (marker
/// template, marker_begin/end, append-default insertion) and enforce
/// cross-field constraints (insertbefore/insertafter mutual exclusion).
impl<'de> Deserialize<'de> for BlockInFileOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let path = match map.remove("path") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "blockinfile.path must be a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::custom("blockinfile: missing required field `path`")),
        };

        let block = match map.remove("block") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "blockinfile.block must be a string, got: {other:?}"
                )))
            }
        };

        let marker = take_optional_field_string(&mut map, "marker")?
            .unwrap_or_else(|| "# {mark} ANSIBLE MANAGED BLOCK".to_string());
        let marker_begin = take_optional_field_string(&mut map, "marker_begin")?
            .unwrap_or_else(|| "BEGIN".to_string());
        let marker_end = take_optional_field_string(&mut map, "marker_end")?
            .unwrap_or_else(|| "END".to_string());
        let insertbefore = take_optional_field_string(&mut map, "insertbefore")?.unwrap_or_default();
        let insertafter = take_optional_field_string(&mut map, "insertafter")?.unwrap_or_default();

        let state = match map.remove("state") {
            None => BlockInFileState::Present,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => BlockInFileState::Present,
                "absent" => BlockInFileState::Absent,
                other => {
                    return Err(D::Error::custom(format!(
                        "blockinfile.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "blockinfile.state must be a string, got: {other:?}"
                )))
            }
        };

        let mode = take_optional_mode(&mut map, "mode")?;
        let create = take_optional_ansible_bool(&mut map, "create")?.unwrap_or(false);

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "blockinfile: unknown field(s): {unknown:?}; expected one of \
                 [path, block, marker, marker_begin, marker_end, state, mode, create, insertbefore, insertafter]"
            )));
        }

        if !insertbefore.is_empty() && !insertafter.is_empty() {
            return Err(D::Error::custom(
                "blockinfile: insertbefore and insertafter are mutually exclusive",
            ));
        }
        if !marker.contains("{mark}") {
            return Err(D::Error::custom(
                "blockinfile.marker must contain the literal token `{mark}`",
            ));
        }

        Ok(BlockInFileOp {
            path,
            block,
            marker,
            marker_begin,
            marker_end,
            state,
            mode,
            create,
            insertbefore,
            insertafter,
        })
    }
}

/// Pull an optional string out of a YAML mapping. None on absent/null;
/// errors on non-string. Used by per-op deserializers; the other
/// `take_optional_string` below is the older, task-shell variant that
/// also formats the task name into errors.
fn take_optional_field_string<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        Some(other) => Err(E::custom(format!(
            "{key}: expected a string, got: {other:?}"
        ))),
    }
}

/// Pull an optional Ansible-flavored bool out of a YAML mapping.
fn take_optional_ansible_bool<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<bool>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" => Ok(Some(true)),
            "no" | "false" | "off" => Ok(Some(false)),
            other => Err(E::custom(format!(
                "{key}: expected bool (true/false/yes/no/on/off), got: {other:?}"
            ))),
        },
        Some(other) => Err(E::custom(format!(
            "{key}: expected bool, got: {other:?}"
        ))),
    }
}

/// Accept either a YAML integer (`port: 22`) or a string (`port:
/// "22:25"`, `port: "ssh"`) and return the string form. Ansible's port
/// fields accept both. Returns None on absent/null.
fn take_optional_port<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        Some(serde_yaml::Value::Number(n)) => Ok(Some(n.to_string())),
        Some(other) => Err(E::custom(format!(
            "{key}: expected a port number or string, got: {other:?}"
        ))),
    }
}

/// Pull an optional Ansible-flavored mode out of a YAML mapping. Accepts
/// int (`0o755`) or string (`"0755"`/`"755"`/`"0o755"`).
fn take_optional_mode<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<u32>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::Number(n)) => {
            let v = n.as_u64().ok_or_else(|| {
                E::custom(format!("{key}: expected non-negative integer, got: {n}"))
            })? as u32;
            if v & !0o7777 != 0 {
                return Err(E::custom(format!(
                    "{key}: only the low 12 bits are meaningful (got 0o{v:o})"
                )));
            }
            Ok(Some(v))
        }
        Some(serde_yaml::Value::String(s)) => {
            let v = parse_mode_str(&s).map_err(E::custom)?;
            if v & !0o7777 != 0 {
                return Err(E::custom(format!(
                    "{key}: only the low 12 bits are meaningful (got 0o{v:o})"
                )));
            }
            Ok(Some(v))
        }
        Some(other) => Err(E::custom(format!(
            "{key}: expected string or int, got: {other:?}"
        ))),
    }
}

/// Keys that select a task body. Exactly one must appear per task.
const BODY_KEYS: &[&str] = &[
    "shell",
    "exec",
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
    "package",
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
    "assert",
    "fail",
    "set_fact",
    "import_tasks",
    "include_role",
    "meta",
];

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
];

impl<'de> Deserialize<'de> for Task {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

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
        let when = take_optional_string(&mut map, "when", &name)?;
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
        let async_seconds = match map.remove("async") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::Number(n)) => Some(n.as_u64().ok_or_else(|| {
                D::Error::custom(format!(
                    "task {name:?}: `async` must be a non-negative integer (seconds), got: {n:?}"
                ))
            })? as u32),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `async` must be an integer number of seconds, got: {other:?}"
                )));
            }
        };
        let poll_seconds = match map.remove("poll") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::Number(n)) => Some(n.as_u64().ok_or_else(|| {
                D::Error::custom(format!(
                    "task {name:?}: `poll` must be a non-negative integer (seconds), got: {n:?}"
                ))
            })? as u32),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `poll` must be an integer number of seconds, got: {other:?}"
                )));
            }
        };
        if poll_seconds.is_some() && async_seconds.is_none() {
            return Err(D::Error::custom(format!(
                "task {name:?}: `poll:` is only meaningful with `async:` set"
            )));
        }
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
                // `apt:` pins manager=Apt; reuses the shared package
                // body parser.
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Package(parse_package_body::<D::Error>(
                    PackageManager::Apt,
                    map,
                )?))
            }
            "package" => {
                // `package:` uses manager=Auto — the agent picks at run
                // time based on what's on PATH / gathered facts. Refuses
                // apt-only knobs since we can't promise the picked
                // backend honors them.
                let map: serde_yaml::Mapping =
                    serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?;
                TaskBody::Op(TaskOp::Package(parse_package_body::<D::Error>(
                    PackageManager::Auto,
                    map,
                )?))
            }
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
            "assert" => TaskBody::Assert(
                serde_yaml::from_value(body_yaml).map_err(D::Error::custom)?,
            ),
            "fail" => TaskBody::Fail(
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
            _ => unreachable!("body key not in BODY_KEYS dispatch"),
        };

        // `vars:` is consumed by the include_role arm above. If it's set
        // on any other body kind, surface the error (rather than silently
        // dropping the override).
        if task_vars.is_some() && !matches!(body, TaskBody::IncludeRole(_)) {
            return Err(D::Error::custom(format!(
                "task {name:?}: `vars:` is only supported on `include_role:` tasks; \
                 use set_fact or play-level vars for general task variables"
            )));
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

fn take_optional_string<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
    task_name: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        // `register: my_name` and `when: x == 1` are always strings in
        // user-facing YAML. Be strict: reject numbers/bools to catch
        // `when: 1` style typos early.
        Some(other) => Err(E::custom(format!(
            "task {task_name:?}: `{key}` must be a string, got: {other:?}"
        ))),
    }
}

/// Accept a YAML field that's either a single string or a list of
/// strings, returning `Option<Vec<String>>` (None on missing/null).
/// Used by openssl_csr_pipe's `subject_alt_name` / `key_usage` /
/// `extended_key_usage` which Ansible permits in both shapes.
fn take_optional_string_list<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<Vec<String>>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(vec![s])),
        Some(serde_yaml::Value::Sequence(seq)) => {
            let mut out = Vec::with_capacity(seq.len());
            for (i, v) in seq.into_iter().enumerate() {
                match v {
                    serde_yaml::Value::String(s) => out.push(s),
                    other => return Err(E::custom(format!(
                        "{key}[{i}]: expected a string, got: {other:?}"
                    ))),
                }
            }
            Ok(Some(out))
        }
        Some(other) => Err(E::custom(format!(
            "{key}: expected a string or list of strings, got: {other:?}"
        ))),
    }
}

/// `shell: "..."` (most common) or `shell: { command: "...", timeout_ms: N }`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ShellOp {
    Simple(String),
    Detailed {
        command: String,
        #[serde(default)]
        timeout_ms: u32,
    },
}

impl ShellOp {
    pub fn command(&self) -> &str {
        match self {
            ShellOp::Simple(s) => s,
            ShellOp::Detailed { command, .. } => command,
        }
    }
    pub fn timeout_ms(&self) -> u32 {
        match self {
            ShellOp::Simple(_) => 0,
            ShellOp::Detailed { timeout_ms, .. } => *timeout_ms,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecOp {
    pub argv: Vec<String>,
    /// Env keys map to string values. YAML often spells these as bare
    /// scalars (`COUNT: 3`, `DEBUG: true`); coerce ints/bools to their
    /// string form to match Ansible's behavior.
    #[serde(default, deserialize_with = "deserialize_scalar_string_map")]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Optional stdin payload, base64-encoded in YAML so binary data survives.
    /// (Empty/absent → empty stdin.) v0 keeps this minimal; we only handle
    /// the UTF-8 string form here. Bytes form lands when we need it.
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub timeout_ms: u32,
}

/// Accept `BTreeMap<String, scalar>` where scalar values may be strings,
/// numbers, or bools — return them all as `String`.
fn deserialize_scalar_string_map<'de, D>(d: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: BTreeMap<String, serde_yaml::Value> = BTreeMap::deserialize(d)?;
    raw.into_iter()
        .map(|(k, v)| {
            let s = match v {
                serde_yaml::Value::String(s) => s,
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::Bool(b) => b.to_string(),
                serde_yaml::Value::Null => String::new(),
                other => {
                    return Err(D::Error::custom(format!(
                        "env value for {k:?} must be a scalar (string/number/bool/null), got: {other:?}"
                    )))
                }
            };
            Ok((k, s))
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WriteFileOp {
    pub path: String,
    /// Octal in YAML (e.g. `0o644`) — serde-yaml parses that natively.
    pub mode: u32,
    pub content: String,
}

/// `template: { src: foo.j2, dest: /etc/foo, mode: 0o644 }`
///
/// `src:` is resolved at playbook load time. When the task came from a
/// role (`task.role_dir.is_some()`), the lookup order is:
///
/// 1. absolute path (used as-is)
/// 2. `<role_dir>/templates/<src>`
/// 3. `<playbook_dir>/templates/<src>`
/// 4. `<playbook_dir>/<src>`
///
/// The resolved file's contents are loaded into `body` during the
/// template-resolution pass and rendered at task execution time. `src`
/// is retained for diagnostics. `body` does not parse from YAML — it's
/// populated by the loader, after which `body.is_some()` indicates the
/// template was found.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TemplateOp {
    pub src: String,
    pub dest: String,
    #[serde(default = "default_template_mode")]
    pub mode: u32,
    /// Populated by the load-time template resolver. `None` until then.
    #[serde(skip, default)]
    pub body: Option<String>,
}

fn default_template_mode() -> u32 {
    // Ansible's `template:` default; matches the surveyed gothab usage
    // where most templated files are non-executable config files.
    0o644
}

/// `copy: { src: foo.bin, dest: /etc/foo, mode: 0o644 }`
///
/// Resolution mirrors `template:` but looks in `files/` rather than
/// `templates/`:
///
/// 1. absolute path (used as-is)
/// 2. `<role_dir>/files/<src>`
/// 3. `<playbook_dir>/files/<src>`
/// 4. `<playbook_dir>/<src>`
///
/// The resolved file is loaded as raw bytes into `body` during the
/// copy-resolution pass; `body` does not parse from YAML. Unlike
/// `template:`, the bytes are shipped verbatim — no Jinja rendering of
/// the content, so `copy:` supports binary blobs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CopyOp {
    pub src: String,
    pub dest: String,
    #[serde(default = "default_template_mode")]
    pub mode: u32,
    /// Populated by the load-time copy resolver. `None` until then.
    #[serde(skip, default)]
    pub body: Option<Vec<u8>>,
}

/// `openssl_privatekey:` parsed form. Maps
/// `community.crypto.openssl_privatekey`. v1 supports `RSA` and
/// `Ed25519` key types. Generation happens controller-side at dispatch
/// time (not load time) — the orchestrator only mints a PEM after it
/// has decided ship-blind vs probe-first, and on the probe branch
/// skips generation entirely when the file already exists. So `body`
/// stays None at parse / validate / template-precompile time.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenSslPrivkeyOp {
    /// Destination path on the remote. Jinja-templatable.
    pub path: String,
    /// `RSA` or `Ed25519`. Default RSA (matches Ansible).
    pub kind: crate::x509::PrivkeyType,
    /// RSA modulus bits. Default 4096. Ignored for Ed25519.
    pub size: u32,
    /// Unix permission bits for the key file. Default 0o600.
    pub mode: u32,
    /// Force the probe-first branch (OpStat → maybe OpWriteFile) even
    /// when the wire-cost heuristic says ship-blind would be cheaper.
    /// Useful when an operator wants exact Ansible-flavored
    /// idempotency reporting (changed=false on the no-op case is then
    /// guaranteed at the cost of one round trip per task).
    pub force_probe: bool,
}

fn default_privkey_size() -> u32 { 4096 }
fn default_privkey_mode() -> u32 { 0o600 }

impl<'de> Deserialize<'de> for OpenSslPrivkeyOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        let path = match map.remove("path") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(serde_yaml::Value::String(_)) => {
                return Err(D::Error::custom("openssl_privatekey.path: must be non-empty"));
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.path: expected a string, got: {other:?}"
                )));
            }
            None => return Err(D::Error::custom("openssl_privatekey: `path` is required")),
        };
        let kind = match map.remove("type") {
            None | Some(serde_yaml::Value::Null) => crate::x509::PrivkeyType::Rsa,
            Some(serde_yaml::Value::String(s)) => crate::x509::PrivkeyType::from_yaml(&s)
                .map_err(|e| D::Error::custom(format!("openssl_privatekey.type: {e}")))?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.type: expected a string, got: {other:?}"
                )));
            }
        };
        let size = match map.remove("size") {
            None | Some(serde_yaml::Value::Null) => default_privkey_size(),
            Some(serde_yaml::Value::Number(n)) => n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| D::Error::custom(format!(
                    "openssl_privatekey.size: expected a positive integer, got: {n}"
                )))?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.size: expected an integer, got: {other:?}"
                )));
            }
        };
        let mode = match map.remove("mode") {
            None | Some(serde_yaml::Value::Null) => default_privkey_mode(),
            Some(serde_yaml::Value::Number(n)) => n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| D::Error::custom(format!(
                    "openssl_privatekey.mode: expected a non-negative integer, got: {n}"
                )))?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.mode: expected an integer (octal in YAML), got: {other:?}"
                )));
            }
        };
        let force_probe = take_optional_ansible_bool::<D::Error>(&mut map, "force_probe")?
            .unwrap_or(false);
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "openssl_privatekey: unknown field(s): {unknown:?}; expected one of \
                 [path, type, size, mode, force_probe]"
            )));
        }
        Ok(OpenSslPrivkeyOp { path, kind, size, mode, force_probe })
    }
}

/// `openssl_csr_pipe:` parsed form. The `_pipe` suffix in Ansible
/// means the CSR PEM is returned via the registered result
/// (`register.content`) rather than written to disk. Controller-side
/// only — no wire dispatch. The private key bytes come from
/// `HostCtx.privkey_pem_cache` keyed by `privatekey_path`.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenSslCsrPipeOp {
    /// Path on the remote that the private key lives at — used purely
    /// as the cache lookup key on the controller's privkey cache.
    /// Jinja-templatable so a per-host path works.
    pub privatekey_path: String,
    /// Subject CN. Jinja-templatable.
    pub common_name: String,
    /// Subject Alt Names, Ansible syntax: `DNS:foo`, `IP:1.2.3.4`,
    /// `email:ops@x`, `URI:https://x/`. Each entry is Jinja-templatable.
    pub subject_alt_name: Vec<String>,
    /// Optional KeyUsage flags (digitalSignature, keyEncipherment, …).
    pub key_usage: Vec<String>,
    /// Optional Extended KeyUsage names or dotted OIDs.
    pub extended_key_usage: Vec<String>,
}

impl<'de> Deserialize<'de> for OpenSslCsrPipeOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        let privatekey_path = match map.remove("privatekey_path") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "openssl_csr_pipe: `privatekey_path` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "openssl_csr_pipe.privatekey_path: expected non-empty string, got: {other:?}"
            ))),
        };
        let common_name = match map.remove("common_name") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "openssl_csr_pipe: `common_name` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "openssl_csr_pipe.common_name: expected non-empty string, got: {other:?}"
            ))),
        };
        let subject_alt_name = take_optional_string_list::<D::Error>(&mut map, "subject_alt_name")?
            .unwrap_or_default();
        let key_usage = take_optional_string_list::<D::Error>(&mut map, "key_usage")?
            .unwrap_or_default();
        let extended_key_usage = take_optional_string_list::<D::Error>(&mut map, "extended_key_usage")?
            .unwrap_or_default();
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "openssl_csr_pipe: unknown field(s): {unknown:?}; expected one of \
                 [privatekey_path, common_name, subject_alt_name, key_usage, extended_key_usage]"
            )));
        }
        Ok(OpenSslCsrPipeOp {
            privatekey_path, common_name, subject_alt_name, key_usage, extended_key_usage,
        })
    }
}

/// `x509_certificate_pipe:` parsed form. v1: self-signed only. The
/// CSR and private key both flow in as PEM strings (typically from
/// `{{ csr_result.content }}` / `{{ privkey_var }}` Jinja
/// expressions), so this op is decoupled from the controller-side
/// privkey cache.
#[derive(Debug, Clone, PartialEq)]
pub struct X509CertificatePipeOp {
    /// CSR PEM string. Jinja-templatable.
    pub csr_content: String,
    /// Private key PEM string used to self-sign. Jinja-templatable.
    pub privatekey_content: String,
    /// Provider name. v1 accepts only "selfsigned".
    pub provider: String,
    /// Validity window in days from controller-now. Default 365.
    pub valid_for_days: u32,
}

fn default_cert_provider() -> String { "selfsigned".to_string() }
fn default_cert_valid_days() -> u32 { 365 }

impl<'de> Deserialize<'de> for X509CertificatePipeOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        let csr_content = match map.remove("csr_content") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "x509_certificate_pipe: `csr_content` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.csr_content: expected non-empty string, got: {other:?}"
            ))),
        };
        let privatekey_content = match map.remove("privatekey_content") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "x509_certificate_pipe: `privatekey_content` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.privatekey_content: expected non-empty string, got: {other:?}"
            ))),
        };
        let provider = match map.remove("provider") {
            None | Some(serde_yaml::Value::Null) => default_cert_provider(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.provider: expected a string, got: {other:?}"
            ))),
        };
        // Fail loudly for the unimplemented providers so users don't
        // get a silently-wrong cert (e.g. a self-signed cert when they
        // asked for a CA-signed one).
        if provider != "selfsigned" {
            return Err(D::Error::custom(format!(
                "x509_certificate_pipe.provider {provider:?} not supported in v1; \
                 expected \"selfsigned\""
            )));
        }
        let valid_for_days = match map.remove("valid_for_days") {
            None | Some(serde_yaml::Value::Null) => default_cert_valid_days(),
            Some(serde_yaml::Value::Number(n)) => n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| D::Error::custom(format!(
                    "x509_certificate_pipe.valid_for_days: expected a positive integer, got: {n}"
                )))?,
            Some(other) => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.valid_for_days: expected an integer, got: {other:?}"
            ))),
        };
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "x509_certificate_pipe: unknown field(s): {unknown:?}; expected one of \
                 [csr_content, privatekey_content, provider, valid_for_days]"
            )));
        }
        Ok(X509CertificatePipeOp { csr_content, privatekey_content, provider, valid_for_days })
    }
}

/// `postgresql_query:` parsed form. Mirrors
/// `community.postgresql.postgresql_query` (subset).
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlQueryOp {
    /// SQL to execute. Jinja-templatable.
    pub query: String,
    /// Database name. Empty = "postgres" (server default).
    pub db: String,
    /// Login user. Empty = peer auth using the agent process uid.
    pub login_user: String,
    /// Login password. Empty = no password (peer/trust auth).
    pub login_password: String,
    /// UNIX socket path (e.g. `/var/run/postgresql`). Empty = use TCP.
    pub login_unix_socket: String,
    /// TCP host (only consulted if `login_unix_socket` is empty).
    /// Empty = `localhost`.
    pub login_host: String,
    /// TCP port. 0 = 5432.
    pub login_port: u16,
    /// `autocommit=true` runs the query outside any transaction
    /// (required for VACUUM, CREATE INDEX CONCURRENTLY, etc.).
    /// Default false → wrapped in BEGIN/COMMIT.
    pub autocommit: bool,
    /// Positional parameters as text. The agent binds these as text and
    /// relies on server-side casts (`WHERE id = $1::int`).
    pub positional_args: Vec<String>,
    /// Controller-classified: true if the SQL is read-only
    /// (SELECT/SHOW/EXPLAIN/VALUES/WITH/TABLE). Drives check-mode skip
    /// and `changed` reporting downstream.
    pub read_only: bool,
}

/// `postgresql_ext:` parsed form. Mirrors
/// `community.postgresql.postgresql_ext` (subset). Version updates
/// not implemented in v1.
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlExtOp {
    /// Extension name (e.g. `pg_stat_statements`).
    pub name: String,
    /// Target state. 0=present, 1=absent — matches the wire byte.
    pub state: u8,
    /// Pinned extension version. Empty = server default.
    pub version: String,
    /// Schema to install into. Empty = default. Field-named
    /// `ext_schema` on the wire to avoid colliding with the SQL
    /// reserved word `schema`.
    pub ext_schema: String,
    /// Add CASCADE to CREATE/DROP EXTENSION.
    pub cascade: bool,
    pub db: String,
    pub login_user: String,
    pub login_password: String,
    pub login_unix_socket: String,
    pub login_host: String,
    pub login_port: u16,
}

/// Classify a SQL statement as read-only or potentially-mutating, used
/// by `--check` to decide whether to dispatch the task or skip it
/// outright on the controller. Heuristic — not a full SQL parser — but
/// sufficient for the well-formed SQL gothab issues:
///
/// 1. Strip leading whitespace, `-- line comments`, and `/* block */`
///    comments (with nesting; postgres supports nested `/* */`).
/// 2. Look at the first identifier token.
/// 3. SELECT, SHOW, VALUES, TABLE → read-only.
///    EXPLAIN → read-only unless the option list / leading bareword
///    options include `ANALYZE` (or `EXECUTE` with non-EXPLAIN payload).
///    `EXPLAIN ANALYZE` runs the wrapped statement; we treat such a
///    body as a fresh sub-statement and recurse.
///    WITH → scan every parenthesised CTE body and the trailing
///    statement; if any of those contain a mutating keyword token
///    (INSERT/UPDATE/DELETE/MERGE/TRUNCATE/CREATE/DROP/…) at top level
///    of their respective sub-expression, the whole WITH is mutating.
///    Everything else → mutating.
///
/// When the SQL contains multiple statements separated by semicolons,
/// classify each; only return true if *every* statement is read-only.
///
/// Remaining caveats (documented; not blocking):
/// - The keyword scanner is identifier-aware (skips string literals,
///   dollar-quoted bodies, and double-quoted identifiers) so column /
///   table names that happen to spell `insert_ts` etc. don't trip it.
/// - We don't try to follow `EXECUTE` of a prepared statement; if a
///   caller uses `EXPLAIN ANALYZE EXECUTE foo`, we treat it as
///   mutating (conservative).
pub fn classify_sql_readonly(sql: &str) -> bool {
    let stripped = strip_sql_comments(sql);
    let statements = split_sql_statements(&stripped);
    if statements.is_empty() {
        // Empty / whitespace-only query: no mutation possible.
        return true;
    }
    statements.iter().all(|s| classify_one_statement_readonly(s))
}

/// Decide whether a single, comment-stripped statement is read-only.
fn classify_one_statement_readonly(stmt: &str) -> bool {
    match first_sql_keyword(stmt).as_deref() {
        Some("SELECT") | Some("SHOW") | Some("VALUES") | Some("TABLE") => true,
        Some("EXPLAIN") => explain_is_readonly(stmt),
        Some("WITH") => with_is_readonly(stmt),
        _ => false,
    }
}

/// Returns true if the EXPLAIN body executes its inner statement.
/// `EXPLAIN ANALYZE …` runs the inner; `EXPLAIN (ANALYZE) …` runs it;
/// `EXPLAIN (ANALYZE false) …` does not. Without ANALYZE the inner is
/// never executed regardless of what it contains.
fn explain_is_readonly(stmt: &str) -> bool {
    if !explain_options_include_analyze(stmt) {
        return true;
    }
    // ANALYZE is on — the wrapped statement runs. Strip the EXPLAIN
    // header (keyword + options block / bareword options) and classify
    // whatever's left as its own statement.
    let inner = strip_explain_header(stmt);
    classify_one_statement_readonly(inner)
}

/// Returns true if a `WITH …` statement is read-only — i.e. every CTE
/// body and the trailing statement use only read verbs.
fn with_is_readonly(stmt: &str) -> bool {
    // Conservative: if any mutating keyword token appears anywhere in
    // the WITH (outside string literals / dollar-quoted bodies /
    // quoted identifiers), call the whole thing mutating. This catches
    // both `WITH x AS (DELETE …) SELECT …` and the trailing-DML form
    // `WITH x AS (SELECT …) DELETE FROM t USING x`.
    !contains_mutating_keyword_token(stmt)
}

/// Mutating keywords we recognise as standalone identifiers. Lowercase
/// inputs are normalised by `next_identifier_token`'s `to_ascii_uppercase`.
const MUTATING_KEYWORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "CREATE", "DROP", "ALTER", "GRANT",
    "REVOKE", "CLUSTER", "REINDEX", "VACUUM", "REFRESH", "COPY", "CALL", "EXECUTE", "DO",
    "LISTEN", "UNLISTEN", "NOTIFY", "LOCK", "PREPARE", "DEALLOCATE", "SET", "RESET",
    "DISCARD", "SECURITY",
];

/// True if any identifier token in `s` (skipping string/identifier/dollar
/// literals) matches one of the mutating keywords.
fn contains_mutating_keyword_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(skip_to) = skip_literal(bytes, i) {
            i = skip_to;
            continue;
        }
        if let Some((tok, next)) = next_identifier_token(bytes, i) {
            i = next;
            if MUTATING_KEYWORDS.iter().any(|k| *k == tok) {
                return true;
            }
            continue;
        }
        i += 1;
    }
    false
}

/// True if the EXPLAIN options preceding the wrapped statement include
/// `ANALYZE` (legacy bareword) or `ANALYZE [TRUE|ON|1]` inside the
/// parenthesised options list. `ANALYZE FALSE` etc. don't count.
fn explain_options_include_analyze(stmt: &str) -> bool {
    let bytes = stmt.as_bytes();
    // Skip "EXPLAIN" keyword.
    let mut i = skip_one_keyword(bytes, 0, "EXPLAIN");
    i = skip_whitespace(bytes, i);
    // Parenthesised options form?
    if bytes.get(i).copied() == Some(b'(') {
        // Find matching ')'.
        let end = find_matching_paren(bytes, i).unwrap_or(bytes.len());
        let opts = &stmt[i + 1..end];
        return options_block_has_analyze_on(opts);
    }
    // Legacy bareword form: scan tokens until we hit something that
    // isn't ANALYZE/VERBOSE.
    let mut j = i;
    while j < bytes.len() {
        j = skip_whitespace(bytes, j);
        let Some((tok, next)) = next_identifier_token(bytes, j) else { return false };
        match tok.as_str() {
            "ANALYZE" => return true,
            "VERBOSE" => {
                j = next;
                continue;
            }
            _ => return false,
        }
    }
    false
}

/// True if a comma-separated EXPLAIN options block (e.g.
/// `ANALYZE, BUFFERS true`) sets ANALYZE to a truthy value (or leaves
/// it bare — defaults to ON).
fn options_block_has_analyze_on(opts: &str) -> bool {
    for opt in opts.split(',') {
        let mut parts = opt.split_ascii_whitespace();
        let Some(name) = parts.next() else { continue };
        if name.eq_ignore_ascii_case("ANALYZE") {
            // ANALYZE alone is ON; ANALYZE TRUE/ON/1 is ON.
            match parts.next() {
                None => return true,
                Some(v) => {
                    let v = v.to_ascii_uppercase();
                    if matches!(v.as_str(), "TRUE" | "ON" | "1") {
                        return true;
                    }
                    if matches!(v.as_str(), "FALSE" | "OFF" | "0") {
                        return false;
                    }
                    // Anything else (e.g. malformed) — conservative ON.
                    return true;
                }
            }
        }
    }
    false
}

/// Strip the `EXPLAIN [(...)] [ANALYZE] [VERBOSE]` header from a
/// statement; return the remaining wrapped statement. Used when ANALYZE
/// is on and we need to recurse on the inner statement.
fn strip_explain_header(stmt: &str) -> &str {
    let bytes = stmt.as_bytes();
    let mut i = skip_one_keyword(bytes, 0, "EXPLAIN");
    i = skip_whitespace(bytes, i);
    if bytes.get(i).copied() == Some(b'(') {
        let end = find_matching_paren(bytes, i).unwrap_or(bytes.len());
        i = end + 1;
        i = skip_whitespace(bytes, i);
    } else {
        // Legacy bareword options.
        while let Some((tok, next)) = next_identifier_token(bytes, i) {
            if matches!(tok.as_str(), "ANALYZE" | "VERBOSE") {
                i = next;
                i = skip_whitespace(bytes, i);
            } else {
                break;
            }
        }
    }
    &stmt[i..]
}

/// If the byte at `start` opens a string literal, identifier-literal, or
/// dollar-quoted body, return the index just past the closing delimiter.
/// Otherwise None.
fn skip_literal(bytes: &[u8], start: usize) -> Option<usize> {
    let b = *bytes.get(start)?;
    match b {
        b'\'' => {
            let mut i = start + 1;
            while i < bytes.len() {
                let c = bytes[i];
                i += 1;
                if c == b'\'' {
                    if bytes.get(i).copied() == Some(b'\'') {
                        i += 1;
                        continue;
                    }
                    return Some(i);
                }
            }
            Some(bytes.len())
        }
        b'"' => {
            let mut i = start + 1;
            while i < bytes.len() {
                let c = bytes[i];
                i += 1;
                if c == b'"' {
                    if bytes.get(i).copied() == Some(b'"') {
                        i += 1;
                        continue;
                    }
                    return Some(i);
                }
            }
            Some(bytes.len())
        }
        b'$' => {
            // Dollar-quoted body: $tag$ ... $tag$. tag may be empty.
            let mut j = start + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if bytes.get(j).copied() != Some(b'$') {
                return None;
            }
            let tag = &bytes[start + 1..j];
            let mut needle = Vec::with_capacity(tag.len() + 2);
            needle.push(b'$');
            needle.extend_from_slice(tag);
            needle.push(b'$');
            let body_start = j + 1;
            if let Some(off) = find_subslice(&bytes[body_start..], &needle) {
                Some(body_start + off + needle.len())
            } else {
                Some(bytes.len())
            }
        }
        _ => None,
    }
}

/// Return the next identifier token starting at `start` (skipping
/// leading whitespace), uppercased, plus the index just past it.
fn next_identifier_token(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = skip_whitespace(bytes, start);
    let token_start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        i += 1;
    }
    // Allow trailing digits/underscores once at least one alpha char has
    // been seen — but to keep keyword matching strict, stop at the first
    // non-alpha-underscore for now (keywords don't contain digits).
    if i == token_start {
        return None;
    }
    let tok = std::str::from_utf8(&bytes[token_start..i])
        .ok()?
        .to_ascii_uppercase();
    Some((tok, i))
}

fn skip_whitespace(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Skip the literal keyword `kw` if it appears at `start` (case
/// insensitive); otherwise return `start` unchanged.
fn skip_one_keyword(bytes: &[u8], start: usize, kw: &str) -> usize {
    let s = skip_whitespace(bytes, start);
    if s + kw.len() <= bytes.len()
        && bytes[s..s + kw.len()].eq_ignore_ascii_case(kw.as_bytes())
        && bytes
            .get(s + kw.len())
            .map(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
            .unwrap_or(true)
    {
        s + kw.len()
    } else {
        start
    }
}

/// Given an index pointing at `(`, find the matching `)`, respecting
/// nested parens and string/dollar/identifier literals inside.
fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 1i32;
    let mut i = open + 1;
    while i < bytes.len() {
        if let Some(skip_to) = skip_literal(bytes, i) {
            i = skip_to;
            continue;
        }
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    (0..=last).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Strip `-- line` and `/* nested */` comments from a SQL string.
/// Preserves string literals and dollar-quoted bodies verbatim — a `--`
/// inside a literal is not a comment.
fn strip_sql_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        match (b, next) {
            (b'-', Some(b'-')) => {
                // Line comment to EOL.
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                // Block comment; postgres supports nesting.
                let mut depth = 1u32;
                i += 2;
                while i + 1 < bytes.len() && depth > 0 {
                    match (bytes[i], bytes[i + 1]) {
                        (b'/', b'*') => {
                            depth += 1;
                            i += 2;
                        }
                        (b'*', b'/') => {
                            depth -= 1;
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
            }
            (b'\'', _) => {
                // Single-quoted literal — copy through, watching for '' escape.
                out.push(b as char);
                i += 1;
                while i < bytes.len() {
                    let c = bytes[i];
                    out.push(c as char);
                    i += 1;
                    if c == b'\'' {
                        // doubled? skip the second one.
                        if bytes.get(i).copied() == Some(b'\'') {
                            out.push('\'');
                            i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// Split a SQL body on unquoted `;`. Returns the trimmed, non-empty
/// statements.
fn split_sql_statements(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' => {
                cur.push(b as char);
                i += 1;
                while i < bytes.len() {
                    let c = bytes[i];
                    cur.push(c as char);
                    i += 1;
                    if c == b'\'' {
                        if bytes.get(i).copied() == Some(b'\'') {
                            cur.push('\'');
                            i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            b';' => {
                let trimmed = cur.trim().to_string();
                if !trimmed.is_empty() {
                    out.push(trimmed);
                }
                cur.clear();
                i += 1;
            }
            _ => {
                cur.push(b as char);
                i += 1;
            }
        }
    }
    let last = cur.trim().to_string();
    if !last.is_empty() {
        out.push(last);
    }
    out
}

/// Return the first identifier in the statement, uppercased.
fn first_sql_keyword(stmt: &str) -> Option<String> {
    let bytes = stmt.as_bytes();
    let mut i = 0;
    // skip whitespace and any leading `(` from things like
    // `( SELECT ... )`
    while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'(') {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        i += 1;
    }
    if i == start {
        return None;
    }
    Some(stmt[start..i].to_ascii_uppercase())
}

impl<'de> Deserialize<'de> for PostgresqlQueryOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let query = match map.remove("query") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::missing_field("query")),
            Some(other) => return Err(D::Error::custom(format!(
                "postgresql_query.query: expected non-empty string, got: {other:?}"
            ))),
        };
        let db = take_optional_field_string(&mut map, "db")?.unwrap_or_default();
        let login_user = take_optional_field_string(&mut map, "login_user")?.unwrap_or_default();
        let login_password =
            take_optional_field_string(&mut map, "login_password")?.unwrap_or_default();
        let login_unix_socket =
            take_optional_field_string(&mut map, "login_unix_socket")?.unwrap_or_default();
        let login_host = take_optional_field_string(&mut map, "login_host")?.unwrap_or_default();
        let login_port = match map.remove("login_port") {
            None | Some(serde_yaml::Value::Null) => 0u16,
            Some(serde_yaml::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .ok_or_else(|| {
                    D::Error::custom(format!(
                        "postgresql_query.login_port: expected uint16, got: {n}"
                    ))
                })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_query.login_port: expected integer, got: {other:?}"
                )))
            }
        };
        let autocommit =
            take_optional_ansible_bool(&mut map, "autocommit")?.unwrap_or(false);
        let positional_args: Vec<String> = match map.remove("positional_args") {
            None | Some(serde_yaml::Value::Null) => Vec::new(),
            Some(serde_yaml::Value::Sequence(seq)) => {
                let mut out = Vec::with_capacity(seq.len());
                for v in seq {
                    let s = match v {
                        serde_yaml::Value::String(s) => s,
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        serde_yaml::Value::Null => String::new(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "postgresql_query.positional_args item: expected scalar, got: {other:?}"
                            )))
                        }
                    };
                    out.push(s);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_query.positional_args: expected a list, got: {other:?}"
                )))
            }
        };

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "postgresql_query: unknown field(s): {unknown:?}; expected one of \
                 [query, db, login_user, login_password, login_unix_socket, \
                 login_host, login_port, autocommit, positional_args]"
            )));
        }

        let read_only = classify_sql_readonly(&query);
        Ok(PostgresqlQueryOp {
            query,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
            autocommit,
            positional_args,
            read_only,
        })
    }
}

impl<'de> Deserialize<'de> for PostgresqlExtOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let name = match map.remove("name") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::missing_field("name")),
            Some(other) => return Err(D::Error::custom(format!(
                "postgresql_ext.name: expected non-empty string, got: {other:?}"
            ))),
        };
        let state = match map.remove("state") {
            None | Some(serde_yaml::Value::Null) => postgresql_ext_state::PRESENT,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => postgresql_ext_state::PRESENT,
                "absent" => postgresql_ext_state::ABSENT,
                other => {
                    return Err(D::Error::custom(format!(
                        "postgresql_ext.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_ext.state: expected string, got: {other:?}"
                )))
            }
        };
        let version = take_optional_field_string(&mut map, "version")?.unwrap_or_default();
        let ext_schema = take_optional_field_string(&mut map, "schema")?.unwrap_or_default();
        let cascade = take_optional_ansible_bool(&mut map, "cascade")?.unwrap_or(false);
        let db = take_optional_field_string(&mut map, "db")?.unwrap_or_default();
        let login_user = take_optional_field_string(&mut map, "login_user")?.unwrap_or_default();
        let login_password =
            take_optional_field_string(&mut map, "login_password")?.unwrap_or_default();
        let login_unix_socket =
            take_optional_field_string(&mut map, "login_unix_socket")?.unwrap_or_default();
        let login_host = take_optional_field_string(&mut map, "login_host")?.unwrap_or_default();
        let login_port = match map.remove("login_port") {
            None | Some(serde_yaml::Value::Null) => 0u16,
            Some(serde_yaml::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .ok_or_else(|| {
                    D::Error::custom(format!(
                        "postgresql_ext.login_port: expected uint16, got: {n}"
                    ))
                })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_ext.login_port: expected integer, got: {other:?}"
                )))
            }
        };

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "postgresql_ext: unknown field(s): {unknown:?}; expected one of \
                 [name, state, version, schema, cascade, db, login_user, \
                 login_password, login_unix_socket, login_host, login_port]"
            )));
        }

        Ok(PostgresqlExtOp {
            name,
            state,
            version,
            ext_schema,
            cascade,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
        })
    }
}

/// `get_url:` parsed form. Mirrors `ansible.builtin.get_url` (subset).
/// All string fields are Jinja-templated at run time by the
/// orchestrator before `to_wire_op`.
#[derive(Debug, Clone, PartialEq)]
pub struct GetUrlOp {
    pub url: String,
    pub dest: String,
    /// `<algo>:<hex>` (sha256/sha1/md5). Empty = no verification.
    pub checksum: String,
    /// Octal file mode applied to dest after rename. 0 = leave alone.
    pub mode: u32,
    /// Owner name (resolved to uid agent-side). Empty = leave alone.
    pub owner: String,
    /// Group name (resolved to gid agent-side). Empty = leave alone.
    pub group: String,
    /// Request headers. BTreeMap = deterministic on the wire.
    pub headers: BTreeMap<String, String>,
    /// Total request timeout in milliseconds. Default 30_000.
    pub timeout_ms: u32,
    /// Force re-download even when dest is already present.
    pub force: bool,
    /// TLS cert/hostname verification. Default true.
    pub validate_certs: bool,
    /// `uri_follow::*` byte: NONE/SAFE/ALL. Default ALL (matches
    /// Ansible's `get_url` default — `safe` would refuse most CDN
    /// redirect chains).
    pub follow_redirects: u8,
    /// Optional mTLS material — paths on the controller, read at
    /// to_wire_op time. Empty = absent.
    pub client_cert: String,
    pub client_key: String,
    pub ca_path: String,
}

impl<'de> Deserialize<'de> for GetUrlOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let url = match map.remove("url") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.url: expected a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("url")),
        };

        let dest = match map.remove("dest") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.dest: expected a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("dest")),
        };

        let checksum = match map.remove("checksum") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.checksum: expected a string like sha256:<hex>, got: {other:?}"
                )))
            }
        };

        // mode — Ansible accepts octal strings ("0644") AND raw ints.
        let mode = match map.remove("mode") {
            None | Some(serde_yaml::Value::Null) => 0u32,
            Some(serde_yaml::Value::String(s)) => parse_octal_mode::<D::Error>(&s)?,
            Some(serde_yaml::Value::Number(n)) => {
                // Bare ints in YAML are decimal — treat as decimal mode
                // (Ansible's behaviour when you write `mode: 644` is to
                // interpret it as 0o1204 which is a bug; we follow the
                // string-form recommendation. For numeric input we just
                // take the bits as given.)
                n.as_u64()
                    .ok_or_else(|| D::Error::custom(format!("get_url.mode: bad number {n:?}")))?
                    as u32
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.mode: expected octal string or int, got: {other:?}"
                )))
            }
        };

        let owner = match map.remove("owner") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.owner: expected a string, got: {other:?}"
                )))
            }
        };
        let group = match map.remove("group") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.group: expected a string, got: {other:?}"
                )))
            }
        };

        let headers: BTreeMap<String, String> = match map.remove("headers") {
            None | Some(serde_yaml::Value::Null) => BTreeMap::new(),
            Some(serde_yaml::Value::Mapping(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    let key = match k {
                        serde_yaml::Value::String(s) => s,
                        other => {
                            return Err(D::Error::custom(format!(
                                "get_url.headers: keys must be strings, got: {other:?}"
                            )))
                        }
                    };
                    let val = match v {
                        serde_yaml::Value::String(s) => s,
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "get_url.headers[{key}]: expected scalar, got: {other:?}"
                            )))
                        }
                    };
                    out.insert(key, val);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.headers: expected a mapping, got: {other:?}"
                )))
            }
        };

        // `timeout:` is in seconds (matching Ansible). Accept int or float.
        let timeout_ms = match map.remove("timeout") {
            None | Some(serde_yaml::Value::Null) => 30_000u32,
            Some(serde_yaml::Value::Number(n)) => {
                if let Some(i) = n.as_u64() {
                    (i * 1000) as u32
                } else if let Some(f) = n.as_f64() {
                    (f * 1000.0) as u32
                } else {
                    return Err(D::Error::custom(format!(
                        "get_url.timeout: bad number {n:?}"
                    )));
                }
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.timeout: expected a number of seconds, got: {other:?}"
                )))
            }
        };

        let force = parse_ansible_bool::<D::Error>(map.remove("force"), "get_url.force", false)?;
        let validate_certs = parse_ansible_bool::<D::Error>(
            map.remove("validate_certs"),
            "get_url.validate_certs",
            true,
        )?;

        let follow_redirects = match map.remove("follow_redirects") {
            None | Some(serde_yaml::Value::Null) => uri_follow::ALL,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "none" => uri_follow::NONE,
                "safe" => uri_follow::SAFE,
                "all" | "yes" | "true" => uri_follow::ALL,
                other => {
                    return Err(D::Error::custom(format!(
                        "get_url.follow_redirects: expected one of [none, safe, all], got: {other:?}"
                    )))
                }
            },
            Some(serde_yaml::Value::Bool(true)) => uri_follow::ALL,
            Some(serde_yaml::Value::Bool(false)) => uri_follow::NONE,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.follow_redirects: expected string or bool, got: {other:?}"
                )))
            }
        };

        let client_cert = take_optional_string(&mut map, "client_cert", "get_url")?
            .unwrap_or_default();
        let client_key = take_optional_string(&mut map, "client_key", "get_url")?
            .unwrap_or_default();
        let ca_path = take_optional_string(&mut map, "ca_path", "get_url")?
            .unwrap_or_default();

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_str().map(String::from))
                .collect();
            return Err(D::Error::custom(format!(
                "get_url: unknown field(s): {unknown:?}; expected one of \
                 [url, dest, checksum, mode, owner, group, headers, timeout, \
                 force, validate_certs, follow_redirects, client_cert, \
                 client_key, ca_path]"
            )));
        }

        Ok(GetUrlOp {
            url,
            dest,
            checksum,
            mode,
            owner,
            group,
            headers,
            timeout_ms,
            force,
            validate_certs,
            follow_redirects,
            client_cert,
            client_key,
            ca_path,
        })
    }
}

impl<'de> Deserialize<'de> for SlurpOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let src = match map.remove("src") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "slurp.src: expected a non-empty string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("src")),
        };

        // Optional rsansible extension: `max_bytes:` safety cap. Zero is
        // the sentinel for "no cap" (matches the wire op). Vanilla
        // Ansible slurp has no cap.
        let max_bytes = match map.remove("max_bytes") {
            None | Some(serde_yaml::Value::Null) => 0u32,
            Some(serde_yaml::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| {
                    D::Error::custom(format!(
                        "slurp.max_bytes: expected non-negative integer ≤ u32::MAX, got: {n}"
                    ))
                })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "slurp.max_bytes: expected integer, got: {other:?}"
                )))
            }
        };

        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "slurp: unknown field {k:?}; only src/max_bytes accepted"
            )));
        }

        Ok(SlurpOp { src, max_bytes })
    }
}

impl<'de> Deserialize<'de> for UnarchiveOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let src = match map.remove("src") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.src: expected a non-empty string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("src")),
        };

        let dest = match map.remove("dest") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.dest: expected a non-empty string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("dest")),
        };

        // v1 requires `remote_src: yes`. The controller-pushed-archive
        // path (`copy:` ... + extract) isn't wired yet; surface a clear
        // error instead of silently uploading nothing.
        let remote_src =
            parse_ansible_bool::<D::Error>(map.remove("remote_src"), "unarchive.remote_src", false)?;
        if !remote_src {
            return Err(D::Error::custom(
                "unarchive: only `remote_src: yes` is supported in v1; \
                 push the archive in a prior copy/get_url task",
            ));
        }
        // `copy` is the deprecated inverse alias. Accept it for
        // compatibility but require it not to contradict remote_src.
        if let Some(v) = map.remove("copy") {
            let copy_val = parse_ansible_bool::<D::Error>(Some(v), "unarchive.copy", false)?;
            // `copy: no` means remote_src: yes (matches). `copy: yes` means push from controller — unsupported.
            if copy_val {
                return Err(D::Error::custom(
                    "unarchive: `copy: yes` (controller→agent push) not supported in v1",
                ));
            }
        }

        let format_str = match map.remove("format") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.format: expected a string, got: {other:?}"
                )))
            }
        };
        let format = match format_str.as_deref() {
            None | Some("") | Some("auto") => rsansible_wire::msg::unarchive_format::AUTO,
            Some("tar.gz") | Some("tgz") | Some("gz") | Some("gzip") => {
                rsansible_wire::msg::unarchive_format::TAR_GZ
            }
            Some("tar.bz2") | Some("tbz2") | Some("tbz") | Some("bz2") | Some("bzip2") => {
                rsansible_wire::msg::unarchive_format::TAR_BZ2
            }
            Some("tar.xz") | Some("txz") | Some("xz") => rsansible_wire::msg::unarchive_format::TAR_XZ,
            Some("tar") => rsansible_wire::msg::unarchive_format::TAR,
            Some("zip") => rsansible_wire::msg::unarchive_format::ZIP,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.format: unknown format {other:?}; \
                     accepted: auto/tar.gz/tgz/tar.bz2/tbz2/tar.xz/txz/tar/zip"
                )))
            }
        };

        let creates = match map.remove("creates") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.creates: expected a string, got: {other:?}"
                )))
            }
        };

        let owner = match map.remove("owner") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.owner: expected a string, got: {other:?}"
                )))
            }
        };
        let group = match map.remove("group") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.group: expected a string, got: {other:?}"
                )))
            }
        };

        let mode = match map.remove("mode") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) => Some(
                parse_mode_str(&s)
                    .map_err(|e| D::Error::custom(format!("unarchive.mode: {e}")))?,
            ),
            Some(serde_yaml::Value::Number(n)) => {
                // Numeric mode in YAML is treated as octal-looking
                // decimal (matches Ansible behaviour: `mode: 0755`).
                let s = n.to_string();
                Some(
                    parse_mode_str(&s)
                        .map_err(|e| D::Error::custom(format!("unarchive.mode: {e}")))?,
                )
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.mode: expected string or number, got: {other:?}"
                )))
            }
        };

        let keep_newer = parse_ansible_bool::<D::Error>(
            map.remove("keep_newer"),
            "unarchive.keep_newer",
            false,
        )?;
        let list_files = parse_ansible_bool::<D::Error>(
            map.remove("list_files"),
            "unarchive.list_files",
            false,
        )?;

        let include = match map.remove("include") {
            None | Some(serde_yaml::Value::Null) => Vec::new(),
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .into_iter()
                .map(|v| match v {
                    serde_yaml::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!(
                        "unarchive.include: each item must be a string, got: {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.include: expected list of strings, got: {other:?}"
                )))
            }
        };
        let exclude = match map.remove("exclude") {
            None | Some(serde_yaml::Value::Null) => Vec::new(),
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .into_iter()
                .map(|v| match v {
                    serde_yaml::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!(
                        "unarchive.exclude: each item must be a string, got: {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.exclude: expected list of strings, got: {other:?}"
                )))
            }
        };

        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "unarchive: unknown field {k:?}"
            )));
        }

        Ok(UnarchiveOp {
            src,
            dest,
            format,
            creates,
            mode,
            owner,
            group,
            keep_newer,
            list_files,
            include,
            exclude,
        })
    }
}

/// Ansible-compatible bool parsing. YAML's `yes`/`no` get quoted by
/// serde_yaml-0.9 (they live in the "schema" core but serde_yaml strips
/// them to strings), so accept the standard truthy/falsy spellings as
/// strings too.
fn parse_ansible_bool<E: serde::de::Error>(
    v: Option<serde_yaml::Value>,
    field: &str,
    default: bool,
) -> Result<bool, E> {
    match v {
        None | Some(serde_yaml::Value::Null) => Ok(default),
        Some(serde_yaml::Value::Bool(b)) => Ok(b),
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" | "1" => Ok(true),
            "no" | "false" | "off" | "0" => Ok(false),
            other => Err(E::custom(format!(
                "{field}: expected bool (yes/no/true/false), got: {other:?}"
            ))),
        },
        Some(other) => Err(E::custom(format!(
            "{field}: expected bool, got: {other:?}"
        ))),
    }
}

fn parse_octal_mode<E: serde::de::Error>(s: &str) -> Result<u32, E> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    let radix_stripped = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
        .unwrap_or(trimmed);
    u32::from_str_radix(radix_stripped, 8).map_err(|e| {
        E::custom(format!("expected octal mode string (e.g. \"0644\"), got {s:?}: {e}"))
    })
}

/// `assert: { that: ["x == 1", "y > 0"], msg: "..." }`
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AssertTask {
    /// One or more Jinja expressions. Ansible accepts a single string in
    /// place of a list; honor that for ergonomics.
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    pub that: Vec<String>,
    #[serde(default)]
    pub msg: Option<String>,
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
}

/// Read a PEM file from the controller filesystem at wire-emit time.
/// Empty path → empty bytes (= absent on the wire). The caller has
/// already rendered any Jinja in the path. Used by `OpUri` for
/// `client_cert` / `client_key` / `ca_path`. Errors are wrapped with
/// the field name so a missing `client_cert` surfaces as a clear
/// per-field message rather than a bare I/O error.
fn read_pem_if_set(path: &str, field: &str) -> Result<Vec<u8>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    std::fs::read(path)
        .with_context(|| format!("uri.{field}: reading PEM from {path:?}"))
}

impl TaskOp {
    /// Convert this playbook-level op into a wire `Op` message body.
    ///
    /// Caller is responsible for having rendered any Jinja in the op
    /// fields before calling this — `to_wire_op` itself is a pure
    /// structural conversion.
    pub fn to_wire_op(&self) -> Result<Op> {
        match self {
            TaskOp::Shell(s) => Ok(op_shell(s.command().to_string(), s.timeout_ms())),
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::generated::Op as WireOp;

    #[test]
    fn shell_simple_to_wire() {
        let t = TaskOp::Shell(ShellOp::Simple("echo hi".into()));
        let WireOp::OpShell(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.kind, 1);
        assert_eq!(s.command, "echo hi");
        assert_eq!(s.timeout_ms, 0);
    }

    #[test]
    fn shell_detailed_to_wire() {
        let t = TaskOp::Shell(ShellOp::Detailed {
            command: "sleep 1".into(),
            timeout_ms: 500,
        });
        let WireOp::OpShell(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.timeout_ms, 500);
    }

    #[test]
    fn exec_to_wire_preserves_env_order() {
        let mut env = BTreeMap::new();
        env.insert("B".into(), "2".into());
        env.insert("A".into(), "1".into());
        let t = TaskOp::Exec(ExecOp {
            argv: vec!["/bin/true".into()],
            env,
            cwd: Some("/tmp".into()),
            stdin: String::new(),
            timeout_ms: 1000,
        });
        let WireOp::OpExec(e) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(e.kind, 0);
        assert_eq!(e.argv, vec!["/bin/true"]);
        // BTreeMap → sorted keys → CSR parallel arrays.
        assert_eq!(e.env_keys, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(e.env_values, vec!["1".to_string(), "2".to_string()]);
        assert_eq!(e.cwd, "/tmp");
        assert_eq!(e.timeout_ms, 1000);
    }

    #[test]
    fn exec_empty_argv_rejected() {
        let t = TaskOp::Exec(ExecOp {
            argv: vec![],
            env: BTreeMap::new(),
            cwd: None,
            stdin: String::new(),
            timeout_ms: 0,
        });
        assert!(t.to_wire_op().is_err());
    }

    #[test]
    fn stat_to_wire_carries_path_and_follow() {
        let t = TaskOp::Stat(StatOp {
            path: "/etc/foo".into(),
            follow: true,
        });
        let WireOp::OpStat(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.kind, 4);
        assert_eq!(s.path, "/etc/foo");
        assert_eq!(s.follow, 1);

        let t = TaskOp::Stat(StatOp {
            path: "/etc/foo".into(),
            follow: false,
        });
        let WireOp::OpStat(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.follow, 0);
    }

    #[test]
    fn write_file_to_wire() {
        let t = TaskOp::WriteFile(WriteFileOp {
            path: "/tmp/x".into(),
            mode: 0o600,
            content: "hello".into(),
        });
        let WireOp::OpWriteFile(w) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(w.kind, 2);
        assert_eq!(w.path, "/tmp/x");
        assert_eq!(w.mode, 0o600);
        assert_eq!(w.content, b"hello");
    }

    fn parse_task(yaml: &str) -> Task {
        serde_yaml::from_str(yaml).expect("parses")
    }

    fn try_parse_task(yaml: &str) -> Result<Task, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
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
                assert_eq!(a.msg.as_deref(), Some("not happy"));
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
    fn parses_stat_minimal() {
        let t = parse_task(
            r#"
name: probe
stat:
  path: /etc/hostname
register: probe_stat
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Stat(s)) => {
                assert_eq!(s.path, "/etc/hostname");
                assert!(s.follow, "follow defaults to true (Ansible default)");
            }
            other => panic!("got {other:?}"),
        }
        assert_eq!(t.register.as_deref(), Some("probe_stat"));
    }

    #[test]
    fn parses_stat_with_follow_false() {
        let t = parse_task(
            r#"
name: probe
stat:
  path: /var/log/foo.log
  follow: no
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Stat(s)) => {
                assert_eq!(s.path, "/var/log/foo.log");
                assert!(!s.follow);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn stat_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
stat:
  path: /x
  bogus: 1
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unknown") || err.contains("bogus"),
            "got: {err}"
        );
    }

    #[test]
    fn stat_rejects_missing_path() {
        let err = try_parse_task(
            r#"
name: t
stat:
  follow: yes
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("path"), "got: {err}");
    }

    #[test]
    fn parses_file_directory_with_mode_string() {
        let t = parse_task(
            r#"
name: mkdir
file:
  path: /opt/foo
  state: directory
  owner: root
  group: root
  mode: "0755"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => {
                assert_eq!(f.path, "/opt/foo");
                assert_eq!(f.state, FileState::Directory);
                assert_eq!(f.owner.as_deref(), Some("root"));
                assert_eq!(f.group.as_deref(), Some("root"));
                assert_eq!(f.mode, Some(0o755));
                assert!(!f.recurse);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_file_absent_minimal() {
        let t = parse_task(
            r#"
name: rm
file:
  path: /tmp/junk
  state: absent
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => {
                assert_eq!(f.state, FileState::Absent);
                assert!(f.mode.is_none());
                assert!(f.owner.is_none());
                assert!(f.group.is_none());
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_file_touch_and_recurse() {
        let t = parse_task(
            r#"
name: t
file:
  path: /tmp/marker
  state: touch
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => assert_eq!(f.state, FileState::Touch),
            other => panic!("got {other:?}"),
        }

        let t = parse_task(
            r#"
name: r
file:
  path: /var/lib/x
  state: directory
  mode: "0700"
  recurse: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => {
                assert!(f.recurse);
                assert_eq!(f.state, FileState::Directory);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn file_mode_accepts_int_and_octal_string() {
        // Plain int (e.g. YAML `0o644` → 420; serde_yaml parses 0o…
        // octal literals).
        let t = parse_task(
            r#"
name: m
file:
  path: /tmp/x
  state: file
  mode: 0o644
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => assert_eq!(f.mode, Some(0o644)),
            other => panic!("got {other:?}"),
        }
        // String form with leading 0.
        let t = parse_task(
            r#"
name: m
file:
  path: /tmp/x
  state: file
  mode: "0644"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => assert_eq!(f.mode, Some(0o644)),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn file_rejects_unknown_state() {
        let err = try_parse_task(
            r#"
name: x
file:
  path: /tmp/x
  state: bogus
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("bogus") || err.contains("unknown variant"), "got: {err}");
    }

    #[test]
    fn file_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: x
file:
  path: /tmp/x
  state: file
  force: yes
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("force") || err.contains("unknown"), "got: {err}");
    }

    #[test]
    fn file_to_wire_carries_state_byte() {
        let t = TaskOp::File(FileOp {
            path: "/tmp/x".into(),
            state: FileState::Directory,
            mode: Some(0o755),
            owner: Some("root".into()),
            group: Some("root".into()),
            recurse: true,
        });
        let WireOp::OpFile(o) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(o.kind, 5);
        assert_eq!(o.path, "/tmp/x");
        assert_eq!(o.state, 0);
        assert_eq!(o.has_mode, 1);
        assert_eq!(o.mode, 0o755);
        assert_eq!(o.owner, "root");
        assert_eq!(o.group, "root");
        assert_eq!(o.recurse, 1);

        let t = TaskOp::File(FileOp {
            path: "/x".into(),
            state: FileState::Absent,
            mode: None,
            owner: None,
            group: None,
            recurse: false,
        });
        let WireOp::OpFile(o) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(o.state, 1);
        assert_eq!(o.has_mode, 0);
        assert_eq!(o.owner, "");
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
    fn vars_on_non_include_role_task_is_rejected() {
        let err = try_parse_task(
            r#"
name: t
shell: echo hi
vars:
  x: 1
"#,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("include_role") && msg.contains("vars"),
            "got: {msg}"
        );
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
        let err = try_parse_task(
            r#"
name: x
loop: [1]
loop_control:
  label: "{{ item }}"
shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("label") || msg.contains("unknown"), "got: {msg}");
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
    fn parses_copy_body() {
        let t = parse_task(
            r#"
name: stage
copy:
  src: foo.bin
  dest: /etc/foo
  mode: 0o600
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Copy(c)) => {
                assert_eq!(c.src, "foo.bin");
                assert_eq!(c.dest, "/etc/foo");
                assert_eq!(c.mode, 0o600);
                assert!(c.body.is_none(), "body is populated by the loader, not parse");
            }
            other => panic!("expected copy, got {other:?}"),
        }
    }

    #[test]
    fn copy_mode_defaults_to_0644() {
        let t = parse_task(
            r#"
name: stage
copy:
  src: foo.bin
  dest: /etc/foo
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Copy(c)) => assert_eq!(c.mode, 0o644),
            _ => panic!(),
        }
    }

    #[test]
    fn copy_rejects_missing_src() {
        let err = try_parse_task(
            r#"
name: stage
copy:
  dest: /etc/foo
"#,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("src"), "got: {err}");
    }

    #[test]
    fn copy_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: stage
copy:
  src: a
  dest: /b
  rogue: 1
"#,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("rogue"), "got: {err}");
    }

    #[test]
    fn copy_to_wire_with_binary_body_ships_bytes_verbatim() {
        let t = TaskOp::Copy(CopyOp {
            src: "blob.bin".into(),
            dest: "/etc/blob".into(),
            mode: 0o600,
            // Non-UTF-8 bytes — would corrupt through a String roundtrip.
            body: Some(vec![0xff, 0x00, 0xfe, 0xfd, 0x7f]),
        });
        let WireOp::OpWriteFile(w) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(w.path, "/etc/blob");
        assert_eq!(w.mode, 0o600);
        assert_eq!(w.content, vec![0xff, 0x00, 0xfe, 0xfd, 0x7f]);
    }

    #[test]
    fn copy_to_wire_errors_when_body_missing() {
        let t = TaskOp::Copy(CopyOp {
            src: "blob.bin".into(),
            dest: "/etc/blob".into(),
            mode: 0o644,
            body: None,
        });
        let err = t.to_wire_op().unwrap_err();
        assert!(format!("{err}").contains("not resolved"), "got: {err}");
    }

    #[test]
    fn parses_wait_for_tcp_basic() {
        let t = parse_task(
            r#"
name: wait
wait_for:
  host: 127.0.0.1
  port: 5432
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert_eq!(w.host.as_deref(), Some("127.0.0.1"));
                assert_eq!(w.port, Some(5432));
                assert!(w.path.is_none());
                assert_eq!(w.state, WaitForState::Present);
            }
            _ => panic!("expected WaitFor body"),
        }
    }

    #[test]
    fn parses_wait_for_path_with_absent() {
        let t = parse_task(
            r#"
name: wait
wait_for:
  path: /var/run/foo.pid
  state: absent
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert_eq!(w.path.as_deref(), Some("/var/run/foo.pid"));
                assert_eq!(w.state, WaitForState::Absent);
            }
            _ => panic!("expected WaitFor body"),
        }
    }

    #[test]
    fn parses_wait_for_state_aliases() {
        for s in ["started", "stopped", "present", "absent"] {
            let yaml = format!(
                "name: t\nwait_for:\n  path: /x\n  state: {s}\n",
            );
            let _ = parse_task(&yaml);
        }
    }

    #[test]
    fn wait_for_rejects_both_modes() {
        let yaml = r#"
name: t
wait_for:
  host: localhost
  port: 22
  path: /x
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("mutually exclusive"),
            "got: {err}"
        );
    }

    #[test]
    fn wait_for_rejects_neither_mode() {
        let yaml = r#"
name: t
wait_for:
  timeout: 10
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("either host+port"),
            "got: {err}"
        );
    }

    #[test]
    fn wait_for_seconds_convert_to_ms() {
        let t = parse_task(
            r#"
name: t
wait_for:
  host: 127.0.0.1
  port: 1
  timeout: 3
  delay: 1
  sleep: 2
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert_eq!(w.timeout_ms, 3_000);
                assert_eq!(w.delay_ms, 1_000);
                assert_eq!(w.sleep_ms, 2_000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn wait_for_to_wire_carries_fields() {
        let t = TaskOp::WaitFor(WaitForOp {
                host: Some("h".into()),
                port: Some(80),
                path: None,
                state: WaitForState::Present,
                timeout_ms: 5000,
                delay_ms: 100,
                sleep_ms: 250,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpWaitFor(w) = wire else {
            panic!("expected OpWaitFor")
        };
        assert_eq!(w.host, "h");
        assert_eq!(w.port, 80);
        assert_eq!(w.path, "");
        assert_eq!(w.state, 0);
        assert_eq!(w.timeout_ms, 5000);
        assert_eq!(w.delay_ms, 100);
        assert_eq!(w.sleep_ms, 250);
    }

    #[test]
    fn parses_lineinfile_minimal() {
        let t = parse_task(
            r#"
name: t
lineinfile:
  path: /etc/foo
  line: bar=1
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::LineInFile(l)) => {
                assert_eq!(l.path, "/etc/foo");
                assert_eq!(l.line, "bar=1");
                assert_eq!(l.state, LineInFileState::Present);
                assert_eq!(l.regexp, "");
                assert!(!l.create);
                assert!(!l.backrefs);
            }
            _ => panic!("expected LineInFile body"),
        }
    }

    #[test]
    fn parses_lineinfile_with_regexp_and_create() {
        let t = parse_task(
            r#"
name: t
lineinfile:
  path: /etc/foo
  regexp: '^foo='
  line: foo=42
  state: present
  create: yes
  mode: '0644'
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::LineInFile(l)) => {
                assert_eq!(l.regexp, "^foo=");
                assert!(l.create);
                assert_eq!(l.mode, Some(0o644));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_lineinfile_absent_state() {
        let t = parse_task(
            r#"
name: t
lineinfile:
  path: /etc/foo
  line: gone
  state: absent
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::LineInFile(l)) => {
                assert_eq!(l.state, LineInFileState::Absent);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn lineinfile_rejects_present_with_empty_line_no_backrefs() {
        let yaml = r#"
name: t
lineinfile:
  path: /etc/foo
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("non-empty `line`"),
            "got: {err}"
        );
    }

    #[test]
    fn lineinfile_rejects_both_insert_anchors() {
        let yaml = r#"
name: t
lineinfile:
  path: /etc/foo
  line: x
  insertbefore: '^A'
  insertafter: '^B'
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("mutually exclusive"),
            "got: {err}"
        );
    }

    #[test]
    fn lineinfile_backrefs_requires_regexp() {
        let yaml = r#"
name: t
lineinfile:
  path: /etc/foo
  line: $1=new
  backrefs: yes
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("backrefs requires"),
            "got: {err}"
        );
    }

    #[test]
    fn lineinfile_to_wire_carries_fields() {
        let t = TaskOp::LineInFile(LineInFileOp {
            path: "/etc/foo".into(),
            regexp: "^foo=".into(),
            line: "foo=42".into(),
            state: LineInFileState::Present,
            mode: Some(0o644),
            create: true,
            insertbefore: String::new(),
            insertafter: "EOF".into(),
            backrefs: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpLineInFile(o) = wire else {
            panic!("expected OpLineInFile")
        };
        assert_eq!(o.path, "/etc/foo");
        assert_eq!(o.regexp, "^foo=");
        assert_eq!(o.line, "foo=42");
        assert_eq!(o.state, 0);
        assert_eq!(o.has_mode, 1);
        assert_eq!(o.mode, 0o644);
        assert_eq!(o.create, 1);
        assert_eq!(o.insertafter, "EOF");
        assert_eq!(o.backrefs, 0);
    }

    #[test]
    fn parses_blockinfile_minimal() {
        let t = parse_task(
            r#"
name: t
blockinfile:
  path: /etc/foo
  block: |
    alpha
    beta
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::BlockInFile(b)) => {
                assert_eq!(b.path, "/etc/foo");
                assert_eq!(b.block, "alpha\nbeta\n");
                assert_eq!(b.marker, "# {mark} ANSIBLE MANAGED BLOCK");
                assert_eq!(b.marker_begin, "BEGIN");
                assert_eq!(b.marker_end, "END");
                assert_eq!(b.state, BlockInFileState::Present);
            }
            _ => panic!("expected BlockInFile body"),
        }
    }

    #[test]
    fn parses_blockinfile_with_custom_markers_and_create() {
        let t = parse_task(
            r#"
name: t
blockinfile:
  path: /etc/foo.conf
  block: "x"
  marker: "// ---- {mark} app ----"
  marker_begin: TOP
  marker_end: BOT
  create: yes
  mode: '0640'
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::BlockInFile(b)) => {
                assert_eq!(b.marker, "// ---- {mark} app ----");
                assert_eq!(b.marker_begin, "TOP");
                assert_eq!(b.marker_end, "BOT");
                assert!(b.create);
                assert_eq!(b.mode, Some(0o640));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn blockinfile_rejects_marker_without_mark_token() {
        let yaml = r#"
name: t
blockinfile:
  path: /etc/foo
  block: x
  marker: "no token here"
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("{mark}"),
            "got: {err}"
        );
    }

    #[test]
    fn blockinfile_rejects_both_insert_anchors() {
        let yaml = r#"
name: t
blockinfile:
  path: /etc/foo
  block: x
  insertbefore: '^A'
  insertafter: '^B'
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("mutually exclusive"),
            "got: {err}"
        );
    }

    #[test]
    fn blockinfile_to_wire_carries_fields() {
        let t = TaskOp::BlockInFile(BlockInFileOp {
            path: "/etc/foo".into(),
            block: "a\nb\n".into(),
            marker: "# {mark} M".into(),
            marker_begin: "BEGIN".into(),
            marker_end: "END".into(),
            state: BlockInFileState::Present,
            mode: Some(0o600),
            create: true,
            insertbefore: String::new(),
            insertafter: "EOF".into(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpBlockInFile(o) = wire else {
            panic!("expected OpBlockInFile")
        };
        assert_eq!(o.path, "/etc/foo");
        assert_eq!(o.block, "a\nb\n");
        assert_eq!(o.marker, "# {mark} M");
        assert_eq!(o.marker_begin, "BEGIN");
        assert_eq!(o.marker_end, "END");
        assert_eq!(o.state, 0);
        assert_eq!(o.has_mode, 1);
        assert_eq!(o.mode, 0o600);
        assert_eq!(o.create, 1);
        assert_eq!(o.insertafter, "EOF");
    }

    #[test]
    fn parses_systemd_started_with_enabled() {
        let t = parse_task(
            r#"
name: t
systemd:
  name: nginx
  state: started
  enabled: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Systemd(s)) => {
                assert_eq!(s.name, "nginx");
                assert_eq!(s.state, SystemdState::Started);
                assert_eq!(s.enabled, Some(true));
                assert!(s.masked.is_none());
                assert!(!s.daemon_reload);
            }
            _ => panic!("expected Systemd"),
        }
    }

    #[test]
    fn parses_systemd_via_service_alias() {
        let t = parse_task(
            r#"
name: t
service:
  name: sshd
  state: reloaded
"#,
        );
        assert!(matches!(t.body, TaskBody::Op(TaskOp::Systemd(_))));
    }

    #[test]
    fn parses_systemd_daemon_reload_only() {
        let t = parse_task(
            r#"
name: t
systemd:
  name: ignored
  daemon_reload: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Systemd(s)) => {
                assert_eq!(s.state, SystemdState::None);
                assert!(s.daemon_reload);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn systemd_rejects_nothing_to_do() {
        let yaml = r#"
name: t
systemd:
  name: x
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("must specify"),
            "got: {err}"
        );
    }

    #[test]
    fn systemd_rejects_user_scope() {
        let yaml = r#"
name: t
systemd:
  name: x
  state: started
  scope: user
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("only `system`"),
            "got: {err}"
        );
    }

    #[test]
    fn parses_apt_single_name_default_state() {
        let t = parse_task(
            r#"
name: t
apt:
  name: nginx
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Apt);
                assert_eq!(p.names, vec!["nginx".to_string()]);
                assert_eq!(p.state, PackageState::Present);
                assert!(!p.update_cache);
                assert!(!p.purge);
            }
            _ => panic!("expected Package"),
        }
    }

    #[test]
    fn parses_apt_name_list_with_state_latest() {
        let t = parse_task(
            r#"
name: t
apt:
  name:
    - nginx
    - curl
  state: latest
  update_cache: yes
  cache_valid_time: 3600
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Apt);
                assert_eq!(p.names, vec!["nginx".to_string(), "curl".to_string()]);
                assert_eq!(p.state, PackageState::Latest);
                assert!(p.update_cache);
                assert_eq!(p.cache_valid_time, 3600);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn apt_rejects_cache_valid_time_without_update_cache() {
        let yaml = r#"
name: t
apt:
  name: nginx
  cache_valid_time: 3600
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("requires `update_cache: true`"),
            "got: {err}"
        );
    }

    #[test]
    fn apt_rejects_unknown_field() {
        let yaml = r#"
name: t
apt:
  name: nginx
  bogus: true
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn apt_accepts_installed_and_removed_aliases() {
        let t = parse_task(
            r#"
name: t
apt:
  name: nginx
  state: installed
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => assert_eq!(p.state, PackageState::Present),
            _ => panic!(),
        }
        let t = parse_task(
            r#"
name: t
apt:
  name: nginx
  state: removed
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => assert_eq!(p.state, PackageState::Absent),
            _ => panic!(),
        }
    }

    #[test]
    fn apt_to_wire_carries_fields() {
        let t = TaskOp::Package(PackageOp {
            manager: PackageManager::Apt,
            names: vec!["nginx".into(), "curl".into()],
            state: PackageState::Latest,
            update_cache: true,
            cache_valid_time: 3600,
            purge: false,
            autoremove: true,
            default_release: "bookworm-backports".into(),
            allow_unauthenticated: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpPackage(o) = wire else {
            panic!("expected OpPackage")
        };
        assert_eq!(o.manager, 1);
        assert_eq!(o.names, vec!["nginx".to_string(), "curl".to_string()]);
        assert_eq!(o.state, 2);
        assert_eq!(o.update_cache, 1);
        assert_eq!(o.cache_valid_time, 3600);
        assert_eq!(o.purge, 0);
        assert_eq!(o.autoremove, 1);
        assert_eq!(o.default_release, "bookworm-backports");
        assert_eq!(o.allow_unauthenticated, 0);
    }

    #[test]
    fn parses_package_generic_sets_manager_auto() {
        // `package:` (no manager-pinning YAML key) → Auto.
        let t = parse_task(
            r#"
name: t
package:
  name: curl
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Auto);
                assert_eq!(p.names, vec!["curl".to_string()]);
                assert_eq!(p.state, PackageState::Present);
            }
            _ => panic!("expected Package"),
        }
    }

    #[test]
    fn parses_package_accepts_name_list_and_update_cache() {
        let t = parse_task(
            r#"
name: t
package:
  name: [nginx, curl]
  state: latest
  update_cache: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Auto);
                assert_eq!(p.names, vec!["nginx".to_string(), "curl".to_string()]);
                assert_eq!(p.state, PackageState::Latest);
                assert!(p.update_cache);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn package_rejects_apt_only_knobs() {
        // `default_release` is apt-specific; it's an error under
        // `package:` because we can't promise the auto-detected backend
        // will honor it.
        let yaml = r#"
name: t
package:
  name: nginx
  default_release: bookworm-backports
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("only valid under `apt:`") && msg.contains("default_release"),
            "got: {msg}"
        );
    }

    #[test]
    fn package_rejects_purge_and_cache_valid_time() {
        for field in ["purge: yes", "cache_valid_time: 3600", "allow_unauthenticated: yes"] {
            let yaml = format!(
                r#"
name: t
package:
  name: nginx
  {field}
"#
            );
            let err = serde_yaml::from_str::<Task>(&yaml).unwrap_err();
            assert!(
                format!("{err}").contains("only valid under `apt:`"),
                "field={field} got: {err}"
            );
        }
    }

    #[test]
    fn package_to_wire_carries_manager_auto() {
        let t = TaskOp::Package(PackageOp {
            manager: PackageManager::Auto,
            names: vec!["curl".into()],
            state: PackageState::Present,
            update_cache: false,
            cache_valid_time: 0,
            purge: false,
            autoremove: false,
            default_release: String::new(),
            allow_unauthenticated: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpPackage(o) = wire else {
            panic!("expected OpPackage")
        };
        assert_eq!(o.manager, 0); // AUTO
        assert_eq!(o.state, 0); // PRESENT
    }

    #[test]
    fn parses_ufw_allow_port() {
        let t = parse_task(
            r#"
name: t
ufw:
  rule: allow
  port: 22
  proto: tcp
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Rule);
                assert_eq!(u.rule, "allow");
                assert_eq!(u.to_port, "22");
                assert_eq!(u.proto, "tcp");
            }
            _ => panic!("expected Ufw"),
        }
    }

    #[test]
    fn parses_ufw_enable_via_state() {
        let t = parse_task(
            r#"
name: t
ufw:
  state: enabled
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Enable);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_ufw_default_policy() {
        let t = parse_task(
            r#"
name: t
ufw:
  default: deny
  direction: in
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Default);
                assert_eq!(u.rule, "deny");
                assert_eq!(u.direction, "in");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_ufw_logging() {
        let t = parse_task(
            r#"
name: t
ufw:
  logging: full
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Logging);
                assert_eq!(u.rule, "full");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ufw_rejects_bad_proto() {
        let yaml = r#"
name: t
ufw:
  rule: allow
  port: 22
  proto: sctp
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("ufw.proto"), "got: {err}");
    }

    #[test]
    fn ufw_rejects_bad_rule() {
        let yaml = r#"
name: t
ufw:
  rule: bogus
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("ufw.rule"), "got: {err}");
    }

    #[test]
    fn ufw_requires_some_op_selector() {
        let yaml = r#"
name: t
ufw:
  proto: tcp
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("must specify"),
            "got: {err}"
        );
    }

    #[test]
    fn ufw_to_wire_carries_fields() {
        let t = TaskOp::Ufw(UfwOp {
            op: UfwOpKind::Rule,
            rule: "allow".into(),
            direction: "in".into(),
            proto: "tcp".into(),
            from_ip: String::new(),
            from_port: String::new(),
            to_ip: String::new(),
            to_port: "22".into(),
            interface: String::new(),
            comment: "ssh".into(),
            delete: false,
            insert: 0,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpUfw(o) = wire else {
            panic!("expected OpUfw")
        };
        assert_eq!(o.op, 0);
        assert_eq!(o.rule, "allow");
        assert_eq!(o.direction, "in");
        assert_eq!(o.proto, "tcp");
        assert_eq!(o.to_port, "22");
        assert_eq!(o.comment, "ssh");
    }

    #[test]
    fn systemd_to_wire_carries_state_and_flags() {
        let t = TaskOp::Systemd(SystemdOp {
            name: "nginx.service".into(),
            state: SystemdState::Started,
            enabled: Some(true),
            masked: None,
            daemon_reload: true,
            no_block: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpSystemd(o) = wire else {
            panic!("expected OpSystemd")
        };
        assert_eq!(o.name, "nginx.service");
        assert_eq!(o.state, 1);
        assert_eq!(o.has_enabled, 1);
        assert_eq!(o.enabled, 1);
        assert_eq!(o.has_masked, 0);
        assert_eq!(o.daemon_reload, 1);
        assert_eq!(o.no_block, 0);
    }

    // ── uri: parsing ─────────────────────────────────────────────────

    fn parse_uri(yaml: &str) -> UriOp {
        let t = parse_task(yaml);
        match t.body {
            TaskBody::Op(TaskOp::Uri(u)) => u,
            other => panic!("expected TaskOp::Uri, got {other:?}"),
        }
    }

    #[test]
    fn uri_minimal_url_defaults() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://example.com/x
"#,
        );
        assert_eq!(u.url, "https://example.com/x");
        assert_eq!(u.method, uri_method::GET);
        assert!(u.headers.is_empty());
        assert_eq!(u.body, "");
        assert_eq!(u.body_format, uri_body_format::RAW);
        assert_eq!(u.status_codes, vec![200]);
        assert_eq!(u.timeout_ms, 30_000);
        assert!(!u.return_content);
        assert!(u.validate_certs);
        assert_eq!(u.follow_redirects, uri_follow::SAFE);
    }

    #[test]
    fn uri_method_case_insensitive() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  method: post
"#,
        );
        assert_eq!(u.method, uri_method::POST);
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  method: PaTcH
"#,
        );
        assert_eq!(u.method, uri_method::PATCH);
    }

    #[test]
    fn uri_status_code_accepts_int_and_list() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  status_code: 201
"#,
        );
        assert_eq!(u.status_codes, vec![201]);
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  status_code: [200, 201, 204]
"#,
        );
        assert_eq!(u.status_codes, vec![200, 201, 204]);
    }

    #[test]
    fn uri_status_code_out_of_range_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  status_code: 99
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("status_code"), "got: {err}");
    }

    #[test]
    fn uri_body_format_json_serializes_map() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  method: post
  body_format: json
  body:
    foo: bar
    n: 42
"#,
        );
        assert_eq!(u.body_format, uri_body_format::JSON);
        // BTreeMap ordering in serde_json::Value::Object → "foo" before "n".
        let parsed: serde_json::Value = serde_json::from_str(&u.body).unwrap();
        assert_eq!(parsed["foo"], serde_json::json!("bar"));
        assert_eq!(parsed["n"], serde_json::json!(42));
    }

    #[test]
    fn uri_body_map_with_raw_body_format_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  body:
    foo: bar
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("body_format: json"),
            "got: {err}"
        );
    }

    #[test]
    fn uri_headers_non_map_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  headers: "Authorization: Bearer xxx"
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("headers"), "got: {err}");
    }

    #[test]
    fn uri_follow_redirects_bogus_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  follow_redirects: maybe
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("follow_redirects"),
            "got: {err}"
        );
    }

    #[test]
    fn uri_timeout_float_seconds_to_ms() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  timeout: 1.5
"#,
        );
        assert_eq!(u.timeout_ms, 1500);
    }

    #[test]
    fn uri_missing_url_rejected() {
        let yaml = r#"
name: t
uri:
  method: get
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("url"), "got: {err}");
    }

    #[test]
    fn uri_to_wire_carries_fields() {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".into(), "Bearer xyz".into());
        headers.insert("Accept".into(), "application/json".into());
        let t = TaskOp::Uri(UriOp {
            url: "https://api/x".into(),
            method: uri_method::POST,
            headers,
            body: r#"{"a":1}"#.into(),
            body_format: uri_body_format::JSON,
            status_codes: vec![200, 201],
            timeout_ms: 5_000,
            return_content: true,
            validate_certs: false,
            follow_redirects: uri_follow::ALL,
            client_cert: String::new(),
            client_key: String::new(),
            ca_path: String::new(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpUri(o) = wire else {
            panic!("expected OpUri")
        };
        assert_eq!(o.kind, 12);
        assert_eq!(o.method, uri_method::POST);
        assert_eq!(o.url, "https://api/x");
        // BTreeMap sorted: Accept before Authorization.
        assert_eq!(o.header_keys, vec!["Accept", "Authorization"]);
        assert_eq!(
            o.header_values,
            vec!["application/json", "Bearer xyz"]
        );
        assert_eq!(o.body, br#"{"a":1}"#.to_vec());
        assert_eq!(o.body_format, uri_body_format::JSON);
        assert_eq!(o.status_codes, vec![200u16, 201u16]);
        assert_eq!(o.timeout_ms, 5_000);
        assert_eq!(o.return_content, 1);
        assert_eq!(o.validate_certs, 0);
        assert_eq!(o.follow_redirects, uri_follow::ALL);
        // No mTLS bytes when paths are empty.
        assert!(o.client_cert_pem.is_empty());
        assert!(o.client_key_pem.is_empty());
        assert!(o.ca_bundle_pem.is_empty());
    }

    #[test]
    fn uri_mtls_paths_are_read_into_wire_bytes() {
        // Write three PEM-ish files to a tempdir; verify to_wire_op
        // slurps them into the wire bytes fields. We don't need real
        // PEM here — agent-side parsing isn't exercised; only the
        // controller's read-file-and-embed pass is.
        let dir = std::env::temp_dir().join(format!(
            "rsansible-mtls-paths-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("client.crt");
        let key_path = dir.join("client.key");
        let ca_path = dir.join("ca.crt");
        std::fs::write(&cert_path, b"CERT-CONTENT").unwrap();
        std::fs::write(&key_path, b"KEY-CONTENT").unwrap();
        std::fs::write(&ca_path, b"CA-CONTENT").unwrap();

        let t = TaskOp::Uri(UriOp {
            url: "https://etcd/v2".into(),
            method: uri_method::GET,
            headers: BTreeMap::new(),
            body: String::new(),
            body_format: uri_body_format::RAW,
            status_codes: vec![200],
            timeout_ms: 30_000,
            return_content: false,
            validate_certs: true,
            follow_redirects: uri_follow::SAFE,
            client_cert: cert_path.to_string_lossy().into_owned(),
            client_key: key_path.to_string_lossy().into_owned(),
            ca_path: ca_path.to_string_lossy().into_owned(),
        });
        let wire = t.to_wire_op().expect("to_wire_op");
        let rsansible_wire::generated::Op::OpUri(o) = wire else {
            panic!("expected OpUri");
        };
        assert_eq!(o.client_cert_pem, b"CERT-CONTENT".to_vec());
        assert_eq!(o.client_key_pem, b"KEY-CONTENT".to_vec());
        assert_eq!(o.ca_bundle_pem, b"CA-CONTENT".to_vec());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uri_mtls_missing_file_surfaces_as_clear_error() {
        let t = TaskOp::Uri(UriOp {
            url: "https://x/".into(),
            method: uri_method::GET,
            headers: BTreeMap::new(),
            body: String::new(),
            body_format: uri_body_format::RAW,
            status_codes: vec![200],
            timeout_ms: 30_000,
            return_content: false,
            validate_certs: true,
            follow_redirects: uri_follow::SAFE,
            client_cert: "/definitely/not/here.crt".into(),
            client_key: "/definitely/not/here.key".into(),
            ca_path: String::new(),
        });
        let err = t.to_wire_op().expect_err("missing file should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("client_cert") && msg.contains("here.crt"),
            "error should mention field+path: {msg}"
        );
    }

    #[test]
    fn uri_rejects_client_cert_without_key() {
        // YAML-level validation: cert without key fails at parse, not
        // wire-emit, so a malformed playbook surfaces during `validate`.
        let yaml = r#"
name: t
uri:
  url: https://x/
  client_cert: /etc/pki/client.crt
"#;
        let err = serde_yaml::from_str::<Task>(yaml).expect_err("should reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("client_key"),
            "expected client_key complaint: {msg}"
        );
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
    fn parses_openssl_privatekey_minimal() {
        let t = parse_task(
            r#"
name: privkey
openssl_privatekey:
  path: /etc/etcd/server.key
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslPrivkey(p)) => {
                assert_eq!(p.path, "/etc/etcd/server.key");
                assert_eq!(p.kind, crate::x509::PrivkeyType::Rsa);
                assert_eq!(p.size, 4096);
                assert_eq!(p.mode, 0o600);
                assert!(!p.force_probe);
            }
            other => panic!("expected OpenSslPrivkey, got {other:?}"),
        }
    }

    #[test]
    fn parses_openssl_privatekey_full() {
        let t = parse_task(
            r#"
name: ed
openssl_privatekey:
  path: /etc/etcd/peer.key
  type: Ed25519
  size: 2048
  mode: 0o400
  force_probe: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslPrivkey(p)) => {
                assert_eq!(p.kind, crate::x509::PrivkeyType::Ed25519);
                assert_eq!(p.size, 2048);
                assert_eq!(p.mode, 0o400);
                assert!(p.force_probe);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_openssl_csr_pipe() {
        let t = parse_task(
            r#"
name: csr
openssl_csr_pipe:
  privatekey_path: /etc/etcd/server.key
  common_name: etcd-server
  subject_alt_name:
    - "DNS:etcd.example.com"
    - "IP:10.0.0.10"
  key_usage: [digitalSignature, keyEncipherment]
  extended_key_usage: [serverAuth, clientAuth]
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslCsrPipe(c)) => {
                assert_eq!(c.privatekey_path, "/etc/etcd/server.key");
                assert_eq!(c.common_name, "etcd-server");
                assert_eq!(c.subject_alt_name.len(), 2);
                assert!(c.subject_alt_name[0].starts_with("DNS:"));
                assert_eq!(c.key_usage, vec!["digitalSignature", "keyEncipherment"]);
                assert_eq!(c.extended_key_usage, vec!["serverAuth", "clientAuth"]);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_x509_certificate_pipe() {
        let t = parse_task(
            r#"
name: cert
x509_certificate_pipe:
  csr_content: "{{ csr.content }}"
  privatekey_content: "{{ key.content }}"
  provider: selfsigned
  valid_for_days: 30
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::X509CertificatePipe(c)) => {
                assert_eq!(c.csr_content, "{{ csr.content }}");
                assert_eq!(c.privatekey_content, "{{ key.content }}");
                assert_eq!(c.provider, "selfsigned");
                assert_eq!(c.valid_for_days, 30);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn rejects_openssl_privatekey_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
openssl_privatekey:
  path: /etc/k
  curve: P-256
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("curve") || msg.contains("unknown"), "got: {msg}");
    }

    // ── SQL classifier ────────────────────────────────────────────

    #[test]
    fn classify_sql_select_is_readonly() {
        assert!(classify_sql_readonly("SELECT 1"));
        assert!(classify_sql_readonly("select pid FROM pg_stat_activity"));
        assert!(classify_sql_readonly("  \n\tSELECT 1"));
        assert!(classify_sql_readonly("SHOW server_version"));
        assert!(classify_sql_readonly("EXPLAIN SELECT 1"));
        assert!(classify_sql_readonly("VALUES (1), (2)"));
        assert!(classify_sql_readonly("WITH x AS (SELECT 1) SELECT * FROM x"));
        assert!(classify_sql_readonly("TABLE pg_class"));
    }

    #[test]
    fn classify_sql_dml_is_mutating() {
        assert!(!classify_sql_readonly("INSERT INTO t VALUES (1)"));
        assert!(!classify_sql_readonly("UPDATE t SET x = 1"));
        assert!(!classify_sql_readonly("DELETE FROM t"));
        assert!(!classify_sql_readonly("CREATE TABLE t (x int)"));
        assert!(!classify_sql_readonly("DROP TABLE t"));
        assert!(!classify_sql_readonly("ALTER SYSTEM SET work_mem = '64MB'"));
        assert!(!classify_sql_readonly("TRUNCATE t"));
        assert!(!classify_sql_readonly("VACUUM"));
        assert!(!classify_sql_readonly("CREATE EXTENSION pg_stat_statements"));
    }

    #[test]
    fn classify_sql_strips_comments_before_classify() {
        assert!(classify_sql_readonly("-- a comment\nSELECT 1"));
        assert!(classify_sql_readonly("/* leading block */ SELECT 1"));
        assert!(!classify_sql_readonly("-- still mutates\nDELETE FROM t"));
        // nested block comments — postgres supports nesting
        assert!(classify_sql_readonly("/* outer /* inner */ outer */ SELECT 1"));
    }

    #[test]
    fn classify_sql_multistmt_any_mutating_is_mutating() {
        assert!(classify_sql_readonly("SELECT 1; SELECT 2"));
        assert!(!classify_sql_readonly("SELECT 1; INSERT INTO t VALUES (1)"));
        assert!(!classify_sql_readonly("INSERT INTO t VALUES (1); SELECT 1"));
    }

    #[test]
    fn classify_sql_semicolons_in_literals_dont_split() {
        // The literal 'INSERT INTO t' should NOT be classified as a
        // mutating statement — it's just a string.
        assert!(classify_sql_readonly(
            "SELECT 'INSERT INTO t VALUES (1)'::text"
        ));
    }

    #[test]
    fn classify_sql_empty_or_whitespace_is_readonly() {
        assert!(classify_sql_readonly(""));
        assert!(classify_sql_readonly("   \n  \t  "));
        assert!(classify_sql_readonly("-- just a comment\n"));
    }

    #[test]
    fn classify_sql_explain_without_analyze_is_readonly() {
        assert!(classify_sql_readonly("EXPLAIN SELECT 1"));
        assert!(classify_sql_readonly("EXPLAIN INSERT INTO t VALUES (1)"));
        assert!(classify_sql_readonly("EXPLAIN VERBOSE INSERT INTO t VALUES (1)"));
        assert!(classify_sql_readonly("EXPLAIN (VERBOSE, BUFFERS) DELETE FROM t"));
        assert!(classify_sql_readonly("EXPLAIN (ANALYZE FALSE) DELETE FROM t"));
        assert!(classify_sql_readonly("EXPLAIN (ANALYZE OFF) DELETE FROM t"));
    }

    #[test]
    fn classify_sql_explain_analyze_dml_is_mutating() {
        // Legacy bareword form.
        assert!(!classify_sql_readonly("EXPLAIN ANALYZE INSERT INTO t VALUES (1)"));
        assert!(!classify_sql_readonly("explain analyze delete from t"));
        assert!(!classify_sql_readonly(
            "EXPLAIN ANALYZE VERBOSE UPDATE t SET x = 1"
        ));
        // Parenthesised options form.
        assert!(!classify_sql_readonly(
            "EXPLAIN (ANALYZE) INSERT INTO t VALUES (1)"
        ));
        assert!(!classify_sql_readonly(
            "EXPLAIN (ANALYZE TRUE, BUFFERS) UPDATE t SET x = 1"
        ));
        assert!(!classify_sql_readonly(
            "EXPLAIN (ANALYZE ON) DELETE FROM t"
        ));
        assert!(!classify_sql_readonly(
            "EXPLAIN (BUFFERS, ANALYZE 1) MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET x = 1"
        ));
        // ANALYZE wrapping a benign SELECT — still read-only because
        // the inner statement is read-only.
        assert!(classify_sql_readonly("EXPLAIN ANALYZE SELECT 1"));
    }

    #[test]
    fn classify_sql_with_data_modifying_cte_is_mutating() {
        assert!(!classify_sql_readonly(
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"
        ));
        assert!(!classify_sql_readonly(
            "WITH i AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM i"
        ));
        assert!(!classify_sql_readonly(
            "WITH u AS (UPDATE t SET x = 1 RETURNING *) SELECT * FROM u"
        ));
        // Trailing DML form.
        assert!(!classify_sql_readonly(
            "WITH x AS (SELECT id FROM s) DELETE FROM t USING x WHERE t.id = x.id"
        ));
        // Read-only WITH still passes.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT 1) SELECT * FROM x"
        ));
        // Multiple CTEs: any mutating CTE → mutating.
        assert!(!classify_sql_readonly(
            "WITH a AS (SELECT 1), b AS (DELETE FROM t RETURNING *) SELECT * FROM a, b"
        ));
    }

    #[test]
    fn classify_sql_with_literal_keywords_dont_trip() {
        // Identifier-aware scanner: 'INSERT INTO t' as a string literal
        // should not flag this WITH as mutating.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT 'INSERT INTO t' AS sql) SELECT * FROM x"
        ));
        // Quoted-identifier column called "delete" — still read-only.
        assert!(classify_sql_readonly(
            r#"WITH x AS (SELECT "delete" FROM t) SELECT * FROM x"#
        ));
        // Column called `update_at` — UPDATE_AT ≠ UPDATE, so not a hit.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT update_at FROM t) SELECT * FROM x"
        ));
        // Dollar-quoted body containing DML keyword — skipped.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT $body$DELETE FROM t$body$ AS sql) SELECT * FROM x"
        ));
    }

    // ── postgresql_query parsing ─────────────────────────────────

    #[test]
    fn parse_postgresql_query_minimal() {
        let t = parse_task(
            r#"
name: t
postgresql_query:
  query: SELECT 1
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlQuery(p)) => {
                assert_eq!(p.query, "SELECT 1");
                assert!(p.read_only);
                assert!(p.db.is_empty());
                assert!(p.login_unix_socket.is_empty());
                assert!(p.positional_args.is_empty());
                assert!(!p.autocommit);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_query_full() {
        let t = parse_task(
            r#"
name: t
postgresql_query:
  query: "INSERT INTO clients(name) VALUES ($1) RETURNING id"
  db: app
  login_user: app_writer
  login_unix_socket: /var/run/postgresql
  autocommit: true
  positional_args:
    - acme corp
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlQuery(p)) => {
                assert_eq!(p.db, "app");
                assert_eq!(p.login_user, "app_writer");
                assert_eq!(p.login_unix_socket, "/var/run/postgresql");
                assert!(p.autocommit);
                assert_eq!(p.positional_args, vec!["acme corp".to_string()]);
                // INSERT — classified mutating.
                assert!(!p.read_only);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_query_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
postgresql_query:
  query: SELECT 1
  named_args: { x: 1 }
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("named_args") || msg.contains("unknown"), "got: {msg}");
    }

    // ── postgresql_ext parsing ───────────────────────────────────

    #[test]
    fn parse_postgresql_ext_default_present() {
        let t = parse_task(
            r#"
name: t
postgresql_ext:
  name: pg_stat_statements
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlExt(p)) => {
                assert_eq!(p.name, "pg_stat_statements");
                assert_eq!(p.state, 0); // PRESENT
                assert!(p.version.is_empty());
                assert!(!p.cascade);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_ext_absent_cascade() {
        let t = parse_task(
            r#"
name: t
postgresql_ext:
  name: hstore
  state: absent
  cascade: yes
  db: app
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlExt(p)) => {
                assert_eq!(p.state, 1); // ABSENT
                assert!(p.cascade);
                assert_eq!(p.db, "app");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_ext_to_wire_op() {
        let t = parse_task(
            r#"
name: t
postgresql_ext:
  name: pg_trgm
  version: "1.6"
  schema: public
"#,
        );
        let TaskBody::Op(op) = t.body else { panic!() };
        let wire = op.to_wire_op().unwrap();
        let WireOp::OpPostgresqlExt(e) = wire else { panic!("got {wire:?}") };
        assert_eq!(e.kind, 14);
        assert_eq!(e.name, "pg_trgm");
        assert_eq!(e.version, "1.6");
        assert_eq!(e.ext_schema, "public");
    }

    // ── get_url: parsing + to_wire_op ───────────────────────────────

    #[test]
    fn parse_get_url_minimal() {
        let t = parse_task(
            r#"
name: t
get_url:
  url: https://example.com/x.tar.gz
  dest: /tmp/x.tar.gz
"#,
        );
        let TaskBody::Op(TaskOp::GetUrl(g)) = t.body else { panic!() };
        assert_eq!(g.url, "https://example.com/x.tar.gz");
        assert_eq!(g.dest, "/tmp/x.tar.gz");
        assert_eq!(g.checksum, "");
        assert_eq!(g.mode, 0);
        assert!(!g.force);
        assert!(g.validate_certs);
        assert_eq!(g.follow_redirects, uri_follow::ALL);
        assert_eq!(g.timeout_ms, 30_000);
    }

    #[test]
    fn parse_get_url_full() {
        let t = parse_task(
            r#"
name: t
get_url:
  url: https://example.com/payload
  dest: /opt/payload
  checksum: sha256:abc123
  mode: "0644"
  owner: root
  group: wheel
  headers:
    Authorization: Bearer xyz
    X-Trace: "42"
  timeout: 60
  force: yes
  validate_certs: no
  follow_redirects: safe
"#,
        );
        let TaskBody::Op(TaskOp::GetUrl(g)) = t.body else { panic!() };
        assert_eq!(g.checksum, "sha256:abc123");
        assert_eq!(g.mode, 0o644);
        assert_eq!(g.owner, "root");
        assert_eq!(g.group, "wheel");
        assert_eq!(g.headers.get("Authorization").unwrap(), "Bearer xyz");
        assert_eq!(g.headers.get("X-Trace").unwrap(), "42");
        assert_eq!(g.timeout_ms, 60_000);
        assert!(g.force);
        assert!(!g.validate_certs);
        assert_eq!(g.follow_redirects, uri_follow::SAFE);
    }

    #[test]
    fn parse_get_url_rejects_unknown_field() {
        let yaml = r#"
name: t
get_url:
  url: https://example.com/x
  dest: /tmp/x
  bogus: yes
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "unknown field should be rejected");
        let err = format!("{:?}", result.err());
        assert!(err.contains("bogus"), "error should mention the unknown field: {err}");
    }

    // ── slurp: parsing + to_wire_op ─────────────────────────────────

    #[test]
    fn parse_slurp_minimal() {
        let t = parse_task(
            r#"
name: t
slurp:
  src: /etc/ssh/ssh_host_ed25519_key.pub
"#,
        );
        let TaskBody::Op(TaskOp::Slurp(s)) = t.body else { panic!() };
        assert_eq!(s.src, "/etc/ssh/ssh_host_ed25519_key.pub");
        assert_eq!(s.max_bytes, 0);
    }

    #[test]
    fn parse_slurp_with_max_bytes() {
        let t = parse_task(
            r#"
name: t
slurp:
  src: /var/lib/pki/ca.pem
  max_bytes: 65536
"#,
        );
        let TaskBody::Op(TaskOp::Slurp(s)) = t.body else { panic!() };
        assert_eq!(s.max_bytes, 65_536);
    }

    #[test]
    fn parse_slurp_rejects_unknown_field() {
        let yaml = r#"
name: t
slurp:
  src: /etc/x
  bogus: yes
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("bogus"));
    }

    #[test]
    fn parse_slurp_rejects_missing_src() {
        let yaml = r#"
name: t
slurp: {}
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("src"));
    }

    // ── unarchive ───────────────────────────────────────────────────

    #[test]
    fn parse_unarchive_minimal() {
        let t = parse_task(
            r#"
name: t
unarchive:
  src: /srv/cache/etcd.tar.gz
  dest: /usr/local/bin
  remote_src: yes
"#,
        );
        let TaskBody::Op(TaskOp::Unarchive(u)) = t.body else { panic!() };
        assert_eq!(u.src, "/srv/cache/etcd.tar.gz");
        assert_eq!(u.dest, "/usr/local/bin");
        assert_eq!(u.format, rsansible_wire::msg::unarchive_format::AUTO);
        assert_eq!(u.creates, "");
        assert_eq!(u.mode, None);
        assert!(!u.keep_newer);
        assert!(!u.list_files);
        assert!(u.include.is_empty());
        assert!(u.exclude.is_empty());
    }

    #[test]
    fn parse_unarchive_full_surface() {
        let t = parse_task(
            r#"
name: t
unarchive:
  src: /srv/cache/etcd.zip
  dest: /opt/etcd
  remote_src: yes
  format: zip
  creates: /opt/etcd/etcd
  keep_newer: yes
  list_files: yes
  owner: root
  group: root
  mode: "0755"
  include:
    - etcd
    - etcdctl
  exclude:
    - README.md
"#,
        );
        let TaskBody::Op(TaskOp::Unarchive(u)) = t.body else { panic!() };
        assert_eq!(u.format, rsansible_wire::msg::unarchive_format::ZIP);
        assert_eq!(u.creates, "/opt/etcd/etcd");
        assert!(u.keep_newer);
        assert!(u.list_files);
        assert_eq!(u.owner, "root");
        assert_eq!(u.group, "root");
        assert_eq!(u.mode, Some(0o755));
        assert_eq!(u.include, vec!["etcd".to_string(), "etcdctl".to_string()]);
        assert_eq!(u.exclude, vec!["README.md".to_string()]);
    }

    #[test]
    fn parse_unarchive_format_aliases() {
        for (label, byte) in [
            ("tgz", rsansible_wire::msg::unarchive_format::TAR_GZ),
            ("tar.bz2", rsansible_wire::msg::unarchive_format::TAR_BZ2),
            ("txz", rsansible_wire::msg::unarchive_format::TAR_XZ),
            ("tar", rsansible_wire::msg::unarchive_format::TAR),
        ] {
            let yaml = format!(
                "name: t\nunarchive:\n  src: /a/b\n  dest: /c\n  remote_src: yes\n  format: {label}\n"
            );
            let t: Task = serde_yaml::from_str(&yaml).unwrap();
            let TaskBody::Op(TaskOp::Unarchive(u)) = t.body else { panic!() };
            assert_eq!(u.format, byte, "format alias {label}");
        }
    }

    #[test]
    fn parse_unarchive_rejects_remote_src_false() {
        let yaml = r#"
name: t
unarchive:
  src: /tmp/a.tar
  dest: /opt
  remote_src: no
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("remote_src"));
    }

    #[test]
    fn parse_unarchive_missing_remote_src_is_default_no_and_rejected() {
        let yaml = r#"
name: t
unarchive:
  src: /tmp/a.tar
  dest: /opt
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unarchive_unknown_field_rejected() {
        let yaml = r#"
name: t
unarchive:
  src: /a
  dest: /b
  remote_src: yes
  bogus: 1
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("bogus"));
    }

    #[test]
    fn parse_unarchive_unknown_format_rejected() {
        let yaml = r#"
name: t
unarchive:
  src: /a
  dest: /b
  remote_src: yes
  format: 7z
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn unarchive_to_wire_op_shape() {
        let op = TaskOp::Unarchive(UnarchiveOp {
            src: "/srv/cache/etcd.tar.gz".into(),
            dest: "/usr/local/bin".into(),
            format: rsansible_wire::msg::unarchive_format::TAR_GZ,
            creates: "/usr/local/bin/etcd".into(),
            mode: Some(0o755),
            owner: "root".into(),
            group: "root".into(),
            keep_newer: true,
            list_files: true,
            include: vec!["etcd".into()],
            exclude: vec!["README.md".into()],
        });
        let wire = op.to_wire_op().unwrap();
        match wire {
            WireOp::OpUnarchive(o) => {
                assert_eq!(o.kind, 19);
                assert_eq!(o.src, "/srv/cache/etcd.tar.gz");
                assert_eq!(o.dest, "/usr/local/bin");
                assert_eq!(o.format, rsansible_wire::msg::unarchive_format::TAR_GZ);
                assert_eq!(o.creates, "/usr/local/bin/etcd");
                assert_eq!(o.has_mode, 1);
                assert_eq!(o.mode, 0o755);
                assert_eq!(o.keep_newer, 1);
                assert_eq!(o.list_files, 1);
                assert_eq!(o.include, vec!["etcd".to_string()]);
                assert_eq!(o.exclude, vec!["README.md".to_string()]);
            }
            other => panic!("expected OpUnarchive, got {other:?}"),
        }
    }

    #[test]
    fn unarchive_to_wire_op_omits_mode_when_unset() {
        let op = TaskOp::Unarchive(UnarchiveOp {
            src: "/a".into(),
            dest: "/b".into(),
            format: rsansible_wire::msg::unarchive_format::AUTO,
            creates: String::new(),
            mode: None,
            owner: String::new(),
            group: String::new(),
            keep_newer: false,
            list_files: false,
            include: Vec::new(),
            exclude: Vec::new(),
        });
        let wire = op.to_wire_op().unwrap();
        let WireOp::OpUnarchive(o) = wire else { panic!() };
        assert_eq!(o.has_mode, 0);
        assert_eq!(o.mode, 0);
    }

    #[test]
    fn slurp_to_wire_op_uses_read_file() {
        let op = TaskOp::Slurp(SlurpOp {
            src: "/etc/etcd/server.key".into(),
            max_bytes: 0,
        });
        let wire = op.to_wire_op().unwrap();
        match wire {
            WireOp::OpReadFile(o) => {
                assert_eq!(o.path, "/etc/etcd/server.key");
                assert_eq!(o.max_bytes, 0);
                assert_eq!(o.kind, 18);
            }
            other => panic!("expected OpReadFile, got {other:?}"),
        }
    }

    // ── async/poll metadata ─────────────────────────────────────────

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
        assert_eq!(t.async_seconds, Some(60));
        assert_eq!(t.poll_seconds, Some(5));
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
        assert_eq!(t.async_seconds, Some(60));
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
        assert_eq!(t.async_seconds, Some(0));
    }

    #[test]
    fn parse_get_url_to_wire_op_round_trip() {
        let t = parse_task(
            r#"
name: t
get_url:
  url: https://example.com/p
  dest: /tmp/p
  checksum: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  mode: "0640"
  force: yes
"#,
        );
        let TaskBody::Op(op) = t.body else { panic!() };
        let wire = op.to_wire_op().unwrap();
        let WireOp::OpGetUrl(g) = wire else { panic!("got {wire:?}") };
        assert_eq!(g.kind, 15);
        assert_eq!(g.url, "https://example.com/p");
        assert_eq!(g.dest, "/tmp/p");
        assert!(g.checksum.starts_with("sha256:"));
        assert_eq!(g.mode, 0o640);
        assert_eq!(g.force, 1);
        assert_eq!(g.validate_certs, 1);
        assert_eq!(g.follow_redirects, uri_follow::ALL);
    }
}
