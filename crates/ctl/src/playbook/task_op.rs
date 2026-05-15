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
        op_apt, op_blockinfile, op_exec, op_file, op_gather_facts, op_lineinfile, op_shell,
        op_stat, op_systemd, op_wait_for, op_write_file,
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
    /// `apt:` — install/remove/upgrade Debian-family packages. Batched
    /// (one wire op carries multiple `name`s). Idempotent via
    /// `dpkg-query`.
    Apt(AptOp),
}

/// `apt:` parsed form. Mirrors Ansible's `ansible.builtin.apt` (subset).
/// `names` is the list of packages — Ansible's `name:` accepts either
/// a single string or a list; we normalize to a Vec at parse time.
#[derive(Debug, Clone, PartialEq)]
pub struct AptOp {
    pub names: Vec<String>,
    pub state: AptState,
    pub update_cache: bool,
    /// Seconds; only meaningful with `update_cache=true`. 0 = always
    /// update.
    pub cache_valid_time: u32,
    pub purge: bool,
    pub autoremove: bool,
    /// Empty = unused; maps to `apt-get -t <release>`.
    pub default_release: String,
    pub allow_unauthenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AptState {
    Present,
    Absent,
    Latest,
}

impl AptState {
    pub fn wire_byte(self) -> u8 {
        match self {
            AptState::Present => 0,
            AptState::Absent => 1,
            AptState::Latest => 2,
        }
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

/// Hand-written so we can:
///   - accept `name:` as either string or list (Ansible's wart)
///   - reject `update_cache: no` + `cache_valid_time: N` (no effect)
///   - default state to Present (Ansible default)
impl<'de> Deserialize<'de> for AptOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        // `name:` is required and may be a string or a list of strings.
        // Ansible also accepts `pkg:` and `package:` as aliases; gothab
        // only uses `name:` so we keep the surface tight.
        let names = match map.remove("name") {
            None => return Err(D::Error::custom("apt: missing required field `name`")),
            Some(serde_yaml::Value::String(s)) => vec![s],
            Some(serde_yaml::Value::Sequence(seq)) => {
                let mut out = Vec::with_capacity(seq.len());
                for v in seq {
                    match v {
                        serde_yaml::Value::String(s) => out.push(s),
                        other => {
                            return Err(D::Error::custom(format!(
                                "apt.name list items must be strings, got: {other:?}"
                            )))
                        }
                    }
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "apt.name must be a string or list of strings, got: {other:?}"
                )))
            }
        };

        let state = match map.remove("state") {
            None => AptState::Present,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" | "installed" => AptState::Present,
                "absent" | "removed" => AptState::Absent,
                "latest" => AptState::Latest,
                other => {
                    return Err(D::Error::custom(format!(
                        "apt.state: expected one of [present, installed, absent, removed, latest], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "apt.state must be a string, got: {other:?}"
                )))
            }
        };

        let update_cache = take_optional_ansible_bool(&mut map, "update_cache")?.unwrap_or(false);
        let cache_valid_time = match map.remove("cache_valid_time") {
            None | Some(serde_yaml::Value::Null) => 0u32,
            Some(serde_yaml::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                D::Error::custom(format!(
                    "apt.cache_valid_time must be a non-negative integer, got: {n}"
                ))
            })? as u32,
            Some(serde_yaml::Value::String(s)) => s.parse::<u32>().map_err(|e| {
                D::Error::custom(format!("apt.cache_valid_time: invalid int {s:?}: {e}"))
            })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "apt.cache_valid_time must be a number, got: {other:?}"
                )))
            }
        };
        let purge = take_optional_ansible_bool(&mut map, "purge")?.unwrap_or(false);
        let autoremove = take_optional_ansible_bool(&mut map, "autoremove")?.unwrap_or(false);
        let default_release =
            take_optional_field_string(&mut map, "default_release")?.unwrap_or_default();
        let allow_unauthenticated =
            take_optional_ansible_bool(&mut map, "allow_unauthenticated")?.unwrap_or(false);
        // Accept and discard `force_apt_get` — we always use apt-get.
        let _ = map.remove("force_apt_get");
        // Accept and discard `install_recommends` for now; gothab doesn't
        // set it. (Ansible's default ON matches apt-get's default ON.)
        let _ = map.remove("install_recommends");

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "apt: unknown field(s): {unknown:?}; expected one of \
                 [name, state, update_cache, cache_valid_time, purge, autoremove, default_release, allow_unauthenticated, install_recommends, force_apt_get]"
            )));
        }

        if names.is_empty() {
            return Err(D::Error::custom(
                "apt.name: must specify at least one package",
            ));
        }
        for n in &names {
            if n.trim().is_empty() {
                return Err(D::Error::custom("apt.name: empty package name"));
            }
        }
        if !update_cache && cache_valid_time != 0 {
            return Err(D::Error::custom(
                "apt: `cache_valid_time` requires `update_cache: true`",
            ));
        }

        Ok(AptOp {
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
            Some(v) => serde_yaml::from_value::<Vec<String>>(v)
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
            "apt" => TaskBody::Op(TaskOp::Apt(
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
        })
    }
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
                Ok(op_write_file(c.dest.clone(), c.mode, body.clone()))
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
            TaskOp::Apt(a) => Ok(op_apt(
                a.names.clone(),
                a.state.wire_byte(),
                a.update_cache,
                a.cache_valid_time,
                a.purge,
                a.autoremove,
                a.default_release.clone(),
                a.allow_unauthenticated,
            )),
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
            TaskBody::Op(TaskOp::Apt(a)) => {
                assert_eq!(a.names, vec!["nginx".to_string()]);
                assert_eq!(a.state, AptState::Present);
                assert!(!a.update_cache);
                assert!(!a.purge);
            }
            _ => panic!("expected Apt"),
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
            TaskBody::Op(TaskOp::Apt(a)) => {
                assert_eq!(a.names, vec!["nginx".to_string(), "curl".to_string()]);
                assert_eq!(a.state, AptState::Latest);
                assert!(a.update_cache);
                assert_eq!(a.cache_valid_time, 3600);
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
            TaskBody::Op(TaskOp::Apt(a)) => assert_eq!(a.state, AptState::Present),
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
            TaskBody::Op(TaskOp::Apt(a)) => assert_eq!(a.state, AptState::Absent),
            _ => panic!(),
        }
    }

    #[test]
    fn apt_to_wire_carries_fields() {
        let t = TaskOp::Apt(AptOp {
            names: vec!["nginx".into(), "curl".into()],
            state: AptState::Latest,
            update_cache: true,
            cache_valid_time: 3600,
            purge: false,
            autoremove: true,
            default_release: "bookworm-backports".into(),
            allow_unauthenticated: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpApt(o) = wire else {
            panic!("expected OpApt")
        };
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
}
