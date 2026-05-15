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
    msg::{op_exec, op_gather_facts, op_shell, op_stat, op_write_file},
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

/// Keys that select a task body. Exactly one must appear per task.
const BODY_KEYS: &[&str] = &[
    "shell",
    "exec",
    "write_file",
    "template",
    "copy",
    "stat",
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
