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
    msg::{op_exec, op_shell, op_write_file},
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
    /// Control-flow marker: e.g. `meta: flush_handlers` to force the
    /// pending-handler queue to drain mid-play.
    Meta(MetaAction),
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
}

/// Keys that select a task body. Exactly one must appear per task.
const BODY_KEYS: &[&str] = &[
    "shell",
    "exec",
    "write_file",
    "assert",
    "fail",
    "set_fact",
    "import_tasks",
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
        let run_once = match map.remove("run_once") {
            None => false,
            Some(serde_yaml::Value::Bool(b)) => b,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "task {name:?}: `run_once` must be a bool, got: {other:?}"
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
