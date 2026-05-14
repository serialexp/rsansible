//! Playbook YAML schema, parsing, and semantic validation.
//!
//! The playbook file is an Ansible-shaped list of plays. Each play has a
//! list of tasks; each task carries one of seven body kinds (shell / exec /
//! write_file / assert / fail / set_fact / import_tasks) plus optional
//! metadata (when / register / loop / loop_control / tags / name).
//!
//! `load()` parses, runs the `import_tasks:` flattening pass, and returns
//! a `Playbook` where every task has a real body (no `ImportTasks` left).
//! `validate()` does semantic checks on top of that.

pub mod import;
pub mod task_op;
mod validate;

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[allow(unused_imports)]
pub use task_op::{
    AssertTask, ExecOp, FailTask, LoopControl, LoopSpec, MetaAction, SetFactMap, ShellOp, Task,
    TaskBody, TaskOp, WriteFileOp,
};
pub use validate::validate;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct Playbook {
    pub plays: Vec<Play>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Play {
    pub name: String,
    #[serde(default)]
    pub hosts: HostSelector,
    #[serde(default)]
    pub strategy: Strategy,
    #[serde(default)]
    pub on_failure: OnFailure,
    pub tasks: Vec<Task>,
    /// Handlers defined at play level. Tasks notify by name; the matching
    /// handler is queued onto the host's pending set and flushed at end-of-
    /// play (or on `meta: flush_handlers`).
    #[serde(default)]
    pub handlers: Vec<Task>,
}

/// `hosts:` accepts either the literal `all` or an explicit list of host names
/// from the inventory.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HostSelector {
    All(AllKeyword),
    Names(Vec<String>),
}

impl Default for HostSelector {
    fn default() -> Self {
        HostSelector::All(AllKeyword::All)
    }
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum AllKeyword {
    All,
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    PerTask,
    PerPlay,
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    #[default]
    Stop,
    Continue,
    MarkHostFailed,
}

/// Load + parse + flatten a playbook from disk.
///
/// Imports (`import_tasks:`) are resolved relative to the playbook file's
/// directory. The returned `Playbook` has no `TaskBody::ImportTasks` left.
pub fn load(path: &Path) -> Result<Playbook> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading playbook {}", path.display()))?;
    let mut pb: Playbook =
        parse(&text).with_context(|| format!("parsing playbook {}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    import::flatten_playbook(&mut pb, base)
        .with_context(|| format!("resolving imports in {}", path.display()))?;
    Ok(pb)
}

/// Parse a playbook from a YAML string. Does *not* resolve `import_tasks:` —
/// use `load()` for that, or call `import::flatten_playbook` yourself with
/// a real base directory.
pub fn parse(text: &str) -> Result<Playbook> {
    let pb: Playbook = serde_yaml::from_str(text)?;
    Ok(pb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn task_op(t: &Task) -> &TaskOp {
        match &t.body {
            TaskBody::Op(op) => op,
            other => panic!("expected Op body, got {other:?}"),
        }
    }

    #[test]
    fn parses_minimal_playbook() {
        let pb = parse(
            r#"
- name: deploy
  tasks:
    - name: greet
      shell: echo hi
"#,
        )
        .unwrap();
        assert_eq!(pb.plays.len(), 1);
        let p = &pb.plays[0];
        assert_eq!(p.name, "deploy");
        assert_eq!(p.strategy, Strategy::PerTask);
        assert_eq!(p.on_failure, OnFailure::Stop);
        assert_eq!(p.hosts, HostSelector::default());
        assert_eq!(p.tasks.len(), 1);
        assert_eq!(p.tasks[0].name, "greet");
        match task_op(&p.tasks[0]) {
            TaskOp::Shell(ShellOp::Simple(s)) => assert_eq!(s, "echo hi"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_full_playbook() {
        let pb = parse(
            r#"
- name: deploy
  hosts: [web1, web2]
  strategy: per_play
  on_failure: mark_host_failed
  tasks:
    - name: run uname
      exec:
        argv: [/bin/uname, -a]
        env:
          FOO: bar
        cwd: /tmp
        timeout_ms: 5000
    - name: write hello
      write_file:
        path: /tmp/hello
        mode: 0o644
        content: "hi\n"
"#,
        )
        .unwrap();
        let p = &pb.plays[0];
        assert_eq!(
            p.hosts,
            HostSelector::Names(vec!["web1".into(), "web2".into()])
        );
        assert_eq!(p.strategy, Strategy::PerPlay);
        assert_eq!(p.on_failure, OnFailure::MarkHostFailed);
        match task_op(&p.tasks[0]) {
            TaskOp::Exec(e) => {
                assert_eq!(e.argv, vec!["/bin/uname", "-a"]);
                assert_eq!(e.env.get("FOO").map(String::as_str), Some("bar"));
                assert_eq!(e.cwd.as_deref(), Some("/tmp"));
                assert_eq!(e.timeout_ms, 5000);
            }
            other => panic!("expected exec, got {other:?}"),
        }
        match task_op(&p.tasks[1]) {
            TaskOp::WriteFile(w) => {
                assert_eq!(w.path, "/tmp/hello");
                assert_eq!(w.mode, 0o644);
                assert_eq!(w.content, "hi\n");
            }
            other => panic!("expected write_file, got {other:?}"),
        }
    }

    #[test]
    fn parses_hosts_all_keyword() {
        let pb = parse(
            r#"
- name: a
  hosts: all
  tasks:
    - name: t
      shell: echo
"#,
        )
        .unwrap();
        assert!(matches!(pb.plays[0].hosts, HostSelector::All(_)));
    }

    #[test]
    fn rejects_unknown_play_key() {
        let err = parse(
            r#"
- name: a
  hostts: all
  tasks:
    - name: t
      shell: echo
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("hostts"), "got: {msg}");
    }

    #[test]
    fn rejects_missing_task_body() {
        let err = parse(
            r#"
- name: a
  tasks:
    - name: t
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing body") || msg.contains("shell"),
            "got: {msg}"
        );
    }

    #[test]
    fn rejects_two_task_body_keys() {
        let err = parse(
            r#"
- name: a
  tasks:
    - name: t
      shell: echo
      exec:
        argv: [/bin/true]
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("more than one") || msg.contains("body") || msg.contains("variant"),
            "got: {msg}"
        );
    }

    #[test]
    fn rejects_unknown_op_kind() {
        let err = parse(
            r#"
- name: a
  tasks:
    - name: t
      definitely_not_a_real_op: yes
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("definitely_not_a_real_op")
                || msg.contains("missing body")
                || msg.contains("variant"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_happy_path() {
        let pb = parse(
            r#"
- name: deploy
  hosts: [web1]
  tasks:
    - name: t
      shell: echo hi
"#,
        )
        .unwrap();
        let inv = crate::inventory::parse(
            r#"
hosts:
  web1:
    host: 10.0.0.1
    user: deploy
"#,
        )
        .unwrap();
        validate(&pb, Some(&inv)).unwrap();
    }

    #[test]
    fn validate_unknown_host_reference() {
        let pb = parse(
            r#"
- name: deploy
  hosts: [web1, missing]
  tasks:
    - name: t
      shell: echo hi
"#,
        )
        .unwrap();
        let inv = crate::inventory::parse(
            r#"
hosts:
  web1:
    host: 10.0.0.1
    user: deploy
"#,
        )
        .unwrap();
        let err = validate(&pb, Some(&inv)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing"), "got: {msg}");
    }

    #[test]
    fn validate_empty_tasks_rejected() {
        let pb = Playbook {
            plays: vec![Play {
                name: "p".into(),
                hosts: HostSelector::default(),
                strategy: Strategy::PerTask,
                on_failure: OnFailure::Stop,
                tasks: vec![],
                handlers: vec![],
            }],
        };
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no tasks"), "got: {msg}");
    }

    #[test]
    fn validate_duplicate_play_names_ok() {
        // Ansible allows it; we do too. Just sanity-check we don't blow up.
        let pb = parse(
            r#"
- name: a
  tasks:
    - name: t
      shell: echo
- name: a
  tasks:
    - name: t
      shell: echo
"#,
        )
        .unwrap();
        validate(&pb, None).unwrap();
    }

    /// `cwd` should round-trip through the env map as expected — type-level
    /// guard that env stays a BTreeMap, not a Vec<String>.
    #[test]
    fn exec_env_is_btreemap() {
        let pb = parse(
            r#"
- name: a
  tasks:
    - name: t
      exec:
        argv: [/bin/true]
        env:
          B: 2
          A: 1
"#,
        )
        .unwrap();
        match task_op(&pb.plays[0].tasks[0]) {
            TaskOp::Exec(e) => {
                // BTreeMap, so keys come out sorted.
                let keys: Vec<_> = e.env.keys().cloned().collect();
                assert_eq!(keys, vec!["A".to_string(), "B".to_string()]);
            }
            other => panic!("{other:?}"),
        }
        // shut up unused-import warning when BTreeMap is needed downstream
        let _ = BTreeMap::<String, String>::new();
    }
}
