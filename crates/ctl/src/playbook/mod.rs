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
pub mod role;
pub mod task_op;
mod validate;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::path::Path;

#[allow(unused_imports)]
pub use task_op::{
    AptOp, AptState, AssertTask, BlockInFileOp, BlockInFileState, CopyOp, ExecOp, FailTask, FileOp,
    FileState, IncludeRoleSpec, LineInFileOp, LineInFileState, LoopControl, LoopSpec, MetaAction,
    SetFactMap, ShellOp, StatOp, SystemdOp, SystemdState, Task, TaskBody, TaskOp, TemplateOp,
    WaitForOp, WaitForState, WriteFileOp,
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
    /// When true (the default), the orchestrator runs an implicit
    /// `Gathering Facts` task as the first step of the play. Matches
    /// Ansible's default; set `gather_facts: false` to skip the
    /// per-host round-trip.
    #[serde(default = "default_gather_facts")]
    pub gather_facts: bool,
    /// Play-scoped variables. Resolved (templated against the inventory_vars-
    /// only view) at the start of each play and layered into every host's
    /// [`crate::exec_ctx::HostCtx::play_vars`].
    #[serde(default)]
    pub vars: BTreeMap<String, serde_yaml::Value>,
    /// `roles:` directive. Each entry resolves to a directory under
    /// `<playbook_dir>/roles/<name>/`; its tasks are prepended to
    /// `tasks` (and handlers to `handlers`) by the role-flatten pass.
    /// Role defaults accumulate into `role_defaults`.
    #[serde(default)]
    pub roles: Vec<RoleInvocation>,
    #[serde(default)]
    pub tasks: Vec<Task>,
    /// Handlers defined at play level. Tasks notify by name; the matching
    /// handler is queued onto the host's pending set and flushed at end-of-
    /// play (or on `meta: flush_handlers`).
    #[serde(default)]
    pub handlers: Vec<Task>,
    /// Merged defaults from every role in this play, in declaration
    /// order (last-wins). Populated by the role-flatten pass; not
    /// Deserialize-able. Lowest-precedence user-defined source — sits
    /// below `inventory_vars` in the precedence chain.
    #[serde(skip)]
    pub role_defaults: BTreeMap<String, JsonValue>,
    /// Play-level `become:` default. Pushed down onto every task in
    /// this play that doesn't explicitly set its own `become:` (the
    /// `inherit_become_defaults` pass in `playbook::load` does the
    /// push). At task scope, `Some(false)` opts out of an inherited
    /// `true`.
    #[serde(rename = "become", default)]
    pub become_: Option<bool>,
    /// Play-level `become_user:` default. Same inheritance model as
    /// `become_`. Only meaningful when become resolves to true at
    /// run time; defaults to `"root"` when unset.
    #[serde(default)]
    pub become_user: Option<String>,
}

fn default_gather_facts() -> bool {
    true
}

/// `roles:` entry — bare string (`- common`) or full form
/// (`- { role: common, tags: [...] }`). Bart's choice: we accept and
/// ignore `tags:` for now — tag filtering isn't wired up yet (cross-
/// cutting TODO).
#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum RoleInvocation {
    Bare(String),
    Full(RoleSpec),
}

impl RoleInvocation {
    pub fn name(&self) -> &str {
        match self {
            RoleInvocation::Bare(n) => n,
            RoleInvocation::Full(s) => &s.role,
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct RoleSpec {
    pub role: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `hosts:` accepts either the literal `all`, a bare host/group name, or
/// an explicit list. The bare-string and list forms both end up as
/// `Names(...)`; the orchestrator resolves names to either a host or a
/// group at run time.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HostSelector {
    All(AllKeyword),
    Names(Vec<String>),
    /// Single name shorthand: `hosts: web` → `Names(vec!["web"])`.
    Name(String),
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
    role::flatten_playbook(&mut pb, base)
        .with_context(|| format!("resolving roles in {}", path.display()))?;
    role::expand_include_roles(&mut pb, base)
        .with_context(|| format!("expanding include_role in {}", path.display()))?;
    role::load_templates(&mut pb, base)
        .with_context(|| format!("loading template sources in {}", path.display()))?;
    role::load_copy_files(&mut pb, base)
        .with_context(|| format!("loading copy sources in {}", path.display()))?;
    inherit_become_defaults(&mut pb);
    Ok(pb)
}

/// Push play-level `become:` / `become_user:` defaults down onto every
/// task (including handlers) that doesn't set its own. Runs after all
/// flatten/expand passes so role-pulled and include_role-pulled tasks
/// see the play's become defaults too. Tasks that explicitly set
/// `become: false` are left alone — the parser distinguishes
/// `Some(false)` from `None` for exactly this reason.
fn inherit_become_defaults(pb: &mut Playbook) {
    for play in &mut pb.plays {
        let play_become = play.become_;
        let play_become_user = play.become_user.clone();
        for task in play.tasks.iter_mut().chain(play.handlers.iter_mut()) {
            if task.become_.is_none() {
                task.become_ = play_become;
            }
            if task.become_user.is_none() {
                task.become_user = play_become_user.clone();
            }
        }
    }
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

    const SIMPLE_INV: &str = r#"
all:
  vars:
    ansible_user: deploy
  children:
    web:
      hosts:
        web1:
          ansible_host: 10.0.0.1
"#;

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
        let inv = crate::inventory::parse(SIMPLE_INV).unwrap();
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
        let inv = crate::inventory::parse(SIMPLE_INV).unwrap();
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
                gather_facts: true,
                vars: BTreeMap::new(),
                roles: Vec::new(),
                tasks: vec![],
                handlers: vec![],
                role_defaults: BTreeMap::new(),
                become_: None,
                become_user: None,
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

    #[test]
    fn play_become_inherited_by_tasks_with_none() {
        let dir = tempfile::TempDir::new().unwrap();
        let pb_path = dir.path().join("pb.yml");
        std::fs::write(
            &pb_path,
            r#"
- name: p
  become: true
  become_user: postgres
  hosts: all
  gather_facts: false
  tasks:
    - name: inherit_both
      shell: echo hi
    - name: opt_out
      become: false
      shell: echo hi
    - name: override_user_only
      become_user: www-data
      shell: echo hi
"#,
        )
        .unwrap();
        let pb = load(&pb_path).unwrap();
        let tasks = &pb.plays[0].tasks;
        // First task: both inherited.
        assert_eq!(tasks[0].become_, Some(true));
        assert_eq!(tasks[0].become_user.as_deref(), Some("postgres"));
        // Second: explicit false stays false; user still inherited.
        assert_eq!(tasks[1].become_, Some(false));
        assert_eq!(tasks[1].become_user.as_deref(), Some("postgres"));
        // Third: become inherited, user overridden.
        assert_eq!(tasks[2].become_, Some(true));
        assert_eq!(tasks[2].become_user.as_deref(), Some("www-data"));
    }

    #[test]
    fn play_without_become_leaves_tasks_at_none() {
        let dir = tempfile::TempDir::new().unwrap();
        let pb_path = dir.path().join("pb.yml");
        std::fs::write(
            &pb_path,
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: t
      shell: echo hi
"#,
        )
        .unwrap();
        let pb = load(&pb_path).unwrap();
        // None preserved → orchestrator falls back to inventory
        // `ansible_become` at run time.
        assert_eq!(pb.plays[0].tasks[0].become_, None);
        assert_eq!(pb.plays[0].tasks[0].become_user, None);
    }
}
