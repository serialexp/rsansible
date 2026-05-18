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
    classify_sql_readonly, AssertTask, AsyncStatusOp, BlockInFileOp, BlockInFileState, BlockSpec,
    CommandOp,
    CopyOp, DebugMsg, DebugTask, ExecOp,
    FailTask, FileOp, FileState, GetUrlOp, IncludeRoleSpec, IptablesAction, IptablesIpVersion,
    IptablesOp, IptablesRuleState, LineInFileOp, LineInFileState,
    LoopControl, LoopSpec, MetaAction, OpenSslCsrPipeOp, OpenSslPrivkeyOp, PackageManager,
    PackageOp, PackageState, PauseTask, PostgresqlExtOp, PostgresqlQueryOp,
    RepositoryManager, RepositoryOp, RepositoryState, SetFactMap, ShellOp,
    SlurpOp,
    StatOp, SystemdOp, SystemdState, Task, TaskBody, TaskOp, TemplateOp, TempfileKind, TempfileOp,
    UfwOp, UfwOpKind, UnarchiveOp, UriOp, WaitForOp, WaitForState, WriteFileOp,
    X509CertificatePipeOp,
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
    /// `vars_files:` — list of YAML files (each a flat or nested mapping)
    /// loaded at playbook-load time and merged into `vars` BEFORE this
    /// struct reaches the orchestrator. Resolution is relative to the
    /// playbook file's directory; absolute paths are used as-is. Inline
    /// `vars:` entries win over anything loaded via `vars_files:`; later
    /// `vars_files:` entries win over earlier ones (Ansible behavior).
    ///
    /// The field is only meaningful between YAML deserialization and
    /// the `merge_vars_files` pass in `load()` — by the time the
    /// orchestrator sees the `Play`, `vars` is the merged final view
    /// and `vars_files` is empty.
    #[serde(default)]
    pub vars_files: Vec<String>,
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
    /// Play-level `connection:` setting (Ansible). Controls how the
    /// controller reaches managed hosts:
    ///
    /// - `ssh` / `smart` — the rsansible default: push the agent over
    ///   SSH and dispatch ops. We accept either spelling.
    /// - `local` — run tasks against the controller's filesystem
    ///   *without* SSH (skip the agent push). Honored only when the
    ///   play also has `hosts: localhost` (or maps to it after
    ///   inventory resolution); rejected otherwise to avoid the
    ///   "silently runs on the wrong machine" Ansible footgun.
    ///
    /// Any other connection plugin (`paramiko_ssh`, `winrm`, `docker`,
    /// …) is rejected at parse time with a "not supported" message.
    /// `None` (the default) is equivalent to `ssh`.
    ///
    /// Runtime semantics for `local`: not yet wired — the parser
    /// accepts the field so playbooks load, but the orchestrator
    /// will surface a clear "controller-side execution not yet
    /// implemented" error when it tries to dispatch.
    #[serde(default, deserialize_with = "deserialize_connection")]
    pub connection: Option<Connection>,
    /// `serial:` — rolling-batch size. Ansible runs the play across
    /// `serial` hosts at a time instead of all-at-once, draining each
    /// batch before starting the next. Accepted forms:
    ///   - integer `serial: 1` — exactly N hosts per batch
    ///   - percentage `serial: "20%"` — N% of the targeted hosts
    ///   - list `serial: [1, 5, "20%"]` — ramp up across batches
    ///
    /// **Parsed but not yet honored** — the orchestrator currently
    /// runs every targeted host concurrently (modulo `--concurrency`
    /// on the connect phase). When rolling batches land, this is the
    /// field that drives them. Storing the raw YAML value avoids
    /// committing to a representation before the runtime semantics
    /// are pinned down.
    #[serde(default)]
    pub serial: Option<serde_yaml::Value>,
}

/// The two connection plugins rsansible recognizes. Mirrors Ansible's
/// `connection:` setting; everything else (paramiko_ssh, winrm, docker,
/// …) is rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connection {
    /// Push the agent over SSH and dispatch ops. The default.
    Ssh,
    /// Run on the controller without SSH. Requires `hosts: localhost`.
    Local,
}

fn deserialize_connection<'de, D>(d: D) -> Result<Option<Connection>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let s: Option<String> = Option::deserialize(d)?;
    match s.as_deref() {
        None => Ok(None),
        // `smart` is Ansible's pick-the-best-SSH-impl shim; for our
        // purposes it's the same as `ssh`.
        Some("ssh") | Some("smart") => Ok(Some(Connection::Ssh)),
        Some("local") => Ok(Some(Connection::Local)),
        Some(other) => Err(D::Error::custom(format!(
            "connection: {other:?} is not supported by rsansible \
             (accepted values: `ssh`, `smart`, `local`)"
        ))),
    }
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

    /// Tags declared on this role invocation (always empty for the bare
    /// shorthand form). Propagated onto every materialized task at
    /// role-flatten time.
    pub fn tags(&self) -> &[String] {
        match self {
            RoleInvocation::Bare(_) => &[],
            RoleInvocation::Full(s) => &s.tags,
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct RoleSpec {
    pub role: String,
    /// `tags:` on a role invocation are propagated onto every task and
    /// handler pulled in from that role at flatten time. Accepts either
    /// a bare string (Ansible-style shorthand) or a YAML sequence.
    #[serde(default, deserialize_with = "crate::playbook::task_op::deserialize_tags")]
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
    merge_vars_files(&mut pb, base)
        .with_context(|| format!("loading vars_files in {}", path.display()))?;
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
    // Push block-level metadata down into block children. Must run
    // AFTER inherit_become_defaults so that block-level become/
    // become_user values inherited from the play also cascade into
    // the block's children.
    for play in &mut pb.plays {
        inherit_block_metadata(&mut play.tasks);
        inherit_block_metadata(&mut play.handlers);
    }
    Ok(pb)
}

/// Resolve every play's `vars_files:` list against `base` and merge the
/// loaded mappings into the play's `vars` field.
///
/// Precedence (low → high, matching Ansible):
/// 1. First `vars_files:` entry loaded
/// 2. … later entries override earlier ones
/// 3. Inline `vars:` on the play wins over everything from `vars_files:`
///
/// After this pass returns, `play.vars_files` is empty and `play.vars`
/// holds the merged final view. The orchestrator never sees the raw
/// file list.
///
/// Errors:
/// * File missing → loud error naming the path.
/// * File parses but isn't a top-level YAML mapping → loud error.
/// * Path resolution: relative paths against `base` (the playbook
///   file's parent directory); absolute paths used as-is.
fn merge_vars_files(pb: &mut Playbook, base: &Path) -> Result<()> {
    for (play_idx, play) in pb.plays.iter_mut().enumerate() {
        // Drain so we don't double-load on a hypothetical second pass.
        let files = std::mem::take(&mut play.vars_files);
        if files.is_empty() {
            continue;
        }
        // Stash inline vars; we re-apply them last so inline wins.
        let inline = std::mem::take(&mut play.vars);
        for rel in files {
            let path = {
                let p = Path::new(&rel);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    base.join(p)
                }
            };
            let text = std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "play[{play_idx}] {:?}: vars_files entry {rel:?} ({})",
                    play.name,
                    path.display(),
                )
            })?;
            let value: serde_yaml::Value = serde_yaml::from_str(&text)
                .with_context(|| {
                    format!(
                        "play[{play_idx}] {:?}: parsing vars_files {rel:?}",
                        play.name,
                    )
                })?;
            let map = match value {
                serde_yaml::Value::Mapping(m) => m,
                serde_yaml::Value::Null => continue, // empty file: skip
                other => {
                    return Err(anyhow::anyhow!(
                        "play[{play_idx}] {:?}: vars_files {rel:?} must be a top-level \
                         YAML mapping, got: {:?}",
                        play.name,
                        kind_of(&other),
                    ));
                }
            };
            for (k, v) in map {
                let key = match k {
                    serde_yaml::Value::String(s) => s,
                    other => {
                        return Err(anyhow::anyhow!(
                            "play[{play_idx}] {:?}: vars_files {rel:?}: \
                             non-string key {other:?}",
                            play.name,
                        ));
                    }
                };
                play.vars.insert(key, v); // later vars_files wins
            }
        }
        // Re-apply inline vars on top.
        for (k, v) in inline {
            play.vars.insert(k, v);
        }
    }
    Ok(())
}

/// Short description of a YAML Value's kind for diagnostics — we don't
/// want to dump the entire offending document into a one-line error.
fn kind_of(v: &serde_yaml::Value) -> &'static str {
    match v {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "bool",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Tagged(_) => "tagged",
    }
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

/// Push block-level metadata down into each block's child tasks
/// (`tasks`, `rescue`, `always`), recursively. Matches Ansible's
/// inheritance semantics so block-level `become:` / `when:` / `tags:`
/// etc. apply to every nested task without per-task duplication.
///
/// Per-field merge rules (parent = block-container task, child =
/// inner task):
/// - `when`: AND-join — `(parent) and (child)` if both set, else
///   whichever is set, else None. Both sides preserve full Jinja.
/// - `tags`: union (parent's tags are appended to child's, dedup'd).
/// - `become`, `become_user`, `ignore_errors`, `check_mode`,
///   `delegate_to`: child's explicit `Some(_)` wins; otherwise the
///   parent's value cascades. (`become: false` on a child opts the
///   child out of an inherited `become: true`.)
/// - `loop_spec` / `loop_control`: NEVER pushed down. The block as
///   a whole is the loop unit — the block executor iterates and
///   sets `item` in scope for the children, but the children's own
///   `loop:` (if any) is a separate per-child loop.
/// - `register` / `notify` / `run_once` / `retries` / `until` /
///   `delay` / `async` / `poll`: rejected at parse time on a block,
///   so no merge logic is needed.
///
/// Called recursively on each block's children too, so nested blocks
/// see the full inheritance chain at every depth.
fn inherit_block_metadata(tasks: &mut Vec<Task>) {
    for task in tasks.iter_mut() {
        if matches!(&task.body, TaskBody::Block(_)) {
            push_block_metadata_to_children(task);
            // Recurse: the block's children may themselves be blocks
            // (nested case) and need their own metadata pushed down.
            if let TaskBody::Block(b) = &mut task.body {
                inherit_block_metadata(&mut b.tasks);
                inherit_block_metadata(&mut b.rescue);
                inherit_block_metadata(&mut b.always);
            }
        }
    }
}

fn push_block_metadata_to_children(block_task: &mut Task) {
    // Snapshot the block container's metadata. We have to clone the
    // Optional fields because we need to assign them into multiple
    // children below, and `&mut self` aliasing rules force us to
    // detach the snapshot from the block before borrowing children.
    let parent_when = block_task.when.clone();
    let parent_tags = block_task.tags.clone();
    let parent_become = block_task.become_;
    let parent_become_user = block_task.become_user.clone();
    let parent_ignore_errors = block_task.ignore_errors;
    let parent_check_mode = block_task.check_mode;
    let parent_delegate_to = block_task.delegate_to.clone();

    let block = match &mut block_task.body {
        TaskBody::Block(b) => b,
        _ => return,
    };

    let apply = |child: &mut Task| {
        // when: AND-join (parent) and (child). Parentheses preserve
        // operator-precedence safety — `a or b` AND `c` should bind
        // as `(a or b) and (c)`, not `a or b and c`. (minijinja uses
        // Python-style precedence where `and` binds tighter than
        // `or`, so this matters.)
        match (&parent_when, &child.when) {
            (Some(p), Some(c)) => {
                child.when = Some(format!("({p}) and ({c})"));
            }
            (Some(p), None) => {
                child.when = Some(p.clone());
            }
            _ => {}
        }
        // tags: union, preserving child's order then parent's
        // remainder. Dedup linearly — tag lists are short.
        for t in &parent_tags {
            if !child.tags.contains(t) {
                child.tags.push(t.clone());
            }
        }
        if child.become_.is_none() {
            child.become_ = parent_become;
        }
        if child.become_user.is_none() {
            child.become_user = parent_become_user.clone();
        }
        if child.ignore_errors.is_none() {
            child.ignore_errors = parent_ignore_errors;
        }
        if child.check_mode.is_none() {
            child.check_mode = parent_check_mode;
        }
        if child.delegate_to.is_none() {
            child.delegate_to = parent_delegate_to.clone();
        }
    };

    for child in block
        .tasks
        .iter_mut()
        .chain(block.rescue.iter_mut())
        .chain(block.always.iter_mut())
    {
        apply(child);
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

    // ---------- vars_files: ----------

    /// Lay out a tempdir with a playbook + vars_files and load it via
    /// the public `load()` entry point, exercising the whole pipeline.
    fn write_playbook_tree(
        playbook_yaml: &str,
        files: &[(&str, &str)],
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let pb_path = dir.path().join("play.yml");
        std::fs::write(&pb_path, playbook_yaml).unwrap();
        for (rel, body) in files {
            let p = dir.path().join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, body).unwrap();
        }
        (dir, pb_path)
    }

    #[test]
    fn vars_files_merges_single_file() {
        let (_dir, path) = write_playbook_tree(
            r#"
- name: p
  hosts: localhost
  vars_files:
    - vars.yml
  tasks:
    - name: t
      shell: "echo {{ greeting }}"
"#,
            &[("vars.yml", "greeting: hello\nport: 8080\n")],
        );
        let pb = load(&path).unwrap();
        let v = &pb.plays[0].vars;
        assert!(pb.plays[0].vars_files.is_empty(), "should be drained");
        assert_eq!(
            v.get("greeting"),
            Some(&serde_yaml::Value::String("hello".into()))
        );
        assert_eq!(
            v.get("port"),
            Some(&serde_yaml::Value::Number(8080.into()))
        );
    }

    #[test]
    fn vars_files_later_overrides_earlier() {
        let (_dir, path) = write_playbook_tree(
            r#"
- name: p
  hosts: localhost
  vars_files:
    - a.yml
    - b.yml
  tasks:
    - name: t
      shell: echo hi
"#,
            &[
                ("a.yml", "x: from-a\ny: only-in-a\n"),
                ("b.yml", "x: from-b\n"),
            ],
        );
        let pb = load(&path).unwrap();
        let v = &pb.plays[0].vars;
        assert_eq!(
            v.get("x"),
            Some(&serde_yaml::Value::String("from-b".into())),
            "later vars_files entry must win"
        );
        assert_eq!(
            v.get("y"),
            Some(&serde_yaml::Value::String("only-in-a".into())),
        );
    }

    #[test]
    fn inline_vars_wins_over_vars_files() {
        let (_dir, path) = write_playbook_tree(
            r#"
- name: p
  hosts: localhost
  vars_files:
    - vars.yml
  vars:
    greeting: inline-wins
    extra: only-inline
  tasks:
    - name: t
      shell: echo hi
"#,
            &[("vars.yml", "greeting: from-file\nport: 8080\n")],
        );
        let pb = load(&path).unwrap();
        let v = &pb.plays[0].vars;
        assert_eq!(
            v.get("greeting"),
            Some(&serde_yaml::Value::String("inline-wins".into())),
            "inline vars: must win over vars_files",
        );
        assert_eq!(
            v.get("port"),
            Some(&serde_yaml::Value::Number(8080.into())),
            "non-conflicting vars_files entry preserved",
        );
        assert_eq!(
            v.get("extra"),
            Some(&serde_yaml::Value::String("only-inline".into())),
        );
    }

    #[test]
    fn vars_files_relative_path_resolves_against_playbook_dir() {
        // Layout:
        //   tempdir/
        //     play.yml          ← playbook
        //     ../sibling.yml    (one level up)
        //   tempdir2/
        // Make a nested layout where vars_files reaches ../shared.yml
        let outer = tempfile::tempdir().unwrap();
        let inner = outer.path().join("playbooks");
        std::fs::create_dir(&inner).unwrap();
        let pb_path = inner.join("play.yml");
        std::fs::write(
            &pb_path,
            r#"
- name: p
  hosts: localhost
  vars_files:
    - ../shared.yml
  tasks:
    - name: t
      shell: echo hi
"#,
        )
        .unwrap();
        std::fs::write(outer.path().join("shared.yml"), "k: found\n").unwrap();
        let pb = load(&pb_path).unwrap();
        assert_eq!(
            pb.plays[0].vars.get("k"),
            Some(&serde_yaml::Value::String("found".into()))
        );
    }

    #[test]
    fn vars_files_absolute_path_used_as_is() {
        let outer = tempfile::tempdir().unwrap();
        let abs = outer.path().join("global.yml");
        std::fs::write(&abs, "absolute: yes\n").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pb_path = dir.path().join("play.yml");
        let pb_yaml = format!(
            r#"
- name: p
  hosts: localhost
  vars_files:
    - {abs}
  tasks:
    - name: t
      shell: echo hi
"#,
            abs = abs.to_str().unwrap()
        );
        std::fs::write(&pb_path, pb_yaml).unwrap();
        let pb = load(&pb_path).unwrap();
        assert_eq!(
            pb.plays[0].vars.get("absolute"),
            Some(&serde_yaml::Value::String("yes".into()))
        );
    }

    #[test]
    fn vars_files_missing_errors_loudly() {
        let (_dir, path) = write_playbook_tree(
            r#"
- name: p
  hosts: localhost
  vars_files:
    - no-such-file.yml
  tasks:
    - name: t
      shell: echo hi
"#,
            &[],
        );
        let err = format!("{:#}", load(&path).unwrap_err());
        assert!(
            err.contains("vars_files") && err.contains("no-such-file.yml"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vars_files_non_mapping_errors_loudly() {
        let (_dir, path) = write_playbook_tree(
            r#"
- name: p
  hosts: localhost
  vars_files:
    - sequence.yml
  tasks:
    - name: t
      shell: echo hi
"#,
            &[("sequence.yml", "- one\n- two\n")],
        );
        let err = format!("{:#}", load(&path).unwrap_err());
        assert!(
            err.contains("vars_files") && err.contains("sequence.yml") && err.contains("mapping"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vars_files_empty_file_is_a_noop() {
        let (_dir, path) = write_playbook_tree(
            r#"
- name: p
  hosts: localhost
  vars_files:
    - empty.yml
  vars:
    x: 1
  tasks:
    - name: t
      shell: echo hi
"#,
            &[("empty.yml", "")],
        );
        let pb = load(&path).unwrap();
        assert_eq!(
            pb.plays[0].vars.get("x"),
            Some(&serde_yaml::Value::Number(1.into()))
        );
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
                vars_files: Vec::new(),
                roles: Vec::new(),
                tasks: vec![],
                handlers: vec![],
                role_defaults: BTreeMap::new(),
                become_: None,
                become_user: None,
                connection: None,
                serial: None,
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

    // ---------- block-level metadata inheritance ----------

    fn write_and_load(yaml: &str) -> Playbook {
        let dir = tempfile::TempDir::new().unwrap();
        let pb_path = dir.path().join("pb.yml");
        std::fs::write(&pb_path, yaml).unwrap();
        let pb = load(&pb_path).unwrap();
        // Keep the tempdir alive past load — leak it. Tests are small,
        // and the tempdir cleanup at process exit is fine here.
        std::mem::forget(dir);
        pb
    }

    fn block_children(t: &Task) -> &BlockSpec {
        match &t.body {
            TaskBody::Block(b) => b,
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn block_pushes_when_down_to_children_with_and_join() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      when: outer_ok | bool
      block:
        - name: bare
          shell: echo hi
        - name: with-when
          when: extra
          shell: echo hi
"#,
        );
        let b = block_children(&pb.plays[0].tasks[0]);
        // Child without a `when:` of its own picks up the block's
        // verbatim.
        assert_eq!(b.tasks[0].when.as_deref(), Some("outer_ok | bool"));
        // Child with its own `when:` gets the AND-joined form,
        // parenthesized to preserve precedence.
        assert_eq!(
            b.tasks[1].when.as_deref(),
            Some("(outer_ok | bool) and (extra)")
        );
    }

    #[test]
    fn block_pushes_become_down_unless_child_overrides() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      become: true
      become_user: postgres
      block:
        - name: inherits
          shell: echo hi
        - name: opts-out
          become: false
          shell: echo hi
        - name: overrides-user
          become_user: www-data
          shell: echo hi
"#,
        );
        let b = block_children(&pb.plays[0].tasks[0]);
        assert_eq!(b.tasks[0].become_, Some(true));
        assert_eq!(b.tasks[0].become_user.as_deref(), Some("postgres"));
        // Explicit `become: false` on child stays.
        assert_eq!(b.tasks[1].become_, Some(false));
        // become_user still inherits even when become is explicit-false
        // (that's how Ansible does it — the user override is
        // independent of the become flag).
        assert_eq!(b.tasks[1].become_user.as_deref(), Some("postgres"));
        // Explicit become_user on child stays; become inherits.
        assert_eq!(b.tasks[2].become_, Some(true));
        assert_eq!(b.tasks[2].become_user.as_deref(), Some("www-data"));
    }

    #[test]
    fn block_pushes_tags_as_union() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      tags: [db, slow]
      block:
        - name: child-no-tags
          shell: echo hi
        - name: child-with-tags
          tags: [migration, db]
          shell: echo hi
"#,
        );
        let b = block_children(&pb.plays[0].tasks[0]);
        // Bare child gets the block's tags.
        assert_eq!(b.tasks[0].tags, vec!["db", "slow"]);
        // Child with its own tags gets the union (child order first,
        // then parent's tags not already present — `db` is in both,
        // appears once).
        assert_eq!(b.tasks[1].tags, vec!["migration", "db", "slow"]);
    }

    #[test]
    fn block_pushes_ignore_errors_and_check_mode_down() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      ignore_errors: true
      check_mode: false
      block:
        - name: inherits
          shell: echo hi
        - name: opts-out-of-ignore
          ignore_errors: false
          shell: echo hi
"#,
        );
        let b = block_children(&pb.plays[0].tasks[0]);
        assert_eq!(b.tasks[0].ignore_errors, Some(true));
        assert_eq!(b.tasks[0].check_mode, Some(false));
        // Explicit false on child stays.
        assert_eq!(b.tasks[1].ignore_errors, Some(false));
        assert_eq!(b.tasks[1].check_mode, Some(false));
    }

    #[test]
    fn block_pushes_delegate_to_down() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      delegate_to: localhost
      block:
        - name: inherits
          shell: echo hi
        - name: overrides
          delegate_to: bastion
          shell: echo hi
"#,
        );
        let b = block_children(&pb.plays[0].tasks[0]);
        assert_eq!(b.tasks[0].delegate_to.as_deref(), Some("localhost"));
        assert_eq!(b.tasks[1].delegate_to.as_deref(), Some("bastion"));
    }

    #[test]
    fn block_pushes_metadata_to_rescue_and_always_arms() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      become: true
      tags: [db]
      block:
        - name: main
          shell: echo hi
      rescue:
        - name: recover
          shell: echo recover
      always:
        - name: cleanup
          shell: echo cleanup
"#,
        );
        let b = block_children(&pb.plays[0].tasks[0]);
        assert_eq!(b.rescue[0].become_, Some(true));
        assert_eq!(b.rescue[0].tags, vec!["db"]);
        assert_eq!(b.always[0].become_, Some(true));
        assert_eq!(b.always[0].tags, vec!["db"]);
    }

    #[test]
    fn nested_block_inheritance_walks_recursively() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      become: true
      tags: [outer-tag]
      block:
        - name: middle
          when: middle_ok
          block:
            - name: inner
              when: inner_ok
              shell: echo hi
"#,
        );
        let outer = block_children(&pb.plays[0].tasks[0]);
        let middle = &outer.tasks[0];
        // Middle inherits outer's metadata.
        assert_eq!(middle.become_, Some(true));
        assert!(middle.tags.contains(&"outer-tag".to_string()));
        let middle_b = match &middle.body {
            TaskBody::Block(b) => b,
            other => panic!("expected nested Block, got {other:?}"),
        };
        let inner = &middle_b.tasks[0];
        // Inner inherits the full chain: become from outer (via middle),
        // tags from outer (via middle), when AND-joined through both
        // levels.
        assert_eq!(inner.become_, Some(true));
        assert!(inner.tags.contains(&"outer-tag".to_string()));
        // The when: chain — middle has `middle_ok`, inner has
        // `inner_ok`, outer doesn't set when so middle's effective is
        // just `middle_ok` (the AND-join only triggers when both sides
        // exist). Then inner gets `(middle_ok) and (inner_ok)`.
        assert_eq!(
            inner.when.as_deref(),
            Some("(middle_ok) and (inner_ok)")
        );
    }

    #[test]
    fn block_loop_not_pushed_down_to_children() {
        let pb = write_and_load(
            r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: outer
      loop: [a, b, c]
      block:
        - name: inner
          shell: "echo {{ item }}"
"#,
        );
        let outer = &pb.plays[0].tasks[0];
        // Outer keeps the loop.
        assert!(outer.loop_spec.is_some());
        let b = block_children(outer);
        // Inner does NOT get a loop_spec pushed down — the block
        // itself iterates, with `item` in scope.
        assert!(b.tasks[0].loop_spec.is_none());
    }
}
