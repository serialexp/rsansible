//! Role discovery + flattening pass.
//!
//! Runs after `import::flatten_playbook`. For each play with a `roles:`
//! directive, expands each role reference (in declaration order) into:
//!
//! - `tasks/main.yml`     → prepended to `play.tasks` (after running
//!                          `import::flatten_tasks` over them with the
//!                          role's `tasks/` dir as base)
//! - `handlers/main.yml`  → prepended to `play.handlers` (same treatment)
//! - `defaults/main.yml`  → merged into `play.role_defaults`
//!                          (shallow; later roles overwrite earlier)
//!
//! Each task pulled in from a role is annotated with `role_dir = Some(...)`
//! so the template-source resolver can locate `templates/*.j2` relative
//! to the originating role.
//!
//! The role directory layout matches Ansible's convention:
//!
//! ```text
//! <playbook_dir>/roles/<name>/
//!     defaults/main.yml
//!     tasks/main.yml + sibling files imported by main.yml
//!     handlers/main.yml + sibling files imported by main.yml
//!     templates/*.j2
//! ```
//!
//! A role directory must exist (else load fails). A role with no
//! tasks/handlers/defaults at all (i.e. only templates/) is currently
//! rejected — those don't show up in the gothab survey and the
//! ambiguity isn't worth carrying.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::exec_ctx::yaml_to_json;
use crate::playbook::import::flatten_tasks;
use crate::playbook::{IncludeRoleSpec, Playbook, SetFactMap, Task, TaskBody, TaskOp};

const MAX_INCLUDE_ROLE_DEPTH: u32 = 16;

/// Resolve every `roles:` directive in the playbook. Run after
/// `import::flatten_playbook` so the role's task files can themselves
/// use `import_tasks:` and get flattened in the same machinery.
pub fn flatten_playbook(pb: &mut Playbook, base_dir: &Path) -> Result<()> {
    for play in &mut pb.plays {
        if play.roles.is_empty() {
            continue;
        }
        let invocations = std::mem::take(&mut play.roles);
        let mut role_tasks: Vec<Task> = Vec::new();
        let mut role_handlers: Vec<Task> = Vec::new();
        for inv in &invocations {
            let name = inv.name();
            let spec_tags = inv.tags();
            let role_dir = resolve_role_dir(base_dir, name).with_context(|| {
                format!("resolving role {name:?} in play {:?}", play.name)
            })?;

            let mut had_content = false;

            // defaults/main.yml
            if let Some(defaults) = load_defaults(&role_dir)? {
                had_content = true;
                for (k, v) in defaults {
                    play.role_defaults.insert(k, v);
                }
            }

            // tasks/main.yml
            if let Some(loaded) = load_task_file(&role_dir, "tasks")? {
                had_content = true;
                let mut tagged = tag_with_role_dir(loaded, &role_dir);
                propagate_tags(&mut tagged, spec_tags);
                role_tasks.extend(tagged);
            }

            // handlers/main.yml
            if let Some(loaded) = load_task_file(&role_dir, "handlers")? {
                had_content = true;
                let mut tagged = tag_with_role_dir(loaded, &role_dir);
                // Handlers aren't filtered by --tags in v1 (matches the
                // simpler Ansible variant), but propagating the
                // role-invocation's tags keeps the data structure honest
                // so a future handler-tag policy has the right inputs.
                propagate_tags(&mut tagged, spec_tags);
                role_handlers.extend(tagged);
            }

            if !had_content {
                bail!(
                    "role {name:?} at {} has no tasks/main.yml, handlers/main.yml, or defaults/main.yml — empty roles aren't supported",
                    role_dir.display()
                );
            }
        }
        // Role tasks/handlers run *before* the play's own tasks/handlers
        // (Ansible's ordering).
        let mut play_tasks = std::mem::take(&mut play.tasks);
        role_tasks.append(&mut play_tasks);
        play.tasks = role_tasks;

        let mut play_handlers = std::mem::take(&mut play.handlers);
        role_handlers.append(&mut play_handlers);
        play.handlers = role_handlers;

        // Restore — `roles:` is consumed but we keep the original Vec
        // empty rather than re-populating it.
        let _ = invocations;
    }
    Ok(())
}

/// Expand every `TaskBody::IncludeRole` in the playbook in place.
///
/// For each include site:
///   - resolve `roles/<name>/` against `base_dir`
///   - merge `defaults/main.yml` into `play.role_defaults`
///     (later-wins, same as the `roles:` flatten)
///   - append `handlers/main.yml` (if any) to `play.handlers`,
///     tagged with the role's directory; duplicates are ignored
///     (handlers are looked up by name — re-including a role that's
///     already in `roles:` is a no-op for handlers)
///   - load `tasks/<tasks_from>(.yml|.yaml)`, flatten its imports
///     against the role's `tasks/` directory, tag the resulting tasks
///     with the role's directory
///   - push the include task's `when:` down onto each spliced task
///     (AND-merge with whatever `when:` the spliced task already had)
///   - if the include site carries `vars:`, prepend a synthetic
///     `set_fact:` to the spliced tasks so those vars are visible
///     to everything that follows
///
/// Recursive: if a tasks_from file itself contains `include_role:`,
/// it gets expanded too, up to `MAX_INCLUDE_ROLE_DEPTH`. Cycles are
/// caught via a (name, tasks_from) visited set per chain.
///
/// Runs *after* `flatten_playbook` (which handles play-level `roles:`)
/// and *before* `load_templates` / `load_copy_files` so the spliced
/// tasks get their src lookups resolved against the included role's
/// directory.
pub fn expand_include_roles(pb: &mut Playbook, base_dir: &Path) -> Result<()> {
    for play in &mut pb.plays {
        let mut visited: BTreeSet<(String, String)> = BTreeSet::new();
        let tasks = std::mem::take(&mut play.tasks);
        let expanded = expand_in_list(
            tasks,
            base_dir,
            &mut play.role_defaults,
            &mut play.handlers,
            &mut visited,
            0,
        )
        .with_context(|| format!("expanding include_role in play {:?}", play.name))?;
        play.tasks = expanded;
    }
    Ok(())
}

fn expand_in_list(
    tasks: Vec<Task>,
    base_dir: &Path,
    role_defaults: &mut std::collections::BTreeMap<String, JsonValue>,
    play_handlers: &mut Vec<Task>,
    visited: &mut BTreeSet<(String, String)>,
    depth: u32,
) -> Result<Vec<Task>> {
    if depth > MAX_INCLUDE_ROLE_DEPTH {
        bail!("include_role recursion depth exceeded {MAX_INCLUDE_ROLE_DEPTH}");
    }
    let mut out: Vec<Task> = Vec::with_capacity(tasks.len());
    for task in tasks {
        match &task.body {
            TaskBody::IncludeRole(ir) => {
                let spliced = expand_one(
                    &task,
                    ir,
                    base_dir,
                    role_defaults,
                    play_handlers,
                    visited,
                    depth,
                )?;
                out.extend(spliced);
            }
            _ => out.push(task),
        }
    }
    Ok(out)
}

fn expand_one(
    include_task: &Task,
    ir: &IncludeRoleSpec,
    base_dir: &Path,
    role_defaults: &mut std::collections::BTreeMap<String, JsonValue>,
    play_handlers: &mut Vec<Task>,
    visited: &mut BTreeSet<(String, String)>,
    depth: u32,
) -> Result<Vec<Task>> {
    let key = (ir.name.clone(), ir.tasks_from.clone());
    if !visited.insert(key.clone()) {
        bail!(
            "include_role cycle detected: {:?} (tasks_from={:?})",
            ir.name,
            ir.tasks_from
        );
    }

    let role_dir = resolve_role_dir(base_dir, &ir.name).with_context(|| {
        format!(
            "resolving include_role {:?} in task {:?}",
            ir.name, include_task.name
        )
    })?;

    // Merge role defaults (later-wins).
    if let Some(defaults) = load_defaults(&role_dir)? {
        for (k, v) in defaults {
            role_defaults.insert(k, v);
        }
    }

    // Append role handlers (handler names are unique within a play,
    // and our validator already rejects duplicates; skip handlers
    // whose names already appear so re-including is idempotent).
    if let Some(loaded) = load_task_file(&role_dir, "handlers")? {
        let existing: BTreeSet<String> =
            play_handlers.iter().map(|h| h.name.clone()).collect();
        let tagged = tag_with_role_dir(loaded, &role_dir);
        for h in tagged {
            if !existing.contains(&h.name) {
                play_handlers.push(h);
            }
        }
    }

    // Load tasks/<tasks_from>(.yml|.yaml). Required to exist.
    let tasks = load_tasks_from(&role_dir, &ir.tasks_from).with_context(|| {
        format!(
            "loading tasks_from {:?} for role {:?} (task {:?})",
            ir.tasks_from, ir.name, include_task.name
        )
    })?;
    let tagged = tag_with_role_dir(tasks, &role_dir);

    // Recurse: spliced tasks themselves may carry `include_role:`.
    let recursed = expand_in_list(
        tagged,
        base_dir,
        role_defaults,
        play_handlers,
        visited,
        depth + 1,
    )?;

    // Push include task's `when:` down onto every spliced task.
    let parent_when = include_task.when.clone();
    let mut spliced: Vec<Task> = recursed
        .into_iter()
        .map(|mut t| {
            t.when = combine_when(parent_when.as_deref(), t.when.as_deref());
            t
        })
        .collect();

    // Push include task's `tags:` down onto every spliced task. Matches
    // the role-invocation tag-inheritance path above.
    propagate_tags(&mut spliced, &include_task.tags);

    // Prepend synthetic set_fact for the include's vars (if any).
    if !ir.vars.is_empty() {
        let synthetic = Task {
            name: format!("set vars for include_role {:?}", ir.name),
            body: TaskBody::SetFact(SetFactMap(ir.vars.clone())),
            when: parent_when,
            register: None,
            loop_spec: None,
            loop_control: None,
            tags: Vec::new(),
            delegate_to: None,
            run_once: false,
            notify: Vec::new(),
            role_dir: Some(role_dir),
            // Synthetic set_fact runs controller-side; no privilege escalation.
            become_: Some(false),
            become_user: None,
            ignore_errors: None,
            check_mode: None,
            async_seconds: None,
            poll_seconds: None,
            retries: None,
            delay: None,
            until: None,
            changed_when: None,
            failed_when: None,
            no_log: None,
            vars: std::collections::BTreeMap::new(),
        };
        spliced.insert(0, synthetic);
    }

    visited.remove(&key);
    Ok(spliced)
}

/// AND-merge two `when:` expressions. Both being `None` → `None`;
/// either alone → that one; both → `(parent) and (child)` in Jinja
/// syntax so precedence is unambiguous regardless of operator mix.
fn combine_when(parent: Option<&str>, child: Option<&str>) -> Option<String> {
    match (parent, child) {
        (None, None) => None,
        (Some(p), None) => Some(p.to_string()),
        (None, Some(c)) => Some(c.to_string()),
        (Some(p), Some(c)) => Some(format!("({p}) and ({c})")),
    }
}

/// Resolve `tasks/<tasks_from>(.yml|.yaml)` under `role_dir` and return
/// the parsed + import-flattened task list. Errors if no extension
/// variant exists.
fn load_tasks_from(role_dir: &Path, tasks_from: &str) -> Result<Vec<Task>> {
    let dir = role_dir.join("tasks");
    // Strip a trailing extension if the user wrote one (Ansible accepts
    // both `tasks_from: setup` and `tasks_from: setup.yml`).
    let stem = match tasks_from
        .strip_suffix(".yml")
        .or_else(|| tasks_from.strip_suffix(".yaml"))
    {
        Some(s) => s,
        None => tasks_from,
    };
    if stem.is_empty() || stem.contains('/') || stem.contains('\\') {
        bail!(
            "include_role tasks_from {:?} must be a simple file stem (no slashes)",
            tasks_from
        );
    }
    let mut candidates = Vec::with_capacity(2);
    for ext in ["yml", "yaml"] {
        candidates.push(dir.join(format!("{stem}.{ext}")));
    }
    let path = candidates
        .iter()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            let listed = candidates
                .iter()
                .map(|p| format!("  {}", p.display()))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow!("tasks_from file not found; tried:\n{listed}")
        })?
        .clone();
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let tasks: Vec<Task> = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    let flattened = flatten_tasks(tasks, &dir, &mut visited, 0)
        .with_context(|| format!("flattening {}", path.display()))?;
    Ok(flattened)
}

/// Walk every task in the playbook; for each `TaskOp::Template`, locate
/// the `src:` file and load its contents into `body`. Resolution order:
///
/// 1. absolute `src` → use as-is
/// 2. `<task.role_dir>/templates/<src>` if role-sourced
/// 3. `<base_dir>/templates/<src>`
/// 4. `<base_dir>/<src>`
///
/// Run after `flatten_playbook` so the `role_dir` annotations are in
/// place. Missing files fail load with the search paths in the error
/// message.
pub fn load_templates(pb: &mut Playbook, base_dir: &Path) -> Result<()> {
    for play in &mut pb.plays {
        for task in play
            .tasks
            .iter_mut()
            .chain(play.handlers.iter_mut())
        {
            resolve_template_for_task(task, base_dir)?;
        }
    }
    Ok(())
}

fn resolve_template_for_task(task: &mut Task, base_dir: &Path) -> Result<()> {
    let TaskBody::Op(TaskOp::Template(t)) = &mut task.body else {
        return Ok(());
    };
    let candidates = file_search_paths(&t.src, task.role_dir.as_deref(), base_dir, "templates");
    for path in &candidates {
        if path.is_file() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading template {}", path.display()))?;
            let body = String::from_utf8(bytes).with_context(|| {
                format!("template {} contains non-UTF-8 bytes", path.display())
            })?;
            t.body = Some(body);
            return Ok(());
        }
    }
    let candidate_list = candidates
        .iter()
        .map(|p| format!("  {}", p.display()))
        .collect::<Vec<_>>()
        .join("\n");
    Err(anyhow!(
        "task {:?}: couldn't locate template src {:?}; tried:\n{candidate_list}",
        task.name,
        t.src
    ))
}

/// Walk every task; for each `TaskOp::Copy`, locate `src:` and load its
/// raw bytes into `body`. Resolution order mirrors `load_templates`,
/// but looks in `files/` rather than `templates/`. Bytes are shipped
/// verbatim — no UTF-8 requirement, no Jinja rendering.
pub fn load_copy_files(pb: &mut Playbook, base_dir: &Path) -> Result<()> {
    for play in &mut pb.plays {
        for task in play
            .tasks
            .iter_mut()
            .chain(play.handlers.iter_mut())
        {
            resolve_copy_for_task(task, base_dir)?;
        }
    }
    Ok(())
}

fn resolve_copy_for_task(task: &mut Task, base_dir: &Path) -> Result<()> {
    let TaskBody::Op(TaskOp::Copy(c)) = &mut task.body else {
        return Ok(());
    };
    let candidates = file_search_paths(&c.src, task.role_dir.as_deref(), base_dir, "files");
    for path in &candidates {
        if path.is_file() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading copy src {}", path.display()))?;
            c.body = Some(bytes);
            return Ok(());
        }
    }
    let candidate_list = candidates
        .iter()
        .map(|p| format!("  {}", p.display()))
        .collect::<Vec<_>>()
        .join("\n");
    Err(anyhow!(
        "task {:?}: couldn't locate copy src {:?}; tried:\n{candidate_list}",
        task.name,
        c.src
    ))
}

/// Build the candidate path list for a role-relative file lookup.
/// `subdir` is `"templates"` for `template:` or `"files"` for `copy:`.
fn file_search_paths(
    src: &str,
    role_dir: Option<&Path>,
    base_dir: &Path,
    subdir: &str,
) -> Vec<PathBuf> {
    let p = PathBuf::from(src);
    if p.is_absolute() {
        return vec![p];
    }
    let mut out = Vec::with_capacity(3);
    if let Some(rd) = role_dir {
        out.push(rd.join(subdir).join(&p));
    }
    out.push(base_dir.join(subdir).join(&p));
    out.push(base_dir.join(&p));
    out
}

fn tag_with_role_dir(mut tasks: Vec<Task>, role_dir: &Path) -> Vec<Task> {
    for t in &mut tasks {
        // Don't clobber a deeper-nested `role_dir` if one is already
        // set (defensive — only the outermost role should annotate).
        if t.role_dir.is_none() {
            t.role_dir = Some(role_dir.to_path_buf());
        }
    }
    tasks
}

/// Union `extra` into every task's `tags` list, sorted and deduped.
/// Used by the role-flatten and `include_role:` paths to propagate
/// the invocation site's tags down onto each materialized task.
fn propagate_tags(tasks: &mut [Task], extra: &[String]) {
    if extra.is_empty() {
        return;
    }
    for t in tasks {
        t.tags.extend(extra.iter().cloned());
        t.tags.sort();
        t.tags.dedup();
    }
}

fn resolve_role_dir(base_dir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() {
        bail!("empty role name");
    }
    // Reject path-y names — `../escape`, `foo/bar` — early. Roles are a
    // flat namespace; anything else is a typo.
    if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        bail!("role name {name:?} must be a simple identifier (no slashes)");
    }
    // Two candidate layouts, checked in order:
    //
    //   1. `<base_dir>/roles/<name>/` — playbook at the project root,
    //      roles alongside it. This is what `ansible-galaxy init` lays
    //      down by default and what our own examples use.
    //
    //   2. `<base_dir>/../roles/<name>/` — playbook in a `playbooks/`
    //      subdirectory, roles as a sibling of that subdirectory. This
    //      is gothab's layout, and matches Ansible's default
    //      `roles_path` resolution when `ansible-playbook` is run from
    //      the project root (where `ansible.cfg` lives) with the
    //      playbook nested one level down.
    //
    // We don't read `ansible.cfg` — its `roles_path` is a colon-
    // separated list and the resolution rules drag in env vars
    // (`ANSIBLE_ROLES_PATH`), the inventory directory, and several
    // other sources. The two layouts above cover every real-world
    // case we've seen; if a project needs something exotic, that's
    // when we add a `--roles-path` CLI flag.
    let candidates = [
        base_dir.join("roles").join(name),
        base_dir.join("..").join("roles").join(name),
    ];
    for dir in &candidates {
        if dir.is_dir() {
            return Ok(dir.clone());
        }
    }
    bail!(
        "role {name:?} not found: searched {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
}

/// Load `<role_dir>/defaults/main.yml` if present. Returns `None` if
/// the file is absent, `Some(empty_map)` for an empty file.
fn load_defaults(role_dir: &Path) -> Result<Option<std::collections::BTreeMap<String, JsonValue>>> {
    let path = role_dir.join("defaults").join("main.yml");
    if !path.is_file() {
        // Also accept .yaml for ergonomics; Ansible accepts both.
        let alt = role_dir.join("defaults").join("main.yaml");
        if !alt.is_file() {
            return Ok(None);
        }
        return load_defaults_at(&alt);
    }
    load_defaults_at(&path)
}

fn load_defaults_at(
    path: &Path,
) -> Result<Option<std::collections::BTreeMap<String, JsonValue>>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(Some(std::collections::BTreeMap::new()));
    }
    let raw: std::collections::BTreeMap<String, serde_yaml::Value> =
        serde_yaml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in raw {
        let json = yaml_to_json(v)
            .with_context(|| format!("{}: key {k}", path.display()))?;
        out.insert(k, json);
    }
    Ok(Some(out))
}

/// Load `<role_dir>/<subdir>/main.yml` as a Task list and flatten any
/// `import_tasks:` against `<role_dir>/<subdir>/`. `subdir` is one of
/// `"tasks"` / `"handlers"`. Returns `None` if no main.yml is present.
fn load_task_file(role_dir: &Path, subdir: &str) -> Result<Option<Vec<Task>>> {
    let dir = role_dir.join(subdir);
    let main = match find_main(&dir)? {
        Some(p) => p,
        None => return Ok(None),
    };
    let text = std::fs::read_to_string(&main)
        .with_context(|| format!("reading {}", main.display()))?;
    let tasks: Vec<Task> = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {}", main.display()))?;
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    let flattened = flatten_tasks(tasks, &dir, &mut visited, 0)
        .with_context(|| format!("flattening {}", main.display()))?;
    Ok(Some(flattened))
}

fn find_main(dir: &Path) -> Result<Option<PathBuf>> {
    if !dir.is_dir() {
        return Ok(None);
    }
    for ext in ["yml", "yaml"] {
        let p = dir.join(format!("main.{ext}"));
        if p.is_file() {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    /// Build a tiny role tree on disk and return the playbook-directory path.
    fn make_role_tree(name: &str, defaults: &str, tasks: &str, handlers: &str) -> TempDir {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles").join(name);
        write(&role.join("defaults/main.yml"), defaults);
        write(&role.join("tasks/main.yml"), tasks);
        write(&role.join("handlers/main.yml"), handlers);
        dir
    }

    #[test]
    fn role_flatten_prepends_tasks_and_merges_defaults() {
        let dir = make_role_tree(
            "web",
            r#"
service_name: demo
port: 80
"#,
            r#"
- name: r1
  shell: "echo r1"
- name: r2
  shell: "echo r2"
"#,
            r#"
- name: bumped
  shell: "echo handler"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles:
    - web
  tasks:
    - name: own
      shell: "echo own"
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        let names: Vec<_> = pb.plays[0].tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["r1", "r2", "own"], "role tasks come first");
        let hnames: Vec<_> = pb.plays[0]
            .handlers
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(hnames, vec!["bumped"]);
        assert_eq!(
            pb.plays[0].role_defaults.get("service_name").and_then(JsonValue::as_str),
            Some("demo")
        );
        assert_eq!(
            pb.plays[0].role_defaults.get("port").and_then(JsonValue::as_u64),
            Some(80)
        );
        // Each role task should be tagged with the role dir.
        for t in &pb.plays[0].tasks[..2] {
            assert!(t.role_dir.is_some(), "{:?} missing role_dir", t.name);
        }
        assert!(pb.plays[0].tasks[2].role_dir.is_none(), "play-direct task shouldn't carry role_dir");
    }

    #[test]
    fn missing_role_dir_fails_load() {
        let dir = TempDir::new().unwrap();
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles:
    - nope
  tasks:
    - name: own
      shell: echo
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let err = playbook::load(&pb_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nope"), "got: {msg}");
    }

    #[test]
    fn role_task_imports_resolve_against_role_tasks_dir() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(&role.join("defaults/main.yml"), "a: 1");
        write(
            &role.join("tasks/main.yml"),
            r#"
- name: include install
  import_tasks: install.yml
- name: post
  shell: "echo post"
"#,
        );
        write(
            &role.join("tasks/install.yml"),
            r#"
- name: install
  shell: "echo install"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [svc]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        let names: Vec<_> = pb.plays[0].tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["install", "post"]);
    }

    #[test]
    fn template_src_resolved_from_role_templates_dir() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/web");
        write(
            &role.join("defaults/main.yml"),
            "service_name: rsansible-demo",
        );
        write(
            &role.join("tasks/main.yml"),
            r#"
- name: render
  template:
    src: web.conf.j2
    dest: /tmp/web.conf
"#,
        );
        write(
            &role.join("templates/web.conf.j2"),
            "service={{ service_name }}\n",
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [web]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        match &pb.plays[0].tasks[0].body {
            TaskBody::Op(TaskOp::Template(t)) => {
                assert_eq!(
                    t.body.as_deref(),
                    Some("service={{ service_name }}\n"),
                );
            }
            other => panic!("expected template body, got {other:?}"),
        }
    }

    #[test]
    fn missing_template_src_fails_load() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/web");
        write(&role.join("defaults/main.yml"), "x: 1");
        write(
            &role.join("tasks/main.yml"),
            r#"
- name: render
  template:
    src: missing.j2
    dest: /tmp/x
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [web]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let err = playbook::load(&pb_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing.j2"), "got: {msg}");
        assert!(msg.contains("templates/missing.j2"), "search paths should be in error: {msg}");
    }

    #[test]
    fn defaults_last_role_wins() {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join("roles/a/defaults/main.yml"), "v: from_a\n");
        write(&dir.path().join("roles/b/defaults/main.yml"), "v: from_b\n");
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [a, b]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        assert_eq!(
            pb.plays[0].role_defaults.get("v").and_then(JsonValue::as_str),
            Some("from_b")
        );
    }

    #[test]
    fn role_full_form_parses() {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join("roles/web/defaults/main.yml"), "x: 1\n");
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles:
    - role: web
      tags: [setup]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        assert_eq!(
            pb.plays[0].role_defaults.get("x").and_then(JsonValue::as_u64),
            Some(1)
        );
    }

    #[test]
    fn role_invocation_tags_propagate_onto_role_tasks() {
        let dir = make_role_tree(
            "web",
            "x: 1",
            r#"
- name: r1
  shell: "echo r1"
- name: r2
  tags: [existing]
  shell: "echo r2"
"#,
            r#"
- name: h
  shell: "echo h"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles:
    - role: web
      tags: [setup, common]
  tasks:
    - name: play_own
      shell: "echo own"
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();

        // Role tasks pick up the invocation tags.
        assert_eq!(pb.plays[0].tasks[0].name, "r1");
        assert_eq!(pb.plays[0].tasks[0].tags, vec!["common", "setup"]);

        // A task that already had tags merges with the role tags (deduped + sorted).
        assert_eq!(pb.plays[0].tasks[1].name, "r2");
        assert_eq!(pb.plays[0].tasks[1].tags, vec!["common", "existing", "setup"]);

        // Play-direct task is untouched.
        assert_eq!(pb.plays[0].tasks[2].name, "play_own");
        assert!(pb.plays[0].tasks[2].tags.is_empty());

        // Role handlers also pick up the tags (no filtering for now, but
        // the data structure stays consistent).
        assert_eq!(pb.plays[0].handlers[0].name, "h");
        assert_eq!(pb.plays[0].handlers[0].tags, vec!["common", "setup"]);
    }

    #[test]
    fn bare_role_invocation_does_not_inject_tags() {
        let dir = make_role_tree(
            "web",
            "x: 1",
            r#"
- name: r1
  tags: [keep]
  shell: "echo r1"
"#,
            "",
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles:
    - web
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        assert_eq!(pb.plays[0].tasks[0].tags, vec!["keep"]);
    }

    #[test]
    fn include_role_tags_propagate_onto_spliced_tasks() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(
            &role.join("tasks/apply.yml"),
            r#"
- name: bare
  shell: "echo bare"
- name: own
  tags: [existing]
  shell: "echo own"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: include
      tags: [outer]
      include_role:
        name: svc
        tasks_from: apply
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        assert_eq!(pb.plays[0].tasks[0].name, "bare");
        assert_eq!(pb.plays[0].tasks[0].tags, vec!["outer"]);
        assert_eq!(pb.plays[0].tasks[1].name, "own");
        assert_eq!(pb.plays[0].tasks[1].tags, vec!["existing", "outer"]);
    }

    #[test]
    fn role_spec_accepts_bare_string_tag() {
        // `tags: setup` (no list).
        let dir = make_role_tree(
            "web",
            "x: 1",
            r#"
- name: r1
  shell: "echo r1"
"#,
            "",
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles:
    - role: web
      tags: setup
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        assert_eq!(pb.plays[0].tasks[0].tags, vec!["setup"]);
    }

    #[test]
    fn play_with_no_tasks_but_roles_is_accepted_at_parse() {
        // Just exercise the schema — full validation happens elsewhere.
        let pb: crate::playbook::Playbook = serde_yaml::from_str(
            r#"
- name: p
  roles:
    - web
"#,
        )
        .unwrap();
        assert_eq!(pb.plays[0].roles.len(), 1);
        assert!(pb.plays[0].tasks.is_empty());
        // unused
        let _ = BTreeMap::<String, JsonValue>::new();
    }

    #[test]
    fn copy_src_resolved_from_role_files_dir() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/web");
        // Need at least one of tasks/handlers/defaults to satisfy the
        // "empty role" check, so the tasks/main.yml below is mandatory.
        write(
            &role.join("tasks/main.yml"),
            r#"
- name: stage asset
  copy:
    src: asset.txt
    dest: /etc/asset
    mode: 0o644
"#,
        );
        write(&role.join("files/asset.txt"), "static content\n");
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [web]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        match &pb.plays[0].tasks[0].body {
            TaskBody::Op(TaskOp::Copy(c)) => {
                assert_eq!(c.body.as_deref(), Some(b"static content\n".as_ref()));
            }
            other => panic!("expected copy body, got {other:?}"),
        }
    }

    #[test]
    fn copy_src_supports_binary_bytes() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/web");
        write(
            &role.join("tasks/main.yml"),
            r#"
- name: blob
  copy:
    src: blob.bin
    dest: /etc/blob
"#,
        );
        // Non-UTF-8 bytes — template: would reject these, copy: should
        // load them verbatim.
        std::fs::create_dir_all(role.join("files")).unwrap();
        std::fs::write(role.join("files/blob.bin"), [0xffu8, 0x00, 0xfe, 0x7f]).unwrap();
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [web]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        match &pb.plays[0].tasks[0].body {
            TaskBody::Op(TaskOp::Copy(c)) => {
                assert_eq!(c.body.as_deref(), Some([0xffu8, 0x00, 0xfe, 0x7f].as_ref()));
            }
            other => panic!("expected copy body, got {other:?}"),
        }
    }

    #[test]
    fn include_role_loads_tasks_from_alternate_file() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(
            &role.join("tasks/main.yml"),
            r#"
- name: main_task
  shell: "echo main"
"#,
        );
        write(
            &role.join("tasks/configure.yml"),
            r#"
- name: configured
  shell: "echo configured"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: pull in svc.configure
      include_role:
        name: svc
        tasks_from: configure
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        let names: Vec<_> = pb.plays[0].tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["configured"]);
        // Spliced task must carry role_dir so template:/copy: resolution
        // knows which role's templates/files to consult.
        assert!(pb.plays[0].tasks[0].role_dir.is_some());
    }

    #[test]
    fn include_role_accepts_explicit_extension() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(
            &role.join("tasks/setup.yml"),
            r#"
- name: setup_task
  shell: "echo setup"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: pull
      include_role:
        name: svc
        tasks_from: setup.yml
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        let names: Vec<_> = pb.plays[0].tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["setup_task"]);
    }

    #[test]
    fn include_role_vars_become_synthetic_set_fact() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(
            &role.join("tasks/apply.yml"),
            r#"
- name: render
  shell: "echo {{ override_val }}"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: include with vars
      include_role:
        name: svc
        tasks_from: apply
      vars:
        override_val: "hello"
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        // First task should be the synthetic set_fact, then the spliced
        // shell task.
        assert_eq!(pb.plays[0].tasks.len(), 2);
        match &pb.plays[0].tasks[0].body {
            TaskBody::SetFact(SetFactMap(m)) => {
                assert_eq!(
                    m.get("override_val").and_then(|v| v.as_str()),
                    Some("hello")
                );
            }
            other => panic!("expected synthetic set_fact, got {other:?}"),
        }
        assert_eq!(pb.plays[0].tasks[1].name, "render");
    }

    #[test]
    fn include_role_merges_defaults() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(&role.join("defaults/main.yml"), "svc_port: 8080\n");
        write(
            &role.join("tasks/apply.yml"),
            r#"
- name: t
  shell: "echo {{ svc_port }}"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: pull
      include_role:
        name: svc
        tasks_from: apply
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        assert_eq!(
            pb.plays[0].role_defaults.get("svc_port").and_then(JsonValue::as_u64),
            Some(8080)
        );
    }

    #[test]
    fn include_role_when_pushes_down_onto_spliced_tasks() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(
            &role.join("tasks/apply.yml"),
            r#"
- name: bare
  shell: "echo bare"
- name: with_when
  when: "inner == 1"
  shell: "echo inner"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: gated include
      when: "outer == 2"
      include_role:
        name: svc
        tasks_from: apply
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        // Parent when only on bare task.
        assert_eq!(pb.plays[0].tasks[0].when.as_deref(), Some("outer == 2"));
        // AND-merged on with_when.
        assert_eq!(
            pb.plays[0].tasks[1].when.as_deref(),
            Some("(outer == 2) and (inner == 1)")
        );
    }

    #[test]
    fn include_role_handlers_are_appended() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(
            &role.join("tasks/apply.yml"),
            r#"
- name: t
  notify: bumped
  shell: "echo t"
"#,
        );
        write(
            &role.join("handlers/main.yml"),
            r#"
- name: bumped
  shell: "echo handler"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: pull
      include_role:
        name: svc
        tasks_from: apply
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        let hnames: Vec<_> = pb.plays[0]
            .handlers
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(hnames, vec!["bumped"]);
    }

    #[test]
    fn include_role_handlers_dedup_with_existing() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(
            &role.join("tasks/apply.yml"),
            r#"
- name: t
  notify: bumped
  shell: "echo t"
"#,
        );
        write(
            &role.join("handlers/main.yml"),
            r#"
- name: bumped
  shell: "echo from role"
"#,
        );
        // Re-include the role both via `roles:` AND `include_role:`.
        // The handler set must remain de-duplicated by name.
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [svc]
  tasks:
    - name: pull
      include_role:
        name: svc
        tasks_from: apply
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        let hnames: Vec<_> = pb.plays[0]
            .handlers
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(hnames, vec!["bumped"]);
    }

    #[test]
    fn include_role_recursive_expansion_supported() {
        let dir = TempDir::new().unwrap();
        // Role A's apply.yml includes role B's setup.yml.
        write(
            &dir.path().join("roles/a/tasks/apply.yml"),
            r#"
- name: pull b
  include_role:
    name: b
    tasks_from: setup
- name: a_final
  shell: "echo a_final"
"#,
        );
        write(
            &dir.path().join("roles/b/tasks/setup.yml"),
            r#"
- name: b_inner
  shell: "echo b_inner"
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: kick
      include_role:
        name: a
        tasks_from: apply
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        let names: Vec<_> = pb.plays[0].tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["b_inner", "a_final"]);
    }

    #[test]
    fn include_role_cycle_is_rejected() {
        let dir = TempDir::new().unwrap();
        write(
            &dir.path().join("roles/a/tasks/main.yml"),
            r#"
- name: kick_b
  include_role:
    name: b
"#,
        );
        write(
            &dir.path().join("roles/b/tasks/main.yml"),
            r#"
- name: kick_a
  include_role:
    name: a
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: kick
      include_role:
        name: a
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let err = playbook::load(&pb_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cycle"), "got: {msg}");
    }

    #[test]
    fn include_role_missing_tasks_from_errors() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/svc");
        write(&role.join("tasks/main.yml"), "[]");
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: pull
      include_role:
        name: svc
        tasks_from: nope
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let err = playbook::load(&pb_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("nope") && msg.contains("tasks_from"),
            "got: {msg}"
        );
    }

    #[test]
    fn include_role_missing_role_dir_errors() {
        let dir = TempDir::new().unwrap();
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: pull
      include_role:
        name: nope
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let err = playbook::load(&pb_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nope"), "got: {msg}");
    }

    #[test]
    fn include_role_resolves_template_against_role_dir() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/web");
        write(
            &role.join("tasks/apply.yml"),
            r#"
- name: render
  template:
    src: cfg.j2
    dest: /etc/cfg
"#,
        );
        write(&role.join("templates/cfg.j2"), "value={{ x }}\n");
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  tasks:
    - name: pull
      include_role:
        name: web
        tasks_from: apply
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let pb = playbook::load(&pb_path).unwrap();
        match &pb.plays[0].tasks[0].body {
            TaskBody::Op(TaskOp::Template(t)) => {
                assert_eq!(t.body.as_deref(), Some("value={{ x }}\n"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn missing_copy_src_fails_load() {
        let dir = TempDir::new().unwrap();
        let role = dir.path().join("roles/web");
        write(&role.join("defaults/main.yml"), "x: 1");
        write(
            &role.join("tasks/main.yml"),
            r#"
- name: blob
  copy:
    src: missing.bin
    dest: /etc/blob
"#,
        );
        let pb_text = r#"
- name: p
  hosts: all
  gather_facts: false
  roles: [web]
"#;
        let pb_path = dir.path().join("playbook.yml");
        write(&pb_path, pb_text);
        let err = playbook::load(&pb_path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing.bin"), "got: {msg}");
        assert!(msg.contains("files/missing.bin"), "search paths should be in error: {msg}");
    }
}
