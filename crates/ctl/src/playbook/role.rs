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
use crate::playbook::{Playbook, Task, TaskBody, TaskOp};

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
                let tagged = tag_with_role_dir(loaded, &role_dir);
                role_tasks.extend(tagged);
            }

            // handlers/main.yml
            if let Some(loaded) = load_task_file(&role_dir, "handlers")? {
                had_content = true;
                let tagged = tag_with_role_dir(loaded, &role_dir);
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

fn resolve_role_dir(base_dir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() {
        bail!("empty role name");
    }
    // Reject path-y names — `../escape`, `foo/bar` — early. Roles are a
    // flat namespace; anything else is a typo.
    if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        bail!("role name {name:?} must be a simple identifier (no slashes)");
    }
    let dir = base_dir.join("roles").join(name);
    if !dir.is_dir() {
        bail!(
            "role {name:?} not found: expected {} to exist",
            dir.display()
        );
    }
    Ok(dir)
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
