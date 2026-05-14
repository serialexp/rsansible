//! `import_tasks:` flattener.
//!
//! Walks every play's task list; whenever a `TaskBody::ImportTasks(path)`
//! is encountered, reads the referenced YAML (a bare list of tasks) and
//! splices it into the parent list. Imports may themselves import; we
//! cap recursion depth and refuse cycles.
//!
//! After `flatten_playbook` returns, no `TaskBody::ImportTasks` should
//! remain anywhere in the playbook.

use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::playbook::{Playbook, Task, TaskBody};

const MAX_DEPTH: u32 = 16;

/// Flatten in place. `base_dir` is the directory imports resolve relative
/// to (typically the playbook file's parent).
pub fn flatten_playbook(pb: &mut Playbook, base_dir: &Path) -> Result<()> {
    for play in &mut pb.plays {
        let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
        play.tasks = flatten_tasks(std::mem::take(&mut play.tasks), base_dir, &mut visited, 0)
            .with_context(|| format!("flattening tasks in play {:?}", play.name))?;
        // Handlers can also be imported. Use a fresh visited-set so a file
        // imported by `tasks:` is still importable by `handlers:` (and vice
        // versa); cycles within handlers themselves remain caught.
        let mut visited_h: BTreeSet<PathBuf> = BTreeSet::new();
        play.handlers =
            flatten_tasks(std::mem::take(&mut play.handlers), base_dir, &mut visited_h, 0)
                .with_context(|| format!("flattening handlers in play {:?}", play.name))?;
    }
    Ok(())
}

fn flatten_tasks(
    tasks: Vec<Task>,
    base_dir: &Path,
    visited: &mut BTreeSet<PathBuf>,
    depth: u32,
) -> Result<Vec<Task>> {
    if depth > MAX_DEPTH {
        bail!("import_tasks recursion depth exceeded {MAX_DEPTH}");
    }
    let mut out = Vec::with_capacity(tasks.len());
    for task in tasks {
        match task.body {
            TaskBody::ImportTasks(ref relative) => {
                let resolved = canonicalize(base_dir, relative).with_context(|| {
                    format!(
                        "resolving import_tasks {:?} (in task {:?})",
                        relative.display(),
                        task.name
                    )
                })?;
                if !visited.insert(resolved.clone()) {
                    bail!(
                        "import cycle detected: {:?} (in task {:?})",
                        resolved.display(),
                        task.name
                    );
                }
                let text = std::fs::read_to_string(&resolved)
                    .with_context(|| format!("reading {}", resolved.display()))?;
                let inner: Vec<Task> = serde_yaml::from_str(&text)
                    .with_context(|| format!("parsing {}", resolved.display()))?;
                let inner_base = resolved
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| base_dir.to_path_buf());
                let flattened = flatten_tasks(inner, &inner_base, visited, depth + 1)?;
                // Imports don't share their visited-set with sibling
                // imports — a file imported twice from different parents
                // is fine, only a *cycle* (re-entering an ancestor) is
                // forbidden. Remove the entry so siblings can re-import.
                visited.remove(&resolved);
                out.extend(flattened);
            }
            _ => out.push(task),
        }
    }
    Ok(out)
}

fn canonicalize(base: &Path, rel: &Path) -> Result<PathBuf> {
    let joined = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        base.join(rel)
    };
    joined
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", joined.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn flattens_single_import() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "common.yml",
            r#"
- name: shared
  shell: "echo shared"
"#,
        );
        let pb_text = r#"
- name: p
  tasks:
    - name: hello
      shell: "echo before"
    - name: bring in shared
      import_tasks: common.yml
    - name: bye
      shell: "echo after"
"#;
        let mut pb: Playbook = serde_yaml::from_str(pb_text).unwrap();
        flatten_playbook(&mut pb, dir.path()).unwrap();
        let names: Vec<_> = pb.plays[0].tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["hello", "shared", "bye"]);
        for t in &pb.plays[0].tasks {
            assert!(!matches!(t.body, TaskBody::ImportTasks(_)));
        }
    }

    #[test]
    fn nested_imports_are_flattened() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "level2.yml",
            r#"
- name: deepest
  shell: "echo deep"
"#,
        );
        write(
            dir.path(),
            "level1.yml",
            r#"
- name: middle
  shell: "echo mid"
- name: go deeper
  import_tasks: level2.yml
"#,
        );
        let pb_text = r#"
- name: p
  tasks:
    - name: kick off
      import_tasks: level1.yml
"#;
        let mut pb: Playbook = serde_yaml::from_str(pb_text).unwrap();
        flatten_playbook(&mut pb, dir.path()).unwrap();
        let names: Vec<_> = pb.plays[0].tasks.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["middle", "deepest"]);
    }

    #[test]
    fn cycle_is_rejected() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "a.yml",
            r#"
- name: b
  import_tasks: b.yml
"#,
        );
        write(
            dir.path(),
            "b.yml",
            r#"
- name: a
  import_tasks: a.yml
"#,
        );
        let pb_text = r#"
- name: p
  tasks:
    - name: kick
      import_tasks: a.yml
"#;
        let mut pb: Playbook = serde_yaml::from_str(pb_text).unwrap();
        let err = flatten_playbook(&mut pb, dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cycle"), "got: {msg}");
    }

    #[test]
    fn missing_import_file_errors() {
        let dir = TempDir::new().unwrap();
        let pb_text = r#"
- name: p
  tasks:
    - name: kick
      import_tasks: nope.yml
"#;
        let mut pb: Playbook = serde_yaml::from_str(pb_text).unwrap();
        let err = flatten_playbook(&mut pb, dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nope.yml"), "got: {msg}");
    }
}
