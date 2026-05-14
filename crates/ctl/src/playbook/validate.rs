//! Semantic validation that runs after serde-level parsing succeeds.
//!
//! Catches things serde can't:
//!   - empty plays (no tasks)
//!   - playbook `hosts:` lists referencing inventory names that don't exist
//!   - empty exec argv / shell command / write_file path
//!   - register / set_fact / loop_var names that aren't valid identifiers
//!
//! Template precompilation (`crate::template::precompile_all`) runs as a
//! separate pass driven from main.rs.

use crate::inventory::Inventory;
use crate::playbook::{HostSelector, Play, Playbook, SetFactMap, Task, TaskBody, TaskOp};
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeSet;

pub fn validate(pb: &Playbook, inventory: Option<&Inventory>) -> Result<()> {
    if pb.plays.is_empty() {
        bail!("playbook has no plays");
    }
    for (i, play) in pb.plays.iter().enumerate() {
        validate_play(play, i, inventory)?;
    }
    Ok(())
}

fn validate_play(play: &Play, idx: usize, inv: Option<&Inventory>) -> Result<()> {
    let where_ = || format!("play[{idx}] {:?}", play.name);
    // After the role-flatten pass any `roles:` content has been moved into
    // `play.tasks`/`play.handlers`. So at validate time the test is just:
    // there must be at least one task body to run.
    if play.tasks.is_empty() {
        bail!("{}: no tasks (and no roles contributing tasks)", where_());
    }
    let names_to_check: Vec<&str> = match &play.hosts {
        HostSelector::All(_) => Vec::new(),
        HostSelector::Names(names) => {
            if names.is_empty() {
                bail!("{}: empty hosts list", where_());
            }
            names.iter().map(String::as_str).collect()
        }
        HostSelector::Name(n) => vec![n.as_str()],
    };
    if let Some(inv) = inv {
        for n in &names_to_check {
            // A `hosts:` entry resolves to either a known host name or
            // a known group name. Group wins if both exist (Ansible's
            // behavior). Anything else is a typo and fails validation.
            if !inv.hosts.contains_key(*n) && !inv.groups.contains_key(*n) {
                return Err(anyhow!(
                    "{}: {:?} is not a known host or group in the inventory",
                    where_(),
                    n
                ));
            }
        }
    }
    // Build the handler-name set first so task notify references can be
    // statically checked when they don't contain Jinja.
    let mut handler_names: BTreeSet<String> = BTreeSet::new();
    for (hi, h) in play.handlers.iter().enumerate() {
        if h.name.is_empty() {
            bail!("{}: handler[{hi}] has empty name", where_());
        }
        if !handler_names.insert(h.name.clone()) {
            bail!(
                "{}: handler[{hi}] {:?}: duplicate handler name (handlers are looked up by name)",
                where_(),
                h.name
            );
        }
        validate_handler(h, &where_(), hi)?;
    }
    for (ti, task) in play.tasks.iter().enumerate() {
        if task.name.is_empty() {
            bail!("{}: task[{ti}] has empty name", where_());
        }
        validate_task(task, &where_(), ti)?;
        // Notify references: literal (no `{{`) names must match a handler.
        for n in &task.notify {
            if !n.contains("{{") && !handler_names.contains(n) {
                bail!(
                    "{}: task[{ti}] {:?}: notify {:?} doesn't match any handler in this play",
                    where_(),
                    task.name,
                    n
                );
            }
        }
    }
    Ok(())
}

fn validate_handler(h: &Task, where_: &str, hi: usize) -> Result<()> {
    if !h.notify.is_empty() {
        bail!(
            "{}: handler[{hi}] {:?}: handlers cannot notify other handlers (listen-chains not supported yet)",
            where_,
            h.name
        );
    }
    if matches!(h.body, TaskBody::ImportTasks(_)) {
        bail!(
            "{}: handler[{hi}] {:?}: import_tasks was not flattened; \
             call playbook::load() to resolve imports before validating",
            where_,
            h.name
        );
    }
    if matches!(h.body, TaskBody::IncludeRole(_)) {
        bail!(
            "{}: handler[{hi}] {:?}: include_role is not supported in handlers",
            where_,
            h.name
        );
    }
    // Reuse the task-shape checks (identifiers, op shape, etc).
    validate_task(h, where_, hi)
}

fn validate_task(task: &Task, where_: &str, ti: usize) -> Result<()> {
    if let Some(name) = &task.register {
        if !is_valid_identifier(name) {
            bail!(
                "{}: task[{ti}] {:?}: register name {:?} is not a valid identifier",
                where_,
                task.name,
                name
            );
        }
    }
    if let Some(lc) = &task.loop_control {
        if let Some(var) = &lc.loop_var {
            if !is_valid_identifier(var) {
                bail!(
                    "{}: task[{ti}] {:?}: loop_control.loop_var {:?} is not a valid identifier",
                    where_,
                    task.name,
                    var
                );
            }
        }
    }
    match &task.body {
        TaskBody::Op(op) => validate_op(op, task, where_, ti)?,
        TaskBody::SetFact(SetFactMap(m)) => {
            for k in m.keys() {
                if !is_valid_identifier(k) {
                    bail!(
                        "{}: task[{ti}] {:?}: set_fact key {:?} is not a valid identifier",
                        where_,
                        task.name,
                        k
                    );
                }
            }
        }
        TaskBody::Assert(a) => {
            if a.that.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: assert.that is empty",
                    where_,
                    task.name
                );
            }
        }
        TaskBody::Fail(_) => {}
        TaskBody::ImportTasks(p) => {
            // After load(), this shouldn't appear. Treat it as an error so a
            // caller that bypasses load() (parse + validate manually) sees a
            // clear message rather than running into "internal" in the
            // orchestrator.
            bail!(
                "{}: task[{ti}] {:?}: import_tasks({}) was not flattened; \
                 call playbook::load() to resolve imports before validating",
                where_,
                task.name,
                p.display()
            );
        }
        TaskBody::IncludeRole(ir) => {
            // After load(), this shouldn't appear either — the
            // role::expand_include_roles pass replaces it with the spliced
            // tasks. If it survives, the caller bypassed load().
            bail!(
                "{}: task[{ti}] {:?}: include_role({:?}, tasks_from={:?}) was not expanded; \
                 call playbook::load() before validating",
                where_,
                task.name,
                ir.name,
                ir.tasks_from
            );
        }
        TaskBody::Meta(_) => {
            // `meta: flush_handlers` is a bare control-flow marker. Reject
            // metadata that wouldn't make sense on it.
            if task.register.is_some() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `register:`",
                    where_,
                    task.name
                );
            }
            if !task.notify.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `notify:`",
                    where_,
                    task.name
                );
            }
            if task.loop_spec.is_some() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `loop:`",
                    where_,
                    task.name
                );
            }
            if task.delegate_to.is_some() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `delegate_to:`",
                    where_,
                    task.name
                );
            }
            if task.run_once {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `run_once:`",
                    where_,
                    task.name
                );
            }
        }
    }
    Ok(())
}

fn validate_op(op: &TaskOp, task: &Task, where_: &str, ti: usize) -> Result<()> {
    match op {
        TaskOp::Exec(e) if e.argv.is_empty() => {
            bail!("{}: task[{ti}] {:?}: exec.argv is empty", where_, task.name)
        }
        TaskOp::WriteFile(w) if w.path.is_empty() => {
            bail!(
                "{}: task[{ti}] {:?}: write_file.path is empty",
                where_,
                task.name
            )
        }
        TaskOp::Shell(s) if s.command().is_empty() => {
            bail!(
                "{}: task[{ti}] {:?}: shell command is empty",
                where_,
                task.name
            )
        }
        TaskOp::Template(t) => {
            if t.src.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: template.src is empty",
                    where_,
                    task.name
                );
            }
            if t.dest.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: template.dest is empty",
                    where_,
                    task.name
                );
            }
            // The body should have been populated by the role-flatten /
            // template-resolution pass run in `playbook::load`. A `None`
            // here means the caller bypassed load() or the file is missing.
            if t.body.is_none() {
                bail!(
                    "{}: task[{ti}] {:?}: template src {:?} was not resolved at load time; \
                     call playbook::load() or ensure the file exists",
                    where_,
                    task.name,
                    t.src
                );
            }
            Ok(())
        }
        TaskOp::Copy(c) => {
            if c.src.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: copy.src is empty",
                    where_,
                    task.name
                );
            }
            if c.dest.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: copy.dest is empty",
                    where_,
                    task.name
                );
            }
            if c.body.is_none() {
                bail!(
                    "{}: task[{ti}] {:?}: copy src {:?} was not resolved at load time; \
                     call playbook::load() or ensure the file exists",
                    where_,
                    task.name,
                    c.src
                );
            }
            Ok(())
        }
        TaskOp::GatherFacts => {
            // Implicit op — only the orchestrator constructs it. If we see
            // one here it means user YAML somehow produced one, which
            // shouldn't happen (no body-key surfaces it).
            bail!(
                "{}: task[{ti}] {:?}: gather_facts isn't a user-callable task body",
                where_,
                task.name
            )
        }
        _ => Ok(()),
    }
}

/// Python-ish identifier: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_rules() {
        assert!(is_valid_identifier("ok"));
        assert!(is_valid_identifier("_x"));
        assert!(is_valid_identifier("a1"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("1x"));
        assert!(!is_valid_identifier("with space"));
        assert!(!is_valid_identifier("dot.name"));
    }

    #[test]
    fn rejects_invalid_register_name() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      register: "bad name"
      shell: echo
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("register"), "got: {msg}");
    }

    #[test]
    fn rejects_invalid_set_fact_key() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      set_fact:
        "bad-key": 1
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("set_fact"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_handler_in_notify() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      notify: nope
      shell: echo
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("notify") && msg.contains("nope"), "got: {msg}");
    }

    #[test]
    fn accepts_templated_notify_without_handler_match() {
        // `{{ ... }}` notify names are resolved at runtime; can't statically
        // verify, so the validator lets them through.
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      notify: "{{ which_handler }}"
      shell: echo
"#,
        )
        .unwrap();
        validate(&pb, None).unwrap();
    }

    #[test]
    fn rejects_duplicate_handler_names() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      shell: echo
  handlers:
    - name: dup
      shell: echo a
    - name: dup
      shell: echo b
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("duplicate") || msg.contains("dup"), "got: {msg}");
    }

    #[test]
    fn rejects_handler_with_notify() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      shell: echo
  handlers:
    - name: chain_attempt
      notify: other_handler
      shell: echo
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("listen-chains") || msg.contains("notify"),
            "got: {msg}"
        );
    }

    #[test]
    fn accepts_valid_handler_chain() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: change_thing
      notify:
        - restart_sshd
        - log_change
      shell: echo
  handlers:
    - name: restart_sshd
      shell: echo restart
    - name: log_change
      shell: echo logged
"#,
        )
        .unwrap();
        validate(&pb, None).unwrap();
    }

    #[test]
    fn rejects_meta_with_register() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: drain
      register: r
      meta: flush_handlers
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("meta") && msg.contains("register"), "got: {msg}");
    }

    #[test]
    fn rejects_unflattened_import_tasks() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      import_tasks: somewhere.yml
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("import_tasks") || msg.contains("flattened"), "got: {msg}");
    }
}
