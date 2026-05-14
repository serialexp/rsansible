//! Template (minijinja) integration.
//!
//! Phase 1a needs Jinja in five places:
//!   * `when:` expressions
//!   * `loop:` strings
//!   * `set_fact:` values (scalar strings)
//!   * `assert.that:` expressions
//!   * task body fields (op argv/env/cwd/command/path/content)
//!
//! All share a single `Environment` configured here: lenient on undefined
//! (Ansible default), with two Ansible-style filters that Phase 1a
//! playbooks already need:
//!
//!   * `mandatory` — raise if the value is undefined/None
//!   * `subelements(field)` — flatten a list-of-dicts paired with each
//!     element of a named sub-list. Mirrors `with_subelements`.
//!
//! `precompile_all` walks the playbook and compiles every Jinja string
//! ahead of time so syntax errors surface at `validate`, not mid-run.

use anyhow::{anyhow, Result};
use minijinja::{Environment, Error as MjError, ErrorKind as MjKind, Value as MjValue};

use crate::playbook::{
    AssertTask, ExecOp, LoopSpec, Playbook, ShellOp, Task, TaskBody, TaskOp, WriteFileOp,
};

/// Build a fresh minijinja `Environment` configured for our use.
pub fn make_env<'a>() -> Environment<'a> {
    let mut env = Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    // Preserve trailing newlines in rendered output — write_file.content
    // sources frequently end in `\n` and we don't want minijinja stripping
    // them silently. Matches Ansible's behavior.
    env.set_keep_trailing_newline(true);
    env.add_filter("mandatory", mandatory_filter);
    env.add_filter("subelements", subelements_filter);
    env
}

/// `value | mandatory` — pass through if defined, raise otherwise.
/// Matches Ansible's filter of the same name.
fn mandatory_filter(value: MjValue) -> Result<MjValue, MjError> {
    if value.is_undefined() || value.is_none() {
        return Err(MjError::new(
            MjKind::UndefinedError,
            "mandatory: variable is not defined",
        ));
    }
    Ok(value)
}

/// `users | subelements('keys')` → `[(user, key0), (user, key1), …]`.
///
/// Input is a sequence of mappings; each mapping must contain `field`,
/// itself a sequence. Output is a sequence of two-element sequences
/// `[parent, child]`, mirroring Ansible's `with_subelements`.
fn subelements_filter(value: MjValue, field: String) -> Result<MjValue, MjError> {
    let parents: Vec<MjValue> = value.try_iter()?.collect();
    let mut out: Vec<MjValue> = Vec::new();
    for parent in parents {
        let children = parent.get_attr(&field)?;
        if children.is_undefined() {
            return Err(MjError::new(
                MjKind::UndefinedError,
                format!("subelements: parent has no field {field:?}"),
            ));
        }
        for child in children.try_iter()? {
            out.push(MjValue::from(vec![parent.clone(), child]));
        }
    }
    Ok(MjValue::from(out))
}

/// Compile every Jinja string in the playbook so syntax errors surface
/// before any host is contacted.
pub fn precompile_all(pb: &Playbook) -> Result<()> {
    let env = make_env();
    for (pi, play) in pb.plays.iter().enumerate() {
        for (ti, task) in play.tasks.iter().enumerate() {
            check_task(&env, task).map_err(|e| {
                anyhow!(
                    "play[{pi}] {:?} task[{ti}] {:?}: {e}",
                    play.name,
                    task.name
                )
            })?;
        }
        for (hi, h) in play.handlers.iter().enumerate() {
            check_task(&env, h).map_err(|e| {
                anyhow!(
                    "play[{pi}] {:?} handler[{hi}] {:?}: {e}",
                    play.name,
                    h.name
                )
            })?;
        }
    }
    Ok(())
}

fn check_task(env: &Environment, task: &Task) -> Result<()> {
    if let Some(expr) = &task.when {
        env.compile_expression(expr)
            .map_err(|e| anyhow!("when: {e}"))?;
    }
    if let Some(LoopSpec::Expr(s)) = &task.loop_spec {
        // Treat the loop expression as a template — they're sometimes
        // bare `{{ var }}` and sometimes more complex `{{ a + b }}`.
        env.template_from_str(s).map_err(|e| anyhow!("loop: {e}"))?;
    }
    if let Some(d) = &task.delegate_to {
        env.template_from_str(d)
            .map_err(|e| anyhow!("delegate_to: {e}"))?;
    }
    for (i, n) in task.notify.iter().enumerate() {
        env.template_from_str(n)
            .map_err(|e| anyhow!("notify[{i}]: {e}"))?;
    }
    match &task.body {
        TaskBody::Op(op) => check_op(env, op)?,
        TaskBody::Assert(a) => check_assert(env, a)?,
        TaskBody::Fail(f) => {
            env.template_from_str(&f.msg)
                .map_err(|e| anyhow!("fail.msg: {e}"))?;
        }
        TaskBody::SetFact(m) => {
            for (k, v) in &m.0 {
                if let serde_yaml::Value::String(s) = v {
                    env.template_from_str(s)
                        .map_err(|e| anyhow!("set_fact.{k}: {e}"))?;
                }
            }
        }
        TaskBody::ImportTasks(_) => {
            // Should already have been flattened away. Leave as a soft
            // skip rather than a hard failure to keep `precompile_all`
            // safe to call on partially-loaded playbooks in tests.
        }
        TaskBody::Meta(_) => {
            // `meta: flush_handlers` has no body fields to compile.
        }
    }
    Ok(())
}

fn check_op(env: &Environment, op: &TaskOp) -> Result<()> {
    match op {
        TaskOp::Shell(ShellOp::Simple(s)) => {
            env.template_from_str(s)
                .map_err(|e| anyhow!("shell: {e}"))?;
        }
        TaskOp::Shell(ShellOp::Detailed { command, .. }) => {
            env.template_from_str(command)
                .map_err(|e| anyhow!("shell.command: {e}"))?;
        }
        TaskOp::Exec(ExecOp {
            argv, env: e_env, cwd, stdin, ..
        }) => {
            for (i, a) in argv.iter().enumerate() {
                env.template_from_str(a)
                    .map_err(|e| anyhow!("exec.argv[{i}]: {e}"))?;
            }
            for (k, v) in e_env {
                env.template_from_str(v)
                    .map_err(|e| anyhow!("exec.env.{k}: {e}"))?;
            }
            if let Some(c) = cwd {
                env.template_from_str(c)
                    .map_err(|e| anyhow!("exec.cwd: {e}"))?;
            }
            env.template_from_str(stdin)
                .map_err(|e| anyhow!("exec.stdin: {e}"))?;
        }
        TaskOp::WriteFile(WriteFileOp { path, content, .. }) => {
            env.template_from_str(path)
                .map_err(|e| anyhow!("write_file.path: {e}"))?;
            env.template_from_str(content)
                .map_err(|e| anyhow!("write_file.content: {e}"))?;
        }
        TaskOp::Template(t) => {
            // `src:` was resolved at load time; only `dest:` is Jinja-able
            // at task time. The template body itself is compiled via the
            // playbook's `TemplateRegistry` rather than here.
            env.template_from_str(&t.dest)
                .map_err(|e| anyhow!("template.dest: {e}"))?;
        }
        TaskOp::Copy(c) => {
            // `src:` is resolved at load time; `body` is raw bytes that
            // ship verbatim and need no Jinja compilation. Only `dest:`
            // is templatable.
            env.template_from_str(&c.dest)
                .map_err(|e| anyhow!("copy.dest: {e}"))?;
        }
        TaskOp::GatherFacts => {
            // Implicit op — no user-supplied fields to compile.
        }
    }
    Ok(())
}

fn check_assert(env: &Environment, a: &AssertTask) -> Result<()> {
    for (i, expr) in a.that.iter().enumerate() {
        env.compile_expression(expr)
            .map_err(|e| anyhow!("assert.that[{i}]: {e}"))?;
    }
    if let Some(msg) = &a.msg {
        env.template_from_str(msg)
            .map_err(|e| anyhow!("assert.msg: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minijinja::context;

    #[test]
    fn env_builds() {
        let env = make_env();
        let tmpl = env.template_from_str("hello {{ name }}").unwrap();
        let out = tmpl.render(context! { name => "world" }).unwrap();
        assert_eq!(out, "hello world");
    }

    #[test]
    fn mandatory_filter_passes_defined() {
        let env = make_env();
        let tmpl = env.template_from_str("{{ x | mandatory }}").unwrap();
        let out = tmpl.render(context! { x => "yes" }).unwrap();
        assert_eq!(out, "yes");
    }

    #[test]
    fn mandatory_filter_errors_on_undefined() {
        let env = make_env();
        let tmpl = env.template_from_str("{{ x | mandatory }}").unwrap();
        let err = tmpl.render(context! {}).unwrap_err();
        assert!(format!("{err}").contains("mandatory"));
    }

    #[test]
    fn subelements_filter_basic() {
        let env = make_env();
        let tmpl = env
            .template_from_str(
                "{% for u, k in users | subelements('keys') %}{{ u.name }}:{{ k }};{% endfor %}",
            )
            .unwrap();
        let users = serde_json::json!([
            {"name": "alice", "keys": ["a1", "a2"]},
            {"name": "bob", "keys": ["b1"]}
        ]);
        let out = tmpl.render(context! { users => users }).unwrap();
        assert_eq!(out, "alice:a1;alice:a2;bob:b1;");
    }

    #[test]
    fn precompile_catches_bad_when_expression() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      when: "1 ===== 2"
      shell: echo
"#,
        )
        .unwrap();
        let err = precompile_all(&pb).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("when"), "got: {msg}");
    }

    #[test]
    fn precompile_catches_bad_template_in_shell() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      shell: "echo {{ unclosed"
"#,
        )
        .unwrap();
        let err = precompile_all(&pb).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("shell"), "got: {msg}");
    }

    #[test]
    fn precompile_accepts_clean_playbook() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: greet
      register: r
      shell: "echo {{ inventory_hostname }}"
    - name: gated
      when: "r.rc == 0"
      shell: "echo ok"
"#,
        )
        .unwrap();
        precompile_all(&pb).unwrap();
    }
}
