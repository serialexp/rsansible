//! Controller-side `become:` argv wrapping.
//!
//! When `become: true` resolves at dispatch time, the orchestrator
//! prepends `sudo -n -u <become_user> --` to the rendered argv (for
//! `exec:`) or the rendered command string (for `shell:`). The agent
//! itself stays oblivious — it sees a `sudo` invocation in the argv
//! and runs it like any other process.
//!
//! Why controller-side: doing it in the agent would need an op-schema
//! field plus duplicated wrapping in every agent module. Doing it in
//! the controller is mechanical, lossless, and keeps the wire schema
//! unchanged.
//!
//! What can't be wrapped:
//!   * `write_file:` / `template:` / `copy:` go through the agent's
//!     own filesystem write path — there's no argv to prepend `sudo`
//!     to. They rely on the agent process having been pushed with
//!     enough privilege to satisfy the eventual mode/owner contract.
//!     With `become_user == "root"` this is fine when the agent runs
//!     as root; non-root targets need agent-side support (planned
//!     post-Phase 3).
//!   * `gather_facts:` is in-process on the agent — same story.
//!
//! Effective-become resolution (in `effective`):
//!   task `become:`        — highest precedence
//!     ↓ if None
//!   inventory `ansible_become`      (per-host, then group, then all)
//!     ↓ if missing or not a bool
//!   default `false`
//!
//! The play-level `become:` keyword is folded into the task's own
//! `become_` at load time by `playbook::inherit_become_defaults`, so
//! this resolution doesn't need to inspect the play.
//!
//! `become_user` follows the same chain, defaulting to `"root"` when
//! `become_` resolves to true but no user is named.

use crate::exec_ctx::HostCtx;
use crate::playbook::{ExecOp, ShellOp, TaskOp, Task};

/// Render-time view of how to apply (or not apply) sudo wrapping to a
/// single op execution.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveBecome {
    pub apply: bool,
    /// Always populated when `apply` is true. Caller is expected to
    /// have validated this is a safe identifier (no shell metacharacters)
    /// at parse / validate time.
    pub user: String,
}

impl EffectiveBecome {
    pub const fn none() -> Self {
        Self { apply: false, user: String::new() }
    }
}

/// Compute the effective become for a task on a specific host.
///
/// Reads from `ctx.inventory_vars` for the `ansible_become` /
/// `ansible_become_user` defaults — that map is already the resolved
/// precedence-chain view (all_vars → group_vars → host_vars →
/// host-inline) built once at play start, so we don't re-walk groups
/// here.
pub fn effective(task: &Task, ctx: &HostCtx) -> EffectiveBecome {
    let apply = match task.become_ {
        Some(b) => b,
        None => ctx
            .inventory_vars
            .get("ansible_become")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    };
    if !apply {
        return EffectiveBecome::none();
    }
    let user = task
        .become_user
        .clone()
        .or_else(|| {
            ctx.inventory_vars
                .get("ansible_become_user")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| "root".to_string());
    EffectiveBecome { apply: true, user }
}

/// Mutate a rendered `TaskOp` in place to wrap argv for `sudo`.
///
/// Only `Shell` and `Exec` are mutated; other ops pass through. Calling
/// this with `eff.apply == false` is a no-op.
pub fn apply(op: &mut TaskOp, eff: &EffectiveBecome) {
    if !eff.apply {
        return;
    }
    match op {
        TaskOp::Shell(s) => wrap_shell(s, &eff.user),
        TaskOp::Exec(e) => wrap_exec(e, &eff.user),
        // Non-argv ops: the agent runs them in-process with its own
        // credentials. There's no command to wrap. See module docs.
        TaskOp::WriteFile(_)
        | TaskOp::Template(_)
        | TaskOp::Copy(_)
        | TaskOp::GatherFacts
        | TaskOp::Stat(_)
        | TaskOp::File(_)
        | TaskOp::WaitFor(_)
        | TaskOp::LineInFile(_)
        | TaskOp::BlockInFile(_)
        | TaskOp::Systemd(_)
        | TaskOp::Package(_)
        | TaskOp::Ufw(_)
        | TaskOp::Uri(_)
        // x509 family is controller-side: privkey desugars to
        // OpWriteFile (no argv); the *_pipe variants don't even
        // dispatch a wire op. become: is meaningless for all three.
        | TaskOp::OpenSslPrivkey(_)
        | TaskOp::OpenSslCsrPipe(_)
        | TaskOp::X509CertificatePipe(_)
        // PostgreSQL ops talk to the DB over UNIX socket or TCP; the
        // agent makes the connection in-process. `become: postgres`
        // is honoured by the surrounding `sudo` wrapping the agent
        // binary itself (so peer auth works), not by mutating the
        // op argv here.
        // get_url: agent runs the HTTP client in-process. become: is
        // honoured by the surrounding sudo wrapping the agent itself
        // (for write-permission to dest), not by mutating any argv.
        | TaskOp::GetUrl(_)
        // slurp: agent reads the file in-process. `become:` is honoured
        // by the surrounding sudo wrapping the agent itself (for read
        // permission on protected files), not by mutating any argv.
        | TaskOp::Slurp(_)
        | TaskOp::PostgresqlQuery(_)
        | TaskOp::PostgresqlExt(_) => {}
    }
}

fn wrap_shell(s: &mut ShellOp, user: &str) {
    // sh -c "<wrapped>" is what the agent will end up running anyway.
    // Prepending `sudo -n -u <user> --` to the command string keeps
    // the inner shell semantics (pipes, redirection) intact: the
    // outer sh runs sudo, sudo execs the target user's shell with
    // `-c "<orig>"`.
    //
    // `-n` makes sudo fail fast rather than prompt for a password —
    // any deployment that needs `become: true` must have NOPASSWD
    // sudoers entries, matching Ansible's default for ssh + become.
    let prefix = format!("sudo -n -u {user} -- ");
    match s {
        ShellOp::Simple(cmd) => *cmd = format!("{prefix}{cmd}"),
        ShellOp::Detailed { command, .. } => *command = format!("{prefix}{command}"),
    }
}

fn wrap_exec(e: &mut ExecOp, user: &str) {
    // For exec we know the literal argv, so wrap structurally rather
    // than via string concat — no quoting concerns.
    let mut prefix = vec![
        "sudo".to_string(),
        "-n".to_string(),
        "-u".to_string(),
        user.to_string(),
        "--".to_string(),
    ];
    prefix.append(&mut e.argv);
    e.argv = prefix;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::{Task, TaskBody, TaskOp};
    use std::collections::BTreeMap;

    fn empty_ctx() -> HostCtx {
        HostCtx::new("host1".to_string())
    }

    fn task_with_become(b: Option<bool>, u: Option<&str>) -> Task {
        Task {
            name: "t".into(),
            body: TaskBody::Op(TaskOp::Shell(ShellOp::Simple("echo hi".into()))),
            when: None,
            register: None,
            loop_spec: None,
            loop_control: None,
            tags: vec![],
            delegate_to: None,
            run_once: false,
            notify: vec![],
            role_dir: None,
            become_: b,
            become_user: u.map(String::from),
            ignore_errors: None,
            check_mode: None,
            async_seconds: None,
            poll_seconds: None,
        }
    }

    #[test]
    fn effective_default_no_wrap() {
        let t = task_with_become(None, None);
        let ctx = empty_ctx();
        let eff = effective(&t, &ctx);
        assert!(!eff.apply);
    }

    #[test]
    fn effective_task_true_defaults_to_root() {
        let t = task_with_become(Some(true), None);
        let ctx = empty_ctx();
        let eff = effective(&t, &ctx);
        assert!(eff.apply);
        assert_eq!(eff.user, "root");
    }

    #[test]
    fn effective_task_true_with_user() {
        let t = task_with_become(Some(true), Some("postgres"));
        let ctx = empty_ctx();
        let eff = effective(&t, &ctx);
        assert!(eff.apply);
        assert_eq!(eff.user, "postgres");
    }

    #[test]
    fn effective_task_false_overrides_inventory_true() {
        let t = task_with_become(Some(false), None);
        let mut ctx = empty_ctx();
        ctx.inventory_vars.insert(
            "ansible_become".into(),
            serde_json::Value::Bool(true),
        );
        let eff = effective(&t, &ctx);
        assert!(!eff.apply, "explicit task false beats inventory true");
    }

    #[test]
    fn effective_inventory_provides_default() {
        let t = task_with_become(None, None);
        let mut ctx = empty_ctx();
        ctx.inventory_vars
            .insert("ansible_become".into(), serde_json::Value::Bool(true));
        ctx.inventory_vars.insert(
            "ansible_become_user".into(),
            serde_json::Value::String("nobody".into()),
        );
        let eff = effective(&t, &ctx);
        assert!(eff.apply);
        assert_eq!(eff.user, "nobody");
    }

    #[test]
    fn wrap_shell_simple() {
        let mut op = TaskOp::Shell(ShellOp::Simple("echo $(whoami)".into()));
        apply(
            &mut op,
            &EffectiveBecome { apply: true, user: "postgres".into() },
        );
        let TaskOp::Shell(ShellOp::Simple(cmd)) = op else { panic!() };
        assert_eq!(cmd, "sudo -n -u postgres -- echo $(whoami)");
    }

    #[test]
    fn wrap_shell_detailed_preserves_timeout() {
        let mut op = TaskOp::Shell(ShellOp::Detailed {
            command: "echo hi".into(),
            timeout_ms: 5000,
        });
        apply(
            &mut op,
            &EffectiveBecome { apply: true, user: "root".into() },
        );
        let TaskOp::Shell(ShellOp::Detailed { command, timeout_ms }) = op else {
            panic!()
        };
        assert_eq!(command, "sudo -n -u root -- echo hi");
        assert_eq!(timeout_ms, 5000);
    }

    #[test]
    fn wrap_exec_prepends_argv() {
        let mut op = TaskOp::Exec(ExecOp {
            argv: vec!["/bin/uname".into(), "-a".into()],
            env: BTreeMap::new(),
            cwd: None,
            stdin: String::new(),
            timeout_ms: 0,
        });
        apply(
            &mut op,
            &EffectiveBecome { apply: true, user: "postgres".into() },
        );
        let TaskOp::Exec(e) = op else { panic!() };
        assert_eq!(
            e.argv,
            vec!["sudo", "-n", "-u", "postgres", "--", "/bin/uname", "-a"]
        );
    }

    #[test]
    fn wrap_noop_when_apply_false() {
        let mut op = TaskOp::Shell(ShellOp::Simple("echo".into()));
        apply(&mut op, &EffectiveBecome::none());
        let TaskOp::Shell(ShellOp::Simple(cmd)) = op else { panic!() };
        assert_eq!(cmd, "echo", "non-applied become must leave op untouched");
    }

    #[test]
    fn wrap_noop_for_non_argv_ops() {
        let mut op = TaskOp::GatherFacts;
        apply(
            &mut op,
            &EffectiveBecome { apply: true, user: "root".into() },
        );
        // Smoke check: still GatherFacts.
        assert!(matches!(op, TaskOp::GatherFacts));
    }
}
