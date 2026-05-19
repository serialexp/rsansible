//! Controller-side `become:` resolution.
//!
//! Per-task effective-become is resolved here and surfaced as a
//! [`BecomeKey`]. The orchestrator routes each task to the agent in
//! its host's [`AgentPool`](crate::ssh::AgentPool) whose slot matches
//! that key — see CLAUDE.md's "Agent-pool become routing" section for
//! the architectural overview.
//!
//! Two pieces live here:
//!
//! 1. [`effective`] — turns the precedence chain (task `become:` →
//!    inventory `ansible_become` → default `false`) into an
//!    `EffectiveBecome { apply, user }`. Also renders `become_user`
//!    against the per-host template context, so playbooks can spell
//!    `become_user: "{{ db_user }}"`.
//! 2. [`BecomeKey`] — `None` for "run as the SSH user" or
//!    `As(user)` for "exec the agent under `sudo -n -u <user>`".
//!    `Hash + Eq + Ord` for use as the pool's map key.
//!
//! Argv-wrapping (the old `sudo -n -u <user> --` prepended to
//! shell/exec/command) is gone — the pool now handles privilege
//! escalation at the transport layer regardless of op type. Two
//! wins: (a) no double-sudo when shell ops happen to be the one type
//! we used to wrap, and (b) every op gets the same become semantics
//! that systemd/copy/file etc. always needed.
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

use crate::exec_ctx::{build_template_ctx, HostCtx, WorldVars};
use crate::playbook::Task;
use anyhow::{anyhow, Result};
use minijinja::Environment;

/// Resolved view of how to apply (or not apply) become for a single
/// task on a single host. `apply == true` means the task's wire ops
/// must dispatch through the `BecomeKey::As(user)` agent in the host's
/// pool; `apply == false` routes to `BecomeKey::None`.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveBecome {
    pub apply: bool,
    /// The resolved (post-Jinja-render) become user. Always populated
    /// when `apply` is true. Empty string when `apply` is false.
    pub user: String,
}

impl EffectiveBecome {
    pub const fn none() -> Self {
        Self { apply: false, user: String::new() }
    }
}

/// Identity of an agent slot inside a host's [`AgentPool`].
///
/// `None` is "the agent we spawned at connect time, running as the
/// SSH user". `As(user)` is "an agent spawned under
/// `sudo -n -u <user> -- <agent_path>`". Two tasks with the same
/// `BecomeKey` share a long-lived agent process; different keys get
/// independent processes.
///
/// `Ord` is derived purely for `BTreeMap` keying — the ordering has
/// no semantic meaning.
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Debug)]
pub enum BecomeKey {
    /// Run as whoever owns the transport — the SSH user for the SSH
    /// path, the controller user for `connection: local`.
    None,
    /// Run as `user` via `sudo -n -u <user>`. NOPASSWD is required;
    /// the sudo invocation is `-n` (non-interactive) and will fail
    /// fast if a password would be prompted, matching Ansible's
    /// default policy.
    As(String),
}

impl BecomeKey {
    pub fn from_effective(eff: &EffectiveBecome) -> Self {
        if eff.apply {
            Self::As(eff.user.clone())
        } else {
            Self::None
        }
    }

    /// Display label for logs / diagnostics ("none" or "as=root").
    pub fn label(&self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::As(u) => format!("as={u}"),
        }
    }
}

/// Compute the effective become for a task on a specific host.
///
/// Reads from `ctx.inventory_vars` for the `ansible_become` /
/// `ansible_become_user` defaults — that map is already the resolved
/// precedence-chain view (all_vars → group_vars → host_vars →
/// host-inline) built once at play start, so we don't re-walk groups
/// here.
///
/// `become_user` is rendered as a Jinja template against the host's
/// template context. A render failure bubbles as a task failure —
/// the caller surfaces it instead of dispatching against a pool slot
/// keyed on the literal unrendered string.
pub fn effective(
    task: &Task,
    ctx: &HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> Result<EffectiveBecome> {
    let apply = match task.become_ {
        Some(b) => b,
        None => ctx
            .inventory_vars
            .get("ansible_become")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    };
    if !apply {
        return Ok(EffectiveBecome::none());
    }
    let raw_user = task
        .become_user
        .clone()
        .or_else(|| {
            ctx.inventory_vars
                .get("ansible_become_user")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| "root".to_string());

    // Common fast path: literal user name, no template. Skip the
    // engine entirely so the parse-render round-trip doesn't show up
    // in flamegraphs for plays with `become: true` everywhere.
    let user = if raw_user.contains("{{") || raw_user.contains("{%") {
        let view = build_template_ctx(ctx, world);
        let tmpl = env
            .template_from_str(&raw_user)
            .map_err(|e| anyhow!("become_user template parse: {e}"))?;
        tmpl.render(&view)
            .map_err(|e| anyhow!("become_user template render: {e}"))?
    } else {
        raw_user
    };

    Ok(EffectiveBecome { apply: true, user })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec_ctx::WorldVars;
    use crate::playbook::{Task, TaskBody, TaskOp, ShellOp};
    use crate::template::make_env;

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
            delegate_facts: false,
            run_once: false,
            notify: vec![],
            role_dir: None,
            become_: b,
            become_user: u.map(String::from),
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
            environment: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn effective_default_no_wrap() {
        let t = task_with_become(None, None);
        let ctx = empty_ctx();
        let env = make_env();
        let eff = effective(&t, &ctx, &env, &WorldVars::default()).unwrap();
        assert!(!eff.apply);
    }

    #[test]
    fn effective_task_true_defaults_to_root() {
        let t = task_with_become(Some(true), None);
        let ctx = empty_ctx();
        let env = make_env();
        let eff = effective(&t, &ctx, &env, &WorldVars::default()).unwrap();
        assert!(eff.apply);
        assert_eq!(eff.user, "root");
    }

    #[test]
    fn effective_task_true_with_user() {
        let t = task_with_become(Some(true), Some("postgres"));
        let ctx = empty_ctx();
        let env = make_env();
        let eff = effective(&t, &ctx, &env, &WorldVars::default()).unwrap();
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
        let env = make_env();
        let eff = effective(&t, &ctx, &env, &WorldVars::default()).unwrap();
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
        let env = make_env();
        let eff = effective(&t, &ctx, &env, &WorldVars::default()).unwrap();
        assert!(eff.apply);
        assert_eq!(eff.user, "nobody");
    }

    #[test]
    fn effective_become_user_renders_jinja() {
        // `become_user: "{{ db_user }}"` should resolve against the
        // host's template ctx before the pool keys on it.
        let t = task_with_become(Some(true), Some("{{ db_user }}"));
        let mut ctx = empty_ctx();
        ctx.inventory_vars
            .insert("db_user".into(), serde_json::Value::String("postgres".into()));
        let env = make_env();
        let eff = effective(&t, &ctx, &env, &WorldVars::default()).unwrap();
        assert_eq!(eff.user, "postgres");
    }

    #[test]
    fn effective_become_user_render_failure_propagates() {
        // Mismatched braces — parse error. Bubbles as anyhow::Error
        // for the orchestrator to surface as task failure.
        let t = task_with_become(Some(true), Some("{{ unterminated"));
        let ctx = empty_ctx();
        let env = make_env();
        let err = effective(&t, &ctx, &env, &WorldVars::default()).unwrap_err();
        let s = format!("{err:#}");
        assert!(
            s.contains("become_user template"),
            "expected render-failure context, got: {s}"
        );
    }

    #[test]
    fn become_key_round_trips_from_effective() {
        // None case.
        let none = BecomeKey::from_effective(&EffectiveBecome::none());
        assert_eq!(none, BecomeKey::None);
        // As(user) case.
        let as_root = BecomeKey::from_effective(&EffectiveBecome {
            apply: true,
            user: "root".into(),
        });
        assert_eq!(as_root, BecomeKey::As("root".into()));
    }

    #[test]
    fn become_key_distinguishes_users() {
        // Two users with the same name MUST be equal (so the pool
        // reuses the same slot); different users MUST differ.
        let a = BecomeKey::As("postgres".into());
        let b = BecomeKey::As("postgres".into());
        let c = BecomeKey::As("root".into());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
