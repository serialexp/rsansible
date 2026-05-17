//! `block:` / `rescue:` / `always:` — controller-side task grouping
//! with optional failure-recovery and cleanup arms.
//!
//! Ansible YAML shape (note that `rescue:` and `always:` are siblings
//! of `block:` on the task mapping, not nested under it):
//!
//! ```yaml
//! - name: do the dance
//!   block:
//!     - name: try
//!       shell: "do-thing"
//!   rescue:
//!     - name: cleanup-failure
//!       shell: "rm /tmp/lock"
//!   always:
//!     - name: notify-prometheus
//!       uri: { url: "...", method: POST }
//! ```
//!
//! Semantics:
//!
//! - Every task in `tasks` runs in sequence on each targeted host.
//! - If any task in `tasks` fails on a host, `rescue` runs on that
//!   host (with `ansible_failed_task` and `ansible_failed_result`
//!   in scope). If rescue completes without failure, the block is
//!   considered recovered and the host stays alive.
//! - `always` runs on every host regardless of outcome, after
//!   `tasks` (and `rescue` if it ran). It runs even when `tasks`
//!   succeeded and even when `rescue` failed.
//!
//! Block-level metadata (`when`, `tags`, `become`, `become_user`,
//! `ignore_errors`, `check_mode`, `delegate_to`) is pushed down into
//! every child task by a load-time pass; see
//! `crates/ctl/src/playbook/mod.rs::inherit_block_metadata`.
//! `loop:` stays on the block container and the executor iterates
//! the whole block→rescue→always triple per item.

use super::Task;

/// Parsed body of a `block:` task. The outer `Task` carries the
/// block's metadata (when, tags, become, loop, etc); this struct holds
/// only the three sub-task lists.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockSpec {
    /// Required. The main body of the block. Must be non-empty
    /// (rejected at parse time otherwise — an empty block is almost
    /// always a YAML error).
    pub tasks: Vec<Task>,
    /// Optional. Runs on any host where `tasks` failed. Empty when
    /// no `rescue:` key was present.
    pub rescue: Vec<Task>,
    /// Optional. Runs on every host after `tasks` (and `rescue` if
    /// it ran), regardless of outcome. Empty when no `always:` key
    /// was present.
    pub always: Vec<Task>,
}

#[cfg(test)]
mod tests {
    use crate::playbook::task_op::{
        try_parse_task_for_test as try_parse_task, BlockSpec, Task, TaskBody, TaskOp,
    };

    fn parse_task(yaml: &str) -> Task {
        try_parse_task(yaml).expect("parses")
    }

    fn as_block(t: &Task) -> &BlockSpec {
        match &t.body {
            TaskBody::Block(b) => b,
            other => panic!("expected Block body, got {other:?}"),
        }
    }

    #[test]
    fn parses_block_with_only_tasks() {
        let t = parse_task(
            r#"
name: outer
block:
  - name: t1
    shell: "echo one"
  - name: t2
    shell: "echo two"
"#,
        );
        let b = as_block(&t);
        assert_eq!(b.tasks.len(), 2);
        assert_eq!(b.rescue.len(), 0);
        assert_eq!(b.always.len(), 0);
        assert_eq!(b.tasks[0].name, "t1");
        assert!(matches!(&b.tasks[0].body, TaskBody::Op(TaskOp::Shell(_))));
        assert_eq!(b.tasks[1].name, "t2");
    }

    #[test]
    fn parses_block_with_rescue() {
        let t = parse_task(
            r#"
name: outer
block:
  - name: try
    shell: "do-thing"
rescue:
  - name: cleanup
    shell: "rm /tmp/lock"
"#,
        );
        let b = as_block(&t);
        assert_eq!(b.tasks.len(), 1);
        assert_eq!(b.rescue.len(), 1);
        assert_eq!(b.always.len(), 0);
        assert_eq!(b.rescue[0].name, "cleanup");
    }

    #[test]
    fn parses_block_with_always() {
        let t = parse_task(
            r#"
name: outer
block:
  - name: try
    shell: "do-thing"
always:
  - name: notify
    debug: { msg: "done" }
"#,
        );
        let b = as_block(&t);
        assert_eq!(b.always.len(), 1);
        assert_eq!(b.always[0].name, "notify");
    }

    #[test]
    fn parses_block_with_all_three() {
        let t = parse_task(
            r#"
name: outer
block:
  - name: try
    shell: "do"
rescue:
  - name: recover
    shell: "fix"
always:
  - name: cleanup
    shell: "rm /tmp/x"
"#,
        );
        let b = as_block(&t);
        assert_eq!(b.tasks.len(), 1);
        assert_eq!(b.rescue.len(), 1);
        assert_eq!(b.always.len(), 1);
    }

    #[test]
    fn parses_nested_block() {
        let t = parse_task(
            r#"
name: outer
block:
  - name: middle
    block:
      - name: inner
        shell: "echo deep"
    rescue:
      - name: inner-rescue
        debug: { msg: "caught inner" }
"#,
        );
        let outer = as_block(&t);
        assert_eq!(outer.tasks.len(), 1);
        let middle = &outer.tasks[0];
        assert_eq!(middle.name, "middle");
        let inner_block = match &middle.body {
            TaskBody::Block(b) => b,
            other => panic!("expected nested Block body, got {other:?}"),
        };
        assert_eq!(inner_block.tasks.len(), 1);
        assert_eq!(inner_block.tasks[0].name, "inner");
        assert_eq!(inner_block.rescue.len(), 1);
        assert_eq!(inner_block.rescue[0].name, "inner-rescue");
    }

    #[test]
    fn block_carries_outer_metadata() {
        // when/tags/become on the block stay on the outer Task and
        // are NOT pushed down by the parser. Inheritance happens at
        // load time, not parse time.
        let t = parse_task(
            r#"
name: outer
become: true
become_user: postgres
when: do_run | bool
tags: [db, migration]
block:
  - name: inner
    shell: "psql -c 'select 1'"
"#,
        );
        assert_eq!(t.become_, Some(true));
        assert_eq!(t.become_user.as_deref(), Some("postgres"));
        assert_eq!(t.when.as_deref(), Some("do_run | bool"));
        assert_eq!(t.tags, vec!["db", "migration"]);
        let b = as_block(&t);
        // Inner task is untouched by the parser (no inheritance yet).
        assert_eq!(b.tasks[0].become_, None);
        assert_eq!(b.tasks[0].when, None);
        assert!(b.tasks[0].tags.is_empty());
    }

    #[test]
    fn block_supports_loop() {
        let t = parse_task(
            r#"
name: outer
loop: [a, b, c]
block:
  - name: inner
    shell: "echo {{ item }}"
"#,
        );
        // loop_spec stays on the outer Task.
        assert!(t.loop_spec.is_some());
        let b = as_block(&t);
        assert_eq!(b.tasks.len(), 1);
        // loop on the inner task is also fine but distinct.
        assert!(b.tasks[0].loop_spec.is_none());
    }

    #[test]
    fn rejects_block_with_retries() {
        let err = try_parse_task(
            r#"
name: outer
retries: 3
block:
  - name: inner
    shell: "true"
"#,
        )
        .expect_err("retries on block should error");
        let msg = err.to_string();
        assert!(
            msg.contains("retries") && msg.contains("block"),
            "msg: {msg}"
        );
    }

    #[test]
    fn rejects_block_with_until() {
        let err = try_parse_task(
            r#"
name: outer
register: r
until: r.rc == 0
block:
  - name: inner
    shell: "true"
"#,
        )
        .expect_err("until on block should error");
        let msg = err.to_string();
        assert!(msg.contains("until") && msg.contains("block"), "msg: {msg}");
    }

    #[test]
    fn rejects_block_with_delay() {
        // delay without retries already errors today, but on a block
        // we additionally want a clearer message even if retries is
        // set. Easiest test: set retries first to get past that gate,
        // then assert the block-specific error.
        let err = try_parse_task(
            r#"
name: outer
retries: 3
delay: 5
block:
  - name: inner
    shell: "true"
"#,
        )
        .expect_err("retries/delay on block should error");
        let msg = err.to_string();
        // Either the retries-on-block error or a delay-on-block error
        // is acceptable; we just need a block-keyword error.
        assert!(msg.contains("block"), "msg: {msg}");
    }

    #[test]
    fn rejects_block_with_register() {
        // register: on a block has no defined semantics in Ansible
        // either (it's silently ignored). We reject loudly so users
        // know to put register on inner tasks instead.
        let err = try_parse_task(
            r#"
name: outer
register: r
block:
  - name: inner
    shell: "true"
"#,
        )
        .expect_err("register on block should error");
        let msg = err.to_string();
        assert!(msg.contains("register") && msg.contains("block"), "msg: {msg}");
    }

    #[test]
    fn rejects_block_with_notify() {
        let err = try_parse_task(
            r#"
name: outer
notify: [some_handler]
block:
  - name: inner
    shell: "true"
"#,
        )
        .expect_err("notify on block should error");
        let msg = err.to_string();
        assert!(msg.contains("notify") && msg.contains("block"), "msg: {msg}");
    }

    #[test]
    fn rejects_block_with_run_once() {
        let err = try_parse_task(
            r#"
name: outer
run_once: true
block:
  - name: inner
    shell: "true"
"#,
        )
        .expect_err("run_once on block should error");
        let msg = err.to_string();
        assert!(msg.contains("run_once") && msg.contains("block"), "msg: {msg}");
    }

    #[test]
    fn rejects_block_missing_tasks_list() {
        // `block:` must be a list. A scalar or mapping should error.
        let err = try_parse_task(
            r#"
name: outer
block: "not a list"
"#,
        )
        .expect_err("block must be a list");
        let msg = err.to_string();
        assert!(msg.contains("block"), "msg: {msg}");
    }

    #[test]
    fn rejects_empty_block_tasks_list() {
        let err = try_parse_task(
            r#"
name: outer
block: []
"#,
        )
        .expect_err("empty block should error");
        let msg = err.to_string();
        assert!(msg.contains("block") && msg.contains("empty"), "msg: {msg}");
    }

    #[test]
    fn rejects_rescue_without_block() {
        let err = try_parse_task(
            r#"
name: outer
rescue:
  - name: r
    shell: "true"
shell: "outer"
"#,
        )
        .expect_err("rescue without block should error");
        let msg = err.to_string();
        assert!(msg.contains("rescue"), "msg: {msg}");
    }

    #[test]
    fn rejects_always_without_block() {
        let err = try_parse_task(
            r#"
name: outer
always:
  - name: a
    shell: "true"
shell: "outer"
"#,
        )
        .expect_err("always without block should error");
        let msg = err.to_string();
        assert!(msg.contains("always"), "msg: {msg}");
    }
}
