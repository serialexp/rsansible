//! End-to-end test for the `--diff` path (`RunSpec.diff_mode`).
//!
//! Spins up one sshd container and runs a small playbook that writes a file and
//! then modifies it, with `diff_mode` enabled and a capturing [`Reporter`]
//! installed. Asserts that the agent-computed `{before, after, …}` payload
//! rides all the way back through `TaskDone.diff` → `RegisterValue.diff` →
//! `TaskRunSummary.diff` → `TaskReport.diff`, and that the controller-side
//! unified-diff renderer turns it into the expected `-old` / `+new` lines.
//!
//! Run:
//!   cargo test -p rsansible-ctl --test diff_e2e -- --ignored --nocapture

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rsansible_ctl::{
    diff_render::render_diff_payload,
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
    report::{Reporter, TaskReport, TaskStatus},
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

#[derive(Default)]
struct Capture {
    tasks: Mutex<Vec<TaskReport>>,
}
impl Reporter for Capture {
    fn on_task(&self, report: &TaskReport) {
        self.tasks.lock().unwrap().push(report.clone());
    }
}

// Two writes to the same path: the first creates it (before is empty), the
// second changes its content (a real before/after diff). Unique path per test
// run isn't needed — the container is fresh — but /tmp keeps it self-cleaning.
const DIFF_PLAYBOOK: &str = r#"
- name: diff-demo
  hosts: all
  strategy: per_task
  on_failure: stop
  tasks:
    - name: create config
      write_file:
        path: /tmp/rsansible-diff-target
        mode: 0o644
        content: |
          line one
          line two
    - name: modify config
      write_file:
        path: /tmp/rsansible-diff-target
        mode: 0o644
        content: |
          line one
          line two changed
          line three
    - name: rewrite same content (no change)
      write_file:
        path: /tmp/rsansible-diff-target
        mode: 0o644
        content: |
          line one
          line two changed
          line three
"#;

#[tokio::test]
#[ignore]
async fn diff_mode_ships_before_after_payload_end_to_end() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let inv = build_single_inventory(&container);
    let pb = playbook::parse(DIFF_PLAYBOOK).context("parsing diff playbook")?;
    playbook::validate(&pb, Some(&inv)).context("validating diff playbook")?;

    let capture = Arc::new(Capture::default());
    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.reporter = capture.clone();
    spec.diff_mode = true;

    let report = orchestrator::run(spec).await.context("orchestrator")?;
    assert!(!report.stopped_early, "playbook should complete end-to-end");
    assert_eq!(report.host_outcomes.get("host1"), Some(&HostOutcome::Ok));

    let tasks = capture.tasks.lock().unwrap().clone();
    eprintln!("captured task reports = {tasks:#?}");

    // --- Task 1: create → diff present, before empty, all additions. ---
    let create = task_named(&tasks, "create config");
    assert_eq!(create.status, TaskStatus::Changed);
    let create_payload = create.diff.as_deref().expect("create should carry a diff");
    let v: serde_json::Value = serde_json::from_str(create_payload).unwrap();
    assert_eq!(v["before"], "", "brand-new file has empty before");
    assert!(v["after"].as_str().unwrap().contains("line two"));
    assert_eq!(v["before_header"], "/tmp/rsansible-diff-target");

    // --- Task 2: modify → before/after both populated, renders a unified diff. ---
    let modify = task_named(&tasks, "modify config");
    assert_eq!(modify.status, TaskStatus::Changed);
    let modify_payload = modify.diff.as_deref().expect("modify should carry a diff");
    let v: serde_json::Value = serde_json::from_str(modify_payload).unwrap();
    assert!(
        v["before"].as_str().unwrap().contains("line two\n"),
        "before is the prior content"
    );
    assert!(v["after"].as_str().unwrap().contains("line two changed"));

    let rendered = render_diff_payload(modify_payload).expect("should render a unified diff");
    eprintln!("rendered diff:\n{rendered}");
    assert!(rendered.contains("--- /tmp/rsansible-diff-target"));
    assert!(rendered.contains("+++ /tmp/rsansible-diff-target"));
    assert!(
        rendered.lines().any(|l| l == "-line two"),
        "old line removed"
    );
    assert!(
        rendered.lines().any(|l| l == "+line two changed"),
        "new line added"
    );
    assert!(
        rendered.lines().any(|l| l == "+line three"),
        "appended line added"
    );

    // --- Task 3: identical rewrite → no change, no diff payload. ---
    let noop = task_named(&tasks, "rewrite same content (no change)");
    assert_eq!(noop.status, TaskStatus::Ok, "same content is not a change");
    assert!(!noop.changed);
    assert!(
        noop.diff.is_none(),
        "an unchanged file ships no diff payload"
    );

    Ok(())
}

fn task_named<'a>(tasks: &'a [TaskReport], name: &str) -> &'a TaskReport {
    tasks
        .iter()
        .find(|t| t.task == name)
        .unwrap_or_else(|| panic!("no captured task named {name:?}"))
}

fn build_single_inventory(c: &SshdContainer) -> Inventory {
    let mut hosts = BTreeMap::new();
    hosts.insert(
        "host1".to_string(),
        Host {
            host: "127.0.0.1".into(),
            port: c.host_port,
            user: c.user.clone(),
            key_path: Some(c.key_path.clone()),
            inline_vars: BTreeMap::new(),
            member_of: vec!["all".to_string()],
        },
    );
    let mut groups = BTreeMap::new();
    groups.insert("all".to_string(), vec!["host1".to_string()]);
    Inventory {
        hosts,
        groups,
        all_vars: BTreeMap::new(),
        group_inline_vars: BTreeMap::new(),
    }
}
