//! End-to-end test for the structured [`rsansible_ctl::report`] path.
//!
//! Spins up one sshd container, runs a small playbook through the real
//! orchestrator with a capturing [`Reporter`] installed on the `RunSpec`, and
//! asserts the emitted per-(host, task) events and the final run outcome.
//! Exercises the whole chain: task body → `HostCtx.last_summary` → the
//! `apply_per_host_result` emission funnel → `Reporter::on_task` / `finish`.
//!
//! Run:
//!   cargo test -p rsansible-ctl --test report_e2e -- --ignored --nocapture

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
    report::{Reporter, RunOutcome, TaskReport, TaskStatus},
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

/// Reporter that records every event in memory for assertions.
#[derive(Default)]
struct Capture {
    tasks: Mutex<Vec<TaskReport>>,
    outcome: Mutex<Option<RunOutcome>>,
}
impl Reporter for Capture {
    fn on_task(&self, report: &TaskReport) {
        self.tasks.lock().unwrap().push(report.clone());
    }
    fn finish(&self, outcome: &RunOutcome) {
        *self.outcome.lock().unwrap() = Some(outcome.clone());
    }
}

const REPORT_PLAYBOOK: &str = r#"
- name: report-demo
  hosts: all
  strategy: per_task
  on_failure: stop
  tasks:
    - name: say hi via shell
      shell: "printf 'hi from %s\\n' \"$(hostname)\""
    - name: drop a marker file
      write_file:
        path: /tmp/rsansible-report-marker
        mode: 0o644
        content: |
          hello from the report test
    - name: this one is skipped
      shell: "echo should-not-run"
      when: "false"
"#;

#[tokio::test]
#[ignore]
async fn structured_report_captures_every_task_on_host() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let inv = build_single_inventory(&container);
    let pb = playbook::parse(REPORT_PLAYBOOK).context("parsing report playbook")?;
    playbook::validate(&pb, Some(&inv)).context("validating report playbook")?;

    let capture = Arc::new(Capture::default());
    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.reporter = capture.clone();

    let report = orchestrator::run(spec).await.context("orchestrator")?;
    assert!(!report.stopped_early, "playbook should complete end-to-end");
    assert_eq!(
        report.host_outcomes.get("host1"),
        Some(&HostOutcome::Ok),
        "host should end Ok"
    );

    let tasks = capture.tasks.lock().unwrap().clone();
    eprintln!("captured task reports = {tasks:#?}");

    // Exactly three task-on-host events, one per task, all for host1.
    assert_eq!(tasks.len(), 3, "one event per task, got {}", tasks.len());
    assert!(tasks.iter().all(|t| t.host == "host1"));
    assert!(tasks.iter().all(|t| t.play == "report-demo"));
    assert!(tasks.iter().all(|t| !t.check_mode));

    let shell = task_named(&tasks, "say hi via shell");
    assert_eq!(shell.status, TaskStatus::Changed, "shell has no idempotency");
    assert!(shell.changed);
    assert_eq!(shell.rc, Some(0), "shell rc should be captured");
    assert!(shell.duration_ms.is_some(), "duration should be captured");
    assert!(shell.reason.is_none());
    assert!(
        shell.diff.is_none(),
        "shell isn't a diffing module, and --diff wasn't requested here anyway"
    );

    let marker = task_named(&tasks, "drop a marker file");
    assert_eq!(
        marker.status,
        TaskStatus::Changed,
        "creating a fresh file is a change"
    );
    assert!(marker.changed);
    assert_eq!(marker.rc, Some(0));

    let skipped = task_named(&tasks, "this one is skipped");
    assert_eq!(skipped.status, TaskStatus::Skipped, "when:false → skipped");
    assert!(!skipped.changed);
    assert!(
        skipped.rc.is_none(),
        "a skipped task ran no module, so no rc"
    );
    assert!(skipped.duration_ms.is_none());

    // Final run outcome reached the sink.
    let outcome = capture
        .outcome
        .lock()
        .unwrap()
        .clone()
        .expect("finish() should have delivered a RunOutcome");
    assert!(!outcome.check_mode);
    assert!(!outcome.stopped_early);
    // Two Ok tasks (shell + write_file) counted; the skipped one is a
    // HostTaskOutcome::Skipped and doesn't add to tasks_ok.
    assert_eq!(outcome.tasks_ok, 2, "shell + write_file counted as ok");
    assert_eq!(outcome.tasks_changed, 2, "both mutating tasks changed");
    assert!(
        matches!(
            outcome.hosts.get("host1"),
            Some(rsansible_ctl::report::HostState::Ok)
        ),
        "host1 should be Ok in the run outcome"
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
