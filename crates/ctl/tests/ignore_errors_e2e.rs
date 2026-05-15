//! End-to-end exercise of task-level `ignore_errors:`.
//!
//! Two runs against a single sshd container:
//!
//!   1. **ignored**: a 3-task playbook where task 2 is `shell: "exit 1"`
//!      with `ignore_errors: true`. Expected: task 1 and task 3 both
//!      ran (their marker files exist), the run completed without
//!      `stopped_early`, and the host outcome stayed `Ok`. The register
//!      for the failing task carries `.failed=true` (verified via a
//!      `when: prev.failed` follow-up that asserts it).
//!
//!   2. **negation**: identical playbook with `ignore_errors:` removed.
//!      Expected: task 3 did NOT run, host outcome is `Failed`, and
//!      `stopped_early` is true.

mod common;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

const PLAYBOOK_IGNORED: &str = r#"
- name: ignore-errors demo
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: pre
      shell: "echo pre > /tmp/rsansible-ie-pre"

    - name: failing step
      shell: "exit 7"
      register: failing
      ignore_errors: true

    - name: assert register reflects failure
      assert:
        that:
          - "failing.failed"
          - "failing.rc == 7"
        msg: "register must capture the failure"

    - name: post
      shell: "echo post > /tmp/rsansible-ie-post"
"#;

const PLAYBOOK_BAILS: &str = r#"
- name: no-ignore control
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: pre
      shell: "echo pre > /tmp/rsansible-ie-pre"

    - name: failing step (no ignore)
      shell: "exit 7"

    - name: post (should not run)
      shell: "echo post > /tmp/rsansible-ie-post"
"#;

#[tokio::test]
#[ignore]
async fn ignore_errors_lets_play_continue_and_register_reflects_failure() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("ignored.yaml");
    std::fs::write(&pb_path, PLAYBOOK_IGNORED)?;

    // Scrub markers from any prior run.
    let _ = container.docker_exec(&["sh", "-c", "rm -f /tmp/rsansible-ie-*"])?;

    let inv = single_host_inventory(&container);
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes.clone());
    spec.max_concurrent_hosts = 1;
    let report = orchestrator::run(spec).await.context("orchestrator")?;

    assert!(
        !report.stopped_early,
        "ignored: play should not have stopped early; report = {report:#?}"
    );
    for (host, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "ignored: host {host} should be Ok, got {outcome:?}"
        );
    }
    // Both pre and post markers should exist — the assert in the middle
    // passed because the register correctly captured the failure.
    assert!(
        marker_exists(&container, "/tmp/rsansible-ie-pre")?,
        "ignored: pre marker should exist"
    );
    assert!(
        marker_exists(&container, "/tmp/rsansible-ie-post")?,
        "ignored: post marker should exist — play continued past the failure"
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn no_ignore_errors_halts_play_under_on_failure_stop() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("bails.yaml");
    std::fs::write(&pb_path, PLAYBOOK_BAILS)?;

    let _ = container.docker_exec(&["sh", "-c", "rm -f /tmp/rsansible-ie-*"])?;

    let inv = single_host_inventory(&container);
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 1;
    let report = orchestrator::run(spec).await.context("orchestrator")?;

    assert!(
        report.stopped_early,
        "control: play should have stopped early; report = {report:#?}"
    );
    let outcome = report
        .host_outcomes
        .values()
        .next()
        .expect("at least one host outcome");
    assert!(
        matches!(outcome, HostOutcome::Failed { .. }),
        "control: host outcome should be Failed, got {outcome:?}"
    );
    assert!(
        marker_exists(&container, "/tmp/rsansible-ie-pre")?,
        "control: pre marker should exist (first task ran before the failure)"
    );
    assert!(
        !marker_exists(&container, "/tmp/rsansible-ie-post")?,
        "control: post marker should NOT exist — play halted on the failure"
    );

    Ok(())
}

fn marker_exists(c: &SshdContainer, path: &str) -> Result<bool> {
    let out = c.docker_exec(&["test", "-f", path])?;
    Ok(out.status.success())
}

fn single_host_inventory(c: &SshdContainer) -> Inventory {
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
