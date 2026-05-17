//! End-to-end exercise of `block:` / `rescue:` / `always:`.
//!
//! Three runs against a single sshd container, all with the same
//! single-host inventory and `on_failure: stop`:
//!
//!   1. **success path**: a block whose tasks all succeed. `rescue:`
//!      MUST NOT run, `always:` MUST run, host outcome `Ok`, no
//!      early stop.
//!
//!   2. **rescue recovers**: a block whose second task `shell: "exit
//!      9"` fails. `rescue:` runs and writes a marker that includes
//!      `{{ ansible_failed_task }}` and a field from
//!      `{{ ansible_failed_result }}`. `always:` runs. Host outcome
//!      `Ok` — rescue recovered. No early stop.
//!
//!   3. **rescue itself fails**: block fails, rescue's inner task
//!      also fails. `always:` MUST still run. Host outcome `Failed`,
//!      play stopped early.

mod common;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

const PLAYBOOK_SUCCESS: &str = r#"
- name: block-success
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: outer block
      block:
        - name: t1
          shell: "echo t1 > /tmp/rsansible-blk-t1"
        - name: t2
          shell: "echo t2 > /tmp/rsansible-blk-t2"
      rescue:
        - name: r1
          shell: "echo r1 > /tmp/rsansible-blk-rescue"
      always:
        - name: a1
          shell: "echo a1 > /tmp/rsansible-blk-always"
"#;

const PLAYBOOK_RESCUE_RECOVERS: &str = r#"
- name: block-rescue-recovers
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: outer block
      block:
        - name: t1
          shell: "echo t1 > /tmp/rsansible-blk-t1"
        - name: the-failing-task
          shell: "exit 9"
        - name: t3 should not run
          shell: "echo t3 > /tmp/rsansible-blk-t3"
      rescue:
        - name: capture failure
          shell: "echo failed_task={{ ansible_failed_task }} rc={{ ansible_failed_result.rc }} > /tmp/rsansible-blk-rescue"
      always:
        - name: always marker
          shell: "echo a > /tmp/rsansible-blk-always"
"#;

const PLAYBOOK_RESCUE_FAILS: &str = r#"
- name: block-rescue-fails
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: outer block
      block:
        - name: pre
          shell: "echo pre > /tmp/rsansible-blk-pre"
        - name: failer
          shell: "exit 1"
      rescue:
        - name: rescue marker
          shell: "echo r > /tmp/rsansible-blk-rescue"
        - name: rescue also fails
          shell: "exit 2"
      always:
        - name: always marker
          shell: "echo a > /tmp/rsansible-blk-always"

    - name: should not run after failed rescue
      shell: "echo post > /tmp/rsansible-blk-post"
"#;

#[tokio::test]
#[ignore]
async fn block_success_runs_always_not_rescue() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    init_tracing();

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("success.yaml");
    std::fs::write(&pb_path, PLAYBOOK_SUCCESS)?;

    scrub_markers(&container)?;

    let inv = single_host_inventory(&container);
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 1;
    let report = orchestrator::run(spec).await.context("orchestrator")?;

    assert!(
        !report.stopped_early,
        "success: play should not have stopped early; report = {report:#?}"
    );
    for (host, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "success: host {host} should be Ok, got {outcome:?}"
        );
    }
    assert!(marker_exists(&container, "/tmp/rsansible-blk-t1")?, "t1 ran");
    assert!(marker_exists(&container, "/tmp/rsansible-blk-t2")?, "t2 ran");
    assert!(
        !marker_exists(&container, "/tmp/rsansible-blk-rescue")?,
        "rescue must NOT have run on success path"
    );
    assert!(
        marker_exists(&container, "/tmp/rsansible-blk-always")?,
        "always must have run"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn block_rescue_recovers_and_sees_ansible_failed_vars() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    init_tracing();

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("rescue.yaml");
    std::fs::write(&pb_path, PLAYBOOK_RESCUE_RECOVERS)?;

    scrub_markers(&container)?;

    let inv = single_host_inventory(&container);
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 1;
    let report = orchestrator::run(spec).await.context("orchestrator")?;

    assert!(
        !report.stopped_early,
        "rescue-recovers: play should not have stopped early; report = {report:#?}"
    );
    for (host, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "rescue-recovers: host {host} should be Ok (rescue recovered), got {outcome:?}"
        );
    }
    assert!(marker_exists(&container, "/tmp/rsansible-blk-t1")?, "t1 ran before failure");
    assert!(
        !marker_exists(&container, "/tmp/rsansible-blk-t3")?,
        "t3 must NOT have run — block aborts at the first failure"
    );
    let rescue_contents = read_marker(&container, "/tmp/rsansible-blk-rescue")?;
    assert!(
        rescue_contents.contains("failed_task=the-failing-task"),
        "rescue should see ansible_failed_task; got: {rescue_contents:?}"
    );
    assert!(
        rescue_contents.contains("rc=9"),
        "rescue should see ansible_failed_result.rc; got: {rescue_contents:?}"
    );
    assert!(
        marker_exists(&container, "/tmp/rsansible-blk-always")?,
        "always must have run"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn block_rescue_also_fails_runs_always_and_halts() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    init_tracing();

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("rescue_fails.yaml");
    std::fs::write(&pb_path, PLAYBOOK_RESCUE_FAILS)?;

    scrub_markers(&container)?;

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
        "rescue-fails: play should have stopped early; report = {report:#?}"
    );
    let outcome = report
        .host_outcomes
        .values()
        .next()
        .expect("at least one host outcome");
    assert!(
        matches!(outcome, HostOutcome::Failed { .. }),
        "rescue-fails: host outcome should be Failed, got {outcome:?}"
    );
    assert!(
        marker_exists(&container, "/tmp/rsansible-blk-pre")?,
        "pre marker should exist"
    );
    assert!(
        marker_exists(&container, "/tmp/rsansible-blk-rescue")?,
        "rescue first-task marker should exist"
    );
    assert!(
        marker_exists(&container, "/tmp/rsansible-blk-always")?,
        "always MUST run even when rescue itself fails"
    );
    assert!(
        !marker_exists(&container, "/tmp/rsansible-blk-post")?,
        "task after the failing block must NOT run under on_failure: stop"
    );
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

fn scrub_markers(c: &SshdContainer) -> Result<()> {
    let _ = c.docker_exec(&["sh", "-c", "rm -f /tmp/rsansible-blk-*"])?;
    Ok(())
}

fn marker_exists(c: &SshdContainer, path: &str) -> Result<bool> {
    let out = c.docker_exec(&["test", "-f", path])?;
    Ok(out.status.success())
}

fn read_marker(c: &SshdContainer, path: &str) -> Result<String> {
    let out = c.docker_exec(&["cat", path])?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
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
