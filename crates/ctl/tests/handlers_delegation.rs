//! End-to-end Phase 1b test: handlers + notify + flush_handlers, plus
//! run_once with controller-side broadcast. Runs against the same
//! 3-container fixture as the Phase 1a test.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

#[tokio::test]
#[ignore]
async fn three_container_handlers_and_delegation_run() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let containers = start_three_containers().await?;
    let inv = build_inventory(&containers);

    let pb_path = examples_dir().join("handlers_and_delegation.yaml");
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 8;
    let report = orchestrator::run(spec).await.context("orchestrator")?;
    eprintln!("report = {report:#?}");

    assert!(!report.stopped_early, "should have completed end-to-end");
    for (name, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "host {name} should be Ok, got {outcome:?}"
        );
    }
    assert_eq!(report.host_outcomes.len(), 3);

    // Capture the token from one container; every container must have the
    // same content (proves run_once broadcast worked).
    let token = {
        let out = containers[0].docker_exec(&["cat", "/tmp/rsansible-token"])?;
        assert!(
            out.status.success(),
            "missing token file on host1: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert!(
        token.starts_with("phase1b-token-"),
        "token didn't look right: {token:?}"
    );

    for c in &containers {
        // run_once broadcast: same token on every host.
        let out = c.docker_exec(&["cat", "/tmp/rsansible-token"])?;
        assert!(out.status.success(), "token missing");
        let body = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(
            body, token,
            "token content differs between hosts — run_once broadcast failed"
        );

        // Mid-play meta: flush_handlers fired the flush_log handler.
        let out = c.docker_exec(&["cat", "/tmp/rsansible-flush-marker"])?;
        assert!(
            out.status.success(),
            "missing /tmp/rsansible-flush-marker — mid-play flush didn't fire"
        );

        // restart_marker handler ran exactly once even though two tasks
        // notified it. Easy check: the file exists and its content is the
        // one-shot marker value (no duplication).
        let out = c.docker_exec(&["cat", "/tmp/rsansible-restart-marker"])?;
        assert!(out.status.success(), "missing restart_marker file");
        let body = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(body, "restarted\n", "restart handler ran more than once: {body:?}");

        // End-of-play implicit flush fired the eop_log handler.
        let out = c.docker_exec(&["cat", "/tmp/rsansible-eop-marker"])?;
        assert!(
            out.status.success(),
            "missing /tmp/rsansible-eop-marker — end-of-play flush didn't fire"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore]
async fn delegate_to_invalid_host_fails_cleanly() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let containers = start_three_containers().await?;
    let inv = build_inventory(&containers);

    // Playbook that delegates to a host that isn't in the inventory.
    let pb_yaml = r#"
- name: bad delegate
  hosts: all
  strategy: per_task
  on_failure: continue
  tasks:
    - name: delegate nowhere
      delegate_to: ghost-host
      shell: echo never
"#;
    let pb = playbook::parse(pb_yaml)?;
    playbook::validate(&pb, Some(&inv))?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 8;
    let report = orchestrator::run(spec).await?;
    eprintln!("report = {report:#?}");

    // Every host should fail at the delegate step.
    let failed = report
        .host_outcomes
        .values()
        .filter(|o| {
            matches!(o, HostOutcome::Failed { task, reason }
                if task == "delegate nowhere" && reason.contains("ghost-host"))
        })
        .count();
    assert_eq!(
        failed, 3,
        "all 3 hosts should report Failed on the bad delegate task; got report: {report:#?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn handler_failure_under_stop_halts_play() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let containers = start_three_containers().await?;
    let inv = build_inventory(&containers);

    // Notify a handler that exits non-zero. Under on_failure: stop, the
    // handler failure should propagate as stopped_early.
    let pb_yaml = r#"
- name: failing handler
  hosts: all
  strategy: per_task
  on_failure: stop
  tasks:
    - name: change something
      notify: bad_handler
      shell: "echo trigger"
  handlers:
    - name: bad_handler
      shell: "exit 7"
"#;
    let pb = playbook::parse(pb_yaml)?;
    playbook::validate(&pb, Some(&inv))?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 8;
    let report = orchestrator::run(spec).await?;
    eprintln!("report = {report:#?}");

    assert!(
        report.stopped_early,
        "failing handler under on_failure=stop should halt the play"
    );
    let handler_failed = report
        .host_outcomes
        .values()
        .filter(|o| matches!(o, HostOutcome::Failed { task, .. } if task == "bad_handler"))
        .count();
    assert!(
        handler_failed >= 1,
        "at least one host should report the handler failure: {report:#?}"
    );
    Ok(())
}

async fn start_three_containers() -> Result<Vec<SshdContainer>> {
    let mut set: tokio::task::JoinSet<Result<SshdContainer>> = tokio::task::JoinSet::new();
    for _ in 0..3 {
        set.spawn(async { SshdContainer::start().await });
    }
    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        out.push(joined.map_err(|e| anyhow!("container task panicked: {e}"))??);
    }
    Ok(out)
}

fn build_inventory(containers: &[SshdContainer]) -> Inventory {
    let mut hosts = BTreeMap::new();
    for (i, c) in containers.iter().enumerate() {
        hosts.insert(
            format!("host{}", i + 1),
            Host {
                host: "127.0.0.1".into(),
                port: c.host_port,
                user: c.user.clone(),
                key_path: Some(c.key_path.clone()),
            },
        );
    }
    Inventory { hosts }
}

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace layout")
        .join("examples")
}
