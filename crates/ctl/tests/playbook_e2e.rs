//! End-to-end orchestrator test: 3 sshd containers, full playbook run.
//!
//! Asserts:
//!   * All three hosts connect, run the play, and report Ok.
//!   * `/tmp/rsansible-hello` exists on each container with the expected
//!     content (verifies OpWriteFile + per-task barrier ran on every host).
//!   * The summary in RunReport matches.
//!
//! Run:
//!   cargo test -p rsansible-ctl --test playbook_e2e -- --ignored --nocapture

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

#[tokio::test]
#[ignore]
async fn three_container_per_task_run() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;

    // Spin up three containers in parallel — saves ~6 seconds vs sequential.
    let containers = start_three_containers().await?;

    let inv = build_inventory(&containers);
    let pb = playbook::parse(EXAMPLE_PLAYBOOK).context("parsing example playbook")?;
    playbook::validate(&pb, Some(&inv)).context("validating example playbook")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 8;

    let report = orchestrator::run(spec).await.context("orchestrator")?;

    eprintln!("report = {report:#?}");
    assert!(
        !report.stopped_early,
        "playbook should have completed end-to-end"
    );
    for (name, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "host {name} should be Ok, got {outcome:?}"
        );
    }
    assert_eq!(report.host_outcomes.len(), 3);

    // Verify the marker file made it onto every container.
    for c in &containers {
        let out = c.docker_exec(&["cat", "/tmp/rsansible-hello"])?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "expected /tmp/rsansible-hello on container; cat exit={:?}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("hello from rsansible"),
            "marker content unexpected: {stdout:?}"
        );
    }

    Ok(())
}

#[tokio::test]
#[ignore]
async fn three_container_failing_task_stops_playbook() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;

    let containers = start_three_containers().await?;
    let inv = build_inventory(&containers);

    // First task: succeeds on every host. Second task: deliberately exits
    // non-zero. With on_failure=stop the third task should never run.
    let pb_yaml = r#"
- name: stop-on-failure-check
  hosts: all
  strategy: per_task
  on_failure: stop
  tasks:
    - name: first ok
      shell: "true"
    - name: deliberate failure
      shell: "exit 7"
    - name: must not run
      write_file:
        path: /tmp/rsansible-should-not-exist
        mode: 0o644
        content: "ghost\n"
"#;
    let pb = playbook::parse(pb_yaml)?;
    playbook::validate(&pb, Some(&inv))?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 8;
    let report = orchestrator::run(spec).await?;
    eprintln!("report = {report:#?}");

    assert!(
        report.stopped_early,
        "on_failure=stop should have halted the playbook"
    );
    // Every host should be marked Failed at "deliberate failure".
    let failed: Vec<&String> = report
        .host_outcomes
        .iter()
        .filter_map(|(n, o)| {
            if let HostOutcome::Failed { task, .. } = o {
                if task == "deliberate failure" {
                    return Some(n);
                }
            }
            None
        })
        .collect();
    assert_eq!(
        failed.len(),
        3,
        "expected all 3 hosts to fail at the failing task, got: {failed:?}"
    );

    // The third task must NOT have produced its file on any host.
    for c in &containers {
        let out = c.docker_exec(&["test", "-e", "/tmp/rsansible-should-not-exist"])?;
        assert!(
            !out.status.success(),
            "third task ran when it shouldn't have on a container"
        );
    }

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

// Inline copy of examples/hello.yaml. Kept here rather than read at runtime
// so the test is hermetic; if examples/hello.yaml drifts, this is the
// canonical contract.
const EXAMPLE_PLAYBOOK: &str = r#"
- name: greet
  hosts: all
  strategy: per_task
  on_failure: stop
  tasks:
    - name: say hi via shell
      shell: "printf 'hello from %s\\n' \"$(hostname)\""
    - name: drop a marker file
      write_file:
        path: /tmp/rsansible-hello
        mode: 0o644
        content: |
          hello from rsansible
    - name: prove the file is there
      exec:
        argv: [/bin/cat, /tmp/rsansible-hello]
        env:
          LC_ALL: C
        timeout_ms: 5000
"#;

// Silence unused-import warnings when this file is half-compiled.
#[allow(dead_code)]
fn _silence(_: PathBuf, _: Arc<()>) {}
