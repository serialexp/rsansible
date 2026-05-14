//! End-to-end Phase 1a programming-model test.
//!
//! Runs `examples/programming_model.yaml` against three sshd containers
//! and asserts:
//!   * Every host reports Ok.
//!   * The imported task fired (greet_result was registered, then a
//!     subsequent `when:`-gated write_file used the captured value).
//!   * The `when: 1 == 2` task did NOT produce its file (skip path).
//!   * The `loop:` produced three marker files per host with templated
//!     content using `item` and `inventory_hostname`.
//!   * A second test forces an `assert:` failure and verifies that
//!     `on_failure: stop` halts the playbook before the next task runs.

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
async fn three_container_programming_model_run() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let containers = start_three_containers().await?;
    let inv = build_inventory(&containers);

    let pb_path = examples_dir().join("programming_model.yaml");
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

    for c in &containers {
        // when-fired marker exists and contains the captured hostname.
        let out = c.docker_exec(&["cat", "/tmp/rsansible-when-fired"])?;
        assert!(
            out.status.success(),
            "expected /tmp/rsansible-when-fired on a container; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let body = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            body.starts_with("hello from "),
            "captured hostname looked wrong: {body:?}"
        );

        // when-false task must NOT have produced its file.
        let ghost = c.docker_exec(&["test", "-e", "/tmp/rsansible-should-not-exist"])?;
        assert!(
            !ghost.status.success(),
            "skipped-by-when task ran when it shouldn't have"
        );

        // Loop produced one file per item.
        for item in ["alpha", "beta", "gamma"] {
            let path = format!("/tmp/rsansible-loop-{item}");
            let out = c.docker_exec(&["cat", &path])?;
            assert!(
                out.status.success(),
                "missing loop file {path}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let body = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(
                body.contains(&format!("name={item}")),
                "loop file content wrong: {body:?}"
            );
            assert!(
                body.contains("host="),
                "loop file missing host=<inventory_hostname>: {body:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore]
async fn assert_failure_triggers_stop() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let containers = start_three_containers().await?;
    let inv = build_inventory(&containers);

    // Hand-built playbook: set a fact, assert that the fact is wrong,
    // expect on_failure=stop to halt before the third task can run.
    let pb_yaml = r#"
- name: assert-and-stop
  hosts: all
  strategy: per_task
  on_failure: stop
  tasks:
    - name: stash fact
      set_fact:
        truth: false
    - name: assert truth
      assert:
        that:
          - "truth"
        msg: "truth was false"
    - name: must not run
      write_file:
        path: /tmp/rsansible-assert-ghost
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
        "failing assert under on_failure=stop should halt the playbook"
    );
    let failed = report
        .host_outcomes
        .values()
        .filter(|o| matches!(o, HostOutcome::Failed { task, .. } if task == "assert truth"))
        .count();
    assert_eq!(failed, 3, "all 3 hosts should fail at the assert step");

    for c in &containers {
        let out = c.docker_exec(&["test", "-e", "/tmp/rsansible-assert-ghost"])?;
        assert!(
            !out.status.success(),
            "third task ran when it shouldn't have"
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

fn examples_dir() -> PathBuf {
    // <repo>/crates/ctl/Cargo.toml → ../../examples
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace layout")
        .join("examples")
}
