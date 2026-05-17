//! End-to-end exercise of `retries:` / `until:` / `delay:`.
//!
//! Three runs against a single sshd container:
//!
//!   1. **recovers**: a shell that fails the first two times and
//!      succeeds on the third (via a counter file). With
//!      `retries: 5, delay: 0, until: r.rc == 0`, the play
//!      completes Ok and `register.attempts == 3`.
//!
//!   2. **exhausts**: a shell that always exits 0 but `until: "r.rc
//!      == 1"` can never be satisfied. `retries: 2, delay: 0` →
//!      3 total attempts, task ends Failed (Ansible flags retries
//!      exhausted as task-failed even when individual attempts
//!      succeed).
//!
//!   3. **attempts-field-absent-without-retries**: a control run
//!      where the task has no retries metadata; the register's
//!      `attempts` key is absent from the JSON shape, so
//!      `{% if r.attempts is defined %}` evaluates false. Verified
//!      by an `assert:` follow-up on the same host.

mod common;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

const PLAYBOOK_RECOVERS: &str = r#"
- name: retries-recovers
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: reset counter
      shell: "rm -f /tmp/rsansible-retry-counter"

    - name: flaky succeeds on third invocation
      shell: |
        n=$(cat /tmp/rsansible-retry-counter 2>/dev/null || echo 0)
        n=$((n + 1))
        echo $n > /tmp/rsansible-retry-counter
        if [ "$n" -ge 3 ]; then
          echo "ok on attempt $n"
        else
          echo "not yet ($n)" 1>&2
          exit 1
        fi
      register: flaky
      retries: 5
      delay: 0
      until: "flaky.rc == 0"

    - name: assert attempts surfaced and equals 3
      assert:
        that:
          - "flaky.attempts == 3"
          - "flaky.rc == 0"
        msg: "expected attempts=3 + rc=0; got attempts={{ flaky.attempts }}, rc={{ flaky.rc }}"
"#;

const PLAYBOOK_EXHAUSTS: &str = r#"
- name: retries-exhausts
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: always succeeds but until never satisfied
      shell: "true"
      register: r
      retries: 2
      delay: 0
      until: "r.rc == 1"
"#;

const PLAYBOOK_NO_RETRIES_NO_ATTEMPTS_KEY: &str = r#"
- name: no-retries-control
  hosts: all
  gather_facts: false
  on_failure: stop
  tasks:
    - name: vanilla succeed
      shell: "echo hi"
      register: r

    - name: assert attempts key absent from register
      assert:
        that:
          - "r.attempts is not defined"
          - "r.rc == 0"
        msg: "vanilla task should not surface r.attempts"
"#;

#[tokio::test]
#[ignore]
async fn retries_recovers_after_temporary_failure() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    init_tracing();

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("recovers.yaml");
    std::fs::write(&pb_path, PLAYBOOK_RECOVERS)?;

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
        "recovers: play should not have stopped early; report = {report:#?}"
    );
    for (host, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "recovers: host {host} should be Ok (assert proved attempts==3), got {outcome:?}"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore]
async fn retries_exhausts_when_until_never_satisfied() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    init_tracing();

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("exhausts.yaml");
    std::fs::write(&pb_path, PLAYBOOK_EXHAUSTS)?;

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
        "exhausts: play should have stopped early; report = {report:#?}"
    );
    let outcome = report
        .host_outcomes
        .values()
        .next()
        .expect("at least one host outcome");
    assert!(
        matches!(outcome, HostOutcome::Failed { .. }),
        "exhausts: host outcome should be Failed (retries exhausted without until), got {outcome:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn no_retries_means_attempts_key_absent_from_register() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    init_tracing();

    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let container = SshdContainer::start().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("no_retries.yaml");
    std::fs::write(&pb_path, PLAYBOOK_NO_RETRIES_NO_ATTEMPTS_KEY)?;

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
        "no-retries: play should not have stopped early; report = {report:#?}"
    );
    for (host, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "no-retries: host {host} should be Ok (assert proved attempts absent), got {outcome:?}"
        );
    }
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
