//! End-to-end Phase 3 test: `become:` argv-wrapping.
//!
//! Runs a tiny playbook against a sudo-enabled sshd container and
//! verifies three things:
//!   1. play-level `become: true` defaults flow into a task that
//!      doesn't override → shell ran as root
//!   2. per-task `become_user: <name>` overrides the play default →
//!      exec ran as the named user
//!   3. per-task `become: false` opts out → shell ran as the SSH login
//!      user, NOT as root
//!
//! The container is set up by `SshdContainer::start_with_sudo()`:
//! sudo is installed, `test` gets NOPASSWD sudo, and a service account
//! `becometest` is created so we can prove the wrap actually changed
//! uid (a wrap that did nothing would still pass a "ran as root" test
//! if the SSH user happened to be root — using a distinct service
//! user avoids that false positive).

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
async fn become_wraps_argv_and_changes_user() -> Result<()> {
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
    let container = SshdContainer::start_with_sudo().await?;
    let inv = single_host_inventory(&container);

    let pb_path = examples_dir().join("become.yaml");
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 1;
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

    // 1. play-level become (no per-task override) → root.
    let as_root = read_file(&container, "/tmp/rsansible-become-shell-root")?;
    assert_eq!(
        as_root.trim(),
        "root",
        "shell with play default `become: true` should run as root; got {as_root:?}"
    );

    // 2. per-task become_user override → becometest.
    let as_becometest = read_file(&container, "/tmp/rsansible-become-exec-becometest")?;
    assert_eq!(
        as_becometest.trim(),
        "becometest",
        "exec with `become_user: becometest` should run as becometest; got {as_becometest:?}"
    );

    // 3. per-task `become: false` → ran as the SSH user (no sudo).
    let no_become = read_file(&container, "/tmp/rsansible-become-noop")?;
    assert_eq!(
        no_become.trim(),
        "test",
        "task with `become: false` should run as the SSH login user (test); got {no_become:?}"
    );

    Ok(())
}

fn read_file(c: &SshdContainer, path: &str) -> Result<String> {
    // Use -u 0 so we can read root-owned files (the first task wrote
    // /tmp/rsansible-become-shell-root as root).
    let out = c.docker_exec_root(&["cat", path])?;
    if !out.status.success() {
        return Err(anyhow!(
            "missing {path}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace layout")
        .join("examples")
}
