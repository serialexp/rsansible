//! End-to-end Phase 3 test: `stat:` filesystem probe.
//!
//! Runs `examples/stat.yaml` against a single sshd container and
//! verifies that:
//!   1. stat on a regular file populates `register.stat` with `exists`,
//!      `isreg`, `size`, and a sha256 `checksum`
//!   2. stat on a directory populates `isdir` (not `isreg`), no `checksum`
//!   3. stat on a missing path reports `exists: false`
//!   4. `when: foo_stat.stat.exists` correctly gates a follow-up task
//!      (one fires, the other is skipped)
//!
//! The container is the standard non-sudo SshdContainer — stat is
//! read-only and the agent runs as the SSH login user (test), which
//! can read everything we probe.

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
async fn stat_lifts_register_and_gates_when() -> Result<()> {
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
    let inv = single_host_inventory(&container);

    let pb_path = examples_dir().join("stat.yaml");
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 1;
    let report = orchestrator::run(spec).await.context("orchestrator")?;
    eprintln!("report = {report:#?}");
    assert!(!report.stopped_early, "playbook should run to completion");
    for (name, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "host {name} should be Ok, got {outcome:?}"
        );
    }

    // 1. Regular file.
    let file_out = read_file(&container, "/tmp/rsansible-stat-file")?;
    let lines: Vec<&str> = file_out.lines().collect();
    assert_eq!(lines.get(0).copied(), Some("true"), "exists=true: {file_out:?}");
    assert_eq!(lines.get(1).copied(), Some("true"), "isreg=true: {file_out:?}");
    assert_eq!(lines.get(2).copied(), Some("6"), "size=6 for \"hello\\n\": {file_out:?}");
    // sha256("hello\n") = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
    assert_eq!(
        lines.get(3).copied(),
        Some("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"),
        "checksum matches sha256(\"hello\\n\"): {file_out:?}"
    );

    // 2. Directory.
    let dir_out = read_file(&container, "/tmp/rsansible-stat-dir")?;
    let lines: Vec<&str> = dir_out.lines().collect();
    assert_eq!(lines.get(0).copied(), Some("true"), "/tmp exists: {dir_out:?}");
    assert_eq!(lines.get(1).copied(), Some("true"), "/tmp isdir: {dir_out:?}");
    assert_eq!(lines.get(2).copied(), Some("false"), "/tmp isreg false: {dir_out:?}");

    // 3. Missing path.
    let missing_out = read_file(&container, "/tmp/rsansible-stat-missing")?;
    assert_eq!(
        missing_out.trim(),
        "false",
        "missing path reports exists=false; got: {missing_out:?}"
    );

    // 4. `when: foo.stat.exists` gating.
    let when_yes = read_file(&container, "/tmp/rsansible-stat-when-yes")?;
    assert_eq!(
        when_yes.trim(),
        "ran",
        "conditional on existing file should have run; got: {when_yes:?}"
    );
    // The negative-case file should NOT exist.
    let out = container.docker_exec(&["cat", "/tmp/rsansible-stat-when-no"])?;
    assert!(
        !out.status.success(),
        "conditional on missing path should have been skipped (file should not exist); \
         stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    Ok(())
}

fn read_file(c: &SshdContainer, path: &str) -> Result<String> {
    let out = c.docker_exec(&["cat", path])?;
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
