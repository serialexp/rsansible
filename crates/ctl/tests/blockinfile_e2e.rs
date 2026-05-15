//! End-to-end Phase 3 test: `blockinfile:` idempotent block edit.

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
async fn blockinfile_seeds_updates_and_removes() -> Result<()> {
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

    let pb_path = examples_dir().join("blockinfile.yaml");
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

    // Before absent: both blocks should be present, body should be the
    // *updated* alpha=10/gamma=3 (not the initial alpha=1/beta=2).
    let before = read_file(&container, "/tmp/rsansible-bi-before-absent")?;
    assert!(
        before.contains("# BEGIN ANSIBLE MANAGED BLOCK"),
        "default begin marker present: {before:?}"
    );
    assert!(
        before.contains("# END ANSIBLE MANAGED BLOCK"),
        "default end marker present"
    );
    assert!(before.contains("alpha=10"), "updated body present");
    assert!(before.contains("gamma=3"), "updated body present");
    assert!(
        !before.contains("beta=2"),
        "stale body should have been replaced; got: {before}"
    );
    assert!(
        before.contains("## ---- BEGIN APP ----"),
        "custom marker block present: {before:?}"
    );
    assert!(before.contains("app_port=8080"), "custom block body present");

    // After absent: default block + markers gone; custom block + section
    // anchor still there.
    let final_text = read_file(&container, "/tmp/rsansible-bi-final")?;
    assert!(
        !final_text.contains("# BEGIN ANSIBLE MANAGED BLOCK"),
        "default block markers removed: {final_text:?}"
    );
    assert!(
        !final_text.contains("alpha=10"),
        "default block body removed: {final_text:?}"
    );
    assert!(
        final_text.contains("## ---- BEGIN APP ----"),
        "custom marker block survives: {final_text:?}"
    );
    assert!(
        final_text.contains("# section: app"),
        "section anchor preserved: {final_text:?}"
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
