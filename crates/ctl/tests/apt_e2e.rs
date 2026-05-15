//! End-to-end Phase 3 test: `apt:` package management.
//!
//! Uses stub `apt-get` + `dpkg-query` scripts planted in /usr/local/bin
//! so we can exercise the full agent code path against an Alpine sshd
//! container that has no real apt. The playbook handles the staging.

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
async fn apt_drives_install_remove_latest() -> Result<()> {
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

    let pb_path = examples_dir().join("apt.yaml");
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

    // Batch install (#3): only curl should be installed, not nginx.
    let batch_log = read_file(&container, "/tmp/rsansible-apt-stub/log.batch")?;
    assert!(
        batch_log.contains("install -y curl"),
        "expected `install -y curl` in batch log: {batch_log:?}"
    );
    assert!(
        !batch_log.contains("install -y nginx"),
        "should not re-install nginx in batch: {batch_log:?}"
    );

    // Final scenario (#8): update precedes install in the final log.
    let final_log = read_file(&container, "/tmp/rsansible-apt-stub/log.final")?;
    let update_pos = final_log.find("update").ok_or_else(|| {
        anyhow!("update line missing from final log: {final_log:?}")
    })?;
    let install_pos = final_log.find("install -y").ok_or_else(|| {
        anyhow!("install line missing from final log: {final_log:?}")
    })?;
    assert!(
        update_pos < install_pos,
        "update must precede install in: {final_log:?}"
    );

    // Scenario #9: `package:` (auto) routes through the apt backend
    // because the planted /usr/local/bin/apt-get satisfies the
    // PATH probe. The auto-detect log must show an `install -y htop`
    // invocation matching the per-manager `apt:` form.
    let auto_log = read_file(&container, "/tmp/rsansible-apt-stub/log.auto")?;
    assert!(
        auto_log.contains("install -y htop"),
        "expected `install -y htop` from auto-detected package: in: {auto_log:?}"
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
