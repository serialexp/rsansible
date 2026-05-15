//! End-to-end Phase 3 test: `lineinfile:` idempotent line edit.
//!
//! Runs `examples/lineinfile.yaml` against a single sshd container and
//! verifies:
//!   - create=yes seeds a file
//!   - re-running the same task is a no-op (`changed=false`)
//!   - regexp + line replaces the value
//!   - insertafter places a line after a matching anchor
//!   - backrefs substitutes capture groups
//!   - state=absent removes matching lines
//!
//! Internal `assert:` tasks in the playbook validate the `changed`
//! reporting; this test reads the final file off the container and
//! cross-checks the line set.

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
async fn lineinfile_create_replace_insert_remove() -> Result<()> {
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

    let pb_path = examples_dir().join("lineinfile.yaml");
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

    // Pre-absent snapshot should still contain the marker.
    let before = read_file(&container, "/tmp/rsansible-li-before-absent")?;
    let before_lines: Vec<&str> = before.lines().collect();
    assert!(
        before_lines.contains(&"foo=42"),
        "value should have been replaced: {before:?}"
    );
    assert!(
        before_lines.contains(&"BAR=HI"),
        "backrefs should have rewritten bar: {before:?}"
    );
    assert!(
        before_lines.contains(&"marker"),
        "marker should still be present pre-absent: {before:?}"
    );

    // Final snapshot — marker removed; other lines preserved; bar
    // appears immediately after foo (insertafter check).
    let final_text = read_file(&container, "/tmp/rsansible-li-final")?;
    let final_lines: Vec<&str> = final_text.lines().collect();
    assert!(
        final_lines.contains(&"foo=42"),
        "foo should still be present: {final_text:?}"
    );
    assert!(
        final_lines.contains(&"BAR=HI"),
        "BAR should still be present: {final_text:?}"
    );
    assert!(
        !final_lines.contains(&"marker"),
        "marker should have been removed: {final_text:?}"
    );

    // Ordering: bar was inserted after foo, so BAR=HI (backrefs target)
    // should still come right after foo=42.
    let foo_idx = final_lines.iter().position(|l| *l == "foo=42");
    let bar_idx = final_lines.iter().position(|l| *l == "BAR=HI");
    assert!(
        foo_idx.is_some() && bar_idx.is_some() && bar_idx.unwrap() == foo_idx.unwrap() + 1,
        "BAR=HI should immediately follow foo=42; lines = {final_lines:?}"
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
