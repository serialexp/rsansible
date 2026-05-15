//! End-to-end exercise of `--tags` / `--skip-tags`.
//!
//! Runs a synthetic 5-task playbook against a single sshd container
//! five times back-to-back, varying the tag flags on each run and
//! asserting which marker files appeared on disk.
//!
//! Task layout (each task writes `/tmp/rsansible-tags-<scenario>`):
//!   setup    — `tags: [setup]`
//!   middle   — no tags
//!   teardown — `tags: [teardown]`
//!   never    — `tags: [never]`        (only runs when explicitly tagged in)
//!   always   — `tags: [always]`       (runs unless explicitly skipped)
//!
//! Scenarios:
//!   1. No flags             → setup, middle, teardown, always (no never)
//!   2. --tags setup         → setup, always
//!   3. --skip-tags teardown → setup, middle, always
//!   4. --tags never         → never, always (always bypasses include)
//!   5. --skip-tags always   → setup, middle, teardown
//!
//! The container is reused across scenarios with the markers cleaned
//! between runs. `gather_facts: false` keeps the implicit `Gathering
//! Facts` task out of the dispatch loop so any breakage there would
//! still let this test pass — but a separate scenario validates that
//! `gather_facts: true` + `--tags setup` still gathers facts (the
//! implicit task is tagged `always`).

mod common;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

const PLAYBOOK: &str = r#"
- name: tags demo
  hosts: all
  gather_facts: false
  tasks:
    - name: clean markers
      shell: "rm -f /tmp/rsansible-tags-*"
      tags: [always]

    - name: setup task
      shell: "echo setup > /tmp/rsansible-tags-setup"
      tags: [setup]

    - name: middle task
      shell: "echo middle > /tmp/rsansible-tags-middle"

    - name: teardown task
      shell: "echo teardown > /tmp/rsansible-tags-teardown"
      tags: [teardown]

    - name: never task
      shell: "echo never > /tmp/rsansible-tags-never"
      tags: [never]

    - name: always task
      shell: "echo always > /tmp/rsansible-tags-always"
      tags: [always]
"#;

/// Each scenario name maps to (`--tags`, `--skip-tags`, expected-present, expected-absent).
struct Scenario {
    name: &'static str,
    tags: Vec<String>,
    skip_tags: Vec<String>,
    expect_present: &'static [&'static str],
    expect_absent: &'static [&'static str],
}

#[tokio::test]
#[ignore]
async fn tags_filter_selects_only_matching_tasks() -> Result<()> {
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

    // Stage the synthetic playbook under a tempdir.
    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("tags_demo.yaml");
    std::fs::write(&pb_path, PLAYBOOK)?;

    let scenarios: &[Scenario] = &[
        Scenario {
            name: "no flags",
            tags: vec![],
            skip_tags: vec![],
            expect_present: &["setup", "middle", "teardown", "always"],
            expect_absent: &["never"],
        },
        Scenario {
            name: "--tags setup",
            tags: vec!["setup".into()],
            skip_tags: vec![],
            expect_present: &["setup", "always"],
            expect_absent: &["middle", "teardown", "never"],
        },
        Scenario {
            name: "--skip-tags teardown",
            tags: vec![],
            skip_tags: vec!["teardown".into()],
            expect_present: &["setup", "middle", "always"],
            expect_absent: &["teardown", "never"],
        },
        Scenario {
            name: "--tags never",
            tags: vec!["never".into()],
            skip_tags: vec![],
            // `always` bypasses --tags; the bare `clean markers` task is
            // also tagged `always` and runs, but it just deletes the
            // file before never/always rewrite them.
            expect_present: &["never", "always"],
            expect_absent: &["setup", "middle", "teardown"],
        },
        Scenario {
            name: "--skip-tags always",
            tags: vec![],
            skip_tags: vec!["always".into()],
            // The `always`-tagged "clean markers" task ALSO gets
            // dropped under --skip-tags always — that's the documented
            // Ansible escape hatch. So leftover files from the previous
            // scenario can survive; pre-clean from the host side.
            expect_present: &["setup", "middle", "teardown"],
            expect_absent: &["always", "never"],
        },
    ];

    for sc in scenarios {
        // Manually scrub markers before each scenario, because the
        // playbook's own `clean markers` task is itself tagged
        // `always` and so gets dropped under `--skip-tags always`.
        let _ = container.docker_exec(&["sh", "-c", "rm -f /tmp/rsansible-tags-*"])?;

        let inv = single_host_inventory(&container);
        let pb = playbook::load(&pb_path)
            .with_context(|| format!("loading {}", pb_path.display()))?;
        playbook::validate(&pb, Some(&inv)).context("validate")?;
        rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

        let mut spec = RunSpec::new(inv, pb, agent_bytes.clone());
        spec.max_concurrent_hosts = 1;
        spec.tags = sc.tags.clone();
        spec.skip_tags = sc.skip_tags.clone();
        let report = orchestrator::run(spec)
            .await
            .with_context(|| format!("scenario {:?}: orchestrator", sc.name))?;
        assert!(
            !report.stopped_early,
            "scenario {:?}: playbook stopped early; report = {report:#?}",
            sc.name
        );
        for (host, outcome) in &report.host_outcomes {
            assert_eq!(
                *outcome,
                HostOutcome::Ok,
                "scenario {:?}: host {host} should be Ok, got {outcome:?}",
                sc.name
            );
        }

        for name in sc.expect_present {
            let path = format!("/tmp/rsansible-tags-{name}");
            assert!(
                marker_exists(&container, &path)?,
                "scenario {:?}: expected marker {path} to exist",
                sc.name,
            );
        }
        for name in sc.expect_absent {
            let path = format!("/tmp/rsansible-tags-{name}");
            assert!(
                !marker_exists(&container, &path)?,
                "scenario {:?}: marker {path} should not exist",
                sc.name,
            );
        }
    }

    Ok(())
}

fn marker_exists(c: &SshdContainer, path: &str) -> Result<bool> {
    let out = c.docker_exec(&["test", "-f", path])?;
    Ok(out.status.success())
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

