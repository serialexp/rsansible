//! End-to-end exercise of `--limit`.
//!
//! Stands up three sshd containers (acting as `web1`, `web2`, `web3`,
//! all members of the `webservers` group plus a `db1` member of `dbs`
//! — actually just three because the test budget doesn't justify a
//! fourth) and runs a trivial marker-writing playbook against the
//! inventory five times, varying `--limit` on each run.
//!
//! Each task writes `/tmp/rsansible-limit-marker` on whatever host
//! receives it. After each scenario we scrub the marker on every
//! container and assert which hosts ended up with one.
//!
//! Scenarios:
//!   1. (no limit)               → all three hosts marked
//!   2. --limit web1             → only web1
//!   3. --limit 'web*,!web2'     → web1 + web3
//!   4. --limit webservers[0]    → web1 (first member by group decl order)
//!   5. --limit nope             → orchestrator bails before SSH

mod common;

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

const PLAYBOOK: &str = r#"
- name: limit demo
  hosts: webservers
  gather_facts: false
  tasks:
    - name: write marker
      shell: "echo marker > /tmp/rsansible-limit-marker"
"#;

struct Scenario {
    name: &'static str,
    limit: Vec<String>,
    /// Subset of `["web1","web2","web3"]` that should have a marker after this run.
    expect_marked: &'static [&'static str],
    /// If true, expect orchestrator::run to fail (zero-match preflight).
    expect_error: bool,
}

#[tokio::test]
#[ignore]
async fn limit_filter_selects_only_matching_hosts() -> Result<()> {
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
    let containers = start_three_containers().await?;

    let tmp = tempfile::TempDir::new()?;
    let pb_path = tmp.path().join("limit_demo.yaml");
    std::fs::write(&pb_path, PLAYBOOK)?;

    let scenarios: &[Scenario] = &[
        Scenario {
            name: "no limit",
            limit: vec![],
            expect_marked: &["web1", "web2", "web3"],
            expect_error: false,
        },
        Scenario {
            name: "--limit web1",
            limit: vec!["web1".into()],
            expect_marked: &["web1"],
            expect_error: false,
        },
        Scenario {
            name: "--limit web*,!web2",
            limit: vec!["web*,!web2".into()],
            expect_marked: &["web1", "web3"],
            expect_error: false,
        },
        Scenario {
            name: "--limit webservers[0]",
            limit: vec!["webservers[0]".into()],
            expect_marked: &["web1"],
            expect_error: false,
        },
        Scenario {
            name: "--limit nope",
            limit: vec!["nope".into()],
            expect_marked: &[],
            expect_error: true,
        },
    ];

    for sc in scenarios {
        // Scrub the marker on every container before this scenario.
        for c in &containers {
            let _ = c.docker_exec(&["rm", "-f", "/tmp/rsansible-limit-marker"])?;
        }

        let inv = three_host_inventory(&containers);
        let pb = playbook::load(&pb_path)
            .with_context(|| format!("loading {}", pb_path.display()))?;
        playbook::validate(&pb, Some(&inv)).context("validate")?;
        rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

        let mut spec = RunSpec::new(inv, pb, agent_bytes.clone());
        spec.max_concurrent_hosts = 4;
        spec.limit = sc.limit.clone();
        let result = orchestrator::run(spec).await;

        if sc.expect_error {
            assert!(
                result.is_err(),
                "scenario {:?}: expected orchestrator::run to error, got {result:?}",
                sc.name
            );
            // No SSH should have happened; markers stay scrubbed.
            for name in ["web1", "web2", "web3"] {
                let c = container_by_name(&containers, name);
                assert!(
                    !marker_exists(c)?,
                    "scenario {:?}: {name} should have no marker after error",
                    sc.name,
                );
            }
            continue;
        }

        let report = result.with_context(|| format!("scenario {:?}", sc.name))?;
        assert!(
            !report.stopped_early,
            "scenario {:?}: stopped early; report = {report:#?}",
            sc.name,
        );
        for (host, outcome) in &report.host_outcomes {
            match outcome {
                HostOutcome::Ok | HostOutcome::NotTargeted => {}
                other => panic!(
                    "scenario {:?}: host {host} unexpected outcome {other:?}",
                    sc.name
                ),
            }
        }

        let expected: std::collections::BTreeSet<&str> =
            sc.expect_marked.iter().copied().collect();
        for name in ["web1", "web2", "web3"] {
            let c = container_by_name(&containers, name);
            let present = marker_exists(c)?;
            let want = expected.contains(name);
            assert_eq!(
                present, want,
                "scenario {:?}: {name} marker presence = {present}, want {want}",
                sc.name,
            );
        }
    }

    Ok(())
}

fn marker_exists(c: &SshdContainer) -> Result<bool> {
    let out = c.docker_exec(&["test", "-f", "/tmp/rsansible-limit-marker"])?;
    Ok(out.status.success())
}

fn container_by_name<'a>(containers: &'a [SshdContainer], name: &str) -> &'a SshdContainer {
    let idx = match name {
        "web1" => 0,
        "web2" => 1,
        "web3" => 2,
        other => panic!("unknown host name {other}"),
    };
    &containers[idx]
}

fn three_host_inventory(containers: &[SshdContainer]) -> Inventory {
    let mut hosts = BTreeMap::new();
    let names = ["web1", "web2", "web3"];
    for (name, c) in names.iter().zip(containers.iter()) {
        hosts.insert(
            (*name).to_string(),
            Host {
                host: "127.0.0.1".into(),
                port: c.host_port,
                user: c.user.clone(),
                key_path: Some(c.key_path.clone()),
                inline_vars: BTreeMap::new(),
                // Declaration order matters: webservers[0] picks the
                // first member.
                member_of: vec!["all".to_string(), "webservers".to_string()],
            },
        );
    }
    let mut groups = BTreeMap::new();
    groups.insert(
        "all".to_string(),
        names.iter().map(|n| (*n).to_string()).collect(),
    );
    groups.insert(
        "webservers".to_string(),
        names.iter().map(|n| (*n).to_string()).collect(),
    );
    Inventory {
        hosts,
        groups,
        all_vars: BTreeMap::new(),
        group_inline_vars: BTreeMap::new(),
    }
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
