//! End-to-end Phase 4 test: `uri:` HTTP client.
//!
//! Runs `examples/uri.yaml` against a single sshd container. The
//! playbook stands up a `busybox httpd` server inside the container
//! and the uri module hits it from the agent (also in-container), so
//! we don't need to bridge networking back to the test host.
//!
//! Verifies four things:
//!   1. GET 200 lifts `register.status`, `register.json.<field>`,
//!      and `register.content` (with `return_content: yes`).
//!   2. `register.json` is the parsed response body (not the envelope).
//!   3. status_code mismatch + ignore_errors → `register.failed` is
//!      true and `register.status` is still populated (envelope is
//!      lifted even on a failed status check, mirroring `shell:`'s
//!      surface-stdout-on-nonzero-rc contract).
//!   4. HEAD reports status 200 and `register.changed == 0`
//!      (GET/HEAD are non-mutating; Ansible's `changed` contract).

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
async fn uri_lifts_envelope_into_register() -> Result<()> {
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

    let pb_path = examples_dir().join("uri.yaml");
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

    // 1+2. GET — status, parsed json.foo / json.n, returned content.
    let get_out = read_file(&container, "/tmp/rsansible-uri-get")?;
    let lines: Vec<&str> = get_out.lines().collect();
    assert_eq!(lines.first().copied(), Some("200"), "status: {get_out:?}");
    assert_eq!(lines.get(1).copied(), Some("bar"), "json.foo: {get_out:?}");
    assert_eq!(lines.get(2).copied(), Some("42"), "json.n: {get_out:?}");
    assert_eq!(
        lines.get(3).copied(),
        Some(r#"{"foo":"bar","n":42}"#),
        "content body verbatim: {get_out:?}"
    );

    // 3. status_code mismatch — failed=true + status still 200.
    let bad_out = read_file(&container, "/tmp/rsansible-uri-bad")?;
    let lines: Vec<&str> = bad_out.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some("true"),
        "failed: {bad_out:?}"
    );
    assert_eq!(
        lines.get(1).copied(),
        Some("200"),
        "status lifted even on failure: {bad_out:?}"
    );

    // 4. HEAD — status=200, changed=False (no mutation for GET/HEAD).
    let head_out = read_file(&container, "/tmp/rsansible-uri-head")?;
    let lines: Vec<&str> = head_out.lines().collect();
    assert_eq!(lines.first().copied(), Some("200"), "HEAD status: {head_out:?}");
    assert_eq!(
        lines.get(1).copied(),
        Some("false"),
        "HEAD changed=false: {head_out:?}"
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
