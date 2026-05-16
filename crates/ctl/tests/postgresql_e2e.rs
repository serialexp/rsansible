//! End-to-end Phase 5 test: `postgresql_query:` + `postgresql_ext:`.
//!
//! Runs `examples/postgresql.yaml` against a single sshd container.
//! The playbook installs postgres in-container (alpine apk), inits a
//! data dir, starts the server, creates a test database, and then
//! exercises the modules against the local UNIX socket.
//!
//! Verifies five things:
//!   1. SELECT — `register.query_result[0].col`, `register.rowcount`,
//!      `register.changed == false` (read-only).
//!   2. Parameterized SELECT — `register.query_result[0].doubled`
//!      reflects `$1` binding.
//!   3. CREATE + INSERT — `register.changed == true` (mutating SQL).
//!   4. `postgresql_ext: pg_trgm` first run — `register.changed == true`,
//!      `register.extension == "pg_trgm"`.
//!   5. Idempotent second run — `register.changed == false`.

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
async fn postgresql_query_and_ext_e2e() -> Result<()> {
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
    // Need sudo for installing postgres + `become_user: postgres` for
    // the query/ext tasks (peer auth requires the agent to actually be
    // running as the postgres OS user).
    let container = SshdContainer::start_with_sudo().await?;
    let inv = single_host_inventory(&container);

    let pb_path = examples_dir().join("postgresql.yaml");
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

    // 1. SELECT — rowcount=1, answer=42, greeting=hello, changed=false.
    let sel = read_file(&container, "/tmp/rsansible-pg-select")?;
    let lines: Vec<&str> = sel.lines().collect();
    assert_eq!(lines.first().copied(), Some("1"), "rowcount: {sel:?}");
    assert_eq!(lines.get(1).copied(), Some("42"), "answer: {sel:?}");
    assert_eq!(lines.get(2).copied(), Some("hello"), "greeting: {sel:?}");
    assert_eq!(
        lines.get(3).copied(),
        Some("false"),
        "SELECT is read-only, changed should be false: {sel:?}"
    );

    // 2. Parameterized — doubled = 21 * 2 = 42.
    let param = read_file(&container, "/tmp/rsansible-pg-param")?;
    let lines: Vec<&str> = param.lines().collect();
    assert_eq!(lines.first().copied(), Some("42"), "doubled: {param:?}");

    // 3. Mutating SQL — changed=true.
    let ins = read_file(&container, "/tmp/rsansible-pg-insert")?;
    let lines: Vec<&str> = ins.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some("true"),
        "INSERT should set changed=true: {ins:?}"
    );

    // 4. Extension install — changed=true, extension name lifted.
    let ext1 = read_file(&container, "/tmp/rsansible-pg-ext1")?;
    let lines: Vec<&str> = ext1.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some("true"),
        "first ext install should be changed=true: {ext1:?}"
    );
    assert_eq!(
        lines.get(1).copied(),
        Some("pg_trgm"),
        "extension name should be lifted: {ext1:?}"
    );

    // 5. Re-install — changed=false (idempotent).
    let ext2 = read_file(&container, "/tmp/rsansible-pg-ext2")?;
    let lines: Vec<&str> = ext2.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some("false"),
        "re-install should be idempotent: {ext2:?}"
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
