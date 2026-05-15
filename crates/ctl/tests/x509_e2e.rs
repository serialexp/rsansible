//! End-to-end test for the x509 family.
//!
//! Runs `examples/x509.yaml` against a single sshd container, twice.
//!
//! First run:
//!   * `openssl_privatekey` generates an Ed25519 key controller-side
//!     and ships it via OpWriteFile (`changed: true`).
//!   * `openssl_csr_pipe` signs a CSR with the cached key
//!     (controller-side, no wire dispatch).
//!   * `x509_certificate_pipe` self-signs the CSR (also controller-side).
//!   * `write_file` lands the cert PEM at `/tmp/rsansible-x509.crt`.
//!
//! Second run (immediately, against the same container):
//!   * `openssl_privatekey` must NOT regenerate / re-ship the key —
//!     the contract is "existing key wins" (idempotency by file
//!     presence). The test asserts `changed: false` on that task by
//!     inspecting the orchestrator's per-task RunReport bookkeeping.
//!
//! Run with: `cargo test -p rsansible-ctl --test x509_e2e -- --ignored`.

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
async fn x509_full_chain_and_idempotent_privkey() -> Result<()> {
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

    let pb_path = examples_dir().join("x509.yaml");

    // ---------- run #1 — full generation chain ----------
    {
        let pb = playbook::load(&pb_path)
            .with_context(|| format!("loading {}", pb_path.display()))?;
        playbook::validate(&pb, Some(&inv)).context("validate run #1")?;
        rsansible_ctl::template::precompile_all(&pb).context("precompile run #1")?;

        let mut spec = RunSpec::new(inv.clone(), pb, agent_bytes.clone());
        spec.max_concurrent_hosts = 1;
        let report = orchestrator::run(spec).await.context("run #1")?;
        eprintln!("run #1 report = {report:#?}");
        assert!(!report.stopped_early, "run #1 should complete");
        for (name, outcome) in &report.host_outcomes {
            assert_eq!(*outcome, HostOutcome::Ok, "host {name}: {outcome:?}");
        }
    }

    // Cert and CSR PEMs should now be on disk in the container.
    let cert_pem = read_file(&container, "/tmp/rsansible-x509.crt")?;
    assert!(
        cert_pem.starts_with("-----BEGIN CERTIFICATE-----"),
        "cert PEM head: {:?}",
        &cert_pem[..cert_pem.len().min(80)]
    );
    assert!(
        cert_pem.trim_end().ends_with("-----END CERTIFICATE-----"),
        "cert PEM tail"
    );
    let csr_pem = read_file(&container, "/tmp/rsansible-x509.csr")?;
    assert!(
        csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
        "csr PEM head: {:?}",
        &csr_pem[..csr_pem.len().min(80)]
    );

    // Key file should be on disk with mode 0600.
    let stat_out = container.docker_exec(&["stat", "-c", "%a", "/tmp/rsansible-x509.key"])?;
    assert!(stat_out.status.success(), "stat key file");
    let mode = String::from_utf8_lossy(&stat_out.stdout).trim().to_string();
    assert_eq!(mode, "600", "key mode (got {mode:?})");

    // First run must have reported the privkey task as changed=true
    // (key didn't exist).
    let first_changed = read_file(&container, "/tmp/rsansible-x509-key-changed")?;
    assert_eq!(
        first_changed.trim(),
        "true",
        "run #1 privkey changed flag (got {first_changed:?})"
    );

    // ---------- run #2 — privkey must be idempotent ----------
    //
    // The marker file gets overwritten with the new run's value.
    // After run #2, `/tmp/rsansible-x509-key-changed` should hold
    // "False" — the key already exists on disk, the agent's
    // only_if_missing short-circuit (or the controller's probe
    // branch) returned no-op, and the register's `changed` field
    // is false.
    {
        let pb = playbook::load(&pb_path)?;
        playbook::validate(&pb, Some(&inv))?;
        rsansible_ctl::template::precompile_all(&pb)?;

        let mut spec = RunSpec::new(inv.clone(), pb, agent_bytes.clone());
        spec.max_concurrent_hosts = 1;
        let report = orchestrator::run(spec).await.context("run #2")?;
        eprintln!("run #2 report = {report:#?}");
        assert!(!report.stopped_early, "run #2 should complete");
        for (name, outcome) in &report.host_outcomes {
            assert_eq!(*outcome, HostOutcome::Ok, "host {name}: {outcome:?}");
        }
    }

    let second_changed = read_file(&container, "/tmp/rsansible-x509-key-changed")?;
    assert_eq!(
        second_changed.trim(),
        "false",
        "run #2 privkey changed flag must be false (got {second_changed:?})"
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
