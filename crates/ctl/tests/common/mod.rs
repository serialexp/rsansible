//! Shared helpers for integration tests.
//!
//! Lives under `tests/common/` because cargo treats every file directly
//! in `tests/` as its own integration-test crate; a subdirectory `mod.rs`
//! is the canonical place to share code.
//!
//! Each test file `mod common; use common::...`.

pub mod sshd;

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Find `rsansible-agent` for integration tests.
///
/// The agent must be musl-static because tests run it inside alpine-based
/// sshd containers — a glibc-linked agent would fail the dynamic linker
/// before it could write a single byte. So we build for
/// `x86_64-unknown-linux-musl` using the `agent` profile.
///
/// Order:
///   1. `RSANSIBLE_AGENT_BIN` env var — escape hatch for CI/burst that
///      already has the binary somewhere convenient.
///   2. Build it via the workspace cargo and use
///      `target/x86_64-unknown-linux-musl/agent/rsansible-agent`.
pub fn locate_agent_binary() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("RSANSIBLE_AGENT_BIN") {
        let path = PathBuf::from(p);
        if !path.exists() {
            bail!("RSANSIBLE_AGENT_BIN points at non-existent path: {path:?}");
        }
        return Ok(path);
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("can't compute workspace root from {manifest_dir:?}"))?;
    const TARGET: &str = "x86_64-unknown-linux-musl";
    let status = Command::new(&cargo)
        .args([
            "build",
            "-p",
            "rsansible-agent",
            "--profile",
            "agent",
            "--target",
            TARGET,
        ])
        .current_dir(workspace_root)
        .status()
        .context("running `cargo build -p rsansible-agent --profile agent --target musl`")?;
    if !status.success() {
        bail!("cargo build for rsansible-agent failed");
    }
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"));
    let bin = target_dir.join(TARGET).join("agent").join("rsansible-agent");
    if !bin.exists() {
        bail!("expected agent at {bin:?} after build, but it isn't there");
    }
    Ok(bin)
}

/// True if integration tests requiring docker should be skipped.
///
/// Skip when `RSANSIBLE_SKIP_DOCKER_TESTS=1` or when the `docker` binary
/// isn't on PATH — so `cargo test -- --include-ignored` doesn't hard-fail
/// in environments without docker.
pub fn should_skip_docker_tests() -> bool {
    if std::env::var_os("RSANSIBLE_SKIP_DOCKER_TESTS").is_some() {
        return true;
    }
    which("docker").is_none()
}

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(prog);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
