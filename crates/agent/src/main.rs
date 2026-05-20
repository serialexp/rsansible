//! rsansible agent — pushed-binary entry point.
//!
//! Pushed to a target host over SSH, exec'd, talks framed binschema over its
//! own stdin/stdout to the controller. Self-unlinks its on-disk binary on
//! startup so cleanup is automatic on exit. Logs go to stderr; stdout is
//! strictly the wire protocol.
//!
//! The loop itself lives in `lib.rs::run_agent_loop` so that forward mode's
//! `rsansible local-agent` subcommand can drive the same code path
//! in-process against a session-B socket. This wrapper only owns the
//! pushed-binary concerns: tokio runtime, self-unlink, tracing init.

#![forbid(unsafe_code)]

use rsansible_agent::run_agent_loop;
use tracing::{debug, warn};

// Multi-thread runtime: `tokio::io::stdin()` and `tokio::io::stdout()` are
// implemented via `spawn_blocking`, so a runtime with a blocking pool plus at
// least one worker is needed to avoid stalls when stdio + child-process I/O
// run concurrently. We allow tokio its default worker count — for an agent
// pushed to a remote box, the cost is negligible and the robustness is worth
// it.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // Best-effort: unlink our own binary from disk. The kernel keeps the
    // running image alive via the inode, so this is safe; the file just
    // disappears from the filesystem immediately, which is the cleanup goal.
    // If it fails (read-only fs, weird permissions), log and carry on — the
    // controller can still issue a `rm` after Bye if it wants belt+braces.
    // Self-unlink so cleanup is automatic on exit — the kernel keeps the
    // running image alive via the inode. Skip when RSANSIBLE_AGENT_KEEP_BINARY
    // is set (used by the integration tests, which share one on-disk binary
    // across many child invocations).
    if std::env::var_os("RSANSIBLE_AGENT_KEEP_BINARY").is_none() {
        if let Ok(path) = std::env::current_exe() {
            match std::fs::remove_file(&path) {
                Ok(()) => debug!(?path, "unlinked own binary"),
                Err(e) => warn!(?path, error = %e, "failed to unlink own binary; continuing"),
            }
        }
    }

    run_agent_loop(tokio::io::stdin(), tokio::io::stdout()).await
}

fn init_tracing() {
    // Plain level filter, not `EnvFilter`. `EnvFilter` parses
    // `module=level` directives which pulls `regex_automata` /
    // `regex_syntax` / `matchers` into the agent — ~165 KiB of .text
    // for a knob nobody uses on a pushed binary. Take only a level name
    // (`trace`/`debug`/`info`/`warn`/`error`) from the env var; default
    // to `warn`. If anyone ever needs per-module filtering on the
    // agent (vs the controller, which keeps full EnvFilter), they can
    // turn this back on at the cost of ~165 KiB.
    use std::str::FromStr;
    use tracing::level_filters::LevelFilter;
    let level = std::env::var("RSANSIBLE_AGENT_LOG")
        .ok()
        .and_then(|s| LevelFilter::from_str(s.trim()).ok())
        .unwrap_or(LevelFilter::WARN);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr) // critical: stdout is wire-protocol-only
        .with_target(false)
        .init();
}
