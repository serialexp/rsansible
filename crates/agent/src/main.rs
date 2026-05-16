//! rsansible agent.
//!
//! Pushed to a target host over SSH, exec'd, talks framed binschema over its
//! own stdin/stdout to the controller. Self-unlinks its on-disk binary on
//! startup so cleanup is automatic on exit. Logs go to stderr; stdout is
//! strictly the wire protocol.

#![forbid(unsafe_code)]

mod facts;
mod modules;
mod writer;

use std::sync::Arc;

use anyhow::Context;
use rsansible_wire::{msg, read_frame, Message};
use tokio::io::BufReader;
use tracing::{debug, error, info, warn};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    // Stdout writer: a dedicated tokio task drains an mpsc of Messages and
    // writes them as frames. Handlers send through the channel without ever
    // touching stdout directly, so we never race on writes.
    let stdout = tokio::io::stdout();
    let (writer_tx, writer_handle) = writer::spawn(stdout);

    // Send Hello as the first frame so the controller knows we're up.
    let hello = facts::gather(AGENT_VERSION).await;
    writer_tx
        .send(hello)
        .await
        .context("sending Hello — controller dropped its stdin?")?;

    let mut stdin = BufReader::new(tokio::io::stdin());
    let ctx = Arc::new(modules::Context::new(writer_tx.clone()));

    loop {
        let frame = match read_frame(&mut stdin).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                info!("controller closed stdin cleanly; exiting");
                break;
            }
            Err(e) => {
                error!(error = %e, "frame read failed; exiting");
                return Err(e.into());
            }
        };

        match frame {
            Message::TaskDispatch(td) => {
                // Sequential per-host execution. Even when controller strategy
                // is "per_play" (which interleaves tasks across hosts at the
                // controller), an individual agent still receives dispatches
                // one at a time per the protocol.
                let seq = td.seq;
                let check_mode = td.check_mode != 0;
                debug!(seq, check_mode, op = ?std::mem::discriminant(&td.op), "dispatching");
                if let Err(e) = modules::dispatch(&ctx, seq, td.op, check_mode).await {
                    // Module-internal errors should already have been reported
                    // as TaskError. If we end up here, log loudly.
                    error!(seq, error = %e, "module dispatch returned an error after handling");
                }
            }
            Message::Bye(_) => {
                info!("received Bye; flushing and exiting");
                break;
            }
            Message::Ping(_) => {
                // Clock-skew probe. T2 is captured right after the read
                // identifies this as a Ping; T3 is captured just before
                // queuing the Pong. Any queue-drain latency between T3
                // and the actual stdout write rolls into the controller's
                // RTT measurement and shows up as half-RTT noise on the
                // offset estimate — fine for a one-shot startup probe.
                let agent_recv = msg::now_unix_ns();
                let agent_sent = msg::now_unix_ns();
                ctx.emit(msg::pong(agent_recv, agent_sent)).await;
            }
            // The controller should never send these — they're agent → ctrl
            // messages. Tolerate them by logging and continuing rather than
            // crashing the loop.
            unexpected @ (Message::Hello(_)
            | Message::TaskProgress(_)
            | Message::TaskDone(_)
            | Message::TaskError(_)
            | Message::Pong(_)) => {
                warn!(?unexpected, "ignoring ctrl→agent message of unexpected variant");
            }
        }
    }

    // Drop the sender so the writer task drains and exits.
    drop(writer_tx);
    drop(ctx);
    writer_handle.await.ok();
    Ok(())
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
