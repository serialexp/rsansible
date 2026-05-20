//! rsansible agent — library entry point.
//!
//! The agent is normally invoked as the pushed `rsansible-agent` binary that
//! talks framed binschema on its own stdin/stdout. Forward mode reuses the
//! same loop in-process inside the controller binary (subcommand
//! `rsansible local-agent`) to drive `connection: local` tasks back from a
//! remote forwarder. This module exposes the loop as
//! [`run_agent_loop`] over arbitrary `AsyncRead` + `AsyncWrite`, so the same
//! code path serves both call sites.
//!
//! The binary's `main.rs` is a thin wrapper that wires this up against the
//! process's stdin/stdout plus the self-unlink discipline. Anything that needs
//! to call the loop without those side effects (forward-mode local-agent, unit
//! tests) goes through this entry point instead.

#![forbid(unsafe_code)]

pub mod facts;
pub mod modules;
pub mod writer;

use std::sync::Arc;

use anyhow::Context as _;
use rsansible_wire::{msg, read_frame, Message};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::{debug, error, info, warn};

/// The agent's package version, exposed so the binary wrapper and any
/// in-process embedder send the same `Hello.version` string.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Drive the agent's request loop against an arbitrary reader/writer pair.
///
/// `reader` is the inbound message stream (framed binschema), `writer` is the
/// outbound stream. The loop:
///
/// 1. Sends a [`Hello`] frame immediately so the peer knows the agent is up.
/// 2. Reads frames until EOF or `Bye`, dispatching `TaskDispatch` ops via
///    [`modules::dispatch`] and answering `Ping` with `Pong`.
/// 3. Drains the writer task on exit so all queued frames are flushed.
///
/// The caller is responsible for any process-level setup that should happen
/// once per invocation (tracing init, self-unlink, etc.). Those concerns live
/// in `main.rs` for the pushed-binary path; the forward-mode `local-agent`
/// caller does its own setup before invoking us.
///
/// [`Hello`]: rsansible_wire::Message::Hello
pub async fn run_agent_loop<R, W>(reader: R, writer: W) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Stdout writer: a dedicated tokio task drains an mpsc of Messages and
    // writes them as frames. Handlers send through the channel without ever
    // touching the writer directly, so we never race on writes.
    let (writer_tx, writer_handle) = writer::spawn(writer);

    // Send Hello as the first frame so the peer knows we're up.
    let hello = facts::gather(AGENT_VERSION).await;
    writer_tx
        .send(hello)
        .await
        .context("sending Hello — peer dropped its read side?")?;

    let mut reader = BufReader::new(reader);
    let ctx = Arc::new(modules::Context::new(writer_tx.clone()));

    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                info!("peer closed read side cleanly; exiting");
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
                // and the actual write rolls into the peer's RTT
                // measurement and shows up as half-RTT noise on the
                // offset estimate — fine for a one-shot startup probe.
                let agent_recv = msg::now_unix_ns();
                let agent_sent = msg::now_unix_ns();
                ctx.emit(msg::pong(agent_recv, agent_sent)).await;
            }
            // The peer should never send these — they're agent → ctrl
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
