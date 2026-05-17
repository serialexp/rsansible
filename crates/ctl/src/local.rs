//! Local-transport flavour of `connect_and_push`.
//!
//! For plays declared with `connection: local`, the controller and the
//! "target host" are the same machine. Instead of pushing the agent
//! binary over SSH and dispatching wire ops to a remote sshd, we
//! spawn the agent binary as a child process and talk to it over
//! stdin / stdout. The wire protocol stays identical — every wire op
//! the orchestrator emits goes through the same framing helpers as
//! the SSH path — so the rest of the dispatch code doesn't need to
//! know which transport is in play.
//!
//! Why subprocess and not "embed the agent crate directly":
//!   * Same wire protocol → same code paths in the orchestrator,
//!     same logs, same backpressure, same test fixtures. A second
//!     code path through the executor would be a maintenance hazard
//!     and we'd lose feature parity the first time a wire op grew.
//!   * The agent already serializes its own state (working dirs,
//!     async-job book-keeping). Reusing that machinery via a child
//!     process is cheaper than re-plumbing it in-process.
//!   * Local stdio is functionally free compared to a single SSH
//!     handshake; the startup penalty of a Command::spawn is
//!     ~milliseconds.

use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tracing::{info, warn};

use rsansible_wire::{read_frame, Message};

use crate::ssh::{AgentConn, BoxedAgentStream, TransportKeepalive};

/// Bidirectional adapter: wraps the child's stdin (write side) and
/// stdout (read side) into a single duplex object so the orchestrator
/// can hand it to `read_frame` / `write_frame` interchangeably with
/// the SSH variant.
///
/// We don't use `tokio::io::join` here because:
///   * the channel-flavoured `Join` type isn't `Unpin` without a
///     dance, and our `BoxedAgentStream` is `Pin<Box<...>>`;
///   * having a real struct makes it obvious in stack traces that
///     a frame failure came from the local-subprocess transport.
pub struct LocalStdioStream {
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl AsyncRead for LocalStdioStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for LocalStdioStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        Pin::new(&mut me.stdin).poll_write(cx, buf)
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.stdin).poll_flush(cx)
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.stdin).poll_shutdown(cx)
    }
}

/// Spawn the agent binary as a subprocess and bring up a wire-level
/// `AgentConn` against its stdio. Mirrors `ssh::connect_and_push` for
/// the SSH path: writes the agent bytes to a temp file, execs it,
/// reads the `Hello` frame, runs the clock-skew probe (offset will
/// be near-zero — same machine), returns the conn.
///
/// `agent_binary` is the in-memory bytes loaded by the CLI; we
/// materialize them to a temp file on the controller filesystem and
/// chmod +x before spawning. The temp file lives only for the
/// duration of this function (we keep its path inside the conn so
/// the process can keep mmap'ing it, but the unlink-on-drop is
/// handled by `tempfile` after the child has started — Linux keeps
/// the inode alive while the process holds a reference).
pub async fn connect_local(
    label: String,
    agent_binary: &[u8],
) -> Result<AgentConn> {
    // Materialize the agent on disk so we can exec it. We use a
    // `NamedTempFile` for the spawn step then immediately detach the
    // path via `.into_temp_path()` so we can `keep()` it for the run
    // — Linux holds the inode alive via the running process, but the
    // explicit path makes troubleshooting easier when something goes
    // sideways mid-run.
    let mut tf = tempfile::Builder::new()
        .prefix("rsansible-agent-")
        .tempfile()
        .context("creating temp file for local agent binary")?;
    use std::io::Write as _;
    tf.write_all(agent_binary)
        .context("writing local agent bytes to temp file")?;
    tf.flush().context("flushing local agent temp file")?;
    // chmod 0700 — owner exec, nothing else. We don't share this
    // binary with anyone.
    use std::os::unix::fs::PermissionsExt as _;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(tf.path(), perms)
        .context("chmod 0700 on local agent temp file")?;
    let agent_path = tf.into_temp_path();
    // Detach: file stays around for the run, deleted when the
    // returned `agent_path` is dropped at end-of-conn. We hold the
    // `TempPath` inside the conn via the Child handle's drop guard
    // — but tokio's `Child` doesn't have a slot for arbitrary
    // payloads, so instead we just `keep()` and rely on a temp-dir
    // cleanup; the path is in $TMPDIR so it gets reaped by the OS.
    let agent_path: std::path::PathBuf = agent_path.keep().context("keep agent temp file")?;
    spawn_against_path(label, &agent_path).await
}

/// Lower-level entry: spawn an already-on-disk agent path. Useful
/// for tests where you don't want the bytes-to-tempfile round-trip
/// and have a real path already.
pub async fn spawn_against_path(label: String, agent_path: &Path) -> Result<AgentConn> {
    let mut child = Command::new(agent_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // stderr inherits — agent logs land in the controller's
        // terminal, which is the convenient default for a play that
        // explicitly opted into local execution.
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning local agent {:?}", agent_path))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("local agent: stdin not piped"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("local agent: stdout not piped"))?;
    let mut stream = LocalStdioStream { stdin, stdout };

    let first = read_frame(&mut stream)
        .await
        .with_context(|| format!("reading Hello from local agent {label}"))?
        .ok_or_else(|| anyhow!("local agent {label} closed stdout before sending Hello"))?;
    let hello = match first {
        Message::Hello(h) => h,
        other => bail!("first frame from local agent {label} was not Hello: {other:?}"),
    };
    info!(
        host = %label,
        agent_version = %hello.agent_version,
        kernel = %hello.kernel,
        transport = "local",
        "agent up",
    );

    // Clock-skew probe is still useful even though offset will be
    // ~0: the RTT measurement informs the wire-cost heuristic, which
    // picks ship-blind vs probe-first for things like
    // `openssl_privatekey`. Local subprocess RTT is microseconds —
    // the heuristic will naturally pick blind for everything, which
    // is the right default for "same machine".
    let (clock_offset_ns, clock_rtt_ns) =
        match crate::ssh::probe_clock_skew(&mut stream, &label).await {
            Ok((offset, rtt)) => (offset, rtt),
            Err(e) => {
                warn!(host = %label, "local clock-skew probe failed (continuing): {e:#}");
                (0, 0)
            }
        };

    Ok(AgentConn {
        label: label.clone(),
        remote_path: agent_path.to_string_lossy().into_owned(),
        hello,
        stream: Box::pin(stream) as BoxedAgentStream,
        clock_offset_ns,
        clock_rtt_ns,
        _keepalive: TransportKeepalive::Local(Box::new(child)),
    })
}
