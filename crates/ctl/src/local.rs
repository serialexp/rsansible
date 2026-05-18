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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tracing::{info, warn};

use rsansible_wire::{read_frame, Message};

use crate::become_::BecomeKey;
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

/// Local-transport analog of [`crate::ssh::SshSession`]: holds the
/// on-disk path of the materialized agent binary plus a display
/// label. Cheap to clone shape-wise (only owned strings/paths) — the
/// expensive step is `write_agent_binary` which lays the bytes down.
///
/// One session backs N pooled processes (one per [`BecomeKey`]).
/// Each `spawn_agent_process` call execs the same binary path under
/// a different identity.
pub struct LocalSession {
    pub agent_path: PathBuf,
    pub label: String,
}

/// Materialize the agent bytes to a temp file on the controller
/// filesystem and chmod 0700. Returns the kept path — the file lives
/// for the rest of the run and the OS reaps `$TMPDIR` eventually.
///
/// We use `NamedTempFile::into_temp_path().keep()` rather than a
/// permanent file by hand because the intermediate `TempPath` gives
/// us atomic-create-with-unique-suffix without us writing the
/// retry-on-collision loop. Linux holds the inode alive via every
/// child process that has it open, so even if `$TMPDIR` is on a
/// short-lived tmpfs we're fine for the duration of any pooled
/// agents.
///
/// Splitting "materialize" from "spawn" lets the pool write the
/// binary once and spawn N child processes (one per `BecomeKey`)
/// against the same path — instead of N temp files.
pub fn write_agent_binary(agent_binary: &[u8]) -> Result<PathBuf> {
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
    let agent_path: PathBuf = agent_path.keep().context("keep agent temp file")?;
    Ok(agent_path)
}

/// Spawn one agent process against an already-materialized binary
/// path under the identity implied by `key`. Mirrors
/// `ssh::spawn_agent_channel` for the local transport: child stdin /
/// stdout become the wire, Hello is read, clock-skew probe runs,
/// returns an [`AgentConn`].
///
/// `BecomeKey::None` execs the binary directly — the agent runs as
/// the controller user.
/// `BecomeKey::As(u)` wraps in `sudo -n -u <u> -- <agent>` — same
/// non-interactive contract as the SSH path, NOPASSWD required, no
/// prompt fallback.
///
/// The returned `AgentConn` carries `TransportKeepalive::Local(child)`
/// — the conn owns its child process, so dropping the conn reaps it.
pub async fn spawn_agent_process(
    session: &LocalSession,
    key: &BecomeKey,
) -> Result<AgentConn> {
    // `RSANSIBLE_AGENT_KEEP_BINARY=1` tells the agent NOT to self-unlink
    // its on-disk binary at startup. The pool may spawn additional agents
    // (one per become-config) from the same on-disk path during the same
    // run, so the file must persist for the lifetime of the LocalSession.
    let mut command = match key {
        BecomeKey::None => {
            let mut c = Command::new(&session.agent_path);
            c.env("RSANSIBLE_AGENT_KEEP_BINARY", "1");
            c
        }
        // `sudo -n` — fail fast if a password would be prompted,
        // matching the SSH path's `become` contract. Sudo's default
        // `env_reset` strips the caller env, so route through `env`
        // to set the keep-binary var for the agent itself.
        BecomeKey::As(user) => {
            let mut c = Command::new("sudo");
            c.args(["-n", "-u", user.as_str(), "--", "env", "RSANSIBLE_AGENT_KEEP_BINARY=1"]);
            c.arg(&session.agent_path);
            c
        }
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // stderr inherits — agent logs land in the controller's
        // terminal, which is the convenient default for a play that
        // explicitly opted into local execution.
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "spawning local agent {:?} ({})",
                session.agent_path,
                key.label()
            )
        })?;

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
        .with_context(|| {
            format!(
                "reading Hello from local agent {} ({})",
                session.label,
                key.label()
            )
        })?
        .ok_or_else(|| {
            anyhow!(
                "local agent {} ({}) closed stdout before sending Hello",
                session.label,
                key.label()
            )
        })?;
    let hello = match first {
        Message::Hello(h) => h,
        other => bail!(
            "first frame from local agent {} ({}) was not Hello: {other:?}",
            session.label,
            key.label()
        ),
    };
    info!(
        host = %session.label,
        agent_version = %hello.agent_version,
        kernel = %hello.kernel,
        transport = "local",
        become = %key.label(),
        "agent up",
    );

    // Clock-skew probe is still useful even though offset will be
    // ~0: the RTT measurement informs the wire-cost heuristic, which
    // picks ship-blind vs probe-first for things like
    // `openssl_privatekey`. Local subprocess RTT is microseconds —
    // the heuristic will naturally pick blind for everything, which
    // is the right default for "same machine".
    let (clock_offset_ns, clock_rtt_ns) =
        match crate::ssh::probe_clock_skew(&mut stream, &session.label).await {
            Ok((offset, rtt)) => (offset, rtt),
            Err(e) => {
                warn!(host = %session.label, become = %key.label(), "local clock-skew probe failed (continuing): {e:#}");
                (0, 0)
            }
        };

    Ok(AgentConn {
        label: session.label.clone(),
        remote_path: session.agent_path.to_string_lossy().into_owned(),
        hello,
        stream: Box::pin(stream) as BoxedAgentStream,
        clock_offset_ns,
        clock_rtt_ns,
        _keepalive: TransportKeepalive::Local(Box::new(child)),
    })
}

/// Thin convenience wrapper preserving the legacy single-conn shape:
/// materializes the agent and spawns one `BecomeKey::None` child.
/// Used by standalone callers (smoke tests, profilers) and by the
/// orchestrator's initial connect phase until the pool refactor
/// lands at the dispatch sites.
pub async fn connect_local(label: String, agent_binary: &[u8]) -> Result<AgentConn> {
    let agent_path = write_agent_binary(agent_binary)?;
    let session = LocalSession { agent_path, label };
    spawn_agent_process(&session, &BecomeKey::None).await
}

/// Lower-level entry retained for tests that have a real on-disk
/// path already (e.g. point at `target/release/rsansible-agent`).
/// Equivalent to constructing a `LocalSession` and calling
/// `spawn_agent_process(&session, &BecomeKey::None)`.
pub async fn spawn_against_path(label: String, agent_path: &Path) -> Result<AgentConn> {
    let session = LocalSession {
        agent_path: agent_path.to_path_buf(),
        label,
    };
    spawn_agent_process(&session, &BecomeKey::None).await
}
