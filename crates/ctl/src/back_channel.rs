//! Forward-mode back-channel transport — agents that live on the
//! operator's laptop, reachable from a remote controller via a unix
//! socket whose other end is tunneled back over SSH.
//!
//! ## Why this exists
//!
//! Forward mode relocates the controller next to the targets so per-op
//! RTT collapses. But `connection: local` still has to mean "where the
//! operator initiated the run" (Bart's design decision #4). The
//! back-channel is how the remote controller dispatches local-mode
//! tasks back to the laptop: it opens a unix-socket connection to a
//! path that SSH `-R` reverse-forwarded from the laptop, the laptop's
//! `local-agent` subcommand accepts the connection, and the agent loop
//! runs there with the operator's identity.
//!
//! ## Wire shape per connection
//!
//! Each connection starts with a single ASCII preamble line:
//!
//! - `BECOME: none\n` — the laptop runs the agent in-process, as the
//!   operator's uid.
//! - `BECOME: as <user>\n` — the laptop spawns a subprocess via
//!   `sudo -n -u <user> -- /proc/self/exe local-agent --inner` and
//!   proxies bytes between the socket and the child's stdio. NOPASSWD
//!   sudoers required, matching the SSH-path become contract.
//!
//! After the preamble, the rest of the connection is the standard
//! binschema agent wire: agent's `Hello` frame first, then the
//! controller's `Ping`/`Pong` clock probe, then ordinary dispatches.
//!
//! Implementation detail: the controller side opens ONE connection per
//! `BecomeKey`, just like SSH/Local pools open one channel/process per
//! key. The laptop side spawns one in-process loop (or sudo subprocess)
//! per accepted connection.

use anyhow::{anyhow, bail, Context, Result};
use rsansible_wire::{read_frame, Message};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tracing::{info, warn};

use crate::become_::BecomeKey;
use crate::ssh::{AgentConn, BoxedAgentStream, TransportKeepalive};

/// Address of the back-channel listener on THIS machine.
///
/// The path is created by SSH `-R` reverse-forwarding from the laptop;
/// connecting to it tunnels through SSH session B back to the laptop's
/// `local-agent` listener. The `label` is the inventory hostname this
/// pool is bound to (always `localhost` or whatever the playbook
/// targets with `connection: local`), used purely for diagnostics.
#[derive(Debug, Clone)]
pub struct BackChannelSession {
    /// Diagnostic label for `info!` / error messages. Almost always
    /// `localhost`, but plays can attach `connection: local` to any
    /// host name.
    pub label: String,
    /// Filesystem path of the unix socket on this machine. The other
    /// end (via SSH `-R`) is a unix socket on the laptop where
    /// `rsansible local-agent --listen` is accepting connections.
    pub socket_path: PathBuf,
}

/// Format the BECOME preamble line. Single source of truth for both
/// sides of the wire so the controller's write and the listener's read
/// stay in lockstep.
pub fn preamble_for(key: &BecomeKey) -> String {
    match key {
        BecomeKey::None => "BECOME: none\n".to_string(),
        BecomeKey::As(user) => format!("BECOME: as {user}\n"),
    }
}

/// Parse the preamble line back into a `BecomeKey`. Lives next to the
/// formatter so a future protocol change touches one site. Returns
/// `Err` on any malformed input — the listener uses the error to drop
/// the connection with a clear diagnostic.
pub fn parse_preamble(line: &str) -> Result<BecomeKey> {
    let line = line
        .strip_suffix('\n')
        .or_else(|| Some(line))
        .unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let rest = line
        .strip_prefix("BECOME: ")
        .ok_or_else(|| anyhow!("back-channel preamble missing `BECOME: ` prefix: {line:?}"))?;
    if rest == "none" {
        return Ok(BecomeKey::None);
    }
    if let Some(user) = rest.strip_prefix("as ") {
        if user.is_empty() {
            bail!("back-channel preamble `BECOME: as ` missing username");
        }
        // Sanity-check: usernames are alnum + `_-`. Refuse anything
        // wilder so we never splice attacker-influenced strings into
        // `sudo -u <user>`. The string came over a unix socket that's
        // SSH-tunneled from the operator's own machine — but the same
        // rule as `is_safe_remote_path`: build it ourselves, assert
        // before splicing.
        if !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        {
            bail!("back-channel preamble has unsafe username {user:?}");
        }
        return Ok(BecomeKey::As(user.to_string()));
    }
    bail!("back-channel preamble has unrecognized body {rest:?}");
}

/// Open one back-channel connection for `key` and bring it up as a
/// full `AgentConn` (Hello + clock-skew probe done).
///
/// Mirrors `ssh::spawn_agent_channel` and `local::spawn_agent_process`
/// for the back-channel transport: a fresh connection per key,
/// returned ready to dispatch ops against.
pub async fn spawn_back_channel_conn(
    session: &BackChannelSession,
    key: &BecomeKey,
) -> Result<AgentConn> {
    let mut stream = UnixStream::connect(&session.socket_path)
        .await
        .with_context(|| {
            format!(
                "connecting back-channel socket {} for {}",
                session.socket_path.display(),
                key.label()
            )
        })?;

    // BECOME preamble. Single write_all — preamble is tiny so we don't
    // need to worry about partial writes (kernel pipe buffers easily
    // hold a 50-byte line) but write_all handles it generically anyway.
    stream
        .write_all(preamble_for(key).as_bytes())
        .await
        .with_context(|| {
            format!(
                "writing BECOME preamble on back-channel {} for {}",
                session.socket_path.display(),
                key.label()
            )
        })?;
    stream.flush().await.context("flushing back-channel preamble")?;

    let first = read_frame(&mut stream)
        .await
        .with_context(|| {
            format!(
                "reading Hello from back-channel {} ({})",
                session.label,
                key.label()
            )
        })?
        .ok_or_else(|| {
            anyhow!(
                "back-channel {} ({}) closed before sending Hello",
                session.label,
                key.label()
            )
        })?;
    let hello = match first {
        Message::Hello(h) => h,
        other => bail!(
            "first frame from back-channel {} ({}) was not Hello: {other:?}",
            session.label,
            key.label()
        ),
    };
    info!(
        host = %session.label,
        agent_version = %hello.agent_version,
        kernel = %hello.kernel,
        transport = "back-channel",
        become = %key.label(),
        "agent up",
    );

    let (clock_offset_ns, clock_rtt_ns) =
        match crate::ssh::probe_clock_skew(&mut stream, &session.label).await {
            Ok((offset, rtt)) => (offset, rtt),
            Err(e) => {
                warn!(
                    host = %session.label,
                    become = %key.label(),
                    "back-channel clock-skew probe failed (continuing): {e:#}",
                );
                (0, 0)
            }
        };

    Ok(AgentConn {
        label: session.label.clone(),
        // No on-disk binary here — back-channel reuses the laptop's
        // in-process loop. Surface the socket path for diagnostics.
        remote_path: session.socket_path.to_string_lossy().into_owned(),
        hello,
        stream: Box::pin(stream) as BoxedAgentStream,
        clock_offset_ns,
        clock_rtt_ns,
        // The pool owns the BackChannelSession; the conn is one of
        // potentially several connections sharing it. Same shape as
        // `Pooled` for the other transports.
        _keepalive: TransportKeepalive::Pooled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_roundtrip_none() {
        let line = preamble_for(&BecomeKey::None);
        assert_eq!(line, "BECOME: none\n");
        assert_eq!(parse_preamble(&line).unwrap(), BecomeKey::None);
    }

    #[test]
    fn preamble_roundtrip_as_user() {
        let key = BecomeKey::As("postgres".into());
        let line = preamble_for(&key);
        assert_eq!(line, "BECOME: as postgres\n");
        assert_eq!(parse_preamble(&line).unwrap(), key);
    }

    /// Trailing `\r\n` from a misbehaving writer must still parse
    /// cleanly. The laptop listener reads with `read_line` which on
    /// some platforms / pipes preserves `\r`; eating it here means the
    /// wire stays tolerant.
    #[test]
    fn preamble_accepts_crlf_line_ending() {
        assert_eq!(parse_preamble("BECOME: none\r\n").unwrap(), BecomeKey::None);
        assert_eq!(
            parse_preamble("BECOME: as root\r\n").unwrap(),
            BecomeKey::As("root".into())
        );
    }

    #[test]
    fn preamble_rejects_unsafe_usernames() {
        assert!(parse_preamble("BECOME: as ../etc/passwd\n").is_err());
        assert!(parse_preamble("BECOME: as user; rm -rf /\n").is_err());
        assert!(parse_preamble("BECOME: as user$x\n").is_err());
        // Spaces inside the username would let an attacker inject sudo
        // flags — refuse.
        assert!(parse_preamble("BECOME: as user --shell\n").is_err());
    }

    #[test]
    fn preamble_rejects_empty_username() {
        assert!(parse_preamble("BECOME: as \n").is_err());
    }

    #[test]
    fn preamble_rejects_missing_prefix() {
        assert!(parse_preamble("hello world\n").is_err());
        assert!(parse_preamble("BECOMES: none\n").is_err());
        assert!(parse_preamble("become: none\n").is_err());
    }

    #[test]
    fn preamble_accepts_alnum_underscore_dash_usernames() {
        // Common real-world shapes.
        for user in &["postgres", "etcd", "service-account", "deploy_bot", "u01"] {
            assert_eq!(
                parse_preamble(&format!("BECOME: as {user}\n")).unwrap(),
                BecomeKey::As((*user).into())
            );
        }
    }
}
