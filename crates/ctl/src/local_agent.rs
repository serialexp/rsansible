//! Forward-mode back-channel agent listener — the LAPTOP side.
//!
//! The remote forwarder reaches back to the operator's laptop via SSH
//! `-R <remote-sock>:<local-sock>`, which reverse-forwards a unix
//! socket. Whatever the forwarder writes to its remote socket arrives
//! here on `<local-sock>`. This module owns that local socket.
//!
//! Two subcommand entry points live here:
//!
//! - [`cmd_local_agent_listen`] — bind the listener, accept
//!   connections forever. Each connection starts with the
//!   `BECOME: …\n` preamble parsed by [`back_channel::parse_preamble`].
//!   For `BecomeKey::None` we drive `run_agent_loop` in-process over
//!   the unix stream; for `BecomeKey::As(user)` we spawn
//!   `sudo -n -u <user> -- /proc/self/exe local-agent --inner` and
//!   bidirectionally proxy bytes between the stream and the child's
//!   stdio. NOPASSWD sudoers required (same contract as the SSH path).
//!
//! - [`cmd_local_agent_inner`] — the sudo'd subprocess target: drives
//!   the agent loop on this process's stdin/stdout. No listener, no
//!   network, just runs the same loop the pushed `rsansible-agent`
//!   binary would but as the sudo'd user on the laptop.
//!
//! ## Why two pieces and not one
//!
//! The listener has to run as the operator (so sudo can elevate from
//! it). The sudo'd inner runs as the becomed user. Splitting the
//! responsibilities means each process sees exactly the privileges
//! it should — the listener never reads files as root, the inner
//! never opens the unix socket.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tracing::{error, info, warn};

use crate::back_channel::parse_preamble;
use crate::become_::BecomeKey;

/// Listen on `socket_path` for back-channel connections from the
/// remote forwarder and run an agent loop (in-process or sudo'd) per
/// accepted connection. Loops forever — exits only on listener error
/// or SIGTERM-equivalent.
///
/// The caller is expected to have stripped/created the socket path
/// already (we do an unlink-then-bind here too, but a stale socket
/// from a previous crashed listener could still be present).
pub async fn cmd_local_agent_listen(socket_path: PathBuf) -> Result<()> {
    // Best-effort cleanup of any stale socket file. Bind will fail
    // with EADDRINUSE otherwise.
    let _ = tokio::fs::remove_file(&socket_path).await;
    let listener = UnixListener::bind(&socket_path).with_context(|| {
        format!("binding local-agent unix socket {}", socket_path.display())
    })?;
    info!(
        socket = %socket_path.display(),
        "local-agent listener up; awaiting back-channel connections",
    );

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "accept() failed on local-agent listener; exiting");
                return Err(e).context("accepting back-channel connection");
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                warn!(error = %format!("{e:#}"), "back-channel connection ended with error");
            }
        });
    }
}

/// Per-connection handler. Reads the BECOME preamble, then either runs
/// the agent loop in-process (None) or proxies to a sudo'd subprocess
/// (As(user)).
async fn handle_connection(mut stream: UnixStream) -> Result<()> {
    let preamble = read_preamble_line(&mut stream)
        .await
        .context("reading BECOME preamble from back-channel connection")?;
    let key = parse_preamble(&preamble)?;
    info!(become = %key.label(), "back-channel connection accepted");

    match key {
        BecomeKey::None => {
            // Drive the agent loop directly on this thread's tokio
            // task. Same operator uid, no subprocess.
            let (reader, writer) = stream.into_split();
            rsansible_agent::run_agent_loop(reader, writer)
                .await
                .context("in-process local-agent loop exited with error")?;
        }
        BecomeKey::As(user) => {
            run_sudo_proxy(stream, &user).await?;
        }
    }
    Ok(())
}

/// Read a single line (terminated by `\n`) byte by byte from `stream`.
/// We deliberately don't use `BufReader::read_line` because that
/// prefetches arbitrarily — we MUST leave subsequent bytes (the agent
/// loop's framed protocol) untouched in the stream. Preambles are
/// tiny, so byte-at-a-time is fine.
async fn read_preamble_line(stream: &mut UnixStream) -> Result<String> {
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.context("reading preamble byte")?;
        if n == 0 {
            bail!("back-channel connection closed before sending BECOME preamble");
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() > 256 {
            bail!("BECOME preamble line exceeded 256 bytes without terminator");
        }
    }
    String::from_utf8(buf).context("BECOME preamble not valid UTF-8")
}

/// Spawn `sudo -n -u <user> -- /proc/self/exe local-agent --inner` and
/// bidirectionally copy bytes between the unix stream and the child's
/// stdio. The inner process runs the agent loop on its stdin/stdout.
async fn run_sudo_proxy(stream: UnixStream, user: &str) -> Result<()> {
    // Defense in depth: parse_preamble already rejected anything but
    // alnum+`_-`, but this is the splice point into argv, so assert
    // again.
    if !user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        bail!("refusing to sudo to unsafe user {user:?}");
    }

    let self_exe = std::env::current_exe().context("locating /proc/self/exe for sudo target")?;
    let mut child = Command::new("sudo")
        .args(["-n", "-u", user, "--"])
        .arg(&self_exe)
        .arg("local-agent")
        .arg("--inner")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning sudo for back-channel become as {user}"))?;

    let mut child_stdin = child
        .stdin
        .take()
        .context("sudo subprocess missing stdin pipe")?;
    let mut child_stdout = child
        .stdout
        .take()
        .context("sudo subprocess missing stdout pipe")?;

    let (mut sock_read, mut sock_write) = stream.into_split();

    // socket → child stdin
    let to_child = async move {
        let r = tokio::io::copy(&mut sock_read, &mut child_stdin).await;
        // EOF on the socket means the controller closed; close child
        // stdin so the agent loop sees its own EOF and exits cleanly.
        let _ = child_stdin.shutdown().await;
        r
    };

    // child stdout → socket
    let from_child = async move {
        let r = tokio::io::copy(&mut child_stdout, &mut sock_write).await;
        // child exited; close write side so peer sees EOF.
        let _ = sock_write.shutdown().await;
        r
    };

    let (a, b) = tokio::join!(to_child, from_child);
    a.context("proxying socket → sudo-child stdin")?;
    b.context("proxying sudo-child stdout → socket")?;

    let status = child.wait().await.context("awaiting sudo child")?;
    if !status.success() {
        warn!(?status, %user, "sudo'd local-agent inner exited non-zero");
    }
    Ok(())
}

/// Subcommand entry: drive the agent loop on this process's
/// stdin/stdout. Used as the sudo'd subprocess target by
/// [`run_sudo_proxy`]; not invoked directly by users.
pub async fn cmd_local_agent_inner() -> Result<()> {
    rsansible_agent::run_agent_loop(tokio::io::stdin(), tokio::io::stdout())
        .await
        .context("local-agent --inner loop exited with error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    /// Smoke test: listener binds, a client connects + writes a
    /// `BECOME: none\n` preamble, the listener accepts and runs the
    /// in-process agent loop. We verify by reading the Hello frame
    /// back. Then we send Bye and confirm the connection closes.
    #[tokio::test]
    async fn listener_accepts_none_and_drives_agent_loop() {
        use rsansible_wire::{msg, read_frame, write_frame, Message};

        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("back.sock");

        // Spawn listener as a background task.
        let sock_clone = sock.clone();
        let listener = tokio::spawn(async move {
            // We don't expect this to ever return Ok in this test —
            // the test drops the listener task at the end.
            let _ = cmd_local_agent_listen(sock_clone).await;
        });

        // Give the listener a tick to bind.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(sock.exists(), "listener socket did not appear in time");

        let mut client = UnixStream::connect(&sock).await.expect("client connect");
        client
            .write_all(b"BECOME: none\n")
            .await
            .expect("write preamble");
        client.flush().await.unwrap();

        // First inbound frame should be Hello.
        let first = read_frame(&mut client).await.unwrap().expect("hello frame");
        match first {
            Message::Hello(_) => {}
            other => panic!("expected Hello, got {other:?}"),
        }

        // Send Bye to shut down the loop cleanly.
        let (mut r, mut w) = client.split();
        write_frame(&mut w, &msg::bye()).await.unwrap();
        // After Bye, read side should EOF.
        let after = read_frame(&mut r).await.unwrap();
        assert!(after.is_none(), "expected EOF after Bye, got {after:?}");

        listener.abort();
    }

    #[tokio::test]
    async fn listener_rejects_malformed_preamble() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("back.sock");

        let sock_clone = sock.clone();
        let listener = tokio::spawn(async move {
            let _ = cmd_local_agent_listen(sock_clone).await;
        });

        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(sock.exists());

        let mut client = UnixStream::connect(&sock).await.unwrap();
        client.write_all(b"GARBAGE\n").await.unwrap();
        client.flush().await.unwrap();

        // The connection handler should error and drop. Reading should
        // see EOF.
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "expected EOF after malformed preamble");

        listener.abort();
    }
}
