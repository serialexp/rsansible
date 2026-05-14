// The orchestrator consumes everything here in the next step. Until then,
// the public surface is exercised only by the unit tests below.
#![allow(dead_code)]

//! SSH transport: open a russh session to a host, push the agent binary,
//! exec it, and hand the orchestrator a framed `AsyncRead + AsyncWrite`
//! stream for binschema-over-stdio.
//!
//! Three exec channels per host (all over one SSH session):
//!   1. `uname -m`           → arch probe (informational in v0)
//!   2. `cat > P && chmod 0755 P`  → upload the agent bytes
//!   3. `P`                  → run the agent; the channel's stream is the
//!                              framed-protocol pipe for the rest of the run
//!
//! Host-key verification in v0 is "accept anything with a warning". A
//! `known_hosts`-backed implementation is a v0.1 task; the policy is
//! plumbed through `ConnectOptions::strict_host_key` so callers can opt in
//! once that lands.

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self, Handle, Msg};
use russh::keys::ssh_key::PublicKey;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, ChannelStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use rsansible_wire::{read_frame, Message};

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_path: Option<PathBuf>,
    /// If true, fail the connect when we can't verify the host key.
    /// v0 default is `false` (accept-with-warning); known_hosts plumbing
    /// lands in v0.1.
    pub strict_host_key: bool,
}

impl ConnectOptions {
    pub fn from_host(h: &crate::inventory::Host) -> Self {
        Self {
            host: h.host.clone(),
            port: h.port,
            user: h.user.clone(),
            key_path: h.key_path.clone(),
            strict_host_key: false,
        }
    }
}

/// An authenticated SSH session running an agent. The `stream` field is
/// the framed-protocol pipe; readers/writers come from `tokio::io::split`.
pub struct AgentConn {
    pub label: String,
    pub remote_path: String,
    /// Reported by the agent's `Hello` frame.
    pub hello: rsansible_wire::generated::HelloOutput,
    pub stream: ChannelStream<Msg>,
    /// Kept alive so the session doesn't drop while we're using `stream`.
    _handle: Handle<Client>,
}

#[derive(Clone)]
pub struct Client {
    label: String,
    strict_host_key: bool,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
        if self.strict_host_key {
            // v0.1: look up in known_hosts.
            warn!(host = %self.label, "strict_host_key requested but verifier not implemented; rejecting");
            return Ok(false);
        }
        debug!(host = %self.label, "accepting unverified host key (v0)");
        Ok(true)
    }
}

/// Connect + auth + arch-probe + upload-agent + exec-agent + read-Hello.
pub async fn connect_and_push(opts: &ConnectOptions, agent_binary: &[u8]) -> Result<AgentConn> {
    let label = format!("{}@{}:{}", opts.user, opts.host, opts.port);
    let key_path = resolve_key_path(opts.key_path.as_deref())
        .with_context(|| format!("resolving SSH key for {label}"))?;
    let key = load_secret_key(&key_path, None)
        .with_context(|| format!("loading SSH key {}", key_path.display()))?;

    let config = Arc::new(client::Config {
        // Half-hour idle is generous but a long playbook can sit waiting on
        // a slow earlier step. We send keepalives implicitly via traffic;
        // bumping this further is cheap if anyone reports a timeout.
        inactivity_timeout: Some(Duration::from_secs(60 * 30)),
        ..Default::default()
    });
    let handler = Client {
        label: label.clone(),
        strict_host_key: opts.strict_host_key,
    };
    let mut handle = client::connect(config, (opts.host.as_str(), opts.port), handler)
        .await
        .with_context(|| format!("ssh connect {label}"))?;

    let rsa_hash = handle
        .best_supported_rsa_hash()
        .await
        .with_context(|| format!("negotiating RSA hash alg with {label}"))?
        .flatten();
    let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
    let auth = handle
        .authenticate_publickey(&opts.user, key_with_alg)
        .await
        .with_context(|| format!("ssh auth {label}"))?;
    if !auth.success() {
        bail!("ssh: publickey auth failed for {label}");
    }

    // Arch probe. We don't gate the upload on this yet (v0 ships one agent
    // binary), but we log it for visibility and so a mismatched binary later
    // produces a meaningful "tried to run x86_64 ELF on aarch64" diagnostic.
    let arch_str = run_remote_command(&mut handle, "uname -m").await?;
    debug!(host = %label, arch = %arch_str.trim(), "remote arch");

    let remote_path = remote_agent_path();
    push_binary(&mut handle, &remote_path, agent_binary)
        .await
        .with_context(|| format!("pushing agent to {label}:{remote_path}"))?;

    let channel = handle
        .channel_open_session()
        .await
        .with_context(|| format!("opening agent exec channel to {label}"))?;
    channel
        .exec(true, remote_path.as_bytes())
        .await
        .with_context(|| format!("exec {remote_path} on {label}"))?;

    let mut stream = channel.into_stream();

    let first = read_frame(&mut stream)
        .await
        .with_context(|| format!("reading Hello from {label}"))?
        .ok_or_else(|| anyhow!("agent on {label} closed stdout before sending Hello"))?;
    let hello = match first {
        Message::Hello(h) => h,
        other => bail!("first frame from {label} was not Hello: {other:?}"),
    };
    info!(
        host = %label,
        agent_version = %hello.agent_version,
        kernel = %hello.kernel,
        "agent up",
    );

    Ok(AgentConn {
        label,
        remote_path,
        hello,
        stream,
        _handle: handle,
    })
}

/// Run a one-shot command on the remote, collecting stdout into a String.
/// Discards stderr. Errors if exit status is non-zero.
async fn run_remote_command(handle: &mut Handle<Client>, cmd: &str) -> Result<String> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, cmd.as_bytes()).await?;
    let mut stdout: Vec<u8> = Vec::new();
    let mut exit: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { .. } => {}
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            _ => {}
        }
    }
    match exit {
        Some(0) => Ok(String::from_utf8_lossy(&stdout).into_owned()),
        Some(code) => bail!("remote `{cmd}` exited with {code}"),
        None => bail!("remote `{cmd}` closed without exit status"),
    }
}

/// Upload `bytes` to `remote_path` by `exec`ing `cat > path && chmod 0755 path`
/// and shoving the bytes down stdin. `remote_path` must be ASCII-safe — we
/// build it ourselves, but assert before splicing into a shell command.
async fn push_binary(handle: &mut Handle<Client>, remote_path: &str, bytes: &[u8]) -> Result<()> {
    if !is_safe_remote_path(remote_path) {
        bail!("internal: refusing to splice {remote_path:?} into shell command");
    }
    let channel = handle.channel_open_session().await?;
    let cmd = format!("cat > {remote_path} && chmod 0755 {remote_path}");
    channel.exec(true, cmd.as_bytes()).await?;

    // `Channel::data` accepts an `AsyncRead`; `&[u8]` implements that.
    channel.data(bytes).await?;
    channel.eof().await?;

    // Split before draining so we keep `wait()` access without `&mut channel`.
    let (mut read_half, _write_half) = channel.split();
    let mut exit: Option<u32> = None;
    while let Some(msg) = read_half.wait().await {
        if let ChannelMsg::ExitStatus { exit_status } = msg {
            exit = Some(exit_status);
        }
    }
    match exit {
        Some(0) => Ok(()),
        Some(code) => bail!("remote `cat > {remote_path}` exited with {code}"),
        None => bail!("remote `cat > {remote_path}` closed without exit status"),
    }
}

/// Sanity-check the remote path before we splice it into a shell command.
/// We build the path ourselves; this asserts nothing unexpected slipped in.
fn is_safe_remote_path(p: &str) -> bool {
    !p.is_empty()
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
}

/// Produce a unique-enough remote path under /tmp. Not security-sensitive —
/// we want to avoid clashing with stale files from a prior crashed run, that
/// is all. The agent self-unlinks at startup anyway.
fn remote_agent_path() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    format!("/tmp/.rsansible-agent.{nanos:016x}")
}

fn resolve_key_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(expand_tilde_with_home(p, std::env::var_os("HOME").as_deref()));
    }
    if let Some(home) = std::env::var_os("HOME") {
        for name in &["id_ed25519", "id_ecdsa", "id_rsa"] {
            let p = PathBuf::from(&home).join(".ssh").join(name);
            if p.exists() {
                return Ok(p);
            }
        }
    }
    bail!("no SSH key found — set key_path in inventory or place one at ~/.ssh/id_ed25519")
}

/// Expand `~/...` relative to an explicit home path. Pure function so tests
/// don't have to mutate global env (`std::env::set_var` is racy under
/// parallel test execution).
fn expand_tilde_with_home(p: &Path, home: Option<&std::ffi::OsStr>) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = home {
            return PathBuf::from(home).join(rest);
        }
    }
    p.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn tilde_expanded_when_home_known() {
        let out = expand_tilde_with_home(Path::new("~/.ssh/id_rsa"), Some(OsStr::new("/home/me")));
        assert_eq!(out, Path::new("/home/me/.ssh/id_rsa"));
    }

    #[test]
    fn no_tilde_is_passthrough() {
        let out = expand_tilde_with_home(Path::new("/etc/key"), Some(OsStr::new("/home/me")));
        assert_eq!(out, Path::new("/etc/key"));
    }

    #[test]
    fn tilde_without_home_returns_input_unchanged() {
        let out = expand_tilde_with_home(Path::new("~/key"), None);
        assert_eq!(out, Path::new("~/key"));
    }

    #[test]
    fn remote_agent_path_is_safe() {
        for _ in 0..32 {
            let p = remote_agent_path();
            assert!(p.starts_with("/tmp/.rsansible-agent."), "{p}");
            assert!(is_safe_remote_path(&p), "{p}");
        }
    }

    #[test]
    fn is_safe_remote_path_rejects_shell_metacharacters() {
        assert!(is_safe_remote_path("/tmp/.rsansible-agent.0123abcd"));
        assert!(!is_safe_remote_path("/tmp/.rsansible-agent.0123 abcd")); // space
        assert!(!is_safe_remote_path("/tmp/foo$bar"));
        assert!(!is_safe_remote_path("/tmp/foo;rm -rf /"));
        assert!(!is_safe_remote_path("/tmp/`whoami`"));
        assert!(!is_safe_remote_path("")); // empty
    }
}
