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
use russh::client::{self, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::become_::BecomeKey;

/// Trait alias bundling the duplex-stream traits we need for the
/// orchestrator-to-agent pipe, plus `Send + Unpin` so it can flow
/// through tokio's mutex / boxed-future plumbing. A blanket impl
/// covers everything that already implements the four constituent
/// traits (russh's `ChannelStream<Msg>`, the local-subprocess duplex
/// from `local.rs`, mocks, …) so callers never have to implement it
/// directly.
pub trait AgentStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AgentStream for T {}

pub type BoxedAgentStream = Pin<Box<dyn AgentStream>>;

use rsansible_wire::{
    msg::{now_unix_ns, ping},
    read_frame, write_frame, Message,
};

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
    /// Duplex pipe to the agent. The orchestrator only reads/writes
    /// length-prefixed frames against this — see `read_frame` /
    /// `write_frame` in `rsansible_wire::framing`. Boxed as a trait
    /// object so the same `AgentConn` shape works for both SSH-pushed
    /// remote agents and locally-spawned subprocess agents (see
    /// `local.rs`).
    pub stream: BoxedAgentStream,
    /// Estimated offset between the agent's wall clock and the
    /// controller's, in nanoseconds. Positive iff the agent is ahead.
    /// Measured once with a single Ping/Pong right after Hello; stable
    /// for the connection (NTP-style adjustments during the run are out
    /// of scope — playbooks finish in seconds-to-minutes, drift is
    /// negligible). 0 if the probe failed.
    pub clock_offset_ns: i64,
    /// Round-trip time observed by the Ping/Pong probe, in nanoseconds.
    /// 0 if the probe failed. Useful for sanity-checking the offset
    /// estimate: a measurement with RTT >> typical task latency is
    /// suspicious.
    pub clock_rtt_ns: u64,
    /// Transport-specific keep-alive payload. For SSH this is the
    /// `russh::client::Handle` whose drop tears the session down. For
    /// local subprocess transport it's the `tokio::process::Child`
    /// handle (wrapped, see `local.rs`). The `AgentConn` doesn't
    /// inspect it — it just needs to own the value until end-of-run
    /// so the underlying transport isn't dropped out from under the
    /// stream. `pub(crate)` so `local.rs` can construct one.
    pub(crate) _keepalive: TransportKeepalive,
}

/// Opaque guard kept alive for the lifetime of an `AgentConn`.
/// Variant per transport — the orchestrator never matches on this,
/// it exists only so dropping the conn drops the right resource.
pub enum TransportKeepalive {
    /// Standalone SSH conn. Drops the session at conn-close. Used by
    /// the legacy `connect_and_push` wrapper (tests) and by any
    /// future single-shot callers that don't want a pool.
    Ssh(Handle<Client>),
    /// Local subprocess child. We wait on it at conn-close time so
    /// orphan agents don't accumulate. Used by both standalone and
    /// pool-managed local conns (each subprocess is independent).
    Local(Box<tokio::process::Child>),
    /// This conn is one slot of an `AgentPool` — the pool owns the
    /// underlying transport (e.g., the SSH `Handle`) and outlives
    /// any single slot. Dropping a pool slot tears down only the
    /// slot's channel; the session stays open for other slots.
    Pooled,
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

/// Established SSH session with the agent binary already pushed.
/// Holds the russh `Handle` (the session keepalive) and the remote
/// path of the uploaded binary; agent channels are spawned on
/// demand by `spawn_agent_channel`.
///
/// Used by `AgentPool` (pool.rs) to lazily open one channel per
/// distinct `BecomeKey`. Standalone callers can also use this
/// directly via `connect_and_push`, which seeds a single
/// `BecomeKey::None` agent and packages everything into one
/// keepalive-bearing `AgentConn`.
pub struct SshSession {
    pub handle: Handle<Client>,
    pub remote_path: String,
    pub label: String,
}

/// Connect + auth + arch probe + push binary. Returns the established
/// session without spawning an agent channel — pool callers want to
/// spawn channels lazily per `BecomeKey`, so we don't presume the
/// first BecomeKey here.
///
/// All the slow / fallible network work happens in this function;
/// `spawn_agent_channel` against the returned session is cheap
/// (one channel open + Hello + clock-skew probe = ~1 RTT total).
pub async fn open_session(opts: &ConnectOptions, agent_binary: &[u8]) -> Result<SshSession> {
    let label = format!("{}@{}:{}", opts.user, opts.host, opts.port);

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

    authenticate(&mut handle, opts, rsa_hash, &label).await?;

    // Arch probe. We don't gate the upload on this yet (v0 ships one agent
    // binary), but we log it for visibility and so a mismatched binary later
    // produces a meaningful "tried to run x86_64 ELF on aarch64" diagnostic.
    let arch_str = run_remote_command(&mut handle, "uname -m").await?;
    debug!(host = %label, arch = %arch_str.trim(), "remote arch");

    let remote_path = remote_agent_path();
    push_binary(&mut handle, &remote_path, agent_binary)
        .await
        .with_context(|| format!("pushing agent to {label}:{remote_path}"))?;

    Ok(SshSession { handle, remote_path, label })
}

/// Open a new channel on the given session and exec the agent under
/// the right user. `BecomeKey::None` runs the agent as the SSH user;
/// `BecomeKey::As(u)` wraps in `sudo -n -u <u> -- <agent>`. Reads the
/// `Hello` frame and runs the clock-skew probe.
///
/// The returned `AgentConn` carries `TransportKeepalive::Pooled` —
/// the pool owns the session, slot drop doesn't tear it down.
pub async fn spawn_agent_channel(
    session: &SshSession,
    key: &BecomeKey,
) -> Result<AgentConn> {
    // `RSANSIBLE_AGENT_KEEP_BINARY=1` tells the agent NOT to self-unlink its
    // on-disk binary at startup. The pool may spawn additional agents (one
    // per become-config) from the same on-disk path within the same SSH
    // session, so the file must persist for the lifetime of the session.
    // Controller-side cleanup happens via Bye / session close.
    let cmd = match key {
        BecomeKey::None => format!(
            "RSANSIBLE_AGENT_KEEP_BINARY=1 {}",
            session.remote_path,
        ),
        // `sudo -n` makes sudo fail fast rather than prompt for a password —
        // any deployment that needs `become: true` must have NOPASSWD
        // sudoers entries, matching Ansible's default for ssh + become.
        //
        // Sudo's default `env_reset` strips RSANSIBLE_AGENT_KEEP_BINARY from
        // the caller env, so we use `env VAR=VAL <cmd>` after the sudo
        // boundary to set it for the agent itself. `env` lives in sudoers'
        // default `secure_path`, so this is universally available.
        BecomeKey::As(user) => format!(
            "sudo -n -u {user} -- env RSANSIBLE_AGENT_KEEP_BINARY=1 {p}",
            p = session.remote_path,
            user = user,
        ),
    };

    let channel = session
        .handle
        .channel_open_session()
        .await
        .with_context(|| format!("opening agent exec channel to {}", session.label))?;
    channel
        .exec(true, cmd.as_bytes())
        .await
        .with_context(|| format!("exec {cmd} on {}", session.label))?;

    let mut stream = channel.into_stream();

    let first = read_frame(&mut stream)
        .await
        .with_context(|| format!("reading Hello from {} ({})", session.label, key.label()))?
        .ok_or_else(|| {
            anyhow!(
                "agent on {} ({}) closed stdout before sending Hello",
                session.label,
                key.label()
            )
        })?;
    let hello = match first {
        Message::Hello(h) => h,
        other => bail!(
            "first frame from {} ({}) was not Hello: {other:?}",
            session.label,
            key.label()
        ),
    };
    info!(
        host = %session.label,
        agent_version = %hello.agent_version,
        kernel = %hello.kernel,
        become = %key.label(),
        "agent up",
    );

    // NTP-style clock-skew probe. Single Ping/Pong, best-effort: if it
    // fails for any reason we proceed with offset=0 rather than aborting
    // the whole connection — task timing traces become less accurate
    // but everything else still works.
    let (clock_offset_ns, clock_rtt_ns) =
        match probe_clock_skew(&mut stream, &session.label).await {
            Ok((offset, rtt)) => {
                info!(
                    host = %session.label,
                    become = %key.label(),
                    offset_us = offset / 1_000,
                    rtt_us = rtt / 1_000,
                    "clock-skew probe done",
                );
                (offset, rtt)
            }
            Err(e) => {
                warn!(host = %session.label, become = %key.label(), "clock-skew probe failed (continuing with offset=0): {e:#}");
                (0, 0)
            }
        };

    Ok(AgentConn {
        label: session.label.clone(),
        remote_path: session.remote_path.clone(),
        hello,
        stream: Box::pin(stream),
        clock_offset_ns,
        clock_rtt_ns,
        _keepalive: TransportKeepalive::Pooled,
    })
}

/// Connect + auth + arch-probe + upload-agent + exec-agent + read-Hello.
///
/// Thin convenience wrapper preserving the legacy single-conn shape:
/// opens a session, spawns one `BecomeKey::None` agent channel,
/// transfers the session `Handle` into the returned conn's
/// `_keepalive` so the conn fully owns the SSH session. Used by
/// standalone callers (smoke tests, profilers) — the orchestrator
/// switched to the pool API.
pub async fn connect_and_push(opts: &ConnectOptions, agent_binary: &[u8]) -> Result<AgentConn> {
    let session = open_session(opts, agent_binary).await?;
    let mut conn = spawn_agent_channel(&session, &BecomeKey::None).await?;
    // Transfer the Handle into the conn — without a pool around it,
    // the conn IS the keepalive.
    conn._keepalive = TransportKeepalive::Ssh(session.handle);
    Ok(conn)
}

/// Drive one Ping/Pong round to estimate the agent's clock offset from
/// the controller's clock. T1 is captured right before writing Ping; T4
/// right after reading Pong. The agent stamps T2 and T3 (Pong fields).
///
/// `offset = ((T2 - T1) + (T3 - T4)) / 2`  (positive iff agent ahead)
/// `rtt    = (T4 - T1) - (T3 - T2)`        (always non-negative)
pub(crate) async fn probe_clock_skew<S>(
    stream: &mut S,
    label: &str,
) -> Result<(i64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let t1 = now_unix_ns();
    write_frame(stream, &ping())
        .await
        .with_context(|| format!("writing Ping to {label}"))?;
    let frame = read_frame(stream)
        .await
        .with_context(|| format!("reading Pong from {label}"))?
        .ok_or_else(|| anyhow!("agent on {label} closed stdout before sending Pong"))?;
    let pong = match frame {
        Message::Pong(p) => p,
        other => bail!("expected Pong from {label}, got {other:?}"),
    };
    let t4 = now_unix_ns();
    let t2 = pong.agent_recv_unix_ns;
    let t3 = pong.agent_sent_unix_ns;
    // Cast to i128 so we don't underflow on a wildly skewed clock.
    let offset_ns =
        (((t2 as i128) - (t1 as i128)) + ((t3 as i128) - (t4 as i128))) / 2;
    let rtt_ns_signed =
        ((t4 as i128) - (t1 as i128)) - ((t3 as i128) - (t2 as i128));
    let rtt_ns = rtt_ns_signed.max(0) as u64;
    let offset_ns =
        offset_ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    Ok((offset_ns, rtt_ns))
}

/// Authenticate an already-connected SSH session. Tries ssh-agent first
/// (via `$SSH_AUTH_SOCK`), iterating every identity the agent offers; on
/// failure (or no agent), falls back to loading the secret key from the
/// configured/default key path.
///
/// We prefer agent auth because it handles passphrase-encrypted keys
/// (operator unlocks once via `ssh-add`) and matches how the rest of the
/// operator's tooling — `git`, `ssh`, `scp` — already behaves. The
/// file-based fallback covers the cookbook case of running without an
/// agent at all (CI workers, scripted bootstrap).
async fn authenticate(
    handle: &mut Handle<Client>,
    opts: &ConnectOptions,
    rsa_hash: Option<HashAlg>,
    label: &str,
) -> Result<()> {
    // ssh-agent path: only attempted if SSH_AUTH_SOCK is set. Empty agent,
    // unreachable socket, or every identity refused — we fall through to
    // the file path and surface a combined error if that fails too.
    let mut agent_err: Option<String> = None;
    if std::env::var_os("SSH_AUTH_SOCK").is_some() {
        match try_agent_auth(handle, &opts.user, rsa_hash, label).await {
            Ok(true) => return Ok(()),
            Ok(false) => agent_err = Some("ssh-agent: no identity accepted".to_string()),
            Err(e) => agent_err = Some(format!("ssh-agent: {e:#}")),
        }
    }

    // File-based fallback. `load_secret_key(_, None)` doesn't prompt for
    // a passphrase — if the key is encrypted, this returns an error
    // (which we combine with the agent-side error below for clarity).
    let key_path = resolve_key_path(opts.key_path.as_deref())
        .with_context(|| format!("resolving SSH key for {label}"))?;
    let key = match load_secret_key(&key_path, None) {
        Ok(k) => k,
        Err(e) => {
            let file_err = format!(
                "loading SSH key {}: {e:#}",
                key_path.display(),
            );
            match agent_err {
                Some(ae) => bail!(
                    "ssh auth {label} failed:\n  - {ae}\n  - {file_err}\n  \
                     (hint: `ssh-add {}` to unlock and offer the key via agent)",
                    key_path.display(),
                ),
                None => bail!("ssh auth {label}: {file_err}"),
            }
        }
    };

    let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
    let auth = handle
        .authenticate_publickey(&opts.user, key_with_alg)
        .await
        .with_context(|| format!("ssh auth {label}"))?;
    if !auth.success() {
        match agent_err {
            Some(ae) => bail!(
                "ssh auth {label}: publickey rejected via both agent and file:\n  - {ae}\n  - file {}: server rejected the key",
                key_path.display(),
            ),
            None => bail!("ssh: publickey auth failed for {label}"),
        }
    }
    Ok(())
}

/// Walk every identity offered by the local ssh-agent and try each one.
/// Returns `Ok(true)` on the first success, `Ok(false)` if the agent had
/// zero identities or all identities were rejected by the server, and
/// `Err` for protocol-level errors talking to the agent.
async fn try_agent_auth(
    handle: &mut Handle<Client>,
    user: &str,
    rsa_hash: Option<HashAlg>,
    label: &str,
) -> Result<bool> {
    let mut client = AgentClient::connect_env()
        .await
        .map_err(|e| anyhow!("connect to SSH_AUTH_SOCK: {e}"))?;
    let identities = client
        .request_identities()
        .await
        .map_err(|e| anyhow!("request_identities: {e}"))?;
    if identities.is_empty() {
        debug!(host = %label, "ssh-agent has no identities loaded");
        return Ok(false);
    }
    for ident in identities {
        let (pubkey, comment) = match &ident {
            AgentIdentity::PublicKey { key, comment } => (key.clone(), comment.clone()),
            AgentIdentity::Certificate { certificate, comment } => (
                PublicKey::new(certificate.public_key().clone(), ""),
                comment.clone(),
            ),
        };
        debug!(host = %label, key = %comment, "trying ssh-agent identity");
        let result = handle
            .authenticate_publickey_with(user, pubkey, rsa_hash, &mut client)
            .await
            .map_err(|e| anyhow!("agent-signed auth attempt: {e}"))?;
        if result.success() {
            info!(host = %label, key = %comment, "authenticated via ssh-agent");
            return Ok(true);
        }
    }
    Ok(false)
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
