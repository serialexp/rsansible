//! Throwaway sshd container helper for integration tests.
//!
//! Each `SshdContainer::start()` call:
//!   1. Generates a fresh ed25519 keypair into a temp dir.
//!   2. Spawns an `linuxserver/openssh-server` container with that
//!      public key injected via the `PUBLIC_KEY` env var.
//!   3. Resolves the host-side ephemeral port for the container's
//!      sshd (port 2222) and waits until it accepts TCP.
//!
//! `Drop` tears the container down. The temp dir is dropped with it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

pub const IMAGE: &str = "lscr.io/linuxserver/openssh-server:latest";
pub const CONTAINER_USER: &str = "test";
const CONTAINER_SSH_PORT: u16 = 2222;

pub struct SshdContainer {
    container_id: String,
    pub host_port: u16,
    pub key_path: PathBuf,
    pub user: String,
    _tmpdir: tempfile::TempDir,
}

impl SshdContainer {
    /// Variant of `start()` that enables `sudo` for `CONTAINER_USER`
    /// with NOPASSWD. Used by `become:` e2e tests. Requires the test
    /// user to also exist as a real Linux account inside the container
    /// (linuxserver/openssh-server creates it from `USER_NAME`).
    ///
    /// Also creates an extra unprivileged account `becometest` so the
    /// container can demonstrate `become_user: becometest` flipping
    /// `whoami` output. We deliberately keep this separate from the
    /// SSH login user so the test can distinguish "the wrap actually
    /// changed user" from "task ran as the SSH user, sudo or no sudo".
    #[allow(dead_code)]
    pub async fn start_with_sudo() -> Result<Self> {
        let c = Self::start_inner(true).await?;
        // Add a passwordless sudoers entry for the test user, plus an
        // additional account we can `become_user:` into.
        let install = c.docker_exec_root(&[
            "sh",
            "-c",
            // alpine ships sudo via SUDO_ACCESS=true; ensure NOPASSWD,
            // create becometest, and make sudo's secure_path includes
            // /bin so plain commands work after the wrap.
            "set -eu; \
             apk add --no-cache sudo >/dev/null 2>&1 || true; \
             adduser -D -H becometest >/dev/null 2>&1 || true; \
             echo 'test ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/test; \
             chmod 440 /etc/sudoers.d/test",
        ])?;
        if !install.status.success() {
            bail!(
                "post-start sudoers setup failed: stdout={:?} stderr={:?}",
                String::from_utf8_lossy(&install.stdout),
                String::from_utf8_lossy(&install.stderr)
            );
        }
        Ok(c)
    }

    #[allow(dead_code)]
    pub async fn start() -> Result<Self> {
        Self::start_inner(false).await
    }

    async fn start_inner(sudo_access: bool) -> Result<Self> {
        let tmpdir = tempfile::tempdir().context("creating tmpdir for keys")?;
        let key_path = tmpdir.path().join("id_ed25519");
        gen_ed25519_keypair(&key_path)?;
        let pub_path = key_path.with_extension("pub");
        let pubkey = std::fs::read_to_string(&pub_path)
            .with_context(|| format!("reading {}", pub_path.display()))?;
        let pubkey = pubkey.trim().to_string();

        // Pull lazily; no-op if already cached.
        let _ = Command::new("docker")
            .args(["pull", IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "-P",
                "-e",
                "PUID=1000",
                "-e",
                "PGID=1000",
                "-e",
                "TZ=Etc/UTC",
                "-e",
                &format!("USER_NAME={CONTAINER_USER}"),
                "-e",
                &format!("PUBLIC_KEY={pubkey}"),
                "-e",
                if sudo_access { "SUDO_ACCESS=true" } else { "SUDO_ACCESS=false" },
                "-e",
                "PASSWORD_ACCESS=false",
                IMAGE,
            ])
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .context("running `docker run`")?;
        if !out.status.success() {
            bail!(
                "docker run failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let container_id = String::from_utf8(out.stdout)
            .context("docker run stdout not utf8")?
            .trim()
            .to_string();

        let host_port = resolve_published_port(&container_id, CONTAINER_SSH_PORT)
            .with_context(|| format!("resolving published port for {container_id}"))?;
        wait_for_sshd("127.0.0.1", host_port).await?;

        Ok(SshdContainer {
            container_id,
            host_port,
            key_path,
            user: CONTAINER_USER.into(),
            _tmpdir: tmpdir,
        })
    }

    /// Run a one-shot command inside the container with `docker exec`.
    /// Useful for inspecting agent side-effects after a test.
    /// (Only some test files use this; `#[allow]` keeps the unused-in-one
    /// integration-test-crate warning quiet.)
    #[allow(dead_code)]
    pub fn docker_exec(&self, argv: &[&str]) -> Result<std::process::Output> {
        let mut cmd = Command::new("docker");
        cmd.arg("exec").arg(&self.container_id);
        for arg in argv {
            cmd.arg(arg);
        }
        cmd.output().context("docker exec failed")
    }

    /// Run a command in the container as UID 0 (root) regardless of
    /// the container's default user. Used by `start_with_sudo` to
    /// install packages and write sudoers entries before the test
    /// connects over SSH.
    #[allow(dead_code)]
    pub fn docker_exec_root(&self, argv: &[&str]) -> Result<std::process::Output> {
        let mut cmd = Command::new("docker");
        cmd.arg("exec").arg("-u").arg("0").arg(&self.container_id);
        for arg in argv {
            cmd.arg(arg);
        }
        cmd.output().context("docker exec failed")
    }
}

impl Drop for SshdContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn gen_ed25519_keypair(out_path: &Path) -> Result<()> {
    let status = Command::new("ssh-keygen")
        .arg("-q")
        .args(["-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(out_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("spawning ssh-keygen")?;
    if !status.success() {
        bail!("ssh-keygen failed");
    }
    Ok(())
}

fn resolve_published_port(container_id: &str, container_port: u16) -> Result<u16> {
    let out = Command::new("docker")
        .args(["port", container_id, &format!("{container_port}/tcp")])
        .output()
        .context("running `docker port`")?;
    if !out.status.success() {
        bail!(
            "docker port failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let first = text
        .lines()
        .next()
        .ok_or_else(|| anyhow!("`docker port` returned empty output"))?;
    let port_str = first
        .rsplit(':')
        .next()
        .ok_or_else(|| anyhow!("could not parse port from {first:?}"))?;
    let port: u16 = port_str
        .trim()
        .parse()
        .with_context(|| format!("parsing port from {port_str:?}"))?;
    Ok(port)
}

async fn wait_for_sshd(host: &str, port: u16) -> Result<()> {
    // Why we read the banner instead of just checking TCP-accept:
    // with `docker run -d -P`, Docker's userland proxy starts accepting
    // on the published port immediately, but if sshd inside the
    // container hasn't bound its listener yet the proxy can't forward
    // the connection and sends RST. A bare TCP-connect probe then
    // returns Ok, the next `ssh::connect_and_push` lands on a RST, and
    // the test fails with "Connection reset by peer". sshd emits the
    // `SSH-2.0-...\r\n` banner immediately after a real accept, so
    // reading those 4 bytes proves the end-to-end path is live, not
    // just the proxy half.
    use tokio::io::AsyncReadExt;
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        if let Ok(mut stream) = tokio::net::TcpStream::connect((host, port)).await {
            let mut buf = [0u8; 4];
            let read = tokio::time::timeout(
                Duration::from_secs(2),
                stream.read_exact(&mut buf),
            )
            .await;
            if matches!(read, Ok(Ok(_))) && &buf == b"SSH-" {
                drop(stream);
                return Ok(());
            }
            // Either timed out or read failed (RST from proxy) — retry.
            drop(stream);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    bail!("sshd at {host}:{port} never became reachable within 45s");
}
