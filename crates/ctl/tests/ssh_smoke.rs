//! End-to-end smoke test for the SSH transport layer.
//!
//! Spins up an `linuxserver/openssh-server` container with a freshly
//! generated ed25519 key, pushes the real agent binary through
//! `connect_and_push`, runs one shell task, and verifies the protocol
//! frames come back as expected.
//!
//! Gated behind `#[ignore]` because it requires docker. Run with:
//!
//!   cargo test -p rsansible-ctl --test ssh_smoke -- --ignored --nocapture
//!
//! Auto-skipped if `RSANSIBLE_SKIP_DOCKER_TESTS=1` or `docker` isn't on
//! PATH.

mod common;

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rsansible_ctl::ssh::{self, ConnectOptions};
use rsansible_wire::{
    generated::Message,
    msg::{op_shell, stream as wire_stream, task_dispatch},
    read_frame, write_frame,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

#[tokio::test]
#[ignore]
async fn end_to_end_shell_task() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }

    let agent_path = locate_agent_binary().context("locating agent binary")?;
    let agent_bytes =
        std::fs::read(&agent_path).with_context(|| format!("reading agent {agent_path:?}"))?;

    let env = SshdContainer::start().await?;

    let opts = ConnectOptions {
        host: "127.0.0.1".into(),
        port: env.host_port,
        user: env.user.clone(),
        key_path: Some(env.key_path.clone()),
        strict_host_key: false,
    };

    let mut conn = ssh::connect_and_push(&opts, &agent_bytes)
        .await
        .context("connect_and_push")?;

    assert_eq!(conn.hello.os, rsansible_wire::msg::os::LINUX);
    assert!(!conn.hello.hostname.is_empty(), "Hello.hostname empty");

    let dispatch = task_dispatch(1, false, op_shell("printf 'hi from agent\\n'".into(), vec![], vec![], 5_000));
    write_frame(&mut conn.stream, &dispatch)
        .await
        .context("writing TaskDispatch")?;

    let mut stdout_seen = Vec::new();
    let mut done: Option<rsansible_wire::generated::TaskDoneOutput> = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let frame = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut conn.stream))
            .await
            .context("read_frame timed out")?
            .context("read_frame failed")?
            .ok_or_else(|| anyhow!("agent closed stdout before TaskDone"))?;
        match frame {
            Message::TaskProgress(p) if p.stream == wire_stream::STDOUT => {
                stdout_seen.extend_from_slice(&p.chunk);
            }
            Message::TaskProgress(_) => {}
            Message::TaskDone(d) => {
                done = Some(d);
                break;
            }
            Message::TaskError(e) => {
                bail!("agent reported TaskError: code={} msg={}", e.code, e.message)
            }
            other => bail!("unexpected frame from agent: {other:?}"),
        }
    }
    let done = done.ok_or_else(|| anyhow!("never received TaskDone"))?;
    assert_eq!(done.seq, 1);
    assert_eq!(done.exit_code, 0, "shell command failed");
    let stdout = String::from_utf8_lossy(&stdout_seen);
    assert!(
        stdout.contains("hi from agent"),
        "expected 'hi from agent' in stdout, got: {stdout:?}"
    );

    write_frame(&mut conn.stream, &rsansible_wire::msg::bye())
        .await
        .context("writing Bye")?;

    Ok(())
}
