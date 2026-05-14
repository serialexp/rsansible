//! `OpExec` (argv form) and `OpShell` (`sh -c`) — both share a single runner
//! that spawns a child, streams its stdout/stderr as `TaskProgress` frames in
//! bounded chunks, and finishes with `TaskDone` carrying the exit code.

use std::process::Stdio;
use std::time::Duration;

use rsansible_wire::generated::{OpExecOutput, OpShellOutput};
use rsansible_wire::msg::{self, now_unix_ns};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

use super::{emit_error, Context};

/// Bound per emitted TaskProgress chunk. Keeps any single frame small so the
/// controller sees output incrementally rather than in giant bursts.
const CHUNK_CAP: usize = 4 * 1024;

pub async fn run_exec(ctx: &Context, seq: u32, op: OpExecOutput) -> anyhow::Result<()> {
    if op.argv.is_empty() {
        emit_error(ctx, seq, msg::err::BAD_REQUEST, "OpExec.argv is empty").await;
        return Ok(());
    }
    let mut cmd = Command::new(&op.argv[0]);
    cmd.args(&op.argv[1..]);

    // Parallel keys[]/values[] is enforced at the protocol boundary; mismatched
    // lengths are a malformed request.
    if op.env_keys.len() != op.env_values.len() {
        emit_error(
            ctx,
            seq,
            msg::err::BAD_REQUEST,
            format!(
                "OpExec.env_keys (len {}) and env_values (len {}) must match",
                op.env_keys.len(),
                op.env_values.len()
            ),
        )
        .await;
        return Ok(());
    }
    // env_clear() so the spawned process is hermetic — only what the
    // controller passes in. Ansible behaves similarly for the `environment`
    // task keyword.
    cmd.env_clear();
    for (k, v) in op.env_keys.iter().zip(op.env_values.iter()) {
        cmd.env(k, v);
    }
    if !op.cwd.is_empty() {
        cmd.current_dir(&op.cwd);
    }
    run_command(
        ctx,
        seq,
        cmd,
        if op.stdin.is_empty() { None } else { Some(op.stdin) },
        op.timeout_ms,
    )
    .await
}

pub async fn run_shell(ctx: &Context, seq: u32, op: OpShellOutput) -> anyhow::Result<()> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(&op.command);
    run_command(ctx, seq, cmd, None, op.timeout_ms).await
}

async fn run_command(
    ctx: &Context,
    seq: u32,
    mut cmd: Command,
    stdin_payload: Option<Vec<u8>>,
    timeout_ms: u32,
) -> anyhow::Result<()> {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin_payload.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // ENOENT, EACCES, etc. — surface clearly.
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => msg::err::NOT_FOUND,
                std::io::ErrorKind::PermissionDenied => msg::err::PERMISSION,
                _ => msg::err::SPAWN_FAILED,
            };
            emit_error(ctx, seq, code, format!("spawn failed: {e}")).await;
            return Ok(());
        }
    };

    // Feed stdin if provided. Doing this concurrently with output collection
    // matters for commands that read large stdin and write to stdout — a
    // single-threaded write-then-read would deadlock on the kernel pipe buffer.
    if let Some(buf) = stdin_payload {
        if let Some(mut stdin) = child.stdin.take() {
            tokio::spawn(async move {
                let _ = stdin.write_all(&buf).await;
                let _ = stdin.shutdown().await;
            });
        }
    }

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let started_unix_ns = now_unix_ns();
    let drain_stdout = pump(ctx, seq, stdout, msg::stream::STDOUT);
    let drain_stderr = pump(ctx, seq, stderr, msg::stream::STDERR);

    let wait_for_exit = wait_with_timeout(&mut child, timeout_ms);

    let (exit_status, _, _) = tokio::join!(wait_for_exit, drain_stdout, drain_stderr);

    let finished_unix_ns = now_unix_ns();

    match exit_status {
        Ok(Some(status)) => {
            let code = status.code().unwrap_or(-1);
            // `changed` semantics: for raw exec/shell, success means we ran the
            // command, not that we mutated state — but Ansible's `command`
            // module flags any successful run as changed. Match that so
            // playbook UX feels familiar.
            let changed = code == 0;
            ctx.emit(msg::task_done(seq, code, changed, started_unix_ns, finished_unix_ns)).await;
        }
        Ok(None) => {
            // Timeout: child was killed by wait_with_timeout.
            emit_error(
                ctx,
                seq,
                msg::err::TIMEOUT,
                format!("command timed out after {timeout_ms} ms"),
            )
            .await;
        }
        Err(e) => {
            emit_error(ctx, seq, msg::err::IO, format!("wait failed: {e}")).await;
        }
    }
    Ok(())
}

/// Read from a child pipe in CHUNK_CAP-sized bites and emit each as
/// `TaskProgress`. Exits cleanly on EOF.
async fn pump<R>(ctx: &Context, seq: u32, mut r: R, stream: u8)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; CHUNK_CAP];
    loop {
        match r.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                ctx.emit(msg::task_progress(seq, stream, buf[..n].to_vec()))
                    .await;
            }
            Err(_e) => return, // pipe died; nothing useful to do, exit handler reports the failure
        }
    }
}

/// Wait for the child to exit, optionally bounded by `timeout_ms` (0 = no
/// limit). On timeout, the child is killed and `Ok(None)` is returned.
async fn wait_with_timeout(
    child: &mut Child,
    timeout_ms: u32,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    if timeout_ms == 0 {
        return child.wait().await.map(Some);
    }
    match tokio::time::timeout(Duration::from_millis(timeout_ms as u64), child.wait()).await {
        Ok(res) => res.map(Some),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Ok(None)
        }
    }
}
