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

pub async fn run_exec(ctx: &Context, seq: u32, op: OpExecOutput, check_mode: bool) -> anyhow::Result<()> {
    if op.argv.is_empty() {
        emit_error(ctx, seq, msg::err::BAD_REQUEST, "OpExec.argv is empty").await;
        return Ok(());
    }
    if check_mode {
        // Arbitrary process execution has no safe probe path — we can't
        // simulate "what would this command have changed?" Skip outright
        // and report `skipped: true` so the controller's summary can
        // distinguish this from a no-op. Per-task `check_mode: false`
        // is the escape hatch for genuinely read-only fact-gathering
        // shells.
        let started_unix_ns = now_unix_ns();
        let finished_unix_ns = started_unix_ns;
        ctx.emit(msg::task_done(seq, 0, false, true, started_unix_ns, finished_unix_ns)).await;
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
    // OVERLAY semantics — match Ansible's `environment:` keyword and
    // the symmetric run_shell path below. The spawned process inherits
    // the agent's env (PATH, HOME, LANG, …) so binaries resolve
    // normally; controller-supplied env_keys/values then layer on top.
    //
    // We previously used `env_clear()` here for "hermetic" execution,
    // but that broke `command: netplan apply` (and similarly for any
    // sbin binary) when PATH wasn't explicitly passed — argv[0]
    // lookup uses the child's PATH, which was empty after the clear.
    // Caught in the gothab drill on monitor-1. Ansible's command
    // module preserves the connection env by default, so this aligns
    // us with that behavior.
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

pub async fn run_shell(ctx: &Context, seq: u32, op: OpShellOutput, check_mode: bool) -> anyhow::Result<()> {
    if check_mode {
        // Mirror run_exec — arbitrary shell has no safe probe.
        let started_unix_ns = now_unix_ns();
        let finished_unix_ns = started_unix_ns;
        ctx.emit(msg::task_done(seq, 0, false, true, started_unix_ns, finished_unix_ns)).await;
        return Ok(());
    }
    if op.env_keys.len() != op.env_values.len() {
        emit_error(
            ctx,
            seq,
            msg::err::BAD_REQUEST,
            format!(
                "OpShell.env_keys (len {}) and env_values (len {}) must match",
                op.env_keys.len(),
                op.env_values.len()
            ),
        )
        .await;
        return Ok(());
    }
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(&op.command);
    // OVERLAY semantics for shell — matches Ansible's `environment:` keyword
    // (additive on top of the inherited connection env). Unlike OpExec we
    // don't `env_clear()`: shell tasks frequently rely on PATH, HOME, LANG,
    // etc. from the agent's environment to find binaries / locale.
    for (k, v) in op.env_keys.iter().zip(op.env_values.iter()) {
        cmd.env(k, v);
    }
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
            ctx.emit(msg::task_done(seq, code, changed, false, started_unix_ns, finished_unix_ns)).await;
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
