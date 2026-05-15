//! Op handlers. Each handler reads inputs from the dispatched Op, may stream
//! `TaskProgress` chunks through the writer channel, and finishes with either
//! `TaskDone` or `TaskError`.

use rsansible_wire::{msg, Op};

use crate::writer::Sender;

mod blockinfile;
mod exec;
mod file;
mod gather_facts;
mod lineinfile;
mod package;
mod stat;
mod systemd;
mod ufw;
mod wait_for;
mod write_file;

/// Shared state passed to every handler. Currently just the writer; future
/// additions (fact caches, working directories, etc.) live here too.
pub struct Context {
    pub writer: Sender,
}

impl Context {
    pub fn new(writer: Sender) -> Self {
        Self { writer }
    }

    /// Send a Message, swallowing channel-closed errors (the writer task has
    /// torn down and there's nothing we can do but stop trying to talk).
    pub async fn emit(&self, m: rsansible_wire::Message) {
        let _ = self.writer.send(m).await;
    }
}

/// Top-level dispatch. Returns Ok even on module-level failure — the failure
/// is communicated to the controller via TaskError. An Err result indicates an
/// agent-internal bug (channel closed, etc.).
pub async fn dispatch(ctx: &Context, seq: u32, op: Op) -> anyhow::Result<()> {
    match op {
        Op::OpExec(o) => exec::run_exec(ctx, seq, o).await,
        Op::OpShell(o) => exec::run_shell(ctx, seq, o).await,
        Op::OpWriteFile(o) => write_file::run(ctx, seq, o).await,
        Op::OpGatherFacts(_) => gather_facts::run(ctx, seq).await,
        Op::OpStat(o) => stat::run(ctx, seq, o).await,
        Op::OpFile(o) => file::run(ctx, seq, o).await,
        Op::OpWaitFor(o) => wait_for::run(ctx, seq, o).await,
        Op::OpLineInFile(o) => lineinfile::run(ctx, seq, o).await,
        Op::OpBlockInFile(o) => blockinfile::run(ctx, seq, o).await,
        Op::OpSystemd(o) => systemd::run(ctx, seq, o).await,
        Op::OpPackage(o) => package::run(ctx, seq, o).await,
        Op::OpUfw(o) => ufw::run(ctx, seq, o).await,
    }
}

/// Convenience: emit a TaskError with the given code and message. Used by
/// handlers when something goes wrong before they can produce TaskDone.
pub async fn emit_error(ctx: &Context, seq: u32, code: u8, message: impl Into<String>) {
    ctx.emit(msg::task_error(seq, code, message.into())).await;
}

/// Spawn `bin args` with bounded retries on ETXTBSY. ETXTBSY ("Text
/// file busy", `errno == 26`) fires when the kernel still sees an open
/// writable fd on the executable's inode at the moment of exec.
///
/// In production this should never happen — `/usr/bin/systemctl`,
/// `/usr/bin/apt-get`, `/usr/sbin/ufw` are all system binaries we never
/// write to ourselves. The retry exists for tests that fork+exec stub
/// scripts they've just laid down on disk: under parallel-cargo-test
/// pressure the kernel occasionally refuses the first exec, but a
/// rewrite+rename ordering + a 5-80ms backoff is sufficient to clear
/// it. Always doing the retry is harmless: the slow path is gated on a
/// specific errno that production never hits.
pub(crate) fn spawn_with_etxtbsy_retry(
    bin: &str,
    args: &[&str],
) -> std::io::Result<std::process::Output> {
    use std::io::ErrorKind;
    use std::process::Command;
    use std::time::Duration;
    let mut delay_ms = 5u64;
    let mut last_err = None;
    for _ in 0..6 {
        match Command::new(bin).args(args).output() {
            Ok(out) => return Ok(out),
            Err(e) if e.raw_os_error() == Some(26) || e.kind() == ErrorKind::ResourceBusy => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(delay_ms));
                delay_ms = (delay_ms * 2).min(80);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("ETXTBSY retries exhausted")))
}
