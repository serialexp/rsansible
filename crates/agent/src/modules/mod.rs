//! Op handlers. Each handler reads inputs from the dispatched Op, may stream
//! `TaskProgress` chunks through the writer channel, and finishes with either
//! `TaskDone` or `TaskError`.

use rsansible_wire::{msg, Op};

use crate::writer::Sender;

mod exec;
mod gather_facts;
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
    }
}

/// Convenience: emit a TaskError with the given code and message. Used by
/// handlers when something goes wrong before they can produce TaskDone.
pub async fn emit_error(ctx: &Context, seq: u32, code: u8, message: impl Into<String>) {
    ctx.emit(msg::task_error(seq, code, message.into())).await;
}
