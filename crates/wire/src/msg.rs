//! Ergonomic constructors for `Message` and `Op` variants.
//!
//! The generated `*Output` structs each carry a `kind: u8` discriminator that
//! must match the variant's wire tag exactly, or peers will fail to decode.
//! Rather than have callers remember which integer goes with which variant —
//! and silently corrupt the wire if they get it wrong — every variant is built
//! through a constructor here that hardcodes the correct kind. Schema and
//! constructors are kept in lockstep manually; a roundtrip test for each
//! variant lives in `framing::tests`.

use crate::generated::*;

// ── Op constructors ─────────────────────────────────────────────────

pub fn op_exec(
    argv: Vec<String>,
    env_keys: Vec<String>,
    env_values: Vec<String>,
    cwd: String,
    stdin: Vec<u8>,
    timeout_ms: u32,
) -> Op {
    Op::OpExec(OpExecOutput {
        kind: 0,
        argv,
        env_keys,
        env_values,
        cwd,
        stdin,
        timeout_ms,
    })
}

pub fn op_shell(command: String, timeout_ms: u32) -> Op {
    Op::OpShell(OpShellOutput {
        kind: 1,
        command,
        timeout_ms,
    })
}

pub fn op_write_file(path: String, mode: u32, content: Vec<u8>) -> Op {
    Op::OpWriteFile(OpWriteFileOutput {
        kind: 2,
        path,
        mode,
        content,
    })
}

pub fn op_gather_facts() -> Op {
    Op::OpGatherFacts(OpGatherFactsOutput { kind: 3 })
}

// ── Message constructors ────────────────────────────────────────────

pub fn hello(
    arch: u8,
    os: u8,
    kernel: String,
    hostname: String,
    uid: u32,
    gid: u32,
    agent_version: String,
) -> Message {
    Message::Hello(HelloOutput {
        kind: 0,
        arch,
        os,
        kernel,
        hostname,
        uid,
        gid,
        agent_version,
    })
}

pub fn task_dispatch(seq: u32, op: Op) -> Message {
    Message::TaskDispatch(TaskDispatchOutput { kind: 1, seq, op })
}

pub fn task_progress(seq: u32, stream: u8, chunk: Vec<u8>) -> Message {
    Message::TaskProgress(TaskProgressOutput {
        kind: 2,
        seq,
        stream,
        chunk,
    })
}

/// Build a `TaskDone` frame. `started_unix_ns` and `finished_unix_ns`
/// are nanoseconds since the UNIX epoch as observed by the *agent's*
/// wall clock — captured before/after the module's work. The
/// controller compares these against its own observed dispatch/receive
/// instants to surface wire latencies (under the `rsansible::timing`
/// tracing target). Skew between the two clocks doesn't affect the
/// agent-local duration `(finished − started)`.
pub fn task_done(
    seq: u32,
    exit_code: i32,
    changed: bool,
    started_unix_ns: u64,
    finished_unix_ns: u64,
) -> Message {
    Message::TaskDone(TaskDoneOutput {
        kind: 3,
        seq,
        exit_code,
        changed: if changed { 1 } else { 0 },
        started_unix_ns,
        finished_unix_ns,
    })
}

/// Capture the wall-clock instant `SystemTime::now()` as nanoseconds
/// since the UNIX epoch. Saturates to 0 on pre-epoch clocks (which
/// shouldn't happen on a sane host but isn't worth panicking over).
pub fn now_unix_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

pub fn task_error(seq: u32, code: u8, message: String) -> Message {
    Message::TaskError(TaskErrorOutput {
        kind: 4,
        seq,
        code,
        message,
    })
}

pub fn bye() -> Message {
    Message::Bye(ByeOutput { kind: 5 })
}

/// Sent controller → agent immediately after Hello. The controller
/// remembers its own send time locally; the wire frame is just the
/// kind byte.
pub fn ping() -> Message {
    Message::Ping(PingOutput { kind: 6 })
}

/// Sent agent → controller in response to `Ping`. Carries the agent's
/// wall-clock receive and send timestamps so the controller can
/// estimate clock offset.
pub fn pong(agent_recv_unix_ns: u64, agent_sent_unix_ns: u64) -> Message {
    Message::Pong(PongOutput {
        kind: 7,
        agent_recv_unix_ns,
        agent_sent_unix_ns,
    })
}

// ── Error-code constants for TaskError.code ─────────────────────────
// Matches the comment in schema/wire.schema.json5. Keep in sync.

pub mod err {
    pub const INTERNAL: u8 = 0;
    pub const BAD_REQUEST: u8 = 1;
    pub const IO: u8 = 2;
    pub const PERMISSION: u8 = 3;
    pub const TIMEOUT: u8 = 4;
    pub const NOT_FOUND: u8 = 5;
    pub const SPAWN_FAILED: u8 = 6;
}

// ── Stream selectors for TaskProgress.stream ────────────────────────

pub mod stream {
    pub const STDOUT: u8 = 0;
    pub const STDERR: u8 = 1;
}

// ── Arch / OS enum bytes for Hello ──────────────────────────────────

pub mod arch {
    pub const UNKNOWN: u8 = 0;
    pub const X86_64: u8 = 1;
    pub const AARCH64: u8 = 2;
    pub const ARM: u8 = 3;
    pub const RISCV64: u8 = 4;
}

pub mod os {
    pub const UNKNOWN: u8 = 0;
    pub const LINUX: u8 = 1;
    pub const DARWIN: u8 = 2;
    pub const FREEBSD: u8 = 3;
}
