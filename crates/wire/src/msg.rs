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

pub fn task_done(seq: u32, exit_code: i32, changed: bool, took_ms: u32) -> Message {
    Message::TaskDone(TaskDoneOutput {
        kind: 3,
        seq,
        exit_code,
        changed: if changed { 1 } else { 0 },
        took_ms,
    })
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
