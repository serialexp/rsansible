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

pub fn op_stat(path: String, follow: bool) -> Op {
    Op::OpStat(OpStatOutput {
        kind: 4,
        path,
        follow: if follow { 1 } else { 0 },
    })
}

/// Numeric `state` enum that matches the schema doc. Kept in sync by
/// convention; constructors below use it so callers don't have to
/// remember the integers.
pub mod file_state {
    pub const DIRECTORY: u8 = 0;
    pub const ABSENT: u8 = 1;
    pub const TOUCH: u8 = 2;
    pub const FILE: u8 = 3;
}

pub mod wait_state {
    pub const PRESENT: u8 = 0;
    pub const ABSENT: u8 = 1;
}

#[allow(clippy::too_many_arguments)]
pub fn op_wait_for(
    host: String,
    port: u32,
    path: String,
    state: u8,
    timeout_ms: u32,
    delay_ms: u32,
    sleep_ms: u32,
) -> Op {
    Op::OpWaitFor(OpWaitForOutput {
        kind: 6,
        host,
        port,
        path,
        state,
        timeout_ms,
        delay_ms,
        sleep_ms,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn op_file(
    path: String,
    state: u8,
    mode: Option<u32>,
    owner: String,
    group: String,
    recurse: bool,
) -> Op {
    let (has_mode, mode_val) = match mode {
        Some(m) => (1u8, m),
        None => (0u8, 0u32),
    };
    Op::OpFile(OpFileOutput {
        kind: 5,
        path,
        state,
        has_mode,
        mode: mode_val,
        owner,
        group,
        recurse: if recurse { 1 } else { 0 },
    })
}

/// `state:` byte values for `OpLineInFile`.
pub mod lineinfile_state {
    pub const PRESENT: u8 = 0;
    pub const ABSENT: u8 = 1;
}

#[allow(clippy::too_many_arguments)]
pub fn op_lineinfile(
    path: String,
    regexp: String,
    line: String,
    state: u8,
    mode: Option<u32>,
    create: bool,
    insertbefore: String,
    insertafter: String,
    backrefs: bool,
) -> Op {
    let (has_mode, mode_val) = match mode {
        Some(m) => (1u8, m),
        None => (0u8, 0u32),
    };
    Op::OpLineInFile(OpLineInFileOutput {
        kind: 7,
        path,
        regexp,
        line,
        state,
        has_mode,
        mode: mode_val,
        create: if create { 1 } else { 0 },
        insertbefore,
        insertafter,
        backrefs: if backrefs { 1 } else { 0 },
    })
}

/// `state:` byte values for `OpBlockInFile`. Same byte assignments as
/// `OpLineInFile` but kept separate so renames stay independent.
pub mod blockinfile_state {
    pub const PRESENT: u8 = 0;
    pub const ABSENT: u8 = 1;
}

#[allow(clippy::too_many_arguments)]
pub fn op_blockinfile(
    path: String,
    block: String,
    marker: String,
    marker_begin: String,
    marker_end: String,
    state: u8,
    mode: Option<u32>,
    create: bool,
    insertbefore: String,
    insertafter: String,
) -> Op {
    let (has_mode, mode_val) = match mode {
        Some(m) => (1u8, m),
        None => (0u8, 0u32),
    };
    Op::OpBlockInFile(OpBlockInFileOutput {
        kind: 8,
        path,
        block,
        marker,
        marker_begin,
        marker_end,
        state,
        has_mode,
        mode: mode_val,
        create: if create { 1 } else { 0 },
        insertbefore,
        insertafter,
    })
}

/// `state:` byte values for `OpSystemd`.
pub mod systemd_state {
    /// Don't touch run-state — only manage enable/mask.
    pub const NONE: u8 = 0;
    pub const STARTED: u8 = 1;
    pub const STOPPED: u8 = 2;
    pub const RESTARTED: u8 = 3;
    pub const RELOADED: u8 = 4;
}

#[allow(clippy::too_many_arguments)]
pub fn op_systemd(
    name: String,
    state: u8,
    enabled: Option<bool>,
    masked: Option<bool>,
    daemon_reload: bool,
    no_block: bool,
) -> Op {
    let (has_enabled, enabled_val) = match enabled {
        Some(b) => (1u8, if b { 1u8 } else { 0u8 }),
        None => (0u8, 0u8),
    };
    let (has_masked, masked_val) = match masked {
        Some(b) => (1u8, if b { 1u8 } else { 0u8 }),
        None => (0u8, 0u8),
    };
    Op::OpSystemd(OpSystemdOutput {
        kind: 9,
        name,
        state,
        has_enabled,
        enabled: enabled_val,
        has_masked,
        masked: masked_val,
        daemon_reload: if daemon_reload { 1 } else { 0 },
        no_block: if no_block { 1 } else { 0 },
    })
}

/// `state:` byte values for `OpApt`.
pub mod apt_state {
    pub const PRESENT: u8 = 0;
    pub const ABSENT: u8 = 1;
    pub const LATEST: u8 = 2;
}

#[allow(clippy::too_many_arguments)]
pub fn op_apt(
    names: Vec<String>,
    state: u8,
    update_cache: bool,
    cache_valid_time: u32,
    purge: bool,
    autoremove: bool,
    default_release: String,
    allow_unauthenticated: bool,
) -> Op {
    Op::OpApt(OpAptOutput {
        kind: 10,
        names,
        state,
        update_cache: if update_cache { 1 } else { 0 },
        cache_valid_time,
        purge: if purge { 1 } else { 0 },
        autoremove: if autoremove { 1 } else { 0 },
        default_release,
        allow_unauthenticated: if allow_unauthenticated { 1 } else { 0 },
    })
}

/// `op:` byte values for `OpUfw`.
pub mod ufw_op {
    pub const RULE: u8 = 0;
    pub const ENABLE: u8 = 1;
    pub const DISABLE: u8 = 2;
    pub const RESET: u8 = 3;
    pub const DEFAULT: u8 = 4;
    pub const RELOAD: u8 = 5;
    pub const LOGGING: u8 = 6;
}

#[allow(clippy::too_many_arguments)]
pub fn op_ufw(
    op: u8,
    rule: String,
    direction: String,
    proto: String,
    from_ip: String,
    from_port: String,
    to_ip: String,
    to_port: String,
    interface: String,
    comment: String,
    delete: bool,
    insert: u32,
) -> Op {
    Op::OpUfw(OpUfwOutput {
        kind: 11,
        op,
        rule,
        direction,
        proto,
        from_ip,
        from_port,
        to_ip,
        to_port,
        interface,
        comment,
        delete: if delete { 1 } else { 0 },
        insert,
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
