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

pub fn op_write_file(path: String, mode: u32, only_if_missing: bool, content: Vec<u8>) -> Op {
    Op::OpWriteFile(OpWriteFileOutput {
        kind: 2,
        path,
        mode,
        only_if_missing: if only_if_missing { 1 } else { 0 },
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

/// `state:` byte values for `OpPackage` (shared across all package
/// managers — present/absent/latest mean the same thing everywhere).
pub mod package_state {
    pub const PRESENT: u8 = 0;
    pub const ABSENT: u8 = 1;
    pub const LATEST: u8 = 2;
}

/// `manager:` byte values for `OpPackage`. 0 = auto (agent picks based
/// on what's on PATH / facts). The numbered values select a specific
/// backend; the agent returns BAD_REQUEST if the requested manager isn't
/// implemented.
pub mod package_manager {
    /// Agent picks a manager based on what's on PATH / gathered facts.
    pub const AUTO: u8 = 0;
    /// Debian-family `apt-get`.
    pub const APT: u8 = 1;
    /// RHEL-family `dnf` (reserved).
    pub const DNF: u8 = 2;
    /// RHEL-family `yum` (reserved).
    pub const YUM: u8 = 3;
    /// Alpine `apk` (reserved).
    pub const APK: u8 = 4;
    /// Arch `pacman` (reserved).
    pub const PACMAN: u8 = 5;
    /// SUSE `zypper` (reserved).
    pub const ZYPPER: u8 = 6;
}

#[allow(clippy::too_many_arguments)]
pub fn op_package(
    manager: u8,
    names: Vec<String>,
    state: u8,
    update_cache: bool,
    cache_valid_time: u32,
    purge: bool,
    autoremove: bool,
    default_release: String,
    allow_unauthenticated: bool,
) -> Op {
    Op::OpPackage(OpPackageOutput {
        kind: 10,
        manager,
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

/// `manager:` byte values for `OpRepository`. Mirrors the
/// `package_manager` byte allocation 1:1 so a single auto-detect step
/// on the agent can pick a backend for both ops. Only `AUTO` and `APT`
/// have an implementation today; the rest are reserved for future
/// backends.
pub mod repository_manager {
    pub const AUTO: u8 = 0;
    pub const APT: u8 = 1;
    pub const DNF: u8 = 2;
    pub const YUM: u8 = 3;
    pub const APK: u8 = 4;
    pub const PACMAN: u8 = 5;
    pub const ZYPPER: u8 = 6;
}

/// `state:` byte values for `OpRepository`. Two states: present
/// (idempotent write of the source-list file), absent (idempotent delete).
pub mod repository_state {
    pub const PRESENT: u8 = 0;
    pub const ABSENT: u8 = 1;
}

#[allow(clippy::too_many_arguments)]
pub fn op_repository(
    manager: u8,
    repo: String,
    state: u8,
    filename: String,
    mode: u32,
    update_cache: bool,
) -> Op {
    Op::OpRepository(OpRepositoryOutput {
        kind: 21,
        manager,
        repo,
        state,
        filename,
        mode,
        update_cache: if update_cache { 1 } else { 0 },
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

/// `rule_state:` byte values for `OpIptables`.
pub mod iptables_state {
    pub const ABSENT: u8 = 0;
    pub const PRESENT: u8 = 1;
}

/// `action:` byte values for `OpIptables`.
pub mod iptables_action {
    /// `-A <chain>` (default).
    pub const APPEND: u8 = 0;
    /// `-I <chain>` (prepend at position 1).
    pub const INSERT: u8 = 1;
}

/// `ip_version:` byte values for `OpIptables`.
pub mod iptables_ip_version {
    /// `iptables` (IPv4, default).
    pub const V4: u8 = 4;
    /// `ip6tables` (IPv6).
    pub const V6: u8 = 6;
}

#[allow(clippy::too_many_arguments)]
pub fn op_iptables(
    table: String,
    chain: String,
    protocol: String,
    source: String,
    destination: String,
    source_port: String,
    destination_port: String,
    in_interface: String,
    out_interface: String,
    jump: String,
    ctstate: String,
    comment: String,
    ip_version: u8,
    action: u8,
    rule_state: u8,
) -> Op {
    Op::OpIptables(OpIptablesOutput {
        kind: 20,
        table,
        chain,
        protocol,
        source,
        destination,
        source_port,
        destination_port,
        in_interface,
        out_interface,
        jump,
        ctstate,
        comment,
        ip_version,
        action,
        rule_state,
    })
}

/// HTTP `method:` byte values for `OpUri`.
pub mod uri_method {
    pub const GET: u8 = 0;
    pub const POST: u8 = 1;
    pub const PUT: u8 = 2;
    pub const PATCH: u8 = 3;
    pub const DELETE: u8 = 4;
    pub const HEAD: u8 = 5;
}

/// `body_format:` byte values for `OpUri`.
pub mod uri_body_format {
    /// Ship the body bytes verbatim; no Content-Type adjustment.
    pub const RAW: u8 = 0;
    /// Body is already JSON-encoded; agent sets `Content-Type:
    /// application/json` if the caller didn't already.
    pub const JSON: u8 = 1;
    /// Body is form-encoded (`k=v&k=v`); agent sets `Content-Type:
    /// application/x-www-form-urlencoded` if the caller didn't already.
    pub const FORM: u8 = 2;
}

/// `follow_redirects:` byte values for `OpUri`.
pub mod uri_follow {
    /// Never follow 3xx; the response surfaces as-is.
    pub const NONE: u8 = 0;
    /// Follow 3xx only when the original method was GET or HEAD,
    /// matching Ansible's default. Capped at 10 hops.
    pub const SAFE: u8 = 1;
    /// Follow 3xx regardless of method. Capped at 10 hops.
    pub const ALL: u8 = 2;
}

#[allow(clippy::too_many_arguments)]
pub fn op_uri(
    method: u8,
    url: String,
    header_keys: Vec<String>,
    header_values: Vec<String>,
    body: Vec<u8>,
    body_format: u8,
    status_codes: Vec<u16>,
    timeout_ms: u32,
    return_content: bool,
    validate_certs: bool,
    follow_redirects: u8,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    ca_bundle_pem: Vec<u8>,
) -> Op {
    Op::OpUri(OpUriOutput {
        kind: 12,
        method,
        url,
        header_keys,
        header_values,
        body,
        body_format,
        status_codes,
        timeout_ms,
        return_content: if return_content { 1 } else { 0 },
        validate_certs: if validate_certs { 1 } else { 0 },
        follow_redirects,
        client_cert_pem,
        client_key_pem,
        ca_bundle_pem,
    })
}

/// `state:` byte values for `OpPostgresqlExt`.
pub mod postgresql_ext_state {
    pub const PRESENT: u8 = 0;
    pub const ABSENT: u8 = 1;
}

#[allow(clippy::too_many_arguments)]
pub fn op_postgresql_query(
    query: String,
    db: String,
    login_user: String,
    login_password: String,
    login_unix_socket: String,
    login_host: String,
    login_port: u16,
    autocommit: bool,
    positional_args: Vec<String>,
    read_only: bool,
) -> Op {
    Op::OpPostgresqlQuery(OpPostgresqlQueryOutput {
        kind: 13,
        query,
        db,
        login_user,
        login_password,
        login_unix_socket,
        login_host,
        login_port,
        autocommit: if autocommit { 1 } else { 0 },
        positional_args,
        read_only: if read_only { 1 } else { 0 },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn op_postgresql_ext(
    name: String,
    state: u8,
    version: String,
    ext_schema: String,
    cascade: bool,
    db: String,
    login_user: String,
    login_password: String,
    login_unix_socket: String,
    login_host: String,
    login_port: u16,
) -> Op {
    Op::OpPostgresqlExt(OpPostgresqlExtOutput {
        kind: 14,
        name,
        state,
        version,
        ext_schema,
        cascade: if cascade { 1 } else { 0 },
        db,
        login_user,
        login_password,
        login_unix_socket,
        login_host,
        login_port,
    })
}

/// Checksum algorithm prefixes for OpGetUrl's `checksum` string.
/// The format is `<algo>:<hex>` where algo is one of these, lowercased.
pub mod get_url_algo {
    pub const SHA256: &str = "sha256";
    pub const SHA1: &str = "sha1";
    pub const MD5: &str = "md5";
}

#[allow(clippy::too_many_arguments)]
pub fn op_get_url(
    url: String,
    dest: String,
    checksum: String,
    mode: u32,
    owner: String,
    group: String,
    header_keys: Vec<String>,
    header_values: Vec<String>,
    timeout_ms: u32,
    force: bool,
    validate_certs: bool,
    follow_redirects: u8,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    ca_bundle_pem: Vec<u8>,
) -> Op {
    Op::OpGetUrl(OpGetUrlOutput {
        kind: 15,
        url,
        dest,
        checksum,
        mode,
        owner,
        group,
        header_keys,
        header_values,
        timeout_ms,
        force: if force { 1 } else { 0 },
        validate_certs: if validate_certs { 1 } else { 0 },
        follow_redirects,
        client_cert_pem,
        client_key_pem,
        ca_bundle_pem,
    })
}

pub fn op_async_start(timeout_ms: u32, inner: Op) -> Op {
    Op::OpAsyncStart(OpAsyncStartOutput {
        kind: 16,
        timeout_ms,
        inner: Box::new(inner),
    })
}

pub fn op_async_status(job_id: u32) -> Op {
    Op::OpAsyncStatus(OpAsyncStatusOutput {
        kind: 17,
        job_id,
    })
}

pub fn op_read_file(path: String, max_bytes: u32) -> Op {
    Op::OpReadFile(OpReadFileOutput {
        kind: 18,
        path,
        max_bytes,
    })
}

/// `unarchive` format selector — keep in sync with the schema docstring.
/// 0=auto, 1=tar.gz, 2=tar.bz2, 3=tar.xz, 4=tar, 5=zip.
pub mod unarchive_format {
    pub const AUTO: u8 = 0;
    pub const TAR_GZ: u8 = 1;
    pub const TAR_BZ2: u8 = 2;
    pub const TAR_XZ: u8 = 3;
    pub const TAR: u8 = 4;
    pub const ZIP: u8 = 5;
}

#[allow(clippy::too_many_arguments)]
pub fn op_unarchive(
    src: String,
    dest: String,
    format: u8,
    creates: String,
    has_mode: u8,
    mode: u32,
    owner: String,
    group: String,
    keep_newer: u8,
    list_files: u8,
    include: Vec<String>,
    exclude: Vec<String>,
) -> Op {
    Op::OpUnarchive(OpUnarchiveOutput {
        kind: 19,
        src,
        dest,
        format,
        creates,
        has_mode,
        mode,
        owner,
        group,
        keep_newer,
        list_files,
        include,
        exclude,
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

pub fn task_dispatch(seq: u32, check_mode: bool, op: Op) -> Message {
    Message::TaskDispatch(TaskDispatchOutput {
        kind: 1,
        seq,
        check_mode: if check_mode { 1 } else { 0 },
        op,
    })
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
    skipped: bool,
    started_unix_ns: u64,
    finished_unix_ns: u64,
) -> Message {
    Message::TaskDone(TaskDoneOutput {
        kind: 3,
        seq,
        exit_code,
        changed: if changed { 1 } else { 0 },
        skipped: if skipped { 1 } else { 0 },
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
