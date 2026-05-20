//! Wire protocol for rsansible.
//!
//! - [`generated`] contains the binschema codegen output for messages and ops.
//!   Regenerate with `just gen-wire`. Do not edit by hand.
//! - [`msg`] exposes constructors that hide each variant's `kind` discriminator
//!   field so callers can't accidentally encode a Message with the wrong tag.
//! - [`framing`] reads and writes length-prefixed frames over async byte
//!   streams (stdin/stdout, SSH channel, TCP — anything `AsyncRead`/`AsyncWrite`).

#![forbid(unsafe_code)]

#[rustfmt::skip]
#[allow(
    clippy::all,
    dead_code,
    unused_imports,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    unused_variables,
)]
pub mod generated;

pub mod framing;
pub mod msg;

pub use framing::{read_frame, write_frame, FramingError, MAX_FRAME_LEN};
pub use generated::{Message, Op};
pub use binschema_runtime as runtime;

impl Op {
    /// Short stable name for this op variant. Used by run-level
    /// observability — `RunMetrics` buckets per-op timing by this
    /// name so the run summary can answer "where did the agents
    /// actually spend their time?". Returning `&'static str` avoids
    /// per-record allocation in the recording hot path.
    pub fn name(&self) -> &'static str {
        match self {
            Op::OpExec(_) => "exec",
            Op::OpShell(_) => "shell",
            Op::OpWriteFile(_) => "write_file",
            Op::OpGatherFacts(_) => "gather_facts",
            Op::OpStat(_) => "stat",
            Op::OpFile(_) => "file",
            Op::OpWaitFor(_) => "wait_for",
            Op::OpLineInFile(_) => "lineinfile",
            Op::OpBlockInFile(_) => "blockinfile",
            Op::OpSystemd(_) => "systemd",
            Op::OpPackage(_) => "package",
            Op::OpUfw(_) => "ufw",
            Op::OpUri(_) => "uri",
            Op::OpPostgresqlQuery(_) => "postgresql_query",
            Op::OpPostgresqlExt(_) => "postgresql_ext",
            Op::OpGetUrl(_) => "get_url",
            Op::OpAsyncStart(_) => "async_start",
            Op::OpAsyncStatus(_) => "async_status",
            Op::OpReadFile(_) => "read_file",
            Op::OpUnarchive(_) => "unarchive",
            Op::OpIptables(_) => "iptables",
            Op::OpRepository(_) => "repository",
            Op::OpUser(_) => "user",
            Op::OpGroup(_) => "group",
            Op::OpAuthorizedKey(_) => "authorized_key",
            Op::OpGetent(_) => "getent",
            Op::OpHostname(_) => "hostname",
            Op::OpTimezone(_) => "timezone",
            Op::OpCopyTarget(_) => "copy_target",
        }
    }
}
