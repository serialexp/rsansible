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
