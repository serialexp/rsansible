//! `OpPackage` — generic package-manager wrapper.
//!
//! Dispatches by the `manager` byte to a per-backend module. Adding a
//! new package manager is a four-step change here:
//!   1. add a `package_manager::<NAME>` constant in `crates/wire/src/msg.rs`
//!   2. add a backend submodule under `package/` exposing `apply()`
//!   3. add a `MANAGER_<NAME>` constant + dispatch arm below
//!   4. (optional) teach `auto_detect` to pick it
//!
//! The wire op carries a *union* of all backends' knobs. Each backend
//! ignores the fields it doesn't understand (e.g. `default_release` is
//! a no-op for everything other than apt). This keeps the wire schema
//! flat at the cost of "some flags are meaningless for some managers";
//! that trade-off is fine while the agent stays the single place that
//! knows which knobs each manager actually consumes.

use rsansible_wire::generated::OpPackageOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

pub(crate) mod apt;

// Manager-byte constants, mirrored from `rsansible_wire::msg::package_manager`.
// We keep a local copy so the dispatch table reads naturally; if it
// drifts, the round-trip tests in `framing` catch it.
const MANAGER_AUTO: u8 = 0;
const MANAGER_APT: u8 = 1;
// const MANAGER_DNF: u8 = 2;  // reserved
// const MANAGER_YUM: u8 = 3;  // reserved
// const MANAGER_APK: u8 = 4;  // reserved
// const MANAGER_PACMAN: u8 = 5;  // reserved
// const MANAGER_ZYPPER: u8 = 6;  // reserved

pub async fn run(ctx: &Context, seq: u32, op: OpPackageOutput, check_mode: bool) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    if op.names.is_empty() && op.update_cache == 0 && op.autoremove == 0 {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            "package: need at least one of [name(s), update_cache, autoremove]",
        )
        .await;
        return Ok(());
    }

    // Resolve `auto` to a concrete manager before dispatching. Doing the
    // detection here (rather than inside each backend) means each
    // backend can assume "I was asked for, I'm the right one to run."
    let manager = if op.manager == MANAGER_AUTO {
        match auto_detect() {
            Some(m) => m,
            None => {
                emit_error(
                    ctx,
                    seq,
                    err::BAD_REQUEST,
                    "package: manager=auto but no supported package manager found on PATH",
                )
                .await;
                return Ok(());
            }
        }
    } else {
        op.manager
    };

    let result = match manager {
        MANAGER_APT => {
            let op = op.clone();
            tokio::task::spawn_blocking(move || apt::apply(&op, check_mode))
                .await
                .map_err(|e| anyhow::anyhow!("package apt join: {e}"))?
        }
        other => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("package: manager byte {other} is not implemented yet"),
            )
            .await;
            return Ok(());
        }
    };

    let changed = match result {
        Ok(c) => c,
        Err(PackageError::Io(m)) => {
            emit_error(ctx, seq, err::IO, m).await;
            return Ok(());
        }
        Err(PackageError::Spawn(m)) => {
            emit_error(ctx, seq, err::SPAWN_FAILED, m).await;
            return Ok(());
        }
        Err(PackageError::BadRequest(m)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, m).await;
            return Ok(());
        }
    };

    let finished = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, false, started_unix_ns, finished))
        .await;
    Ok(())
}

/// Errors shared across backends. Each variant maps to a `TaskError.code`
/// in the caller.
#[derive(Debug)]
pub(crate) enum PackageError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

/// Auto-detection: probe `PATH` for known manager binaries in order of
/// specificity (apt before yum/dnf for Debian boxes, apk for Alpine,
/// etc.). Returns the manager byte to dispatch to, or None if nothing
/// recognized was found.
///
/// We only check binaries we have backends for; reserved-but-unimplemented
/// constants are intentionally absent so `auto` can't pick a backend
/// that would then return BAD_REQUEST.
fn auto_detect() -> Option<u8> {
    if which("apt-get") {
        return Some(MANAGER_APT);
    }
    None
}

/// Cheap PATH probe — split `$PATH` on `:`, look for an executable file
/// named `bin`. Avoids a `which` dependency.
fn which(bin: &str) -> bool {
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };
    for entry in std::env::split_paths(&path) {
        let candidate = entry.join(bin);
        if let Ok(md) = std::fs::metadata(&candidate) {
            if md.is_file() {
                use std::os::unix::fs::PermissionsExt;
                if md.permissions().mode() & 0o111 != 0 {
                    return true;
                }
            }
        }
    }
    false
}
