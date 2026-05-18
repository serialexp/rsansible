//! `OpRepository` — generic package-repository wrapper.
//!
//! Dispatches by the `manager` byte to a per-backend module. Mirrors the
//! `package` module's shape (and shares its `auto_detect` lookup table)
//! so adding a new backend only touches the spot under `repository/` and
//! the byte table — never both.

use rsansible_wire::generated::OpRepositoryOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

pub(crate) mod apt;

const MANAGER_AUTO: u8 = 0;
const MANAGER_APT: u8 = 1;

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpRepositoryOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    if op.repo.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "repository: empty `repo`").await;
        return Ok(());
    }

    let manager = if op.manager == MANAGER_AUTO {
        match auto_detect() {
            Some(m) => m,
            None => {
                emit_error(
                    ctx,
                    seq,
                    err::BAD_REQUEST,
                    "repository: manager=auto but no supported package manager found on PATH",
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
                .map_err(|e| anyhow::anyhow!("repository apt join: {e}"))?
        }
        other => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("repository: manager byte {other} is not implemented yet"),
            )
            .await;
            return Ok(());
        }
    };

    let changed = match result {
        Ok(c) => c,
        Err(RepositoryError::Io(m)) => {
            emit_error(ctx, seq, err::IO, m).await;
            return Ok(());
        }
        Err(RepositoryError::Spawn(m)) => {
            emit_error(ctx, seq, err::SPAWN_FAILED, m).await;
            return Ok(());
        }
        Err(RepositoryError::BadRequest(m)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, m).await;
            return Ok(());
        }
    };

    let finished = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, false, started_unix_ns, finished))
        .await;
    Ok(())
}

#[derive(Debug)]
pub(crate) enum RepositoryError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

fn auto_detect() -> Option<u8> {
    // Share the `package` module's heuristic — same set of supported
    // managers means same detection order. (We don't import the function
    // because it's private; a copy is cheaper than re-shaping the API.)
    if which("apt-get") {
        return Some(MANAGER_APT);
    }
    None
}

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
