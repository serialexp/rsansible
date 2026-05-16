//! `OpWriteFile` — atomic write to `path`.
//!
//! - Writes the payload to a sibling `*.rsansible.tmp.<pid>.<seq>` file with the
//!   requested mode, fsyncs it, then renames over the target. Rename within
//!   the same directory is atomic on POSIX filesystems.
//! - `changed` is reported true iff the target's prior content or mode differed
//!   from what we just wrote. Matches Ansible's `copy` module semantics.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use rsansible_wire::generated::OpWriteFileOutput;
use rsansible_wire::msg::{self, now_unix_ns};
use tokio::io::AsyncWriteExt;

use super::{emit_error, Context};

pub async fn run(ctx: &Context, seq: u32, op: OpWriteFileOutput, check_mode: bool) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    let path = PathBuf::from(&op.path);
    let mode = op.mode;

    // `only_if_missing=1` short-circuits without reading or writing: if the
    // file exists, we report changed=false and bail. Used by the controller's
    // ship-blind privkey path so a generated PEM doesn't clobber a key the
    // operator already has on disk. A bare `symlink_metadata` is enough — we
    // don't care whether the target is a regular file, only whether the path
    // is occupied.
    if op.only_if_missing != 0 {
        match tokio::fs::symlink_metadata(&path).await {
            Ok(_) => {
                let finished_unix_ns = now_unix_ns();
                ctx.emit(msg::task_done(seq, 0, false, false, started_unix_ns, finished_unix_ns))
                    .await;
                return Ok(());
            }
            // Path doesn't exist → fall through to the normal write path.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Any other lstat error is a real failure (e.g. EACCES on the
            // parent dir) and should surface — same shape as a read failure
            // on the regular path.
            Err(e) => {
                emit_error(
                    ctx,
                    seq,
                    map_io_err(&e),
                    format!("stat {}: {e}", op.path),
                )
                .await;
                return Ok(());
            }
        }
    }

    // Determine prior state for the `changed` flag.
    let prior = match tokio::fs::read(&path).await {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                map_io_err(&e),
                format!("read prior {}: {e}", op.path),
            )
            .await;
            return Ok(());
        }
    };
    let prior_mode = match tokio::fs::metadata(&path).await {
        Ok(m) => Some(m.permissions().mode() & 0o7777),
        Err(_) => None,
    };
    // Compute the would-change diff up front; both the check-mode path
    // and the normal post-write path use it.
    let would_change = prior.as_deref() != Some(op.content.as_slice())
        || prior_mode.map(|m| m != (mode & 0o7777)).unwrap_or(true);

    // Dry-run: report what we'd change without touching the file. The
    // diff is exact (we read prior content and mode above) so the
    // `changed` flag is the same value we'd report on a real run.
    if check_mode {
        let finished_unix_ns = now_unix_ns();
        ctx.emit(msg::task_done(
            seq,
            0,
            would_change,
            false,
            started_unix_ns,
            finished_unix_ns,
        ))
        .await;
        return Ok(());
    }

    // Stage to a tmp file in the same directory so rename(2) is atomic. If the
    // target has no parent (i.e. relative bare filename), stage in CWD.
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let pid = std::process::id();
    let tmp_name = format!(
        ".{}.rsansible.tmp.{pid}.{seq}",
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "out".into())
    );
    let tmp_path = match parent {
        Some(p) => p.join(&tmp_name),
        None => PathBuf::from(&tmp_name),
    };

    // Write + fsync + rename.
    let write_result = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        f.write_all(&op.content).await?;
        // Sync the file's data and the rename's directory entry. The data sync
        // ensures the content is durable; the rename itself is atomic but we
        // skip parent-dir fsync here — that's a v0 simplification, real Ansible
        // doesn't do it either. Power-loss durability of the rename is left to
        // the filesystem's journaling.
        f.sync_all().await?;
        drop(f);

        tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode)).await?;
        tokio::fs::rename(&tmp_path, &path).await?;
        Ok::<_, std::io::Error>(())
    }
    .await;

    if let Err(e) = write_result {
        // Best-effort cleanup of the staged tmp file — if it leaked, the next
        // run with the same pid+seq would conflict (unlikely, but bounded by
        // PID space). Silently ignore the cleanup error.
        let _ = tokio::fs::remove_file(&tmp_path).await;
        emit_error(
            ctx,
            seq,
            map_io_err(&e),
            format!("write {}: {e}", op.path),
        )
        .await;
        return Ok(());
    }

    let changed = would_change;

    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, false, started_unix_ns, finished_unix_ns)).await;
    Ok(())
}

fn map_io_err(e: &std::io::Error) -> u8 {
    match e.kind() {
        std::io::ErrorKind::NotFound => msg::err::NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => msg::err::PERMISSION,
        _ => msg::err::IO,
    }
}
