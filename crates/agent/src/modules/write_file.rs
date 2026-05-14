//! `OpWriteFile` — atomic write to `path`.
//!
//! - Writes the payload to a sibling `*.rsansible.tmp.<pid>.<seq>` file with the
//!   requested mode, fsyncs it, then renames over the target. Rename within
//!   the same directory is atomic on POSIX filesystems.
//! - `changed` is reported true iff the target's prior content or mode differed
//!   from what we just wrote. Matches Ansible's `copy` module semantics.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Instant;

use rsansible_wire::generated::OpWriteFileOutput;
use rsansible_wire::msg;
use tokio::io::AsyncWriteExt;

use super::{emit_error, Context};

pub async fn run(ctx: &Context, seq: u32, op: OpWriteFileOutput) -> anyhow::Result<()> {
    let started = Instant::now();
    let path = PathBuf::from(&op.path);
    let mode = op.mode;

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

    let changed = prior.as_deref() != Some(op.content.as_slice())
        || prior_mode.map(|m| m != (mode & 0o7777)).unwrap_or(true);

    let took_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
    ctx.emit(msg::task_done(seq, 0, changed, took_ms)).await;
    Ok(())
}

fn map_io_err(e: &std::io::Error) -> u8 {
    match e.kind() {
        std::io::ErrorKind::NotFound => msg::err::NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => msg::err::PERMISSION,
        _ => msg::err::IO,
    }
}
