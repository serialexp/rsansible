//! `OpWriteFile` — atomic write to `path`.
//!
//! - Writes the payload to a sibling `*.rsansible.tmp.<pid>.<seq>` file with the
//!   requested mode, fsyncs it, then renames over the target. Rename within
//!   the same directory is atomic on POSIX filesystems.
//! - When `validate` is non-empty, the command is run against the staged tmp
//!   file before the rename. Non-zero exit code: unlink tmp, leave dest
//!   untouched, fail the task with the validator's stderr. The literal token
//!   `%s` in `validate` is substituted with the tmp path (matches Ansible's
//!   `validate:` semantics on `copy`/`template`/`lineinfile`/`blockinfile`).
//! - `changed` is reported true iff the target's prior content or mode differed
//!   from what we just wrote. Matches Ansible's `copy` module semantics.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use rsansible_wire::generated::OpWriteFileOutput;
use rsansible_wire::msg::{self, now_unix_ns};
use tokio::io::AsyncWriteExt;

use super::file::{
    chown_group_only, chown_user_only, lchown_path, resolve_group, resolve_user,
};
use super::validate_helper::{validate_tmp, ValidateError};
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
    // Capture prior mode + ownership in one stat — both feed into the
    // `would_change` heuristic. We don't separate the two stats because
    // the file is already touched here on the read path above; one
    // metadata() is no cheaper than coalescing here.
    let prior_meta = tokio::fs::metadata(&path).await.ok();
    let prior_mode = prior_meta.as_ref().map(|m| m.permissions().mode() & 0o7777);
    let prior_uid = prior_meta.as_ref().map(|m| m.uid());
    let prior_gid = prior_meta.as_ref().map(|m| m.gid());

    // Resolve owner/group up front so we can fail before touching the
    // dest with a clear BAD_REQUEST if either is unknown. Empty
    // string = don't chown (matches OpCopyTarget / OpFile semantics).
    let target_uid: Option<u32> = if op.owner.is_empty() {
        None
    } else {
        match resolve_user(&op.owner) {
            Ok(uid) => Some(uid),
            Err(name) => {
                emit_error(
                    ctx,
                    seq,
                    msg::err::BAD_REQUEST,
                    format!("unknown owner {name:?} for {}", op.path),
                )
                .await;
                return Ok(());
            }
        }
    };
    let target_gid: Option<u32> = if op.group.is_empty() {
        None
    } else {
        match resolve_group(&op.group) {
            Ok(gid) => Some(gid),
            Err(name) => {
                emit_error(
                    ctx,
                    seq,
                    msg::err::BAD_REQUEST,
                    format!("unknown group {name:?} for {}", op.path),
                )
                .await;
                return Ok(());
            }
        }
    };

    // Compute the would-change diff up front; both the check-mode path
    // and the normal post-write path use it. A request to chown to a
    // different uid/gid (or to chown a file that doesn't yet exist)
    // counts as a change.
    let content_diff = prior.as_deref() != Some(op.content.as_slice());
    let mode_diff = prior_mode.map(|m| m != (mode & 0o7777)).unwrap_or(true);
    let uid_diff = match (target_uid, prior_uid) {
        (Some(want), Some(have)) => want != have,
        (Some(_), None) => true, // file doesn't exist yet
        (None, _) => false,
    };
    let gid_diff = match (target_gid, prior_gid) {
        (Some(want), Some(have)) => want != have,
        (Some(_), None) => true,
        (None, _) => false,
    };
    let would_change = content_diff || mode_diff || uid_diff || gid_diff;

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

    // Apply chown to the staged tmp before the rename — landing the
    // final ownership atomically with the swap. Mirrors OpCopyTarget's
    // contract: empty owner / group means "don't change"; non-empty
    // values are resolved on the agent host and applied. Anchoring the
    // chown to the tmp (rather than chown'ing the post-rename dest)
    // means an in-flight reader of `path` never sees a transient
    // root-owned file when the playbook asked for caddy-owned. Caught
    // in the gothab drill: Caddyfile deployed as root:root despite
    // playbook saying `group: caddy`, so `systemctl reload caddy`
    // failed with `permission denied` because caddy can't read its
    // own config.
    // Three combinations: owner+group (both → lchown_path), owner only
    // (chown_user_only — leaves group intact), group only
    // (chown_group_only — leaves owner intact). Single-side variants
    // delegate to `chown :<gid>` / `chown <uid>` semantics so the
    // unspecified field carries through from the staged tmp without
    // needing to know the agent's current EUID/EGID.
    let chown_result = match (target_uid, target_gid) {
        (Some(uid), Some(gid)) => lchown_path(&tmp_path, uid, gid),
        (Some(uid), None) => chown_user_only(&tmp_path, uid),
        (None, Some(gid)) => chown_group_only(&tmp_path, gid),
        (None, None) => Ok(()),
    };
    if let Err(msg_text) = chown_result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        emit_error(
            ctx,
            seq,
            msg::err::IO,
            format!("chown {}: {msg_text}", op.path),
        )
        .await;
        return Ok(());
    }

    // Validate the staged tmp file before swapping it into place. If the
    // validator fails (non-zero exit, missing binary, no `%s` to substitute,
    // ...), the dest is left untouched and the task fails. This is the
    // *whole point* of `validate:` — broken sudoers / nginx config / sshd
    // config never reaches the real path. Run the (sync) validator on the
    // blocking pool so we don't park the agent's I/O reactor on it.
    if !op.validate.is_empty() {
        let validate_str = op.validate.clone();
        let tmp_for_validate = tmp_path.clone();
        let validate_result = tokio::task::spawn_blocking(move || {
            validate_tmp(&validate_str, &tmp_for_validate)
        })
        .await
        .expect("validate task panicked");
        match validate_result {
            Ok(()) => { /* fall through to rename */ }
            Err(ValidateError::BadRequest(msg_text)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                emit_error(ctx, seq, msg::err::BAD_REQUEST, msg_text).await;
                return Ok(());
            }
            Err(ValidateError::Failed { code, stderr }) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                let trimmed = stderr.trim();
                let reason = if trimmed.is_empty() {
                    format!(
                        "validate command exited {code} for {} — leaving dest untouched",
                        op.path
                    )
                } else {
                    format!(
                        "validate command exited {code} for {} — leaving dest untouched: {trimmed}",
                        op.path
                    )
                };
                emit_error(ctx, seq, msg::err::BAD_REQUEST, reason).await;
                return Ok(());
            }
            Err(ValidateError::Spawn(e)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                emit_error(
                    ctx,
                    seq,
                    msg::err::IO,
                    format!("validate spawn failed for {}: {e}", op.path),
                )
                .await;
                return Ok(());
            }
        }
    }

    if let Err(e) = tokio::fs::rename(&tmp_path, &path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        emit_error(
            ctx,
            seq,
            map_io_err(&e),
            format!("rename {} -> {}: {e}", tmp_path.display(), op.path),
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
