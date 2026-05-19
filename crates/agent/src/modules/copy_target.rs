//! `OpCopyTarget` — host-local copy from one path on the agent host to
//! another. Maps Ansible's `copy:` module with `remote_src: yes`.
//!
//! The controller never reads the source bytes; we read `src` here and
//! lay them down at `dest` using the same staged-tmp + chmod + chown +
//! validate + rename ceremony as `OpWriteFile`. The validator path is
//! identical (and uses the same shared `validate_helper`).
//!
//! Idempotency: `changed=1` iff the dest's prior content, mode, or
//! ownership differed from what we just wrote.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use rsansible_wire::generated::OpCopyTargetOutput;
use rsansible_wire::msg::{self, now_unix_ns};
use tokio::io::AsyncWriteExt;

use super::file::{lchown_path, resolve_group, resolve_user};
use super::validate_helper::{validate_tmp, ValidateError};
use super::{emit_error, Context};

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpCopyTargetOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    let src = PathBuf::from(&op.src);
    let dest = PathBuf::from(&op.dest);

    // Read src bytes. `tokio::fs::read` follows symlinks, which matches
    // Ansible's copy semantics. NotFound is surfaced as NOT_FOUND so the
    // task error is actionable.
    let src_bytes = match tokio::fs::read(&src).await {
        Ok(b) => b,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                map_io_err(&e),
                format!("read src {}: {e}", op.src),
            )
            .await;
            return Ok(());
        }
    };

    // Resolve owner/group up front so we can fail fast without touching
    // the filesystem if the name isn't in /etc/passwd or /etc/group.
    let want_uid = if op.owner.is_empty() {
        None
    } else {
        match resolve_user(&op.owner) {
            Ok(u) => Some(u),
            Err(name) => {
                emit_error(
                    ctx,
                    seq,
                    msg::err::BAD_REQUEST,
                    format!("unknown user {name:?}"),
                )
                .await;
                return Ok(());
            }
        }
    };
    let want_gid = if op.group.is_empty() {
        None
    } else {
        match resolve_group(&op.group) {
            Ok(g) => Some(g),
            Err(name) => {
                emit_error(
                    ctx,
                    seq,
                    msg::err::BAD_REQUEST,
                    format!("unknown group {name:?}"),
                )
                .await;
                return Ok(());
            }
        }
    };

    // Determine the prior dest state for the changed flag and the
    // would-change short-circuit in check mode.
    let prior_meta = tokio::fs::metadata(&dest).await.ok();
    let prior_bytes = match tokio::fs::read(&dest).await {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                map_io_err(&e),
                format!("read prior {}: {e}", op.dest),
            )
            .await;
            return Ok(());
        }
    };
    let content_diff = prior_bytes.as_deref() != Some(src_bytes.as_slice());
    let mode_diff = if op.has_mode != 0 {
        prior_meta
            .as_ref()
            .map(|m| (m.permissions().mode() & 0o7777) != (op.mode & 0o7777))
            .unwrap_or(true)
    } else {
        false
    };
    let owner_diff = match (want_uid, prior_meta.as_ref()) {
        (Some(u), Some(m)) => m.uid() != u,
        (Some(_), None) => true,
        _ => false,
    };
    let group_diff = match (want_gid, prior_meta.as_ref()) {
        (Some(g), Some(m)) => m.gid() != g,
        (Some(_), None) => true,
        _ => false,
    };
    let would_change = content_diff || mode_diff || owner_diff || group_diff;

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

    // Stage to a sibling tmp file so the rename is atomic on POSIX.
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let pid = std::process::id();
    let tmp_name = format!(
        ".{}.rsansible.tmp.{pid}.{seq}",
        dest.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "out".into())
    );
    let tmp_path = match parent {
        Some(p) => p.join(&tmp_name),
        None => PathBuf::from(&tmp_name),
    };

    let write_result = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        f.write_all(&src_bytes).await?;
        f.sync_all().await?;
        drop(f);
        if op.has_mode != 0 {
            tokio::fs::set_permissions(
                &tmp_path,
                std::fs::Permissions::from_mode(op.mode & 0o7777),
            )
            .await?;
        }
        Ok::<_, std::io::Error>(())
    }
    .await;

    if let Err(e) = write_result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        emit_error(
            ctx,
            seq,
            map_io_err(&e),
            format!("write {}: {e}", op.dest),
        )
        .await;
        return Ok(());
    }

    // Chown the staged tmp before validation/rename so the final swap
    // is one atomic step. `lchown_path` doesn't follow symlinks but the
    // tmp is a fresh regular file so that's a no-op distinction.
    if want_uid.is_some() || want_gid.is_some() {
        // Fill in "unchanged" with the tmp's current uid/gid so chown
        // only flips what was asked. The tmp was just created by us so
        // it has our euid/egid.
        let (current_uid, current_gid) = match tokio::fs::metadata(&tmp_path).await {
            Ok(m) => (m.uid(), m.gid()),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                emit_error(
                    ctx,
                    seq,
                    map_io_err(&e),
                    format!("stat staged tmp {}: {e}", tmp_path.display()),
                )
                .await;
                return Ok(());
            }
        };
        let uid = want_uid.unwrap_or(current_uid);
        let gid = want_gid.unwrap_or(current_gid);
        if let Err(reason) = lchown_path(&tmp_path, uid, gid) {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            emit_error(ctx, seq, msg::err::IO, reason).await;
            return Ok(());
        }
    }

    // Optional validate before swap. Same contract as OpWriteFile.
    if !op.validate.is_empty() {
        let validate_str = op.validate.clone();
        let tmp_for_validate = tmp_path.clone();
        let validate_result =
            tokio::task::spawn_blocking(move || validate_tmp(&validate_str, &tmp_for_validate))
                .await
                .expect("validate task panicked");
        match validate_result {
            Ok(()) => {}
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
                        op.dest
                    )
                } else {
                    format!(
                        "validate command exited {code} for {} — leaving dest untouched: {trimmed}",
                        op.dest
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
                    format!("validate spawn failed for {}: {e}", op.dest),
                )
                .await;
                return Ok(());
            }
        }
    }

    if let Err(e) = tokio::fs::rename(&tmp_path, &dest).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        emit_error(
            ctx,
            seq,
            map_io_err(&e),
            format!("rename {} -> {}: {e}", tmp_path.display(), op.dest),
        )
        .await;
        return Ok(());
    }

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
    Ok(())
}

fn map_io_err(e: &std::io::Error) -> u8 {
    match e.kind() {
        std::io::ErrorKind::NotFound => msg::err::NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => msg::err::PERMISSION,
        _ => msg::err::IO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::msg::op_copy_target;
    use rsansible_wire::Op;
    use std::fs;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    fn ctx_and_rx() -> (Context, mpsc::Receiver<rsansible_wire::Message>) {
        let (tx, rx) = mpsc::channel(64);
        (Context::new(crate::writer::Sender(tx)), rx)
    }

    async fn drain(mut rx: mpsc::Receiver<rsansible_wire::Message>) -> Vec<rsansible_wire::Message> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        // Drain anything pending.
        while let Ok(Some(m)) =
            tokio::time::timeout(std::time::Duration::from_millis(10), rx.recv()).await
        {
            out.push(m);
        }
        out
    }

    #[tokio::test]
    async fn copy_target_copies_bytes_and_reports_changed() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        fs::write(&src, b"hello world").unwrap();

        let (ctx, rx) = ctx_and_rx();
        let Op::OpCopyTarget(op) = op_copy_target(
            src.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
            Some(0o644),
            String::new(),
            String::new(),
            String::new(),
        ) else {
            panic!()
        };
        run(&ctx, 1, op, false).await.unwrap();
        drop(ctx);

        assert_eq!(fs::read(&dest).unwrap(), b"hello world");
        let msgs = drain(rx).await;
        let done = msgs.iter().find_map(|m| match m {
            rsansible_wire::Message::TaskDone(d) => Some(d),
            _ => None,
        });
        let done = done.expect("expected TaskDone");
        assert_eq!(done.changed, 1);
        assert_eq!(done.exit_code, 0);
    }

    #[tokio::test]
    async fn copy_target_idempotent_no_change_when_identical() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        fs::write(&src, b"same").unwrap();
        fs::write(&dest, b"same").unwrap();
        // Match mode so mode_diff is also false.
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o644)).unwrap();

        let (ctx, rx) = ctx_and_rx();
        let Op::OpCopyTarget(op) = op_copy_target(
            src.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
            Some(0o644),
            String::new(),
            String::new(),
            String::new(),
        ) else {
            panic!()
        };
        run(&ctx, 2, op, false).await.unwrap();
        drop(ctx);

        let msgs = drain(rx).await;
        let done = msgs.iter().find_map(|m| match m {
            rsansible_wire::Message::TaskDone(d) => Some(d),
            _ => None,
        });
        assert_eq!(done.expect("done").changed, 0);
    }

    #[tokio::test]
    async fn copy_target_validate_failure_leaves_dest_untouched() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        fs::write(&src, b"new").unwrap();
        fs::write(&dest, b"old").unwrap();

        let (ctx, rx) = ctx_and_rx();
        let Op::OpCopyTarget(op) = op_copy_target(
            src.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
            Some(0o644),
            String::new(),
            String::new(),
            // /bin/false always exits non-zero — should kill the swap.
            "/bin/false %s".to_string(),
        ) else {
            panic!()
        };
        run(&ctx, 3, op, false).await.unwrap();
        drop(ctx);

        // Dest must still be the original bytes.
        assert_eq!(fs::read(&dest).unwrap(), b"old");
        let msgs = drain(rx).await;
        let err = msgs.iter().find_map(|m| match m {
            rsansible_wire::Message::TaskError(e) => Some(e),
            _ => None,
        });
        assert!(err.is_some(), "expected TaskError, got {msgs:#?}");
    }

    #[tokio::test]
    async fn copy_target_missing_src_emits_not_found() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("nope.bin");
        let dest = dir.path().join("dest.bin");

        let (ctx, rx) = ctx_and_rx();
        let Op::OpCopyTarget(op) = op_copy_target(
            src.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
            None,
            String::new(),
            String::new(),
            String::new(),
        ) else {
            panic!()
        };
        run(&ctx, 4, op, false).await.unwrap();
        drop(ctx);

        let msgs = drain(rx).await;
        let err = msgs.iter().find_map(|m| match m {
            rsansible_wire::Message::TaskError(e) => Some(e),
            _ => None,
        });
        let err = err.expect("expected TaskError");
        assert_eq!(err.code, msg::err::NOT_FOUND);
    }

    #[tokio::test]
    async fn copy_target_check_mode_reports_would_change_without_writing() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        fs::write(&src, b"new").unwrap();
        // dest doesn't exist — would_change=true.

        let (ctx, rx) = ctx_and_rx();
        let Op::OpCopyTarget(op) = op_copy_target(
            src.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
            Some(0o644),
            String::new(),
            String::new(),
            String::new(),
        ) else {
            panic!()
        };
        run(&ctx, 5, op, true).await.unwrap();
        drop(ctx);

        assert!(!dest.exists(), "check mode must not write dest");
        let msgs = drain(rx).await;
        let done = msgs.iter().find_map(|m| match m {
            rsansible_wire::Message::TaskDone(d) => Some(d),
            _ => None,
        });
        let done = done.expect("done");
        assert_eq!(done.changed, 1);
        assert_eq!(done.exit_code, 0);
    }
}
