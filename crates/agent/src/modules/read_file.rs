//! `OpReadFile` — read a file on the agent host, ship its bytes back to
//! the controller in a base64-encoded envelope shaped like Ansible's
//! `ansible.builtin.slurp`.
//!
//! Output envelope on stdout:
//! ```json
//! {
//!   "content":  "<base64-encoded file bytes>",
//!   "source":   "<requested path>",
//!   "encoding": "base64"
//! }
//! ```
//!
//! `max_bytes=0` is the "no cap" sentinel; any other value rejects files
//! whose length on disk exceeds the cap with `TaskError(BAD_REQUEST)`
//! before reading the body. The size check is taken from
//! `std::fs::metadata` (after symlink resolution — slurp follows links),
//! so a file growing under us between metadata-check and read may still
//! end up larger than `max_bytes`; the read itself is still bounded by
//! the controller-supplied cap via `take()` on the file handle.
//!
//! Missing path → `TaskError(NOT_FOUND)`. Permission denied opening the
//! file → `TaskError(PERMISSION)`. Other IO → `TaskError(IO)`.

use base64::Engine as _;
use rsansible_wire::generated::OpReadFileOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};
use serde_json::json;
use std::io::Read;

use super::{emit_error, Context};

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpReadFileOutput,
    _check_mode: bool,
) -> anyhow::Result<()> {
    // Reading is read-only — `_check_mode` is accepted for uniform
    // plumbing and ignored. A `--check` run still ships the file's
    // contents because the contents are observation, not mutation.
    let started_unix_ns = now_unix_ns();
    let path = op.path;
    let cap = op.max_bytes;

    let path_buf = std::path::PathBuf::from(&path);

    // Metadata first — gives us a fast NOT_FOUND / type / size answer
    // without opening the file.
    let meta = match std::fs::metadata(&path_buf) {
        Ok(m) => m,
        Err(e) => {
            return emit_io_error(ctx, seq, &path, e).await;
        }
    };

    if !meta.is_file() {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            format!("read_file: {path} is not a regular file"),
        )
        .await;
        return Ok(());
    }

    if cap > 0 && meta.len() > u64::from(cap) {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            format!(
                "read_file: {path} is {} bytes, exceeds max_bytes={cap}",
                meta.len()
            ),
        )
        .await;
        return Ok(());
    }

    // Read, with a defence-in-depth cap on the read side. If `cap==0`,
    // read the whole file.
    let read_limit = if cap == 0 { u64::MAX } else { u64::from(cap) };
    let mut buf: Vec<u8> = Vec::with_capacity(meta.len().min(read_limit) as usize);
    let file = match std::fs::File::open(&path_buf) {
        Ok(f) => f,
        Err(e) => {
            return emit_io_error(ctx, seq, &path, e).await;
        }
    };
    if let Err(e) = file.take(read_limit).read_to_end(&mut buf) {
        emit_error(
            ctx,
            seq,
            err::IO,
            format!("read_file: read({path}): {e}"),
        )
        .await;
        return Ok(());
    }

    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
    let envelope = json!({
        "content":  b64,
        "source":   path,
        "encoding": "base64",
    });
    let bytes = serde_json::to_vec(&envelope)?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;

    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        /*changed=*/ false,
        /*skipped=*/ false,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

async fn emit_io_error(
    ctx: &Context,
    seq: u32,
    path: &str,
    e: std::io::Error,
) -> anyhow::Result<()> {
    let code = match e.kind() {
        std::io::ErrorKind::NotFound => err::NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => err::PERMISSION,
        _ => err::IO,
    };
    emit_error(ctx, seq, code, format!("read_file: {path}: {e}")).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::Sender;
    use rsansible_wire::Message;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::sync::mpsc;

    fn make_ctx() -> (Context, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel::<Message>(64);
        (Context::new(Sender(tx)), rx)
    }

    async fn drain(rx: &mut mpsc::Receiver<Message>) -> Vec<Message> {
        let mut out = Vec::new();
        while let Ok(m) = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            rx.recv(),
        )
        .await
        {
            match m {
                Some(m) => out.push(m),
                None => break,
            }
        }
        out
    }

    fn envelope_from(msgs: &[Message]) -> Option<serde_json::Value> {
        for m in msgs {
            if let Message::TaskProgress(p) = m {
                if p.stream == msg::stream::STDOUT {
                    return serde_json::from_slice(&p.chunk).ok();
                }
            }
        }
        None
    }

    fn done_of(msgs: &[Message]) -> Option<&rsansible_wire::generated::TaskDoneOutput> {
        msgs.iter().find_map(|m| match m {
            Message::TaskDone(d) => Some(d),
            _ => None,
        })
    }

    fn error_of(msgs: &[Message]) -> Option<&rsansible_wire::generated::TaskErrorOutput> {
        msgs.iter().find_map(|m| match m {
            Message::TaskError(e) => Some(e),
            _ => None,
        })
    }

    fn op_for(path: &str, max_bytes: u32) -> OpReadFileOutput {
        OpReadFileOutput {
            kind: 18,
            path: path.into(),
            max_bytes,
        }
    }

    #[tokio::test]
    async fn happy_path_round_trips_content() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"the quick brown fox\n").unwrap();
        let path = file.path().to_string_lossy().to_string();

        let (ctx, mut rx) = make_ctx();
        run(&ctx, 1, op_for(&path, 0), false).await.unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let env = envelope_from(&msgs).expect("envelope on stdout");
        let done = done_of(&msgs).expect("TaskDone");
        assert_eq!(done.exit_code, 0);
        assert_eq!(done.changed, 0);
        assert_eq!(env["encoding"], "base64");
        assert_eq!(env["source"], path);
        let content = env["content"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(content)
            .unwrap();
        assert_eq!(decoded, b"the quick brown fox\n");
    }

    #[tokio::test]
    async fn missing_path_emits_not_found() {
        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            2,
            op_for("/this/path/almost/certainly/does/not/exist", 0),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let e = error_of(&msgs).expect("TaskError");
        assert_eq!(e.code, err::NOT_FOUND);
    }

    #[tokio::test]
    async fn directory_rejected_as_bad_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().to_string();
        let (ctx, mut rx) = make_ctx();
        run(&ctx, 3, op_for(&path, 0), false).await.unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let e = error_of(&msgs).expect("TaskError");
        assert_eq!(e.code, err::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cap_exceeded_rejected_before_read() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&vec![b'x'; 4096]).unwrap();
        let path = file.path().to_string_lossy().to_string();

        let (ctx, mut rx) = make_ctx();
        run(&ctx, 4, op_for(&path, 100), false).await.unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let e = error_of(&msgs).expect("TaskError");
        assert_eq!(e.code, err::BAD_REQUEST);
        assert!(e.message.contains("exceeds max_bytes"));
    }

    #[tokio::test]
    async fn empty_file_round_trips_empty_content() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();

        let (ctx, mut rx) = make_ctx();
        run(&ctx, 5, op_for(&path, 0), false).await.unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let env = envelope_from(&msgs).expect("envelope on stdout");
        let content = env["content"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(content)
            .unwrap();
        assert_eq!(decoded, b"");
    }

    #[tokio::test]
    async fn binary_content_round_trips_through_base64() {
        let mut file = NamedTempFile::new().unwrap();
        let payload: Vec<u8> = (0u8..=255).collect();
        file.write_all(&payload).unwrap();
        let path = file.path().to_string_lossy().to_string();

        let (ctx, mut rx) = make_ctx();
        run(&ctx, 6, op_for(&path, 0), false).await.unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let env = envelope_from(&msgs).expect("envelope on stdout");
        let content = env["content"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(content)
            .unwrap();
        assert_eq!(decoded, payload);
    }
}
