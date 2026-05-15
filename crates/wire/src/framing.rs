//! Length-prefix framing for `Message`.
//!
//! Frame layout: `u32` little-endian length (in bytes) followed by exactly that
//! many bytes of an encoded `Message`. We pick u32 over u16 because file ops
//! (`OpWriteFile`, `OpExec.stdin`) already carry u32-prefixed payloads — a u16
//! frame cap would create an artificial 64 KiB ceiling. The 2 extra bytes per
//! frame are negligible.
//!
//! Frames are capped at [`MAX_FRAME_LEN`] to bound memory on the decode path
//! and reject corrupted input early. Set generously above any reasonable
//! single-op payload; large file pushes will eventually be chunked at a layer
//! above this one.

use crate::generated::Message;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed frame body length. 64 MiB.
///
/// Chosen as a soft DoS guard, not a protocol invariant. If a future op needs
/// to push more than this in a single message we'll either raise it or chunk.
pub const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame body length {0} exceeds MAX_FRAME_LEN ({1})")]
    TooLarge(u32, u32),
    #[error("binschema encode/decode error: {0}")]
    Codec(String),
}

impl From<binschema_runtime::BinSchemaError> for FramingError {
    fn from(e: binschema_runtime::BinSchemaError) -> Self {
        FramingError::Codec(e.to_string())
    }
}

/// Read one length-prefixed frame from `r` and decode it.
///
/// Returns `Ok(None)` if the stream is closed cleanly at a frame boundary
/// (i.e. EOF before any bytes of the next length prefix arrived). Returns
/// `Err(FramingError::Io(UnexpectedEof))` if EOF lands mid-frame.
pub async fn read_frame<R>(r: &mut R) -> Result<Option<Message>, FramingError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];

    // Distinguish clean-close-at-boundary from mid-frame EOF: read the first
    // byte, then read the rest. read_exact returns UnexpectedEof when partial,
    // so we have to handle that ourselves for the boundary case.
    match r.read(&mut len_buf[..1]).await {
        Ok(0) => return Ok(None), // clean close
        Ok(_) => {}
        Err(e) => return Err(FramingError::Io(e)),
    }
    r.read_exact(&mut len_buf[1..]).await?;

    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FramingError::TooLarge(len, MAX_FRAME_LEN));
    }

    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    let msg = Message::decode(&body)?;
    Ok(Some(msg))
}

/// Encode `msg` and write it as one length-prefixed frame to `w`. The caller
/// is responsible for flushing if write coalescing matters.
pub async fn write_frame<W>(w: &mut W, msg: &Message) -> Result<(), FramingError>
where
    W: AsyncWrite + Unpin,
{
    let body = msg.encode()?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| FramingError::TooLarge(u32::MAX, MAX_FRAME_LEN))?;
    if len > MAX_FRAME_LEN {
        return Err(FramingError::TooLarge(len, MAX_FRAME_LEN));
    }
    // Single `write_all` per buffer; let the BufWriter / pipe do the coalescing.
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg;
    use std::io::Cursor;
    use tokio::io::BufReader;

    async fn roundtrip(m: Message) {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &m).await.unwrap();
        let mut r = BufReader::new(Cursor::new(buf));
        let got = read_frame(&mut r).await.unwrap().expect("frame missing");
        assert_eq!(got, m);
    }

    #[tokio::test]
    async fn roundtrip_hello() {
        roundtrip(msg::hello(
            1,
            1,
            "Linux 6.5".into(),
            "host01".into(),
            1000,
            1000,
            "0.0.1".into(),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_shell() {
        roundtrip(msg::task_dispatch(42, msg::op_shell("echo hi".into(), 0))).await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_exec() {
        roundtrip(msg::task_dispatch(
            7,
            msg::op_exec(
                vec!["/bin/true".into()],
                vec!["FOO".into()],
                vec!["bar".into()],
                "".into(),
                vec![],
                0,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_write_file() {
        roundtrip(msg::task_dispatch(
            99,
            msg::op_write_file("/etc/motd".into(), 0o644, b"hello world\n".to_vec()),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_gather_facts() {
        roundtrip(msg::task_dispatch(101, msg::op_gather_facts())).await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_file() {
        roundtrip(msg::task_dispatch(
            104,
            msg::op_file(
                "/etc/foo".into(),
                msg::file_state::DIRECTORY,
                Some(0o755),
                "root".into(),
                "root".into(),
                false,
            ),
        ))
        .await;
        // mode=None branch + empty owner/group + recurse.
        roundtrip(msg::task_dispatch(
            105,
            msg::op_file(
                "/var/log/app".into(),
                msg::file_state::DIRECTORY,
                None,
                String::new(),
                String::new(),
                true,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_stat() {
        roundtrip(msg::task_dispatch(
            102,
            msg::op_stat("/etc/hostname".into(), true),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            103,
            msg::op_stat("/nope".into(), false),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_progress() {
        roundtrip(msg::task_progress(42, 0, b"line of output\n".to_vec())).await;
    }

    #[tokio::test]
    async fn roundtrip_task_done() {
        roundtrip(msg::task_done(42, 0, true, 1_700_000_000_000_000_000, 1_700_000_000_137_000_000)).await;
    }

    #[tokio::test]
    async fn roundtrip_task_error() {
        roundtrip(msg::task_error(42, 4, "timed out".into())).await;
    }

    #[tokio::test]
    async fn roundtrip_bye() {
        roundtrip(msg::bye()).await;
    }

    #[tokio::test]
    async fn roundtrip_ping() {
        roundtrip(msg::ping()).await;
    }

    #[tokio::test]
    async fn roundtrip_pong() {
        roundtrip(msg::pong(1_700_000_000_111_000_000, 1_700_000_000_222_000_000)).await;
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let mut r = BufReader::new(Cursor::new(Vec::<u8>::new()));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn partial_length_prefix_is_io_error() {
        // Length prefix is 4 bytes; supplying 2 should fail as mid-frame EOF.
        let mut r = BufReader::new(Cursor::new(vec![0x01, 0x00]));
        let err = read_frame(&mut r).await.unwrap_err();
        assert!(matches!(err, FramingError::Io(_)));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
        let mut r = BufReader::new(Cursor::new(buf));
        let err = read_frame(&mut r).await.unwrap_err();
        assert!(matches!(err, FramingError::TooLarge(_, _)));
    }

    #[tokio::test]
    async fn multiple_frames_back_to_back() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &msg::bye()).await.unwrap();
        write_frame(&mut buf, &msg::task_done(1, 0, false, 100, 110))
            .await
            .unwrap();
        let mut r = BufReader::new(Cursor::new(buf));
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), msg::bye());
        assert_eq!(
            read_frame(&mut r).await.unwrap().unwrap(),
            msg::task_done(1, 0, false, 100, 110)
        );
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }
}
