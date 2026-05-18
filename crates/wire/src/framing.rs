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
        roundtrip(msg::task_dispatch(42, false, msg::op_shell("echo hi".into(), 0))).await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_exec() {
        roundtrip(msg::task_dispatch(
            7,
            false,
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
            false,
            msg::op_write_file("/etc/motd".into(), 0o644, false, b"hello world\n".to_vec()),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_gather_facts() {
        roundtrip(msg::task_dispatch(101, false, msg::op_gather_facts())).await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_wait_for() {
        // TCP-mode
        roundtrip(msg::task_dispatch(
            106,
            false,
            msg::op_wait_for(
                "10.0.0.5".into(),
                8080,
                String::new(),
                msg::wait_state::PRESENT,
                30_000,
                0,
                1_000,
            ),
        ))
        .await;
        // path-mode (port=0)
        roundtrip(msg::task_dispatch(
            107,
            false,
            msg::op_wait_for(
                String::new(),
                0,
                "/var/run/foo.pid".into(),
                msg::wait_state::ABSENT,
                10_000,
                500,
                250,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_file() {
        roundtrip(msg::task_dispatch(
            104,
            false,
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
            false,
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
    async fn roundtrip_task_dispatch_lineinfile() {
        // state=present with regexp + insertafter.
        roundtrip(msg::task_dispatch(
            108,
            false,
            msg::op_lineinfile(
                "/etc/foo.conf".into(),
                "^foo=".into(),
                "foo=42".into(),
                msg::lineinfile_state::PRESENT,
                Some(0o644),
                true,
                String::new(),
                "^# foo section".into(),
                false,
            ),
        ))
        .await;
        // state=absent with empty regexp + create=false + mode=None.
        roundtrip(msg::task_dispatch(
            109,
            false,
            msg::op_lineinfile(
                "/etc/bar".into(),
                String::new(),
                "obsolete".into(),
                msg::lineinfile_state::ABSENT,
                None,
                false,
                String::new(),
                String::new(),
                false,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_blockinfile() {
        roundtrip(msg::task_dispatch(
            110,
            false,
            msg::op_blockinfile(
                "/etc/foo".into(),
                "alpha\nbeta\n".into(),
                "# {mark} ANSIBLE MANAGED BLOCK".into(),
                "BEGIN".into(),
                "END".into(),
                msg::blockinfile_state::PRESENT,
                Some(0o644),
                true,
                String::new(),
                "EOF".into(),
            ),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            111,
            false,
            msg::op_blockinfile(
                "/etc/foo".into(),
                String::new(),
                "// {mark} app".into(),
                "begin".into(),
                "end".into(),
                msg::blockinfile_state::ABSENT,
                None,
                false,
                "^EXIT".into(),
                String::new(),
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_systemd() {
        roundtrip(msg::task_dispatch(
            112,
            false,
            msg::op_systemd(
                "nginx.service".into(),
                msg::systemd_state::RESTARTED,
                Some(true),
                None,
                true,
                false,
            ),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            113,
            false,
            msg::op_systemd(
                "foo.service".into(),
                msg::systemd_state::NONE,
                None,
                Some(false),
                false,
                true,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_ufw() {
        roundtrip(msg::task_dispatch(
            116,
            false,
            msg::op_ufw(
                msg::ufw_op::RULE,
                "allow".into(),
                "in".into(),
                "tcp".into(),
                String::new(),
                String::new(),
                String::new(),
                "22".into(),
                String::new(),
                "ssh".into(),
                false,
                0,
            ),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            117,
            false,
            msg::op_ufw(
                msg::ufw_op::ENABLE,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                false,
                0,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_package() {
        roundtrip(msg::task_dispatch(
            114,
            false,
            msg::op_package(
                msg::package_manager::APT,
                vec!["nginx".into(), "curl".into()],
                msg::package_state::PRESENT,
                true,
                3600,
                false,
                true,
                String::new(),
                false,
            ),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            115,
            false,
            msg::op_package(
                msg::package_manager::APT,
                vec!["openssh-server".into()],
                msg::package_state::LATEST,
                false,
                0,
                false,
                false,
                "bookworm-backports".into(),
                true,
            ),
        ))
        .await;
        // Auto-manager (no specific backend pinned).
        roundtrip(msg::task_dispatch(
            116,
            false,
            msg::op_package(
                msg::package_manager::AUTO,
                vec!["curl".into()],
                msg::package_state::PRESENT,
                false,
                0,
                false,
                false,
                String::new(),
                false,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_repository() {
        // present, apt-pinned, explicit filename + mode + update_cache.
        roundtrip(msg::task_dispatch(
            120,
            false,
            msg::op_repository(
                msg::repository_manager::APT,
                "deb [signed-by=/etc/apt/keyrings/pg.asc] https://apt.postgresql.org/pub/repos/apt focal-pgdg main".into(),
                msg::repository_state::PRESENT,
                "pgdg".into(),
                0o644,
                true,
            ),
        ))
        .await;
        // absent, auto-manager, derived filename (empty string on the wire).
        roundtrip(msg::task_dispatch(
            121,
            false,
            msg::op_repository(
                msg::repository_manager::AUTO,
                "deb https://example.com/repo focal main".into(),
                msg::repository_state::ABSENT,
                String::new(),
                0,
                false,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_group() {
        roundtrip(msg::task_dispatch(
            130,
            false,
            msg::op_group("etcd".into(), msg::identity_state::PRESENT, true),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            131,
            false,
            msg::op_group("docker".into(), msg::identity_state::ABSENT, false),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_user() {
        // Present, system, full optional surface.
        roundtrip(msg::task_dispatch(
            132,
            false,
            msg::op_user(
                "etcd".into(),
                msg::identity_state::PRESENT,
                true,
                Some("/usr/sbin/nologin".into()),
                Some("/var/lib/etcd".into()),
                true,
                "etcd".into(),
                vec!["ssl-cert".into(), "wheel".into()],
                true,
            ),
        ))
        .await;
        // Absent, minimal surface (None shell/home, no supplementary groups).
        roundtrip(msg::task_dispatch(
            133,
            false,
            msg::op_user(
                "olduser".into(),
                msg::identity_state::ABSENT,
                false,
                None,
                None,
                false,
                String::new(),
                Vec::new(),
                false,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_authorized_key() {
        roundtrip(msg::task_dispatch(
            134,
            false,
            msg::op_authorized_key(
                "bart".into(),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI bart@laptop".into(),
                msg::identity_state::PRESENT,
                false,
            ),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            135,
            false,
            msg::op_authorized_key(
                "bart".into(),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI bart@laptop".into(),
                msg::identity_state::ABSENT,
                true,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_stat() {
        roundtrip(msg::task_dispatch(
            102,
            false,
            msg::op_stat("/etc/hostname".into(), true),
        ))
        .await;
        roundtrip(msg::task_dispatch(
            103,
            false,
            msg::op_stat("/nope".into(), false),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_write_file_only_if_missing() {
        // only_if_missing=true variant must roundtrip with the byte set
        // — otherwise the agent's skip-if-exists branch never fires.
        roundtrip(msg::task_dispatch(
            42,
            false,
            msg::op_write_file("/etc/ssl/key.pem".into(), 0o600, true, b"PEM".to_vec()),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_uri_with_mtls() {
        // Exercise the three PEM-bytes fields on OpUri so a schema-vs-
        // wire-vs-runtime mismatch surfaces here, not in production.
        roundtrip(msg::task_dispatch(
            77,
            false,
            msg::op_uri(
                msg::uri_method::GET,
                "https://etcd.example/v2".into(),
                vec![],
                vec![],
                Vec::new(),
                msg::uri_body_format::RAW,
                vec![200],
                5_000,
                false,
                true,
                msg::uri_follow::SAFE,
                b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n".to_vec(),
                b"-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----\n".to_vec(),
                b"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n".to_vec(),
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_postgresql_query() {
        roundtrip(msg::task_dispatch(
            81,
            false,
            msg::op_postgresql_query(
                "SELECT pid, state FROM pg_stat_activity WHERE state = $1".into(),
                "postgres".into(),
                "".into(),
                "".into(),
                "/var/run/postgresql".into(),
                "".into(),
                0,
                false,
                vec!["active".into()],
                /*read_only=*/ true,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_postgresql_ext() {
        roundtrip(msg::task_dispatch(
            82,
            false,
            msg::op_postgresql_ext(
                "pg_stat_statements".into(),
                msg::postgresql_ext_state::PRESENT,
                "".into(),
                "public".into(),
                false,
                "postgres".into(),
                "".into(),
                "".into(),
                "/var/run/postgresql".into(),
                "".into(),
                0,
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_get_url() {
        roundtrip(msg::task_dispatch(
            83,
            false,
            msg::op_get_url(
                "https://example.com/payload.tar.gz".into(),
                "/var/cache/payload.tar.gz".into(),
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                0o644,
                "root".into(),
                "root".into(),
                vec!["Authorization".into(), "User-Agent".into()],
                vec!["Bearer xyz".into(), "rsansible/0.0.1".into()],
                30_000,
                /*force=*/ false,
                /*validate_certs=*/ true,
                /*follow_redirects=*/ 1,
                vec![],
                vec![],
                vec![],
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_async_start_wraps_inner_op() {
        // OpAsyncStart carries a nested Op. Roundtrip a wrapped shell op
        // to exercise the recursive Op codec.
        roundtrip(msg::task_dispatch(
            84,
            false,
            msg::op_async_start(
                300_000,
                msg::op_shell("sleep 5 && echo done".into(), 0),
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_async_status() {
        roundtrip(msg::task_dispatch(85, false, msg::op_async_status(84))).await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_read_file() {
        roundtrip(msg::task_dispatch(
            86,
            false,
            msg::op_read_file("/etc/etcd/server.key".into(), 65_536),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_read_file_no_cap() {
        // max_bytes=0 sentinel for "no cap" should survive the wire.
        roundtrip(msg::task_dispatch(
            87,
            false,
            msg::op_read_file("/var/lib/pki/ca.pem".into(), 0),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_unarchive() {
        roundtrip(msg::task_dispatch(
            88,
            false,
            msg::op_unarchive(
                "/srv/cache/etcd-v3.5.tar.gz".into(),
                "/usr/local/bin".into(),
                msg::unarchive_format::TAR_GZ,
                "/usr/local/bin/etcd".into(),
                1,
                0o755,
                "root".into(),
                "root".into(),
                /*keep_newer=*/ 1,
                /*list_files=*/ 1,
                /*include=*/ vec!["etcd".into(), "etcdctl".into()],
                /*exclude=*/ vec!["README.md".into()],
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_unarchive_minimal() {
        // Auto-format + no creates/owner/group/include/exclude. Every
        // empty string + empty array still has to survive the wire.
        roundtrip(msg::task_dispatch(
            89,
            false,
            msg::op_unarchive(
                "/tmp/x.zip".into(),
                "/opt".into(),
                msg::unarchive_format::AUTO,
                String::new(),
                0,
                0,
                String::new(),
                String::new(),
                0,
                0,
                Vec::new(),
                Vec::new(),
            ),
        ))
        .await;
    }

    #[tokio::test]
    async fn roundtrip_task_progress() {
        roundtrip(msg::task_progress(42, 0, b"line of output\n".to_vec())).await;
    }

    #[tokio::test]
    async fn roundtrip_task_done() {
        roundtrip(msg::task_done(42, 0, true, false, 1_700_000_000_000_000_000, 1_700_000_000_137_000_000)).await;
    }

    #[tokio::test]
    async fn roundtrip_task_done_skipped() {
        // skipped=true is set by modules that decline under check_mode
        // (exec/shell, and uri for mutating verbs).
        roundtrip(msg::task_done(43, 0, false, true, 1_700_000_000_000_000_000, 1_700_000_000_001_000_000)).await;
    }

    #[tokio::test]
    async fn roundtrip_task_dispatch_check_mode() {
        // check_mode=true should roundtrip through the envelope.
        roundtrip(msg::task_dispatch(
            44,
            true,
            msg::op_shell("echo dry-run".into(), 0),
        ))
        .await;
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
        write_frame(&mut buf, &msg::task_done(1, 0, false, false, 100, 110))
            .await
            .unwrap();
        let mut r = BufReader::new(Cursor::new(buf));
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), msg::bye());
        assert_eq!(
            read_frame(&mut r).await.unwrap().unwrap(),
            msg::task_done(1, 0, false, false, 100, 110)
        );
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }
}
