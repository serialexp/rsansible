//! `OpGetUrl` — file downloader. Ansible's `get_url:` module.
//!
//! Flow:
//!
//!   1. **Stat-skip path.** If `dest` already exists and `force=0`, we
//!      hash it on disk and decide without contacting the network. With
//!      a non-empty `checksum`, an exact match → `changed=false`. Without
//!      a checksum, the mere existence of `dest` is enough — that's the
//!      Ansible default (the operator is asking for "make sure this file
//!      is present", not "make sure this URL is canonical"). Mode/owner
//!      still get reconciled on the stat-skip path so changing only the
//!      permissions of an existing file flips `changed=true`.
//!
//!   2. **Download path.** Stream the response to `{dest}.rsansible.partial`,
//!      compute its sha256 as we go, verify the operator-supplied
//!      checksum (if any), apply mode/owner/group, then atomic-rename
//!      onto `dest`. The tmp file is cleaned up on every error.
//!
//! `checksum` is `<algo>:<hex>` with algo in {sha256, sha1, md5}. We
//! don't bother with the rare exotic algos — anything else surfaces as
//! BAD_REQUEST so the operator notices.
//!
//! The envelope on stdout matches `ansible.builtin.get_url`'s register
//! shape (`dest`, `url`, `checksum_src`, `checksum_dest`, `size`,
//! `status_code`, `msg`). `checksum_dest` is the *actual* sha256 of the
//! file on disk after the op finishes, regardless of which algo the
//! operator asked us to verify against — playbooks routinely assert
//! against it directly (`register.checksum_dest == expected_hash`).

use std::path::Path;
use std::time::{Duration, Instant};

use rsansible_wire::generated::OpGetUrlOutput;
use rsansible_wire::msg::{self, err, get_url_algo, now_unix_ns, uri_follow};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{emit_error, Context};

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpGetUrlOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    if op.dest.is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "dest is empty").await;
        return Ok(());
    }
    if op.url.is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "url is empty").await;
        return Ok(());
    }

    // Parse `checksum` early so we fail fast on garbage like "sha256:".
    let want_checksum = match parse_checksum(&op.checksum) {
        Ok(c) => c,
        Err(e) => {
            emit_error(ctx, seq, err::BAD_REQUEST, e).await;
            return Ok(());
        }
    };

    let dest = Path::new(&op.dest).to_path_buf();
    let mode_opt = if op.mode == 0 { None } else { Some(op.mode) };
    let owner_opt = (!op.owner.is_empty()).then(|| op.owner.clone());
    let group_opt = (!op.group.is_empty()).then(|| op.group.clone());

    // Decide whether we even need to fetch.
    let stat_exists = tokio::fs::metadata(&dest).await.ok();
    let need_download = if op.force != 0 {
        true
    } else if stat_exists.is_none() {
        true
    } else if let Some(wc) = &want_checksum {
        // dest exists; if its hash already matches we can stat-skip.
        match hash_file(&dest, wc.algo).await {
            Ok(actual) => actual != wc.hex,
            Err(e) => {
                emit_error(ctx, seq, err::IO, format!("hashing existing dest: {e}")).await;
                return Ok(());
            }
        }
    } else {
        // dest exists, no checksum requested, force=0 → trust dest.
        false
    };

    // Check mode: declare what *would* happen without doing it. We
    // synthesize an envelope so registers downstream still have
    // something to look at.
    if check_mode {
        let mut envelope = Map::new();
        envelope.insert("url".into(), Value::String(op.url.clone()));
        envelope.insert("dest".into(), Value::String(op.dest.clone()));
        envelope.insert("checksum_src".into(), Value::String(op.checksum.clone()));
        envelope.insert("checksum_dest".into(), Value::String(String::new()));
        envelope.insert("size".into(), Value::from(0u64));
        envelope.insert("status_code".into(), Value::from(0u16));
        envelope.insert(
            "msg".into(),
            Value::String(if need_download {
                "would download".into()
            } else {
                "dest already present".into()
            }),
        );
        let bytes = serde_json::to_vec(&Value::Object(envelope))?;
        ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
            .await;
        let finished_unix_ns = now_unix_ns();
        ctx.emit(msg::task_done(
            seq,
            0,
            need_download,
            true,
            started_unix_ns,
            finished_unix_ns,
        ))
        .await;
        return Ok(());
    }

    let mut changed = false;
    let mut status_code: u16 = 0;
    let mut size_on_disk: u64 = 0;
    let msg_text;

    if need_download {
        // Build the HTTP client. Same shape as uri.rs but no body / no
        // body_format — get_url is always GET.
        let client = match build_client(&op) {
            Ok(c) => c,
            Err(e) => {
                emit_error(ctx, seq, err::BAD_REQUEST, e).await;
                return Ok(());
            }
        };
        let req = match build_request(&client, &op) {
            Ok(r) => r,
            Err(e) => {
                emit_error(ctx, seq, err::BAD_REQUEST, e).await;
                return Ok(());
            }
        };

        let started_wall = Instant::now();
        let resp = match client.execute(req).await {
            Ok(r) => r,
            Err(e) => {
                let code = if e.is_timeout() {
                    err::TIMEOUT
                } else {
                    err::BAD_REQUEST
                };
                emit_error(ctx, seq, code, format!("{e}")).await;
                return Ok(());
            }
        };
        status_code = resp.status().as_u16();
        if !resp.status().is_success() {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("HTTP {status_code} for {}", op.url),
            )
            .await;
            return Ok(());
        }

        // Stream body → tmp file. Bounded scratch buffer; reqwest's
        // chunk stream owns the network buffer so we just hand it
        // through.
        let tmp = tmp_path(&dest);
        let mut tmp_file = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                emit_error(
                    ctx,
                    seq,
                    err::IO,
                    format!("creating tmp {}: {e}", tmp.display()),
                )
                .await;
                return Ok(());
            }
        };

        let mut stream = resp;
        let mut size: u64 = 0;
        // We always compute sha256 (for the envelope's checksum_dest).
        // If the operator wanted a different algo we also feed a second
        // hasher.
        let mut sha256_hasher = Sha256::new();
        let mut algo_hasher: Option<DigestSink> = match &want_checksum {
            Some(wc) if wc.algo != ChecksumAlgo::Sha256 => Some(DigestSink::new(wc.algo)),
            _ => None,
        };

        loop {
            let chunk = match stream.chunk().await {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    emit_error(ctx, seq, err::IO, format!("reading body: {e}")).await;
                    return Ok(());
                }
            };
            if let Err(e) = tmp_file.write_all(&chunk).await {
                let _ = tokio::fs::remove_file(&tmp).await;
                emit_error(
                    ctx,
                    seq,
                    err::IO,
                    format!("writing tmp {}: {e}", tmp.display()),
                )
                .await;
                return Ok(());
            }
            size += chunk.len() as u64;
            sha256_hasher.update(&chunk);
            if let Some(h) = algo_hasher.as_mut() {
                h.update(&chunk);
            }
        }
        if let Err(e) = tmp_file.sync_all().await {
            let _ = tokio::fs::remove_file(&tmp).await;
            emit_error(ctx, seq, err::IO, format!("fsync tmp: {e}")).await;
            return Ok(());
        }
        drop(tmp_file);
        let _elapsed = started_wall.elapsed();
        size_on_disk = size;

        // Operator-supplied checksum verification.
        if let Some(wc) = &want_checksum {
            let actual = match wc.algo {
                ChecksumAlgo::Sha256 => hex_of(sha256_hasher.clone().finalize().as_slice()),
                _ => algo_hasher
                    .as_ref()
                    .map(|h| h.hex())
                    .expect("non-sha256 hasher present"),
            };
            if actual != wc.hex {
                let _ = tokio::fs::remove_file(&tmp).await;
                emit_error(
                    ctx,
                    seq,
                    err::BAD_REQUEST,
                    format!(
                        "checksum mismatch: requested {}:{}, got {}:{}",
                        wc.algo.label(),
                        wc.hex,
                        wc.algo.label(),
                        actual
                    ),
                )
                .await;
                return Ok(());
            }
        }

        // Atomic rename onto dest.
        if let Err(e) = tokio::fs::rename(&tmp, &dest).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            emit_error(
                ctx,
                seq,
                err::IO,
                format!("rename {} → {}: {e}", tmp.display(), dest.display()),
            )
            .await;
            return Ok(());
        }
        changed = true;
        msg_text = "OK".into();
    } else {
        msg_text = "file already exists".into();
        if let Some(meta) = stat_exists.as_ref() {
            size_on_disk = meta.len();
        }
    }

    // Apply mode/owner/group regardless of download path — Ansible
    // reconciles permissions on stat-skip too. Track changed.
    let perms_changed = match apply_attrs(&dest, mode_opt, owner_opt.as_deref(), group_opt.as_deref()).await {
        Ok(c) => c,
        Err(e) => {
            emit_error(ctx, seq, err::IO, e).await;
            return Ok(());
        }
    };
    if perms_changed {
        changed = true;
    }

    // Always recompute sha256 of the final on-disk file so the envelope
    // is honest even on the stat-skip path. Cheap relative to anything
    // the operator is likely doing with the result.
    let checksum_dest = match hash_file(&dest, ChecksumAlgo::Sha256).await {
        Ok(h) => h,
        Err(e) => {
            emit_error(ctx, seq, err::IO, format!("hashing dest: {e}")).await;
            return Ok(());
        }
    };

    let mut envelope = Map::new();
    envelope.insert("url".into(), Value::String(op.url.clone()));
    envelope.insert("dest".into(), Value::String(op.dest.clone()));
    envelope.insert("checksum_src".into(), Value::String(op.checksum.clone()));
    envelope.insert("checksum_dest".into(), Value::String(checksum_dest));
    envelope.insert("size".into(), Value::from(size_on_disk));
    envelope.insert("status_code".into(), Value::from(status_code));
    envelope.insert("msg".into(), Value::String(msg_text));

    let bytes = serde_json::to_vec(&Value::Object(envelope))?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;
    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        changed,
        false,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

// ── Checksum parsing / hashing ──────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChecksumAlgo {
    Sha256,
    Sha1,
    Md5,
}

impl ChecksumAlgo {
    fn label(&self) -> &'static str {
        match self {
            Self::Sha256 => get_url_algo::SHA256,
            Self::Sha1 => get_url_algo::SHA1,
            Self::Md5 => get_url_algo::MD5,
        }
    }

    fn hex_len(&self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha1 => 40,
            Self::Md5 => 32,
        }
    }
}

struct WantChecksum {
    algo: ChecksumAlgo,
    hex: String,
}

fn parse_checksum(s: &str) -> Result<Option<WantChecksum>, String> {
    if s.is_empty() {
        return Ok(None);
    }
    let (algo_str, hex) = s
        .split_once(':')
        .ok_or_else(|| format!("checksum {s:?} must be <algo>:<hex>"))?;
    let algo = match algo_str.to_ascii_lowercase().as_str() {
        "sha256" => ChecksumAlgo::Sha256,
        "sha1" => ChecksumAlgo::Sha1,
        "md5" => ChecksumAlgo::Md5,
        other => {
            return Err(format!(
                "checksum algorithm {other:?} not supported (use sha256/sha1/md5)"
            ))
        }
    };
    let hex_norm = hex.trim().to_ascii_lowercase();
    if hex_norm.len() != algo.hex_len() || !hex_norm.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "checksum hex {hex:?} not a valid {} digest",
            algo.label()
        ));
    }
    Ok(Some(WantChecksum {
        algo,
        hex: hex_norm,
    }))
}

/// Variant-dispatching hasher. We can't put `Sha256/Sha1/Md5` in the
/// same trait object without pulling in `digest::DynDigest`, so just
/// enum it.
enum DigestSink {
    Sha256(Sha256),
    Sha1(sha1::Sha1),
    Md5(md5::Md5),
}

impl DigestSink {
    fn new(algo: ChecksumAlgo) -> Self {
        match algo {
            ChecksumAlgo::Sha256 => Self::Sha256(Sha256::new()),
            ChecksumAlgo::Sha1 => Self::Sha1(sha1::Sha1::new()),
            ChecksumAlgo::Md5 => Self::Md5(md5::Md5::new()),
        }
    }
    fn update(&mut self, b: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(b),
            Self::Sha1(h) => h.update(b),
            Self::Md5(h) => h.update(b),
        }
    }
    fn hex(&self) -> String {
        match self {
            Self::Sha256(h) => hex_of(h.clone().finalize().as_slice()),
            Self::Sha1(h) => hex_of(h.clone().finalize().as_slice()),
            Self::Md5(h) => hex_of(h.clone().finalize().as_slice()),
        }
    }
}

async fn hash_file(path: &Path, algo: ChecksumAlgo) -> std::io::Result<String> {
    let mut f = File::open(path).await?;
    let mut sink = DigestSink::new(algo);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        sink.update(&buf[..n]);
    }
    Ok(sink.hex())
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ── HTTP client / request ───────────────────────────────────────────

fn build_client(op: &OpGetUrlOutput) -> Result<reqwest::Client, String> {
    use reqwest::redirect::Policy;
    let policy = match op.follow_redirects {
        uri_follow::NONE => Policy::none(),
        uri_follow::ALL => Policy::limited(10),
        uri_follow::SAFE => Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }),
        other => return Err(format!("unknown follow_redirects byte: {other}")),
    };
    let mut builder = reqwest::Client::builder().redirect(policy);
    if op.timeout_ms > 0 {
        builder = builder.timeout(Duration::from_millis(op.timeout_ms as u64));
    }
    if op.validate_certs == 0 {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if !op.ca_bundle_pem.is_empty() {
        let cert = reqwest::Certificate::from_pem(&op.ca_bundle_pem)
            .map_err(|e| format!("parsing ca_bundle_pem: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    if !op.client_cert_pem.is_empty() {
        if op.client_key_pem.is_empty() {
            return Err("client_cert_pem set but client_key_pem is empty".into());
        }
        let mut bundle =
            Vec::with_capacity(op.client_cert_pem.len() + op.client_key_pem.len() + 1);
        bundle.extend_from_slice(&op.client_cert_pem);
        if !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        bundle.extend_from_slice(&op.client_key_pem);
        let id = reqwest::Identity::from_pem(&bundle)
            .map_err(|e| format!("parsing client cert/key: {e}"))?;
        builder = builder.identity(id);
    } else if !op.client_key_pem.is_empty() {
        return Err("client_key_pem set but client_cert_pem is empty".into());
    }
    builder
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

fn build_request(
    client: &reqwest::Client,
    op: &OpGetUrlOutput,
) -> Result<reqwest::Request, String> {
    use reqwest::header::{HeaderName, HeaderValue};
    let url =
        reqwest::Url::parse(&op.url).map_err(|e| format!("parsing url {:?}: {e}", op.url))?;
    let mut req = client.request(reqwest::Method::GET, url);
    if op.header_keys.len() != op.header_values.len() {
        return Err(format!(
            "header_keys.len({}) != header_values.len({})",
            op.header_keys.len(),
            op.header_values.len()
        ));
    }
    for (k, v) in op.header_keys.iter().zip(op.header_values.iter()) {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| format!("invalid header name {k:?}: {e}"))?;
        let val = HeaderValue::from_str(v)
            .map_err(|e| format!("invalid header value for {k:?}: {e}"))?;
        req = req.header(name, val);
    }
    req.build().map_err(|e| format!("building request: {e}"))
}

// ── File attribute application ──────────────────────────────────────

async fn apply_attrs(
    path: &Path,
    mode: Option<u32>,
    owner: Option<&str>,
    group: Option<&str>,
) -> Result<bool, String> {
    let mut changed = false;
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("stat {}: {e}", path.display()))?;
    if let Some(want) = mode {
        use std::os::unix::fs::PermissionsExt;
        let cur = meta.permissions().mode() & 0o7777;
        let want = want & 0o7777;
        if cur != want {
            let perms = std::fs::Permissions::from_mode(want);
            tokio::fs::set_permissions(path, perms)
                .await
                .map_err(|e| format!("chmod {}: {e}", path.display()))?;
            changed = true;
        }
    }
    if owner.is_some() || group.is_some() {
        // Resolve names → ids and shell out to chown (matches file.rs
        // approach; avoids unsafe libc).
        let uid_str = match owner {
            Some(n) => resolve_user(n).ok_or_else(|| format!("unknown user: {n}"))?.to_string(),
            None => String::new(),
        };
        let gid_str = match group {
            Some(n) => resolve_group(n).ok_or_else(|| format!("unknown group: {n}"))?.to_string(),
            None => String::new(),
        };
        let spec = format!("{uid_str}:{gid_str}");
        use std::os::unix::fs::MetadataExt;
        let cur_uid = meta.uid();
        let cur_gid = meta.gid();
        let want_uid = if uid_str.is_empty() {
            cur_uid
        } else {
            uid_str.parse::<u32>().unwrap()
        };
        let want_gid = if gid_str.is_empty() {
            cur_gid
        } else {
            gid_str.parse::<u32>().unwrap()
        };
        if want_uid != cur_uid || want_gid != cur_gid {
            let out = tokio::process::Command::new("chown")
                .arg("--")
                .arg(&spec)
                .arg(path)
                .output()
                .await
                .map_err(|e| format!("spawn chown: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "chown {spec} {}: {}",
                    path.display(),
                    String::from_utf8_lossy(&out.stderr).trim_end()
                ));
            }
            changed = true;
        }
    }
    Ok(changed)
}

fn resolve_user(name: &str) -> Option<u32> {
    parse_passwd_field(&std::fs::read_to_string("/etc/passwd").unwrap_or_default(), name)
}

fn resolve_group(name: &str) -> Option<u32> {
    parse_passwd_field(&std::fs::read_to_string("/etc/group").unwrap_or_default(), name)
}

fn parse_passwd_field(text: &str, name: &str) -> Option<u32> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.split(':');
        let first = cols.next()?;
        if first != name {
            continue;
        }
        // Skip 2 cols (passwd/x) to land on uid/gid at index 2.
        let nth = cols.nth(1)?;
        return nth.parse::<u32>().ok();
    }
    None
}

fn tmp_path(dest: &Path) -> std::path::PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(".rsansible.partial");
    std::path::PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_checksum_empty_is_none() {
        assert!(parse_checksum("").unwrap().is_none());
    }

    #[test]
    fn parse_checksum_sha256_roundtrip() {
        let hex = "a".repeat(64);
        let wc = parse_checksum(&format!("sha256:{hex}")).unwrap().unwrap();
        assert_eq!(wc.algo, ChecksumAlgo::Sha256);
        assert_eq!(wc.hex, hex);
    }

    #[test]
    fn parse_checksum_uppercase_normalises() {
        let hex = "A".repeat(64);
        let wc = parse_checksum(&format!("SHA256:{hex}")).unwrap().unwrap();
        assert_eq!(wc.algo, ChecksumAlgo::Sha256);
        assert_eq!(wc.hex, hex.to_lowercase());
    }

    #[test]
    fn parse_checksum_wrong_length_rejected() {
        assert!(parse_checksum("sha256:deadbeef").is_err());
    }

    #[test]
    fn parse_checksum_unknown_algo_rejected() {
        assert!(parse_checksum(&format!("sha512:{}", "b".repeat(128))).is_err());
    }

    #[test]
    fn parse_checksum_missing_colon_rejected() {
        assert!(parse_checksum("sha256deadbeef").is_err());
    }

    #[tokio::test]
    async fn hash_file_matches_sha256_of_known_content() {
        let pid = std::process::id();
        let nonce = now_unix_ns();
        let p = std::path::PathBuf::from(format!("/tmp/rsansible-get_url-test-{pid}-{nonce}"));
        tokio::fs::write(&p, b"hello world\n").await.unwrap();
        let h = hash_file(&p, ChecksumAlgo::Sha256).await.unwrap();
        // echo -n "hello world\n" | sha256sum
        assert_eq!(
            h,
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );
        tokio::fs::remove_file(&p).await.unwrap();
    }

    #[test]
    fn tmp_path_appends_suffix() {
        assert_eq!(
            tmp_path(Path::new("/var/foo")),
            Path::new("/var/foo.rsansible.partial")
        );
    }

    // ── Integration tests against an in-process axum server ─────────

    use axum::body::Bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use serde_json::Value as JsonValue;
    use tokio::sync::mpsc;

    fn op_for(url: &str, dest: &str) -> OpGetUrlOutput {
        OpGetUrlOutput {
            kind: 15,
            url: url.into(),
            dest: dest.into(),
            checksum: String::new(),
            mode: 0,
            owner: String::new(),
            group: String::new(),
            header_keys: vec![],
            header_values: vec![],
            timeout_ms: 5_000,
            force: 0,
            validate_certs: 1,
            follow_redirects: uri_follow::SAFE,
            client_cert_pem: vec![],
            client_key_pem: vec![],
            ca_bundle_pem: vec![],
        }
    }

    struct RunResult {
        envelope: Option<JsonValue>,
        changed: bool,
        exit_code: i32,
        error: Option<(u8, String)>,
    }

    async fn run_op(op: OpGetUrlOutput, check_mode: bool) -> RunResult {
        let (tx, mut rx) = mpsc::channel::<rsansible_wire::Message>(64);
        let ctx = Context::new(crate::writer::Sender(tx));
        run(&ctx, 1, op, check_mode).await.unwrap();
        drop(ctx);

        let mut envelope = None;
        let mut exit_code = 0;
        let mut changed = false;
        let mut error = None;
        while let Some(m) = rx.recv().await {
            match m {
                rsansible_wire::Message::TaskProgress(p) if p.stream == 0 => {
                    envelope = Some(serde_json::from_slice(&p.chunk).unwrap());
                }
                rsansible_wire::Message::TaskDone(d) => {
                    exit_code = d.exit_code;
                    changed = d.changed != 0;
                }
                rsansible_wire::Message::TaskError(e) => {
                    error = Some((e.code, e.message));
                }
                _ => {}
            }
        }
        RunResult {
            envelope,
            changed,
            exit_code,
            error,
        }
    }

    async fn boot(router: Router) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        port
    }

    fn tempdir() -> std::path::PathBuf {
        let pid = std::process::id();
        let nonce = now_unix_ns();
        let p = std::path::PathBuf::from(format!("/tmp/rsansible-geturl-{pid}-{nonce}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn download_writes_file_with_changed_true() {
        let app = Router::new().route("/payload", get(|| async { "hello world\n" }));
        let port = boot(app).await;
        let dir = tempdir();
        let dest = dir.join("payload.txt");
        let op = op_for(&format!("http://127.0.0.1:{port}/payload"), dest.to_str().unwrap());
        let r = run_op(op, false).await;
        assert!(r.error.is_none(), "no TaskError; got {:?}", r.error);
        assert_eq!(r.exit_code, 0);
        assert!(r.changed);
        let env = r.envelope.unwrap();
        assert_eq!(env["status_code"], 200);
        assert_eq!(env["size"], 12);
        assert!(env["checksum_dest"].as_str().unwrap().len() == 64);
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "hello world\n");
    }

    #[tokio::test]
    async fn existing_dest_without_force_skips_download() {
        let app = Router::new().route(
            "/p",
            get(|| async {
                let _: () = panic!("server should not be hit when dest exists & force=0");
                ""
            }),
        );
        let port = boot(app).await;
        let dir = tempdir();
        let dest = dir.join("p.txt");
        std::fs::write(&dest, b"already here\n").unwrap();
        let op = op_for(&format!("http://127.0.0.1:{port}/p"), dest.to_str().unwrap());
        let r = run_op(op, false).await;
        assert!(r.error.is_none());
        assert!(!r.changed, "stat-skip path");
        assert_eq!(r.envelope.as_ref().unwrap()["status_code"], 0);
    }

    #[tokio::test]
    async fn checksum_match_on_existing_dest_skips() {
        let dir = tempdir();
        let dest = dir.join("c.txt");
        std::fs::write(&dest, b"hello world\n").unwrap();
        let app = Router::new().route(
            "/c",
            get(|| async {
                let _: () = panic!("server should not be hit on checksum-match");
                ""
            }),
        );
        let port = boot(app).await;
        let mut op = op_for(&format!("http://127.0.0.1:{port}/c"), dest.to_str().unwrap());
        op.checksum =
            "sha256:a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447".into();
        let r = run_op(op, false).await;
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(!r.changed);
    }

    #[tokio::test]
    async fn checksum_mismatch_post_download_fails() {
        let app = Router::new().route("/m", get(|| async { "not the body you expect" }));
        let port = boot(app).await;
        let dir = tempdir();
        let dest = dir.join("m.txt");
        let mut op = op_for(&format!("http://127.0.0.1:{port}/m"), dest.to_str().unwrap());
        op.checksum = format!("sha256:{}", "0".repeat(64));
        let r = run_op(op, false).await;
        assert!(r.error.is_some(), "expected TaskError on mismatch");
        let (code, msg) = r.error.unwrap();
        assert_eq!(code, err::BAD_REQUEST);
        assert!(msg.contains("checksum mismatch"));
        // Tmp file must be cleaned up; dest must not exist.
        assert!(!dest.exists());
        assert!(!dir.join("m.txt.rsansible.partial").exists());
    }

    #[tokio::test]
    async fn http_404_surfaces_as_error_and_no_dest() {
        let app = Router::new().route(
            "/x",
            get(|| async { (StatusCode::NOT_FOUND, "nope") }),
        );
        let port = boot(app).await;
        let dir = tempdir();
        let dest = dir.join("x.txt");
        let op = op_for(&format!("http://127.0.0.1:{port}/x"), dest.to_str().unwrap());
        let r = run_op(op, false).await;
        assert!(r.error.is_some());
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn check_mode_skips_without_touching_dest() {
        let app = Router::new().route(
            "/k",
            get(|| async {
                let _: () = panic!("server should not be hit under check_mode");
                ""
            }),
        );
        let port = boot(app).await;
        let dir = tempdir();
        let dest = dir.join("k.txt");
        let op = op_for(&format!("http://127.0.0.1:{port}/k"), dest.to_str().unwrap());
        let r = run_op(op, true).await;
        assert!(r.error.is_none());
        assert!(r.changed, "would-download case");
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn force_redownload_even_when_dest_present() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let app = Router::new().route(
            "/f",
            get(move || {
                let c = counter_clone.clone();
                async move {
                    c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    "fresh\n".into_response()
                }
            }),
        );
        let port = boot(app).await;
        let dir = tempdir();
        let dest = dir.join("f.txt");
        std::fs::write(&dest, b"stale\n").unwrap();
        let mut op = op_for(&format!("http://127.0.0.1:{port}/f"), dest.to_str().unwrap());
        op.force = 1;
        let r = run_op(op, false).await;
        assert!(r.error.is_none());
        assert!(r.changed);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "fresh\n");
    }

    // Suppress unused-import warning when tests aren't run.
    #[allow(dead_code)]
    fn _bytes(b: Bytes) -> Bytes {
        b
    }
}
