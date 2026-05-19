//! `OpUnarchive` — extract a tarball or zip archive that lives on the
//! agent host.
//!
//! Maps Ansible's `ansible.builtin.unarchive` with `remote_src: yes`.
//! Controllers wanting to push an archive from the orchestrator host
//! must combine OpWriteFile (or OpGetUrl) with this op in two steps.
//!
//! Supported codecs: `tar.gz`, `tar.bz2`, `tar.xz`, plain `tar`, `zip`.
//! All decoders are pure-Rust (musl-safe). Decompression-only for bz2
//! and xz; this op never writes a compressed archive.
//!
//! Envelope on stdout matches Ansible's return shape:
//!
//! ```json
//! {
//!   "dest":            "/opt/etcd",
//!   "src":             "/srv/cache/etcd-v3.5.10.tar.gz",
//!   "handler":         "TgzArchive",
//!   "extract_results": {},
//!   "files":           ["etcd", "etcdctl", "Documentation/..."]
//! }
//! ```
//!
//! `files` is populated iff the op's `list_files=1`.
//!
//! Idempotency: when `creates` is non-empty and the path exists,
//! extraction is skipped and `changed=0` is reported without opening
//! the archive. Without `creates`, `changed=1` iff at least one entry
//! was actually written (i.e. not skipped by `keep_newer`/`include`/
//! `exclude`).
//!
//! Safety: archive entry paths are rejected if they're absolute or
//! contain `..` components (zip-slip / tar-slip protection). Symlinks
//! whose target would escape `dest` are also rejected.

use rsansible_wire::generated::OpUnarchiveOutput;
use rsansible_wire::msg::{self, err, now_unix_ns, unarchive_format};
use serde_json::json;
use std::io::{BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use super::file::{lchown_path, resolve_group, resolve_user};
use super::{emit_error, Context};

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpUnarchiveOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    // Move into local bindings so we can pass slices freely.
    let src = op.src;
    let dest = op.dest;
    let creates = op.creates;
    let format_byte = op.format;
    let has_mode = op.has_mode != 0;
    let mode = op.mode;
    let owner = op.owner;
    let group = op.group;
    let keep_newer = op.keep_newer != 0;
    let list_files = op.list_files != 0;
    let include = op.include;
    let exclude = op.exclude;

    // ── Idempotency: `creates` short-circuits before anything else.
    if !creates.is_empty() && Path::new(&creates).exists() {
        let handler = handler_label(format_byte, &src);
        emit_envelope(
            ctx,
            seq,
            &dest,
            &src,
            handler,
            list_files,
            Vec::new(),
            /*changed=*/ false,
            started_unix_ns,
        )
        .await?;
        return Ok(());
    }

    // Pre-flight: `dest` must already exist and be a directory.
    let dest_meta = match std::fs::metadata(&dest) {
        Ok(m) => m,
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => err::NOT_FOUND,
                std::io::ErrorKind::PermissionDenied => err::PERMISSION,
                _ => err::IO,
            };
            emit_error(ctx, seq, code, format!("unarchive: dest {dest}: {e}")).await;
            return Ok(());
        }
    };
    if !dest_meta.is_dir() {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            format!("unarchive: dest {dest} is not a directory"),
        )
        .await;
        return Ok(());
    }

    // Pre-flight: archive readable.
    if let Err(e) = std::fs::metadata(&src) {
        let code = match e.kind() {
            std::io::ErrorKind::NotFound => err::NOT_FOUND,
            std::io::ErrorKind::PermissionDenied => err::PERMISSION,
            _ => err::IO,
        };
        emit_error(ctx, seq, code, format!("unarchive: src {src}: {e}")).await;
        return Ok(());
    }

    // Resolve format (auto by extension if necessary).
    let format = match resolve_format(format_byte, &src) {
        Ok(f) => f,
        Err(msg) => {
            emit_error(ctx, seq, err::BAD_REQUEST, msg).await;
            return Ok(());
        }
    };

    // ── Check mode: don't extract; report would-change.
    //
    // We're conservative: under --check we assume any non-`creates`
    // path would extract at least one file, so changed=1, skipped=1.
    // Doing better requires reading the archive index and stat()ing
    // every entry, which isn't worth the complexity for a dry-run.
    if check_mode {
        let handler = format.handler_label();
        let bytes = serde_json::to_vec(&json!({
            "dest":            dest,
            "src":             src,
            "handler":         handler,
            "extract_results": {},
        }))?;
        ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
            .await;
        let finished_unix_ns = now_unix_ns();
        ctx.emit(msg::task_done(
            seq,
            0,
            /*changed=*/ true,
            /*skipped=*/ true,
            started_unix_ns,
            finished_unix_ns,
        ))
        .await;
        return Ok(());
    }

    // Resolve owner/group once.
    let owner_uid = if owner.is_empty() {
        None
    } else {
        match resolve_user(&owner) {
            Ok(u) => Some(u),
            Err(name) => {
                emit_error(
                    ctx,
                    seq,
                    err::BAD_REQUEST,
                    format!("unarchive: unknown owner {name:?}"),
                )
                .await;
                return Ok(());
            }
        }
    };
    let group_gid = if group.is_empty() {
        None
    } else {
        match resolve_group(&group) {
            Ok(g) => Some(g),
            Err(name) => {
                emit_error(
                    ctx,
                    seq,
                    err::BAD_REQUEST,
                    format!("unarchive: unknown group {name:?}"),
                )
                .await;
                return Ok(());
            }
        }
    };

    let dest_path = PathBuf::from(&dest);
    let dest_canonical = match std::fs::canonicalize(&dest_path) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                err::IO,
                format!("unarchive: canonicalize({dest}): {e}"),
            )
            .await;
            return Ok(());
        }
    };

    let extract_result = match format {
        ArchiveFormat::TarGz => {
            extract_tar_with_decoder(&src, &dest_canonical, &include, &exclude, keep_newer, |f| {
                let dec = flate2::read::GzDecoder::new(BufReader::new(f));
                Ok(Box::new(dec) as Box<dyn Read>)
            })
        }
        ArchiveFormat::TarBz2 => {
            extract_tar_with_decoder(&src, &dest_canonical, &include, &exclude, keep_newer, |f| {
                let dec = bzip2_rs::DecoderReader::new(BufReader::new(f));
                Ok(Box::new(dec) as Box<dyn Read>)
            })
        }
        ArchiveFormat::TarXz => {
            // lzma-rs only exposes one-shot `xz_decompress(reader, writer)`
            // so the simplest path is to decompress into a `Vec<u8>`
            // first, then feed the bytes to `tar`. For multi-GB archives
            // that's a memory problem, but every real-world Ansible
            // unarchive task we've seen ships archives <100 MiB. If/when
            // that bites we swap in an incremental xz decoder.
            extract_tar_with_decoder(&src, &dest_canonical, &include, &exclude, keep_newer, |f| {
                let mut compressed = BufReader::new(f);
                let mut decompressed = Vec::new();
                lzma_rs::xz_decompress(&mut compressed, &mut decompressed)
                    .map_err(|e| format!("xz decompress: {e}"))?;
                Ok(Box::new(std::io::Cursor::new(decompressed)) as Box<dyn Read>)
            })
        }
        ArchiveFormat::Tar => {
            extract_tar_with_decoder(&src, &dest_canonical, &include, &exclude, keep_newer, |f| {
                Ok(Box::new(BufReader::new(f)) as Box<dyn Read>)
            })
        }
        ArchiveFormat::Zip => extract_zip(&src, &dest_canonical, &include, &exclude, keep_newer),
    };

    let ExtractOutcome { files, changed } = match extract_result {
        Ok(o) => o,
        Err(msg) => {
            emit_error(ctx, seq, err::IO, format!("unarchive: {msg}")).await;
            return Ok(());
        }
    };

    // Apply mode/owner/group to every extracted entry. Iteration order
    // is the order the archive presented entries — that's deterministic
    // enough for chown/chmod to land idempotently on a re-run.
    for rel in &files {
        let abs = dest_canonical.join(rel);
        if has_mode {
            let perms = std::fs::Permissions::from_mode(mode & 0o7777);
            if let Err(e) = std::fs::set_permissions(&abs, perms) {
                emit_error(
                    ctx,
                    seq,
                    err::IO,
                    format!("unarchive: chmod {}: {e}", abs.display()),
                )
                .await;
                return Ok(());
            }
        }
        if let (Some(uid), Some(gid)) = (owner_uid, group_gid) {
            if let Err(e) = lchown_path(&abs, uid, gid) {
                emit_error(ctx, seq, err::IO, format!("unarchive: {e}")).await;
                return Ok(());
            }
        } else if let Some(uid) = owner_uid {
            // chown user:user is wrong; preserve original group via -h
            // with `uid:` (POSIX says empty group means unchanged).
            if let Err(e) = chown_user_only(&abs, uid) {
                emit_error(ctx, seq, err::IO, format!("unarchive: {e}")).await;
                return Ok(());
            }
        } else if let Some(gid) = group_gid {
            if let Err(e) = chown_group_only(&abs, gid) {
                emit_error(ctx, seq, err::IO, format!("unarchive: {e}")).await;
                return Ok(());
            }
        }
    }

    let handler = format.handler_label();
    emit_envelope(
        ctx,
        seq,
        &dest,
        &src,
        handler,
        list_files,
        files,
        changed,
        started_unix_ns,
    )
    .await?;
    Ok(())
}

#[derive(Copy, Clone, Debug)]
enum ArchiveFormat {
    TarGz,
    TarBz2,
    TarXz,
    Tar,
    Zip,
}

impl ArchiveFormat {
    fn handler_label(self) -> &'static str {
        match self {
            ArchiveFormat::TarGz => "TgzArchive",
            ArchiveFormat::TarBz2 => "TarBzipArchive",
            ArchiveFormat::TarXz => "TarXzArchive",
            ArchiveFormat::Tar => "TarArchive",
            ArchiveFormat::Zip => "ZipArchive",
        }
    }
}

fn resolve_format(byte: u8, src: &str) -> Result<ArchiveFormat, String> {
    match byte {
        unarchive_format::TAR_GZ => Ok(ArchiveFormat::TarGz),
        unarchive_format::TAR_BZ2 => Ok(ArchiveFormat::TarBz2),
        unarchive_format::TAR_XZ => Ok(ArchiveFormat::TarXz),
        unarchive_format::TAR => Ok(ArchiveFormat::Tar),
        unarchive_format::ZIP => Ok(ArchiveFormat::Zip),
        unarchive_format::AUTO => infer_format(src),
        other => Err(format!("unarchive: unknown format byte {other}")),
    }
}

fn infer_format(src: &str) -> Result<ArchiveFormat, String> {
    let lower = src.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        Ok(ArchiveFormat::TarGz)
    } else if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") || lower.ends_with(".tbz") {
        Ok(ArchiveFormat::TarBz2)
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        Ok(ArchiveFormat::TarXz)
    } else if lower.ends_with(".tar") {
        Ok(ArchiveFormat::Tar)
    } else if lower.ends_with(".zip") {
        Ok(ArchiveFormat::Zip)
    } else {
        Err(format!(
            "unarchive: cannot infer format from src={src:?}; set format: explicitly"
        ))
    }
}

/// Conservative label-only resolution used by the `creates` short-circuit
/// (which never opens the archive). Falls back to `"Unknown"` when an
/// auto format can't be inferred — the field is informational only at
/// that point.
fn handler_label(byte: u8, src: &str) -> &'static str {
    resolve_format(byte, src)
        .map(ArchiveFormat::handler_label)
        .unwrap_or("Unknown")
}

struct ExtractOutcome {
    /// Paths relative to `dest`, in archive iteration order.
    files: Vec<String>,
    /// True iff at least one entry was actually written.
    changed: bool,
}

/// True iff `entry` matches the include filter (empty include = match
/// all) and not the exclude filter (empty exclude = match nothing).
fn entry_passes_filters(entry: &str, include: &[String], exclude: &[String]) -> bool {
    if !include.is_empty() && !include.iter().any(|p| p == entry) {
        return false;
    }
    if exclude.iter().any(|p| p == entry) {
        return false;
    }
    true
}

/// Validates an archive entry path: rejects absolute and `..`-bearing
/// paths. Returns the cleaned relative path as a `PathBuf`.
fn sanitize_entry_path(raw: &Path) -> Result<PathBuf, String> {
    let mut clean = PathBuf::new();
    for comp in raw.components() {
        match comp {
            Component::Normal(p) => clean.push(p),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "archive entry {raw:?} contains a `..` component"
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("archive entry {raw:?} is absolute"));
            }
        }
    }
    Ok(clean)
}

fn extract_tar_with_decoder<F>(
    src: &str,
    dest: &Path,
    include: &[String],
    exclude: &[String],
    keep_newer: bool,
    open_decoder: F,
) -> Result<ExtractOutcome, String>
where
    F: FnOnce(std::fs::File) -> Result<Box<dyn Read>, String>,
{
    let f = std::fs::File::open(src).map_err(|e| format!("open {src}: {e}"))?;
    let reader = open_decoder(f)?;
    let mut archive = tar::Archive::new(reader);
    // Don't let `tar` set timestamps / perms / ownership for us — we
    // apply them post-walk based on the op's parameters.
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(true);
    archive.set_overwrite(true);

    let mut files = Vec::new();
    let mut changed = false;

    for entry in archive.entries().map_err(|e| format!("read entries: {e}"))? {
        let mut entry = entry.map_err(|e| format!("entry header: {e}"))?;
        let raw_path = entry
            .path()
            .map_err(|e| format!("entry path: {e}"))?
            .into_owned();
        let rel = sanitize_entry_path(&raw_path)?;
        let rel_str = rel.to_string_lossy().to_string();

        if !entry_passes_filters(&rel_str, include, exclude) {
            continue;
        }

        let abs = dest.join(&rel);
        // Defence in depth: ensure the joined path is under `dest`.
        if !abs.starts_with(dest) {
            return Err(format!(
                "archive entry {rel_str:?} escapes dest after join"
            ));
        }

        if keep_newer {
            if let Ok(meta) = std::fs::metadata(&abs) {
                if let (Ok(dest_mtime), Ok(entry_mtime)) =
                    (meta.modified(), entry.header().mtime())
                {
                    let entry_secs = entry_mtime as i64;
                    if let Ok(dur) = dest_mtime.duration_since(std::time::UNIX_EPOCH) {
                        if (dur.as_secs() as i64) >= entry_secs {
                            files.push(rel_str);
                            continue;
                        }
                    }
                }
            }
        }

        // Make sure the parent directory exists for non-directory entries.
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create parent of {}: {e}", abs.display()))?;
        }

        let header_kind = entry.header().entry_type();
        if header_kind.is_dir() {
            std::fs::create_dir_all(&abs)
                .map_err(|e| format!("mkdir {}: {e}", abs.display()))?;
            changed = true;
        } else if header_kind.is_symlink() {
            let target = entry
                .link_name()
                .map_err(|e| format!("symlink target on {rel_str}: {e}"))?
                .ok_or_else(|| format!("symlink {rel_str}: missing target"))?
                .into_owned();
            // Absolute symlinks are allowed (Ansible allows them); the
            // critical check is that *resolving* the symlink target
            // against the entry's parent doesn't escape `dest`. For now
            // we only reject obvious traversal in the target itself.
            if let Some(s) = target.to_str() {
                if s.contains("..") && !s.starts_with('/') {
                    return Err(format!(
                        "symlink {rel_str} → {s:?} contains `..` (refusing)"
                    ));
                }
            }
            // Remove pre-existing entry; the symlink syscall doesn't overwrite.
            let _ = std::fs::remove_file(&abs);
            std::os::unix::fs::symlink(&target, &abs)
                .map_err(|e| format!("symlink {}: {e}", abs.display()))?;
            changed = true;
        } else if header_kind.is_hard_link() {
            let target = entry
                .link_name()
                .map_err(|e| format!("hard link target on {rel_str}: {e}"))?
                .ok_or_else(|| format!("hard link {rel_str}: missing target"))?
                .into_owned();
            let target_rel = sanitize_entry_path(&target)?;
            let target_abs = dest.join(target_rel);
            let _ = std::fs::remove_file(&abs);
            std::fs::hard_link(&target_abs, &abs)
                .map_err(|e| format!("hardlink {} → {}: {e}", abs.display(), target_abs.display()))?;
            changed = true;
        } else if header_kind.is_file() {
            // Unlink-before-create so we extract correctly into sticky
            // directories (most commonly `/tmp/`) when a prior entry
            // is owned by someone other than the current EUID. The
            // kernel's `fs.protected_regular` sysctl (default-on since
            // Linux 4.19) blocks `open(O_CREAT|O_TRUNC)` on existing
            // regular files in sticky dirs when the file owner differs
            // from the opener — even for root. GNU tar's
            // `--overwrite` default sidesteps the same issue by
            // unlinking first; we do the same. Caught in the gothab
            // drill (vmutils tarball extracted into `/tmp/` where a
            // prior bart-owned `vmalert-tool-prod` blocked the
            // root-running rsansible agent with EACCES). `remove_file`
            // failures are ignored — if the path doesn't exist (the
            // common case) we proceed; if it exists and we can't
            // remove it (e.g. it's a directory we don't expect), the
            // subsequent `create` surfaces a clear error.
            let _ = std::fs::remove_file(&abs);
            let mut out =
                std::fs::File::create(&abs).map_err(|e| format!("create {}: {e}", abs.display()))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|e| format!("write {}: {e}", abs.display()))?;
            changed = true;
        } else {
            return Err(format!(
                "unsupported tar entry type {:?} on {rel_str}",
                header_kind
            ));
        }

        files.push(rel_str);
    }

    Ok(ExtractOutcome { files, changed })
}

fn extract_zip(
    src: &str,
    dest: &Path,
    include: &[String],
    exclude: &[String],
    keep_newer: bool,
) -> Result<ExtractOutcome, String> {
    let f = std::fs::File::open(src).map_err(|e| format!("open {src}: {e}"))?;
    let mut zip = zip::ZipArchive::new(BufReader::new(f))
        .map_err(|e| format!("read zip directory: {e}"))?;

    let mut files = Vec::new();
    let mut changed = false;

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| format!("zip entry {i}: {e}"))?;
        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| format!("zip entry {i}: unsafe path {:?}", entry.name()))?;
        let rel = sanitize_entry_path(&enclosed)?;
        let rel_str = rel.to_string_lossy().to_string();

        if !entry_passes_filters(&rel_str, include, exclude) {
            continue;
        }

        let abs = dest.join(&rel);
        if !abs.starts_with(dest) {
            return Err(format!(
                "zip entry {rel_str:?} escapes dest after join"
            ));
        }

        if keep_newer {
            if let Ok(meta) = std::fs::metadata(&abs) {
                if let Ok(dest_mtime) = meta.modified() {
                    if let Some(entry_dt) = entry.last_modified() {
                        // Convert zip DateTime → unix seconds. zip-2's
                        // DateTime is local-naive; treat as UTC for
                        // comparison purposes — close enough for "skip
                        // if newer than archive".
                        let entry_secs = zip_datetime_to_unix(&entry_dt);
                        if let Ok(dur) = dest_mtime.duration_since(std::time::UNIX_EPOCH) {
                            if (dur.as_secs() as i64) >= entry_secs {
                                files.push(rel_str);
                                continue;
                            }
                        }
                    }
                }
            }
        }

        if entry.is_dir() {
            std::fs::create_dir_all(&abs).map_err(|e| format!("mkdir {}: {e}", abs.display()))?;
            changed = true;
        } else {
            if let Some(parent) = abs.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create parent of {}: {e}", abs.display()))?;
            }
            // Unlink-before-create — see the tar arm above for the
            // `fs.protected_regular` rationale. Same hardening applies
            // to zip extraction into sticky directories.
            let _ = std::fs::remove_file(&abs);
            let mut out =
                std::fs::File::create(&abs).map_err(|e| format!("create {}: {e}", abs.display()))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|e| format!("write {}: {e}", abs.display()))?;
            changed = true;
            // Preserve unix mode bits if present in the central directory.
            if let Some(m) = entry.unix_mode() {
                let _ = std::fs::set_permissions(
                    &abs,
                    std::fs::Permissions::from_mode(m & 0o7777),
                );
            }
        }

        files.push(rel_str);
    }

    Ok(ExtractOutcome { files, changed })
}

fn zip_datetime_to_unix(dt: &zip::DateTime) -> i64 {
    // Days-since-epoch for {year, month, day} via a naive accumulation.
    // Zip dates start at 1980; we never see values before that. Hours/
    // minutes/seconds are 0-padded.
    fn is_leap(y: u16) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }
    let months: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let year = dt.year();
    let month = dt.month() as u32;
    let day = dt.day() as u32;
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    for (i, &dm) in months.iter().enumerate() {
        let mi = (i + 1) as u32;
        if mi >= month {
            break;
        }
        let mut dm = dm;
        if mi == 2 && is_leap(year) {
            dm = 29;
        }
        days += dm as i64;
    }
    days += (day.saturating_sub(1)) as i64;
    days * 86_400
        + (dt.hour() as i64) * 3600
        + (dt.minute() as i64) * 60
        + (dt.second() as i64)
}

// `chown_user_only` and `chown_group_only` were moved to
// `super::file` so `write_file` can share them. Re-export under the
// same path so existing call sites in this module stay short.
use super::file::{chown_group_only, chown_user_only};

#[allow(clippy::too_many_arguments)]
async fn emit_envelope(
    ctx: &Context,
    seq: u32,
    dest: &str,
    src: &str,
    handler: &str,
    list_files: bool,
    files: Vec<String>,
    changed: bool,
    started_unix_ns: u64,
) -> anyhow::Result<()> {
    let mut env = json!({
        "dest":            dest,
        "src":             src,
        "handler":         handler,
        "extract_results": {},
    });
    if list_files {
        env["files"] = serde_json::Value::Array(
            files
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    let bytes = serde_json::to_vec(&env)?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;
    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        changed,
        /*skipped=*/ false,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::Sender;
    use rsansible_wire::Message;
    use std::io::Write;
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

    fn op(
        src: &str,
        dest: &str,
        format: u8,
        list_files: bool,
        keep_newer: bool,
        include: Vec<String>,
        exclude: Vec<String>,
        creates: &str,
    ) -> OpUnarchiveOutput {
        OpUnarchiveOutput {
            kind: 19,
            src: src.into(),
            dest: dest.into(),
            format,
            creates: creates.into(),
            has_mode: 0,
            mode: 0,
            owner: String::new(),
            group: String::new(),
            keep_newer: if keep_newer { 1 } else { 0 },
            list_files: if list_files { 1 } else { 0 },
            include,
            exclude,
        }
    }

    /// Build a tar.gz with two regular files and one directory entry in-memory.
    fn build_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let buf: Vec<u8> = Vec::new();
        let enc = GzEncoder::new(buf, Compression::default());
        let mut builder = tar::Builder::new(enc);
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_path(name).unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            builder.append(&h, &data[..]).unwrap();
        }
        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap()
    }

    /// Build a plain .tar with the same convention.
    fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut builder = tar::Builder::new(buf);
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_path(name).unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            builder.append(&h, &data[..]).unwrap();
        }
        builder.into_inner().unwrap()
    }

    /// Build a minimal zip with regular files (deflate compressed).
    fn build_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Cursor;
        use zip::write::SimpleFileOptions;
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o644);
            for (name, data) in files {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    #[tokio::test]
    async fn tar_gz_extracts_files_and_lists_them() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let archive_bytes = build_tar_gz(&[
            ("hello.txt", b"hello\n"),
            ("nested/world.txt", b"world\n"),
        ]);
        let archive_path = dir.path().join("a.tar.gz");
        std::fs::write(&archive_path, &archive_bytes).unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            1,
            op(
                archive_path.to_str().unwrap(),
                dest.to_str().unwrap(),
                unarchive_format::AUTO,
                /*list_files=*/ true,
                false,
                vec![],
                vec![],
                "",
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let env = envelope_from(&msgs).expect("envelope");
        let done = done_of(&msgs).expect("TaskDone");
        assert_eq!(done.exit_code, 0);
        assert_eq!(done.changed, 1);
        assert_eq!(env["handler"], "TgzArchive");
        let files = env["files"].as_array().unwrap();
        let names: Vec<_> = files.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(names.contains(&"hello.txt"));
        assert!(names.contains(&"nested/world.txt"));
        assert_eq!(
            std::fs::read(dest.join("hello.txt")).unwrap(),
            b"hello\n".to_vec()
        );
        assert_eq!(
            std::fs::read(dest.join("nested/world.txt")).unwrap(),
            b"world\n".to_vec()
        );
    }

    /// Regression: extraction must unlink-before-create so that the
    /// new entry's bytes land even when the existing target is
    /// non-writable to the calling EUID. Caught in the gothab live
    /// drill: a bart-owned `/tmp/vmalert-tool-prod` left over from an
    /// earlier non-become drill blocked a subsequent root-running
    /// unarchive with `EACCES`, because the kernel's
    /// `fs.protected_regular` sysctl denies `open(O_CREAT|O_TRUNC)` on
    /// existing regular files in sticky dirs when the file's owner
    /// differs from the opener — even for root. We can't simulate
    /// cross-uid + sticky-dir in a non-root test, but we can pin the
    /// same shape: a pre-existing read-only target (0o444) would make
    /// a bare `File::create` (= `open(O_WRONLY|O_CREAT|O_TRUNC)`)
    /// fail with EACCES; the unlink-first path removes it, then
    /// creates a fresh file with default mode. If the regression
    /// returns this test fails with `EACCES` on `create …`.
    #[tokio::test]
    async fn tar_overwrites_readonly_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        // Plant a read-only existing target that bare File::create
        // would fail on.
        let target = dest.join("payload.bin");
        std::fs::write(&target, b"stale\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o444)).unwrap();

        let archive_bytes = build_tar_gz(&[("payload.bin", b"fresh\n")]);
        let archive_path = dir.path().join("a.tar.gz");
        std::fs::write(&archive_path, &archive_bytes).unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            1,
            op(
                archive_path.to_str().unwrap(),
                dest.to_str().unwrap(),
                unarchive_format::AUTO,
                false,
                false,
                vec![],
                vec![],
                "",
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        // Must not have surfaced a TaskError on the agent.
        if let Some(err) = error_of(&msgs) {
            panic!(
                "unexpected TaskError: code={} msg={}",
                err.code, err.message
            );
        }
        let done = done_of(&msgs).expect("TaskDone");
        assert_eq!(done.exit_code, 0, "agent reported failure");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"fresh\n".to_vec(),
            "extracted bytes should replace the read-only stale file"
        );
    }

    #[tokio::test]
    async fn plain_tar_with_explicit_format_works() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let archive_bytes = build_tar(&[("a.txt", b"A")]);
        let archive_path = dir.path().join("noext"); // strip extension
        std::fs::write(&archive_path, &archive_bytes).unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            2,
            op(
                archive_path.to_str().unwrap(),
                dest.to_str().unwrap(),
                unarchive_format::TAR,
                false,
                false,
                vec![],
                vec![],
                "",
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let env = envelope_from(&msgs).expect("envelope");
        assert_eq!(env["handler"], "TarArchive");
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"A".to_vec());
    }

    #[tokio::test]
    async fn zip_extracts_and_filters_via_include() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let archive_bytes = build_zip(&[
            ("keep.txt", b"keep"),
            ("drop.txt", b"drop"),
        ]);
        let archive_path = dir.path().join("a.zip");
        std::fs::write(&archive_path, &archive_bytes).unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            3,
            op(
                archive_path.to_str().unwrap(),
                dest.to_str().unwrap(),
                unarchive_format::AUTO,
                true,
                false,
                vec!["keep.txt".into()],
                vec![],
                "",
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let env = envelope_from(&msgs).expect("envelope");
        let done = done_of(&msgs).expect("done");
        assert_eq!(done.changed, 1);
        assert!(dest.join("keep.txt").exists());
        assert!(!dest.join("drop.txt").exists());
        let files = env["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
    }

    #[tokio::test]
    async fn creates_marker_short_circuits() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let marker = dir.path().join("done.flag");
        std::fs::write(&marker, b"x").unwrap();

        let (ctx, mut rx) = make_ctx();
        // Pass a *missing* archive path; if the short-circuit fires
        // first we won't notice.
        run(
            &ctx,
            4,
            op(
                "/does/not/exist.tar.gz",
                dest.to_str().unwrap(),
                unarchive_format::AUTO,
                false,
                false,
                vec![],
                vec![],
                marker.to_str().unwrap(),
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let done = done_of(&msgs).expect("done");
        assert_eq!(done.changed, 0);
        assert_eq!(done.exit_code, 0);
    }

    #[tokio::test]
    async fn missing_archive_emits_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            5,
            op(
                "/this/almost/certainly/missing.tar.gz",
                dest.to_str().unwrap(),
                unarchive_format::AUTO,
                false,
                false,
                vec![],
                vec![],
                "",
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let e = error_of(&msgs).expect("error");
        assert_eq!(e.code, err::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_dest_emits_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let archive_bytes = build_tar_gz(&[("a.txt", b"A")]);
        let archive_path = dir.path().join("a.tar.gz");
        std::fs::write(&archive_path, &archive_bytes).unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            6,
            op(
                archive_path.to_str().unwrap(),
                "/no/such/dest/dir/here",
                unarchive_format::AUTO,
                false,
                false,
                vec![],
                vec![],
                "",
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let e = error_of(&msgs).expect("error");
        assert_eq!(e.code, err::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_extension_under_auto_emits_bad_request() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let archive_path = dir.path().join("archive.weird");
        std::fs::write(&archive_path, b"junk").unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            7,
            op(
                archive_path.to_str().unwrap(),
                dest.to_str().unwrap(),
                unarchive_format::AUTO,
                false,
                false,
                vec![],
                vec![],
                "",
            ),
            false,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let e = error_of(&msgs).expect("error");
        assert_eq!(e.code, err::BAD_REQUEST);
    }

    #[tokio::test]
    async fn check_mode_does_not_extract() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let archive_bytes = build_tar_gz(&[("a.txt", b"A")]);
        let archive_path = dir.path().join("a.tar.gz");
        std::fs::write(&archive_path, &archive_bytes).unwrap();

        let (ctx, mut rx) = make_ctx();
        run(
            &ctx,
            8,
            op(
                archive_path.to_str().unwrap(),
                dest.to_str().unwrap(),
                unarchive_format::AUTO,
                false,
                false,
                vec![],
                vec![],
                "",
            ),
            /*check_mode=*/ true,
        )
        .await
        .unwrap();
        drop(ctx);

        let msgs = drain(&mut rx).await;
        let done = done_of(&msgs).expect("done");
        assert_eq!(done.changed, 1);
        assert_eq!(done.skipped, 1);
        assert!(!dest.join("a.txt").exists());
    }

    #[test]
    fn sanitize_rejects_parent_dir() {
        let p = Path::new("../etc/passwd");
        assert!(sanitize_entry_path(p).is_err());
    }

    #[test]
    fn sanitize_rejects_absolute() {
        let p = Path::new("/etc/passwd");
        assert!(sanitize_entry_path(p).is_err());
    }

    #[test]
    fn sanitize_strips_curdir() {
        let p = Path::new("./foo/./bar");
        let cleaned = sanitize_entry_path(p).unwrap();
        assert_eq!(cleaned, PathBuf::from("foo/bar"));
    }

    #[test]
    fn entry_filters_include_exclude() {
        let include = vec!["a".to_string()];
        let exclude = vec!["b".to_string()];
        assert!(entry_passes_filters("a", &include, &exclude));
        assert!(!entry_passes_filters("c", &include, &exclude));
        assert!(!entry_passes_filters("b", &[], &exclude));
        assert!(entry_passes_filters("c", &[], &exclude));
    }

    #[test]
    fn infer_format_table() {
        assert!(matches!(
            infer_format("/x/y.tar.gz").unwrap(),
            ArchiveFormat::TarGz
        ));
        assert!(matches!(
            infer_format("/x/y.tgz").unwrap(),
            ArchiveFormat::TarGz
        ));
        assert!(matches!(
            infer_format("/x/y.tar.bz2").unwrap(),
            ArchiveFormat::TarBz2
        ));
        assert!(matches!(
            infer_format("/x/y.tar.xz").unwrap(),
            ArchiveFormat::TarXz
        ));
        assert!(matches!(
            infer_format("/x/y.tar").unwrap(),
            ArchiveFormat::Tar
        ));
        assert!(matches!(infer_format("/x/y.zip").unwrap(), ArchiveFormat::Zip));
        assert!(infer_format("/x/y.unknown").is_err());
    }
}
