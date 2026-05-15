//! `OpStat` — stat a single filesystem path.
//!
//! Output is a JSON object written to stdout via a single `TaskProgress`
//! chunk followed by `TaskDone(exit_code=0)`. The controller parses the
//! stdout and lifts it into `register.stat.<field>`, matching Ansible's
//! `ansible.builtin.stat` shape.
//!
//! A missing path is **not** an error — the JSON simply reports
//! `{"exists": false, "path": "..."}`. Hard failures (permission denied
//! on a parent directory, etc.) surface as `TaskError`.
//!
//! `follow` selects `stat(2)` (follow final symlink) vs `lstat(2)`
//! (don't). Ansible defaults `follow: yes`; this op carries an explicit
//! byte so the controller can opt out.
//!
//! Fields emitted on the happy path:
//!   - `exists`             — bool
//!   - `path`               — string (echoed back so a register holding multiple results stays self-describing)
//!   - `isreg` / `isdir` / `islnk` / `isblk` / `ischr` / `isfifo` / `issock` — bool
//!   - `mode`               — string, 4-digit octal (e.g. `"0644"`)
//!   - `size`               — number (bytes)
//!   - `uid` / `gid`        — number
//!   - `mtime` / `atime` / `ctime` — number (seconds since UNIX epoch, fractional)
//!   - `checksum`           — string (sha256 hex). Present iff the path is a
//!                            regular file (after `follow` has been applied)
//!                            AND we could open+read it. Skipped silently on
//!                            permission errors so a non-readable file still
//!                            stats cleanly with `exists: true`.
//!   - `lnk_source`         — string. Present iff the *stated* path is a
//!                            symlink (i.e. `follow=false` AND `islnk=true`)
//!                            AND we could resolve readlink(2).

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use rsansible_wire::msg::{self, now_unix_ns};
use rsansible_wire::generated::OpStatOutput;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{emit_error, Context};

pub async fn run(ctx: &Context, seq: u32, op: OpStatOutput) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    let follow = op.follow != 0;
    let path = op.path;

    let value = match stat_path(&path, follow) {
        Ok(v) => v,
        Err(StatError::HardIo(msg)) => {
            emit_error(ctx, seq, rsansible_wire::msg::err::IO, msg).await;
            return Ok(());
        }
        Err(StatError::Permission(msg)) => {
            emit_error(ctx, seq, rsansible_wire::msg::err::PERMISSION, msg).await;
            return Ok(());
        }
    };

    let bytes = serde_json::to_vec(&value)?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;
    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        false,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

#[derive(Debug)]
enum StatError {
    /// Parent directory unreadable, weird I/O failure, etc.
    HardIo(String),
    /// EACCES on the path itself (not the parent).
    Permission(String),
}

fn stat_path(path: &str, follow: bool) -> Result<Value, StatError> {
    let p = Path::new(path);
    let meta_res = if follow {
        std::fs::metadata(p)
    } else {
        std::fs::symlink_metadata(p)
    };
    let meta = match meta_res {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({ "exists": false, "path": path }));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(StatError::Permission(format!(
                "stat {path:?}: permission denied"
            )));
        }
        Err(e) => {
            return Err(StatError::HardIo(format!("stat {path:?}: {e}")));
        }
    };

    let ft = meta.file_type();
    let islnk = ft.is_symlink();
    let isreg = ft.is_file();
    let isdir = ft.is_dir();
    // Unix-specific bits live behind `std::os::unix::fs::FileTypeExt`.
    use std::os::unix::fs::FileTypeExt;
    let isblk = ft.is_block_device();
    let ischr = ft.is_char_device();
    let isfifo = ft.is_fifo();
    let issock = ft.is_socket();

    let mode_bits = meta.mode() & 0o7777;
    let mode_str = format!("{mode_bits:04o}");

    let mut out: Map<String, Value> = Map::new();
    out.insert("exists".into(), Value::Bool(true));
    out.insert("path".into(), Value::String(path.to_string()));
    out.insert("isreg".into(), Value::Bool(isreg));
    out.insert("isdir".into(), Value::Bool(isdir));
    out.insert("islnk".into(), Value::Bool(islnk));
    out.insert("isblk".into(), Value::Bool(isblk));
    out.insert("ischr".into(), Value::Bool(ischr));
    out.insert("isfifo".into(), Value::Bool(isfifo));
    out.insert("issock".into(), Value::Bool(issock));
    out.insert("mode".into(), Value::String(mode_str));
    out.insert("size".into(), Value::from(meta.size()));
    out.insert("uid".into(), Value::from(meta.uid()));
    out.insert("gid".into(), Value::from(meta.gid()));
    out.insert("mtime".into(), Value::from(seconds_f64(meta.mtime(), meta.mtime_nsec())));
    out.insert("atime".into(), Value::from(seconds_f64(meta.atime(), meta.atime_nsec())));
    out.insert("ctime".into(), Value::from(seconds_f64(meta.ctime(), meta.ctime_nsec())));

    // Checksum: only for regular files (matches Ansible's default
    // `get_checksum: true`). If we can't open the file, we leave the
    // field off rather than failing the whole stat — a follow-up shell
    // can probe permissions if the user cares.
    if isreg {
        if let Some(hex) = sha256_of(p) {
            out.insert("checksum".into(), Value::String(hex));
        }
    }

    // Link target: only meaningful when the *stated* path itself was a
    // symlink. If follow=true and we followed through, `islnk` is already
    // false and we don't need to readlink.
    if islnk {
        if let Ok(target) = std::fs::read_link(p) {
            out.insert(
                "lnk_source".into(),
                Value::String(target.to_string_lossy().into_owned()),
            );
        }
    }

    let _ = UNIX_EPOCH + Duration::from_secs(0); // keep import warning-free if mtime path collapses
    Ok(Value::Object(out))
}

/// Combine seconds + nanoseconds into a fractional seconds value. Returns
/// as `f64` so JSON renders it naturally. Negative times (pre-epoch) are
/// theoretically possible on weird systems; we don't bother guarding.
fn seconds_f64(secs: i64, nanos: i64) -> f64 {
    secs as f64 + (nanos as f64) / 1_000_000_000.0
}

fn sha256_of(p: &Path) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Some(hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn stat_missing_returns_exists_false() {
        let v = stat_path("/definitely/does/not/exist/rsansible-stat", true).unwrap();
        assert_eq!(v["exists"], Value::Bool(false));
        assert_eq!(v["path"], Value::String("/definitely/does/not/exist/rsansible-stat".into()));
    }

    #[test]
    fn stat_regular_file_includes_checksum() {
        let dir = tempdir();
        let path = dir.join("hello.txt");
        std::fs::write(&path, b"hello\n").unwrap();
        let v = stat_path(path.to_str().unwrap(), true).unwrap();
        assert_eq!(v["exists"], Value::Bool(true));
        assert_eq!(v["isreg"], Value::Bool(true));
        assert_eq!(v["isdir"], Value::Bool(false));
        assert_eq!(v["islnk"], Value::Bool(false));
        assert_eq!(v["size"], Value::from(6u64));
        // sha256("hello\n") = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
        assert_eq!(
            v["checksum"],
            Value::String(
                "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".into()
            )
        );
        // Mode includes the low 12 bits, formatted 4-wide. We don't pin
        // the exact value because umask varies.
        assert!(v["mode"].as_str().unwrap().len() == 4);
    }

    #[test]
    fn stat_directory_no_checksum() {
        let dir = tempdir();
        let v = stat_path(dir.to_str().unwrap(), true).unwrap();
        assert_eq!(v["exists"], Value::Bool(true));
        assert_eq!(v["isdir"], Value::Bool(true));
        assert_eq!(v["isreg"], Value::Bool(false));
        assert!(v.get("checksum").is_none(), "dirs don't get checksums");
    }

    #[test]
    fn stat_symlink_lstat_vs_stat() {
        let dir = tempdir();
        let target = dir.join("target.txt");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // follow=true → file's stat
        let v = stat_path(link.to_str().unwrap(), true).unwrap();
        assert_eq!(v["islnk"], Value::Bool(false));
        assert_eq!(v["isreg"], Value::Bool(true));
        assert!(v.get("lnk_source").is_none());

        // follow=false → link's own stat with target
        let v = stat_path(link.to_str().unwrap(), false).unwrap();
        assert_eq!(v["islnk"], Value::Bool(true));
        assert_eq!(v["isreg"], Value::Bool(false));
        assert_eq!(
            v["lnk_source"],
            Value::String(target.to_string_lossy().into_owned())
        );
    }

    #[test]
    fn stat_dangling_symlink() {
        let dir = tempdir();
        let link = dir.join("dangling");
        std::os::unix::fs::symlink("/nope/nada", &link).unwrap();
        // follow=true: the target is missing — should report exists:false
        let v = stat_path(link.to_str().unwrap(), true).unwrap();
        assert_eq!(v["exists"], Value::Bool(false));
        // follow=false: the link itself exists
        let v = stat_path(link.to_str().unwrap(), false).unwrap();
        assert_eq!(v["exists"], Value::Bool(true));
        assert_eq!(v["islnk"], Value::Bool(true));
    }

    #[test]
    fn mode_is_octal_4_digits() {
        let dir = tempdir();
        let p = dir.join("m.txt");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let v = stat_path(p.to_str().unwrap(), true).unwrap();
        assert_eq!(v["mode"], Value::String("0600".into()));
    }

    fn tempdir() -> std::path::PathBuf {
        // Lightweight tempdir — pick a unique name under /tmp. Cleanup
        // is "best-effort" (process exit). Avoids pulling in `tempfile`.
        let pid = std::process::id();
        let nonce = now_unix_ns();
        let p = std::path::PathBuf::from(format!("/tmp/rsansible-stat-test-{pid}-{nonce}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
