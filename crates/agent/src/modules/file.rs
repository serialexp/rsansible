//! `OpFile` — Ansible's `file:` module.
//!
//! Supported states:
//!   - `directory` — mkdir -p; apply mode/owner/group; recursive if `recurse=1`
//!   - `absent`    — rm -rf (dir) / unlink (file or symlink)
//!   - `touch`     — create empty file if missing; always bumps mtime/atime
//!                   (Ansible reports touch as always-changed)
//!   - `file`      — assert that a regular file exists; apply mode/owner/group
//!
//! `changed` semantics:
//!   - directory: changed iff path was created, OR mode/owner/group changed,
//!                OR (recurse=1) any descendant's mode/owner/group changed
//!   - absent:    changed iff the path existed before this op
//!   - touch:     always changed (Ansible's contract)
//!   - file:      changed iff mode/owner/group changed
//!
//! Owner/group resolution uses /etc/passwd and /etc/group — no NSS. That's
//! fine for the targets we run on (Debian/Ubuntu/Alpine boxes where the
//! relevant users come from package install). If a name isn't found we
//! surface TaskError(BAD_REQUEST) so the user knows immediately rather than
//! silently no-op.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;

use rsansible_wire::generated::OpFileOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_DIRECTORY: u8 = 0;
const STATE_ABSENT: u8 = 1;
const STATE_TOUCH: u8 = 2;
const STATE_FILE: u8 = 3;

pub async fn run(ctx: &Context, seq: u32, op: OpFileOutput) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    let path = op.path;
    let mode = if op.has_mode != 0 { Some(op.mode & 0o7777) } else { None };
    let recurse = op.recurse != 0;
    let owner = if op.owner.is_empty() { None } else { Some(op.owner.as_str()) };
    let group = if op.group.is_empty() { None } else { Some(op.group.as_str()) };

    // Resolve owner/group up front — fail fast with BAD_REQUEST rather
    // than partial work.
    let uid = match owner.map(resolve_user) {
        None => None,
        Some(Ok(u)) => Some(u),
        Some(Err(name)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, format!("unknown user: {name:?}"))
                .await;
            return Ok(());
        }
    };
    let gid = match group.map(resolve_group) {
        None => None,
        Some(Ok(g)) => Some(g),
        Some(Err(name)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, format!("unknown group: {name:?}"))
                .await;
            return Ok(());
        }
    };

    let result = match op.state {
        STATE_DIRECTORY => apply_directory(Path::new(&path), mode, uid, gid, recurse),
        STATE_ABSENT => apply_absent(Path::new(&path)),
        STATE_TOUCH => apply_touch(Path::new(&path), mode, uid, gid),
        STATE_FILE => apply_file(Path::new(&path), mode, uid, gid),
        other => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("file: unknown state byte {other}"),
            )
            .await;
            return Ok(());
        }
    };

    let changed = match result {
        Ok(c) => c,
        Err(FileError::Io(msg)) => {
            emit_error(ctx, seq, err::IO, msg).await;
            return Ok(());
        }
        Err(FileError::Permission(msg)) => {
            emit_error(ctx, seq, err::PERMISSION, msg).await;
            return Ok(());
        }
        Err(FileError::NotFound(msg)) => {
            emit_error(ctx, seq, err::NOT_FOUND, msg).await;
            return Ok(());
        }
        Err(FileError::BadRequest(msg)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, msg).await;
            return Ok(());
        }
    };

    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, started_unix_ns, finished_unix_ns))
        .await;
    Ok(())
}

#[derive(Debug)]
enum FileError {
    Io(String),
    Permission(String),
    NotFound(String),
    BadRequest(String),
}

impl From<std::io::Error> for FileError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::PermissionDenied => FileError::Permission(e.to_string()),
            std::io::ErrorKind::NotFound => FileError::NotFound(e.to_string()),
            _ => FileError::Io(e.to_string()),
        }
    }
}

fn apply_directory(
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    recurse: bool,
) -> Result<bool, FileError> {
    let mut changed = false;
    // Snapshot pre-state so we can decide `changed`.
    let pre = std::fs::symlink_metadata(path).ok();
    let exists_as_dir = pre.as_ref().map(|m| m.is_dir()).unwrap_or(false);
    if let Some(m) = &pre {
        if !m.is_dir() {
            return Err(FileError::BadRequest(format!(
                "{} exists but isn't a directory (type={:?})",
                path.display(),
                m.file_type()
            )));
        }
    }
    if !exists_as_dir {
        std::fs::create_dir_all(path).map_err(FileError::from)?;
        changed = true;
    }
    // Apply mode/owner/group to the top-level path.
    if apply_mode_owner_group(path, mode, uid, gid)? {
        changed = true;
    }
    if recurse {
        walk_apply(path, mode, uid, gid, &mut changed)?;
    }
    Ok(changed)
}

fn apply_absent(path: &Path) -> Result<bool, FileError> {
    let pre = std::fs::symlink_metadata(path);
    match pre {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(FileError::from(e)),
        Ok(m) => {
            // Symlinks count as "not a directory" even when their target
            // is — removing the link itself is what we want.
            if m.is_dir() && !m.file_type().is_symlink() {
                std::fs::remove_dir_all(path).map_err(FileError::from)?;
            } else {
                std::fs::remove_file(path).map_err(FileError::from)?;
            }
            Ok(true)
        }
    }
}

fn apply_touch(
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<bool, FileError> {
    let existed = path.exists();
    if !existed {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(FileError::from)?;
    }
    // Bump atime+mtime to now using utimensat via std-only API. We use
    // `set_times` from filetime-free approach: open + futimens via
    // rustix to stay FFI-light.
    let now = SystemTime::now();
    set_file_times(path, now, now)?;
    // Apply mode/owner/group. The return tells us whether they changed
    // but touch is always-changed by Ansible's contract.
    let _ = apply_mode_owner_group(path, mode, uid, gid)?;
    let _ = existed; // suppress unused warning if branches collapse
    Ok(true)
}

fn apply_file(
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<bool, FileError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            FileError::NotFound(format!(
                "state=file requires the path to exist already: {}",
                path.display()
            ))
        } else {
            FileError::from(e)
        }
    })?;
    if !meta.is_file() {
        return Err(FileError::BadRequest(format!(
            "state=file: {} is not a regular file (type={:?})",
            path.display(),
            meta.file_type()
        )));
    }
    apply_mode_owner_group(path, mode, uid, gid)
}

/// Apply mode/owner/group to `path` if they differ from current. Returns
/// true iff anything actually changed. Uses lchown so we don't follow
/// symlinks for ownership; mode is applied via chmod (which DOES follow
/// symlinks, but file:'s contract with mode on a symlink is "mode of
/// target" — matches Ansible).
fn apply_mode_owner_group(
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<bool, FileError> {
    let meta = std::fs::symlink_metadata(path).map_err(FileError::from)?;
    let mut changed = false;

    if let Some(want) = mode {
        // chmod is meaningless on a symlink (chmod follows; lchmod isn't
        // POSIX). Skip silently for symlinks to match Ansible.
        if !meta.file_type().is_symlink() {
            let cur = meta.permissions().mode() & 0o7777;
            if cur != want & 0o7777 {
                let perms = std::fs::Permissions::from_mode(want & 0o7777);
                std::fs::set_permissions(path, perms).map_err(FileError::from)?;
                changed = true;
            }
        }
    }

    use std::os::unix::fs::MetadataExt;
    let cur_uid = meta.uid();
    let cur_gid = meta.gid();
    let want_uid = uid.unwrap_or(cur_uid);
    let want_gid = gid.unwrap_or(cur_gid);
    if want_uid != cur_uid || want_gid != cur_gid {
        lchown(path, want_uid, want_gid)?;
        changed = true;
    }

    Ok(changed)
}

fn walk_apply(
    root: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    changed: &mut bool,
) -> Result<(), FileError> {
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(it) => it,
            Err(e) => return Err(FileError::from(e)),
        };
        for ent in entries {
            let ent = ent.map_err(FileError::from)?;
            let p = ent.path();
            // Don't descend through symlinks (Ansible's recurse behavior).
            let m = ent.metadata().map_err(FileError::from)?;
            if apply_mode_owner_group(&p, mode, uid, gid)? {
                *changed = true;
            }
            if m.is_dir() && !m.file_type().is_symlink() {
                stack.push(p);
            }
        }
    }
    Ok(())
}

/// `touch -a -m <path>` to bump both atime and mtime to "now". We
/// deliberately shell out instead of pulling in `filetime` or using
/// `rustix::fs::utimensat` (which requires constructing Uid/Gid via
/// `unsafe` in rustix 0.38 — the agent is `forbid(unsafe_code)`).
fn set_file_times(path: &Path, _atime: SystemTime, _mtime: SystemTime) -> Result<(), FileError> {
    let out = std::process::Command::new("touch")
        .arg("-a")
        .arg("-m")
        .arg("--")
        .arg(path)
        .output()
        .map_err(|e| FileError::Io(format!("spawn touch: {e}")))?;
    if !out.status.success() {
        return Err(FileError::Io(format!(
            "touch {}: {}",
            path.display(),
            String::from_utf8_lossy(out.stderr.trim_ascii_end())
        )));
    }
    Ok(())
}

/// `chown -h <uid>:<gid> <path>` — `-h` is the `lchown` flavor that
/// doesn't follow symlinks. Shell-out for the same reason as
/// `set_file_times`: keeps the agent FFI-free and `forbid(unsafe_code)`.
fn lchown(path: &Path, uid: u32, gid: u32) -> Result<(), FileError> {
    let spec = format!("{uid}:{gid}");
    let out = std::process::Command::new("chown")
        .arg("-h")
        .arg("--")
        .arg(&spec)
        .arg(path)
        .output()
        .map_err(|e| FileError::Io(format!("spawn chown: {e}")))?;
    if !out.status.success() {
        return Err(FileError::Io(format!(
            "chown -h {spec} {}: {}",
            path.display(),
            String::from_utf8_lossy(out.stderr.trim_ascii_end())
        )));
    }
    Ok(())
}

/// Resolve a username → uid by parsing /etc/passwd. NSS-free; this is
/// fine for the systems rsansible targets. Returns Err(name) on miss so
/// the caller can surface a useful TaskError.
fn resolve_user(name: &str) -> Result<u32, String> {
    parse_passwd_field(&std::fs::read_to_string("/etc/passwd").unwrap_or_default(), name, 2)
        .ok_or_else(|| name.to_string())
}

fn resolve_group(name: &str) -> Result<u32, String> {
    parse_passwd_field(&std::fs::read_to_string("/etc/group").unwrap_or_default(), name, 2)
        .ok_or_else(|| name.to_string())
}

/// Walk an `:`-delimited file (passwd or group), find the row whose
/// first column matches `name`, return the value at `field_idx` parsed
/// as u32. Lines starting with `#` are skipped.
fn parse_passwd_field(text: &str, name: &str, field_idx: usize) -> Option<u32> {
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
        let nth = cols.nth(field_idx.saturating_sub(1))?;
        return nth.parse::<u32>().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tempdir() -> std::path::PathBuf {
        let pid = std::process::id();
        let nonce = now_unix_ns();
        let p = std::path::PathBuf::from(format!("/tmp/rsansible-file-test-{pid}-{nonce}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn directory_create_then_idempotent() {
        let root = tempdir();
        let p = root.join("a/b/c");
        let changed = apply_directory(&p, Some(0o755), None, None, false).unwrap();
        assert!(changed, "first apply creates");
        assert!(p.is_dir());
        let changed = apply_directory(&p, Some(0o755), None, None, false).unwrap();
        assert!(!changed, "second apply is a no-op");
    }

    #[test]
    fn directory_mode_change_is_reported_changed() {
        let root = tempdir();
        let p = root.join("d");
        apply_directory(&p, Some(0o700), None, None, false).unwrap();
        let changed = apply_directory(&p, Some(0o755), None, None, false).unwrap();
        assert!(changed, "mode flip should report changed");
        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o755);
    }

    #[test]
    fn directory_existing_non_dir_errors() {
        let root = tempdir();
        let p = root.join("conflict");
        std::fs::write(&p, b"x").unwrap();
        let err = apply_directory(&p, None, None, None, false).unwrap_err();
        match err {
            FileError::BadRequest(m) => assert!(m.contains("isn't a directory"), "got {m}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn absent_removes_file_and_dir() {
        let root = tempdir();
        let f = root.join("file");
        std::fs::write(&f, b"x").unwrap();
        let changed = apply_absent(&f).unwrap();
        assert!(changed);
        assert!(!f.exists());
        // Second time = no-op.
        let changed = apply_absent(&f).unwrap();
        assert!(!changed);

        let d = root.join("d/sub");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("inside"), b"x").unwrap();
        let changed = apply_absent(&root.join("d")).unwrap();
        assert!(changed);
        assert!(!root.join("d").exists());
    }

    #[test]
    fn touch_creates_and_always_changed() {
        let root = tempdir();
        let p = root.join("ping");
        let changed = apply_touch(&p, Some(0o644), None, None).unwrap();
        assert!(changed);
        assert!(p.exists());
        // Second touch on existing file is still changed (Ansible contract).
        let changed = apply_touch(&p, Some(0o644), None, None).unwrap();
        assert!(changed);
    }

    #[test]
    fn file_state_errors_when_missing() {
        let root = tempdir();
        let p = root.join("nope");
        let err = apply_file(&p, None, None, None).unwrap_err();
        match err {
            FileError::NotFound(_) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn file_state_applies_mode_idempotently() {
        let root = tempdir();
        let p = root.join("f");
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let changed = apply_file(&p, Some(0o644), None, None).unwrap();
        assert!(changed, "mode change");
        let changed = apply_file(&p, Some(0o644), None, None).unwrap();
        assert!(!changed, "re-apply is a no-op");
    }

    #[test]
    fn recurse_applies_mode_to_descendants() {
        let root = tempdir();
        let a = root.join("r/a");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("inside"), b"x").unwrap();
        std::fs::set_permissions(a.join("inside"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let changed = apply_directory(&root.join("r"), Some(0o755), None, None, true).unwrap();
        assert!(changed);
        let m = std::fs::metadata(a.join("inside")).unwrap().permissions().mode() & 0o7777;
        // Inner file gets the same mode.
        assert_eq!(m, 0o755);
    }

    #[test]
    fn parse_passwd_field_works() {
        let text = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh\n";
        assert_eq!(parse_passwd_field(text, "root", 2), Some(0));
        assert_eq!(parse_passwd_field(text, "user", 2), Some(1000));
        assert_eq!(parse_passwd_field(text, "user", 3), Some(1000));
        assert_eq!(parse_passwd_field(text, "missing", 2), None);
    }

    #[test]
    fn parse_passwd_field_skips_comments_and_blanks() {
        let text = "# comment\n\nroot:x:0:0::/root:/bin/sh\n";
        assert_eq!(parse_passwd_field(text, "root", 2), Some(0));
    }
}
