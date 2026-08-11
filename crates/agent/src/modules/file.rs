//! `OpFile` — Ansible's `file:` module.
//!
//! Supported states:
//!   - `directory` — mkdir -p; apply mode/owner/group; recursive if `recurse=1`
//!   - `absent`    — rm -rf (dir) / unlink (file or symlink)
//!   - `touch`     — create empty file if missing; always bumps mtime/atime
//!                   (Ansible reports touch as always-changed)
//!   - `file`      — assert that a regular file exists; apply mode/owner/group
//!   - `link`      — ensure `path` is a symlink pointing at `src`; create if
//!                   missing, atomically repoint if it targets something else,
//!                   no-op if already correct. Errors if `path` exists and is
//!                   not a symlink (`force` is not supported). Owner/group are
//!                   applied to the link itself via lchown; mode is ignored.
//!
//! `changed` semantics:
//!   - directory: changed iff path was created, OR mode/owner/group changed,
//!                OR (recurse=1) any descendant's mode/owner/group changed
//!   - absent:    changed iff the path existed before this op
//!   - touch:     always changed (Ansible's contract)
//!   - file:      changed iff mode/owner/group changed
//!   - link:      changed iff the link was created, its target repointed, or
//!                its owner/group changed
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
const STATE_LINK: u8 = 4;

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpFileOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    let path = op.path;
    let src = op.src;
    let mode = if op.has_mode != 0 {
        Some(op.mode & 0o7777)
    } else {
        None
    };
    let recurse = op.recurse != 0;
    let owner = if op.owner.is_empty() {
        None
    } else {
        Some(op.owner.as_str())
    };
    let group = if op.group.is_empty() {
        None
    } else {
        Some(op.group.as_str())
    };

    // Resolve owner/group up front — fail fast with BAD_REQUEST rather
    // than partial work.
    let uid = match owner.map(resolve_user) {
        None => None,
        Some(Ok(u)) => Some(u),
        Some(Err(name)) => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("unknown user: {name:?}"),
            )
            .await;
            return Ok(());
        }
    };
    let gid = match group.map(resolve_group) {
        None => None,
        Some(Ok(g)) => Some(g),
        Some(Err(name)) => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("unknown group: {name:?}"),
            )
            .await;
            return Ok(());
        }
    };

    let result = match op.state {
        STATE_DIRECTORY => apply_directory(Path::new(&path), mode, uid, gid, recurse, check_mode),
        STATE_ABSENT => apply_absent(Path::new(&path), check_mode),
        STATE_TOUCH => apply_touch(Path::new(&path), mode, uid, gid, check_mode),
        STATE_FILE => apply_file(Path::new(&path), mode, uid, gid, check_mode),
        STATE_LINK => apply_link(Path::new(&path), &src, uid, gid, check_mode),
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
    check_mode: bool,
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
        if !check_mode {
            std::fs::create_dir_all(path).map_err(FileError::from)?;
        }
        changed = true;
        // Under check_mode the directory doesn't exist yet, so further
        // probes (mode/owner/group/recurse) have nothing to look at.
        if check_mode {
            return Ok(true);
        }
    }
    // Apply mode/owner/group to the top-level path.
    if apply_mode_owner_group(path, mode, uid, gid, check_mode)? {
        changed = true;
    }
    if recurse {
        walk_apply(path, mode, uid, gid, &mut changed, check_mode)?;
    }
    Ok(changed)
}

fn apply_absent(path: &Path, check_mode: bool) -> Result<bool, FileError> {
    let pre = std::fs::symlink_metadata(path);
    match pre {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(FileError::from(e)),
        Ok(m) => {
            if check_mode {
                return Ok(true);
            }
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
    check_mode: bool,
) -> Result<bool, FileError> {
    let existed = path.exists();
    // Touch is always-changed by Ansible's contract — under check_mode
    // we report changed=true and skip the file ops entirely.
    if check_mode {
        return Ok(true);
    }
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
    let _ = apply_mode_owner_group(path, mode, uid, gid, false)?;
    let _ = existed; // suppress unused warning if branches collapse
    Ok(true)
}

fn apply_file(
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    check_mode: bool,
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
    apply_mode_owner_group(path, mode, uid, gid, check_mode)
}

/// `state: link` — ensure `path` is a symlink pointing at `src`.
///
/// Idempotent: a symlink already pointing at `src` is a no-op; one pointing
/// elsewhere is atomically repointed; a missing path is created. If `path`
/// exists and is NOT a symlink we refuse (Ansible's `force: no` default) with
/// BAD_REQUEST rather than clobbering a real file/dir. Owner/group (if given)
/// are applied to the link itself via lchown; `mode` is ignored because chmod
/// is meaningless on a symlink.
fn apply_link(
    path: &Path,
    src: &str,
    uid: Option<u32>,
    gid: Option<u32>,
    check_mode: bool,
) -> Result<bool, FileError> {
    if src.is_empty() {
        return Err(FileError::BadRequest(
            "state=link requires a non-empty src (symlink target)".to_string(),
        ));
    }
    let src_path = Path::new(src);
    let pre = std::fs::symlink_metadata(path).ok();
    let mut changed = false;
    // Whether a symlink exists on disk after our action — gates the
    // owner/group probe (skip it on the check_mode "would-create" path).
    let mut link_on_disk = false;

    match &pre {
        Some(m) if m.file_type().is_symlink() => {
            let cur = std::fs::read_link(path).map_err(FileError::from)?;
            if cur != src_path {
                if !check_mode {
                    replace_symlink_atomic(src_path, path)?;
                }
                changed = true;
            }
            link_on_disk = true;
        }
        Some(m) => {
            return Err(FileError::BadRequest(format!(
                "state=link: {} exists and is not a symlink (type={:?}); \
                 refusing to replace (force is not supported)",
                path.display(),
                m.file_type()
            )));
        }
        None => {
            if !check_mode {
                replace_symlink_atomic(src_path, path)?;
                link_on_disk = true;
            }
            changed = true;
        }
    }

    // Owner/group on the link itself (lchown, never follows). mode=None so no
    // chmod is attempted. apply_mode_owner_group already skips chmod for
    // symlinks, but passing None makes the intent explicit and cheap.
    if link_on_disk && (uid.is_some() || gid.is_some()) {
        if apply_mode_owner_group(path, None, uid, gid, check_mode)? {
            changed = true;
        }
    }

    Ok(changed)
}

/// Create-or-repoint a symlink atomically: make the link under a temp name in
/// the same directory, then `rename` it over `path` (an atomic replace on the
/// same filesystem). Never leaves `path` pointing at a half-written target.
fn replace_symlink_atomic(src: &Path, path: &Path) -> Result<(), FileError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let fname = path.file_name().ok_or_else(|| {
        FileError::BadRequest(format!(
            "state=link: destination has no file name: {}",
            path.display()
        ))
    })?;
    let tmp = parent.join(format!(
        ".{}.rsansible-lnk-{}",
        fname.to_string_lossy(),
        now_unix_ns()
    ));
    // Clear any stale tmp from a previously crashed run before symlinking.
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(src, &tmp).map_err(FileError::from)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(FileError::from(e))
        }
    }
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
    check_mode: bool,
) -> Result<bool, FileError> {
    let meta = std::fs::symlink_metadata(path).map_err(FileError::from)?;
    let mut changed = false;

    if let Some(want) = mode {
        // chmod is meaningless on a symlink (chmod follows; lchmod isn't
        // POSIX). Skip silently for symlinks to match Ansible.
        if !meta.file_type().is_symlink() {
            let cur = meta.permissions().mode() & 0o7777;
            if cur != want & 0o7777 {
                if !check_mode {
                    let perms = std::fs::Permissions::from_mode(want & 0o7777);
                    std::fs::set_permissions(path, perms).map_err(FileError::from)?;
                }
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
        if !check_mode {
            lchown(path, want_uid, want_gid)?;
        }
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
    check_mode: bool,
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
            if apply_mode_owner_group(&p, mode, uid, gid, check_mode)? {
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
pub(crate) fn resolve_user(name: &str) -> Result<u32, String> {
    parse_passwd_field(
        &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
        name,
        2,
    )
    .ok_or_else(|| name.to_string())
}

pub(crate) fn resolve_group(name: &str) -> Result<u32, String> {
    parse_passwd_field(
        &std::fs::read_to_string("/etc/group").unwrap_or_default(),
        name,
        2,
    )
    .ok_or_else(|| name.to_string())
}

/// `chown -h <uid>:<gid> <path>` — `-h` flavour that doesn't follow
/// symlinks. Shared with `unarchive` so it can chown extracted entries
/// after the archive walk without re-implementing the same shell-out
/// fallback. Returns Err(message) on failure.
pub(crate) fn lchown_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let spec = format!("{uid}:{gid}");
    let out = std::process::Command::new("chown")
        .arg("-h")
        .arg("--")
        .arg(&spec)
        .arg(path)
        .output()
        .map_err(|e| format!("spawn chown: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chown -h {spec} {}: {}",
            path.display(),
            String::from_utf8_lossy(out.stderr.trim_ascii_end())
        ));
    }
    Ok(())
}

/// `chown -h <uid> <path>` — set owner only, leave group untouched.
/// Lives here rather than in `unarchive` (the original home) so
/// `write_file` can share it for `template:` / `copy:` dispatches that
/// specify `owner:` without `group:`.
pub(crate) fn chown_user_only(path: &Path, uid: u32) -> Result<(), String> {
    let spec = format!("{uid}");
    let out = std::process::Command::new("chown")
        .arg("-h")
        .arg("--")
        .arg(&spec)
        .arg(path)
        .output()
        .map_err(|e| format!("spawn chown: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chown -h {spec} {}: {}",
            path.display(),
            String::from_utf8_lossy(out.stderr.trim_ascii_end())
        ));
    }
    Ok(())
}

/// `chown -h :<gid> <path>` — set group only, leave owner untouched.
/// Symmetric to `chown_user_only`.
pub(crate) fn chown_group_only(path: &Path, gid: u32) -> Result<(), String> {
    let spec = format!(":{gid}");
    let out = std::process::Command::new("chown")
        .arg("-h")
        .arg("--")
        .arg(&spec)
        .arg(path)
        .output()
        .map_err(|e| format!("spawn chown: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chown -h {spec} {}: {}",
            path.display(),
            String::from_utf8_lossy(out.stderr.trim_ascii_end())
        ));
    }
    Ok(())
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
        let changed = apply_directory(&p, Some(0o755), None, None, false, false).unwrap();
        assert!(changed, "first apply creates");
        assert!(p.is_dir());
        let changed = apply_directory(&p, Some(0o755), None, None, false, false).unwrap();
        assert!(!changed, "second apply is a no-op");
    }

    #[test]
    fn directory_mode_change_is_reported_changed() {
        let root = tempdir();
        let p = root.join("d");
        apply_directory(&p, Some(0o700), None, None, false, false).unwrap();
        let changed = apply_directory(&p, Some(0o755), None, None, false, false).unwrap();
        assert!(changed, "mode flip should report changed");
        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o755);
    }

    #[test]
    fn directory_existing_non_dir_errors() {
        let root = tempdir();
        let p = root.join("conflict");
        std::fs::write(&p, b"x").unwrap();
        let err = apply_directory(&p, None, None, None, false, false).unwrap_err();
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
        let changed = apply_absent(&f, false).unwrap();
        assert!(changed);
        assert!(!f.exists());
        // Second time = no-op.
        let changed = apply_absent(&f, false).unwrap();
        assert!(!changed);

        let d = root.join("d/sub");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("inside"), b"x").unwrap();
        let changed = apply_absent(&root.join("d"), false).unwrap();
        assert!(changed);
        assert!(!root.join("d").exists());
    }

    #[test]
    fn touch_creates_and_always_changed() {
        let root = tempdir();
        let p = root.join("ping");
        let changed = apply_touch(&p, Some(0o644), None, None, false).unwrap();
        assert!(changed);
        assert!(p.exists());
        // Second touch on existing file is still changed (Ansible contract).
        let changed = apply_touch(&p, Some(0o644), None, None, false).unwrap();
        assert!(changed);
    }

    #[test]
    fn file_state_errors_when_missing() {
        let root = tempdir();
        let p = root.join("nope");
        let err = apply_file(&p, None, None, None, false).unwrap_err();
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
        let changed = apply_file(&p, Some(0o644), None, None, false).unwrap();
        assert!(changed, "mode change");
        let changed = apply_file(&p, Some(0o644), None, None, false).unwrap();
        assert!(!changed, "re-apply is a no-op");
    }

    #[test]
    fn recurse_applies_mode_to_descendants() {
        let root = tempdir();
        let a = root.join("r/a");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("inside"), b"x").unwrap();
        std::fs::set_permissions(a.join("inside"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let changed =
            apply_directory(&root.join("r"), Some(0o755), None, None, true, false).unwrap();
        assert!(changed);
        let m = std::fs::metadata(a.join("inside"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        // Inner file gets the same mode.
        assert_eq!(m, 0o755);
    }

    #[test]
    fn check_mode_directory_does_not_create() {
        let root = tempdir();
        let p = root.join("ck/a/b");
        let changed = apply_directory(&p, Some(0o755), None, None, false, true).unwrap();
        assert!(changed, "absent dir should report would-change");
        assert!(!p.exists(), "check_mode must NOT create the directory");
    }

    #[test]
    fn check_mode_directory_mode_change_does_not_apply() {
        let root = tempdir();
        let p = root.join("ck-mode");
        apply_directory(&p, Some(0o700), None, None, false, false).unwrap();
        let changed = apply_directory(&p, Some(0o755), None, None, false, true).unwrap();
        assert!(changed, "mode diff should report would-change");
        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(m, 0o700, "check_mode must not apply chmod");
    }

    #[test]
    fn check_mode_absent_does_not_remove() {
        let root = tempdir();
        let p = root.join("ck-rm");
        std::fs::write(&p, b"x").unwrap();
        let changed = apply_absent(&p, true).unwrap();
        assert!(changed, "existing file should report would-change");
        assert!(p.exists(), "check_mode must NOT delete the file");
    }

    #[test]
    fn check_mode_absent_missing_is_noop() {
        let root = tempdir();
        let p = root.join("ck-nope");
        let changed = apply_absent(&p, true).unwrap();
        assert!(!changed);
        assert!(!p.exists());
    }

    #[test]
    fn check_mode_touch_reports_changed_without_creating() {
        let root = tempdir();
        let p = root.join("ck-touch");
        let changed = apply_touch(&p, Some(0o644), None, None, true).unwrap();
        assert!(changed, "touch is always-changed (Ansible contract)");
        assert!(!p.exists(), "check_mode must NOT create the file");
    }

    #[test]
    fn link_creates_then_idempotent() {
        let root = tempdir();
        let target = root.join("real-target");
        std::fs::write(&target, b"x").unwrap();
        let link = root.join("the-link");
        let target_s = target.to_string_lossy().to_string();

        let changed = apply_link(&link, &target_s, None, None, false).unwrap();
        assert!(changed, "first apply creates the symlink");
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), target);

        let changed = apply_link(&link, &target_s, None, None, false).unwrap();
        assert!(!changed, "re-apply to same target is a no-op");
    }

    #[test]
    fn link_repoints_when_target_differs() {
        let root = tempdir();
        let link = root.join("l");
        std::os::unix::fs::symlink("/old/target", &link).unwrap();
        let changed = apply_link(&link, "/new/target", None, None, false).unwrap();
        assert!(changed, "different target should repoint");
        assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("/new/target"));
        // Repoint preserves the symlink (didn't turn it into a regular file).
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn link_refuses_to_clobber_regular_file() {
        let root = tempdir();
        let p = root.join("real");
        std::fs::write(&p, b"important").unwrap();
        let err = apply_link(&p, "/some/target", None, None, false).unwrap_err();
        match err {
            FileError::BadRequest(m) => assert!(m.contains("not a symlink"), "got {m}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
        // The real file is untouched.
        assert_eq!(std::fs::read(&p).unwrap(), b"important");
    }

    #[test]
    fn link_empty_src_is_bad_request() {
        let root = tempdir();
        let p = root.join("l");
        let err = apply_link(&p, "", None, None, false).unwrap_err();
        match err {
            FileError::BadRequest(m) => assert!(m.contains("src"), "got {m}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn check_mode_link_reports_change_without_creating() {
        let root = tempdir();
        let p = root.join("would-link");
        let changed = apply_link(&p, "/target", None, None, true).unwrap();
        assert!(changed, "absent link should report would-change");
        assert!(
            std::fs::symlink_metadata(&p).is_err(),
            "check_mode must NOT create the symlink"
        );
    }

    #[test]
    fn check_mode_link_repoint_does_not_apply() {
        let root = tempdir();
        let link = root.join("l");
        std::os::unix::fs::symlink("/old", &link).unwrap();
        let changed = apply_link(&link, "/new", None, None, true).unwrap();
        assert!(changed, "target diff should report would-change");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("/old"),
            "check_mode must NOT repoint"
        );
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
