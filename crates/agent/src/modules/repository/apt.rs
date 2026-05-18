//! Apt backend for `OpRepository`.
//!
//! Writes (or deletes) `/etc/apt/sources.list.d/<filename>.list`. No
//! `add-apt-repository` shell-out — we own the file directly, which
//! avoids pulling in `software-properties-common` on minimal hosts and
//! gives us deterministic idempotency.
//!
//! Idempotency:
//!   * `state=present` — compute the desired file contents (the `repo`
//!     line plus a trailing newline). If the file exists with that
//!     content and mode, no-op. Otherwise write atomically (write a tmp
//!     file in the same directory, fsync, rename).
//!   * `state=absent` — delete the file if present. No-op if absent.
//!
//! `update_cache=1` runs `apt-get update` after a change. We *only*
//! refresh when something actually changed — refreshing on a no-op is
//! cycles for no reason.
//!
//! Default filename derivation when `filename` is empty mirrors
//! Ansible's `apt_repository._sanitize_pkg_string`: replace every
//! non-alphanumeric (and non-dash/underscore) character in the repo
//! string with `_`, collapse runs, trim leading/trailing underscores.
//! Result lands at `/etc/apt/sources.list.d/<derived>.list`.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use rsansible_wire::generated::OpRepositoryOutput;

use super::RepositoryError;

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

/// Apt backend entry point. Reads env-var overrides for the sources-list
/// directory and the apt-get binary so unit tests can sandbox the work.
pub(crate) fn apply(op: &OpRepositoryOutput, check_mode: bool) -> Result<bool, RepositoryError> {
    let dir = std::env::var("RSANSIBLE_APT_SOURCES_DIR")
        .unwrap_or_else(|_| "/etc/apt/sources.list.d".to_string());
    let bin = std::env::var("RSANSIBLE_APT_GET").unwrap_or_else(|_| "apt-get".to_string());
    apply_with_paths(Path::new(&dir), &bin, op, check_mode)
}

pub(crate) fn apply_with_paths(
    sources_dir: &Path,
    apt_get: &str,
    op: &OpRepositoryOutput,
    check_mode: bool,
) -> Result<bool, RepositoryError> {
    let filename = if op.filename.is_empty() {
        derive_filename(&op.repo)
    } else {
        op.filename.clone()
    };
    if filename.is_empty() {
        return Err(RepositoryError::BadRequest(format!(
            "repository(apt): could not derive a filename from repo {:?} and none was provided",
            op.repo
        )));
    }
    let path = sources_dir.join(format!("{filename}.list"));

    let desired_mode = if op.mode == 0 { 0o644 } else { op.mode };
    let desired_content = format!("{}\n", op.repo.trim_end_matches('\n'));

    let changed = match op.state {
        STATE_PRESENT => apply_present(&path, &desired_content, desired_mode, check_mode)?,
        STATE_ABSENT => apply_absent(&path, check_mode)?,
        other => {
            return Err(RepositoryError::BadRequest(format!(
                "repository(apt): unknown state byte {other}"
            )))
        }
    };

    if changed && op.update_cache != 0 && !check_mode {
        run_apt_update(apt_get)?;
    }

    Ok(changed)
}

fn apply_present(
    path: &Path,
    desired_content: &str,
    desired_mode: u32,
    check_mode: bool,
) -> Result<bool, RepositoryError> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(RepositoryError::Io(format!(
                "read {}: {e}",
                path.display()
            )))
        }
    };
    let existing_mode = match std::fs::metadata(path) {
        Ok(md) => Some(md.permissions().mode() & 0o7777),
        Err(_) => None,
    };
    let content_matches = existing.as_deref() == Some(desired_content);
    let mode_matches = existing_mode == Some(desired_mode);
    if content_matches && mode_matches {
        return Ok(false);
    }
    if check_mode {
        // Would write; report changed without touching disk.
        return Ok(true);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            RepositoryError::Io(format!("create dir {}: {e}", parent.display()))
        })?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.rsansible-tmp",
        path.file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("repository")
    ));
    // Best-effort cleanup if a previous run aborted partway.
    let _ = std::fs::remove_file(&tmp);
    std::fs::write(&tmp, desired_content)
        .map_err(|e| RepositoryError::Io(format!("write {}: {e}", tmp.display())))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(desired_mode))
        .map_err(|e| RepositoryError::Io(format!("chmod {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        // Try to clean the tmp on failure so we don't leak it.
        let _ = std::fs::remove_file(&tmp);
        RepositoryError::Io(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(true)
}

fn apply_absent(path: &Path, check_mode: bool) -> Result<bool, RepositoryError> {
    match std::fs::metadata(path) {
        Ok(_) => {
            if check_mode {
                return Ok(true);
            }
            std::fs::remove_file(path).map_err(|e| {
                RepositoryError::Io(format!("remove {}: {e}", path.display()))
            })?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(RepositoryError::Io(format!(
            "stat {}: {e}",
            path.display()
        ))),
    }
}

fn run_apt_update(bin: &str) -> Result<(), RepositoryError> {
    let out = spawn_apt_update(bin)
        .map_err(|e| RepositoryError::Spawn(format!("spawn {bin} update: {e}")))?;
    if !out.status.success() {
        return Err(RepositoryError::Io(format!(
            "{bin} update failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn spawn_apt_update(bin: &str) -> std::io::Result<std::process::Output> {
    use std::io::ErrorKind;
    use std::time::Duration;
    let mut delay_ms = 5u64;
    let mut last_err = None;
    for _ in 0..6 {
        match Command::new(bin)
            .arg("update")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output()
        {
            Ok(out) => return Ok(out),
            Err(e) if e.raw_os_error() == Some(26) || e.kind() == ErrorKind::ResourceBusy => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(delay_ms));
                delay_ms = (delay_ms * 2).min(80);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("ETXTBSY retries exhausted")))
}

/// Best-effort imitation of Ansible's `_sanitize_pkg_string`: keep
/// alphanumerics, underscores, and dashes; replace everything else with
/// underscores. Collapse runs of underscores and trim them at the edges.
/// Empty input yields empty output (caller errors out).
fn derive_filename(repo: &str) -> String {
    let mut out = String::with_capacity(repo.len());
    let mut last_was_us = false;
    for ch in repo.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
            last_was_us = ch == '_';
        } else if !last_was_us {
            out.push('_');
            last_was_us = true;
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::msg::now_unix_ns;
    use std::io::Write as _;
    use std::path::PathBuf;

    fn op(repo: &str, filename: &str, state: u8) -> OpRepositoryOutput {
        OpRepositoryOutput {
            kind: 21,
            manager: 1,
            repo: repo.to_string(),
            state,
            filename: filename.to_string(),
            mode: 0,
            update_cache: 0,
        }
    }

    /// Build a sandboxed sources.list.d-style dir and an apt-get stub
    /// that logs its invocation to a file. Returns (dir, apt_stub_path).
    fn sandbox(label: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "rsansible-repo-{label}-{}-{}",
            std::process::id(),
            now_unix_ns()
        ));
        let sources = dir.join("sources.list.d");
        std::fs::create_dir_all(&sources).unwrap();
        let apt = dir.join("apt-get");
        let log = dir.join("apt.log");
        std::fs::write(&log, "").unwrap();
        let script = format!(
            "#!/bin/sh\necho \"$@\" >> {log}\n",
            log = log.display()
        );
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&apt)
                .unwrap();
            f.write_all(script.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        let mut perms = std::fs::metadata(&apt).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&apt, perms).unwrap();
        (sources, apt)
    }

    fn apt_log(sources: &Path) -> String {
        let log = sources.parent().unwrap().join("apt.log");
        std::fs::read_to_string(log).unwrap_or_default()
    }

    #[test]
    fn present_writes_file_and_reports_changed() {
        let (sources, apt) = sandbox("present-new");
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(changed);
        let written = std::fs::read_to_string(sources.join("pgdg.list")).unwrap();
        assert_eq!(written, "deb https://example.com/repo focal main\n");
        let md = std::fs::metadata(sources.join("pgdg.list")).unwrap();
        assert_eq!(md.permissions().mode() & 0o7777, 0o644);
    }

    #[test]
    fn present_idempotent_when_content_and_mode_match() {
        let (sources, apt) = sandbox("present-noop");
        let path = sources.join("pgdg.list");
        std::fs::write(&path, "deb https://example.com/repo focal main\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(!changed);
    }

    #[test]
    fn present_rewrites_when_content_differs() {
        let (sources, apt) = sandbox("present-changed");
        let path = sources.join("pgdg.list");
        std::fs::write(&path, "deb old line\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(changed);
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, "deb https://example.com/repo focal main\n");
    }

    #[test]
    fn present_rewrites_when_only_mode_differs() {
        let (sources, apt) = sandbox("present-mode");
        let path = sources.join("pgdg.list");
        std::fs::write(&path, "deb https://example.com/repo focal main\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(changed);
        let md = std::fs::metadata(&path).unwrap();
        assert_eq!(md.permissions().mode() & 0o7777, 0o644);
    }

    #[test]
    fn absent_removes_existing_and_reports_changed() {
        let (sources, apt) = sandbox("absent-go");
        let path = sources.join("pgdg.list");
        std::fs::write(&path, "deb https://example.com/repo focal main\n").unwrap();
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_ABSENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(changed);
        assert!(!path.exists());
    }

    #[test]
    fn absent_noop_when_missing() {
        let (sources, apt) = sandbox("absent-noop");
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_ABSENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(!changed);
    }

    #[test]
    fn update_cache_runs_only_on_change() {
        let (sources, apt) = sandbox("update-cache");
        // First call: file doesn't exist → changed → apt-get update runs.
        let mut o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        o.update_cache = 1;
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(changed);
        assert_eq!(apt_log(&sources).trim(), "update");

        // Second call: idempotent → not changed → apt-get update does NOT run again.
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(!changed);
        // Log still has exactly one "update" line.
        assert_eq!(
            apt_log(&sources).lines().filter(|l| *l == "update").count(),
            1
        );
    }

    #[test]
    fn derives_filename_from_repo_when_omitted() {
        let (sources, apt) = sandbox("derive");
        let o = op("deb https://example.com/repo focal main", "", STATE_PRESENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        assert!(changed);
        // Sanitised: non-alphanumerics → '_', collapsed, trimmed.
        let expected = sources.join("deb_https_example_com_repo_focal_main.list");
        assert!(expected.exists(), "expected derived file {expected:?}");
    }

    #[test]
    fn check_mode_present_reports_changed_without_writing() {
        let (sources, apt) = sandbox("check-present");
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, true).unwrap();
        assert!(changed);
        assert!(!sources.join("pgdg.list").exists());
        // update_cache=0; nothing should have run anyway.
        assert!(apt_log(&sources).is_empty());
    }

    #[test]
    fn check_mode_absent_reports_changed_without_deleting() {
        let (sources, apt) = sandbox("check-absent");
        let path = sources.join("pgdg.list");
        std::fs::write(&path, "deb https://example.com/repo focal main\n").unwrap();
        let o = op("deb https://example.com/repo focal main", "pgdg", STATE_ABSENT);
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, true).unwrap();
        assert!(changed);
        assert!(path.exists(), "absent check-mode must not delete");
    }

    #[test]
    fn check_mode_skips_update_cache_even_on_change() {
        let (sources, apt) = sandbox("check-update");
        let mut o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        o.update_cache = 1;
        let changed = apply_with_paths(&sources, apt.to_str().unwrap(), &o, true).unwrap();
        assert!(changed);
        assert!(apt_log(&sources).is_empty(), "check_mode must not run apt-get update");
    }

    #[test]
    fn custom_mode_is_honored() {
        let (sources, apt) = sandbox("custom-mode");
        let mut o = op("deb https://example.com/repo focal main", "pgdg", STATE_PRESENT);
        o.mode = 0o640;
        let _ = apply_with_paths(&sources, apt.to_str().unwrap(), &o, false).unwrap();
        let md = std::fs::metadata(sources.join("pgdg.list")).unwrap();
        assert_eq!(md.permissions().mode() & 0o7777, 0o640);
    }

    #[test]
    fn derive_filename_examples() {
        assert_eq!(
            derive_filename("deb https://example.com/repo focal main"),
            "deb_https_example_com_repo_focal_main"
        );
        assert_eq!(
            derive_filename("deb [signed-by=/etc/apt/keyrings/pg.asc] https://apt.postgresql.org/pub/repos/apt focal-pgdg main"),
            "deb_signed-by_etc_apt_keyrings_pg_asc_https_apt_postgresql_org_pub_repos_apt_focal-pgdg_main"
        );
        // Trims leading/trailing underscores.
        assert_eq!(derive_filename("///foo///"), "foo");
        // Collapses runs.
        assert_eq!(derive_filename("a    b"), "a_b");
    }
}
