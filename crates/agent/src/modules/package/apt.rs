//! Apt backend for `OpPackage`.
//!
//! Wraps `apt-get` with `DEBIAN_FRONTEND=noninteractive`.
//!
//! Idempotency:
//!   * **present** — probes each requested package via `dpkg-query`,
//!     skips packages already installed, calls `apt-get install -y` on
//!     the remainder. `changed=1` iff anything had to be installed.
//!   * **absent** — probes each package; calls `apt-get remove -y`
//!     (`purge` when `purge=1`) on the installed subset.
//!     `changed=1` iff anything had to be removed.
//!   * **latest** — probes pre-versions, runs `apt-get install -y`
//!     (no `--only-upgrade` — Ansible includes "install if missing" in
//!     latest), probes post-versions. `changed=1` iff any version moved.
//!
//! `update_cache=1` runs `apt-get update` first, suppressed by
//! `cache_valid_time` if the package cache mtime is fresher than that
//! many seconds. The cache-update itself never counts as `changed`
//! (matches Ansible's `cache_updated` field, which is separate).
//!
//! `autoremove=1` runs `apt-get autoremove -y` after the main op
//! regardless of state.
//!
//! Fields that aren't apt-specific (`manager`) are read by the
//! dispatcher; fields that *are* meaningful only for apt
//! (`default_release`, `allow_unauthenticated`, `purge`,
//! `cache_valid_time`) are honored here. The `OpPackage` wire shape
//! carries the union of all backends' knobs; we ignore what we don't
//! consume.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::SystemTime;

use rsansible_wire::generated::OpPackageOutput;

use super::super::spawn_with_etxtbsy_retry;
use super::PackageError;

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;
const STATE_LATEST: u8 = 2;

/// Apt backend entry point. Reads env-var overrides for the apt-get and
/// dpkg-query binary paths (used by tests with stubs) and does the work.
pub(crate) fn apply(op: &OpPackageOutput, check_mode: bool) -> Result<bool, PackageError> {
    let bin = std::env::var("RSANSIBLE_APT_GET").unwrap_or_else(|_| "apt-get".to_string());
    let dpkg = std::env::var("RSANSIBLE_DPKG_QUERY").unwrap_or_else(|_| "dpkg-query".to_string());
    apply_with_bins(&bin, &dpkg, op, check_mode)
}

/// Test-visible apply: caller passes explicit binary paths so unit
/// tests can plant stubs without env-var contamination.
pub(crate) fn apply_with_bins(
    bin: &str,
    dpkg: &str,
    op: &OpPackageOutput,
    check_mode: bool,
) -> Result<bool, PackageError> {
    let mut changed = false;

    // 1. update_cache (with cache_valid_time gate).
    if op.update_cache != 0 && cache_update_needed(op.cache_valid_time) {
        if !check_mode {
            run_apt(bin, &["update"])?;
        }
        // Per Ansible, cache_updated is reported separately and doesn't
        // by itself set `changed`. We follow that here — only package
        // movement counts.
    }

    // 2. Main op per state.
    match op.state {
        STATE_PRESENT => {
            let installed = probe_installed(dpkg, &op.names)?;
            let missing: Vec<&str> = op
                .names
                .iter()
                .filter(|n| !installed.contains_key(n.as_str()))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                if !check_mode {
                    let mut args: Vec<String> = vec!["install".into(), "-y".into()];
                    push_install_flags(&mut args, op);
                    args.extend(missing.iter().map(|s| s.to_string()));
                    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                    run_apt(bin, &argv)?;
                }
                changed = true;
            }
        }
        STATE_ABSENT => {
            let installed = probe_installed(dpkg, &op.names)?;
            let present: Vec<&str> = op
                .names
                .iter()
                .filter(|n| installed.contains_key(n.as_str()))
                .map(String::as_str)
                .collect();
            if !present.is_empty() {
                if !check_mode {
                    let verb = if op.purge != 0 { "purge" } else { "remove" };
                    let mut args: Vec<String> = vec![verb.into(), "-y".into()];
                    args.extend(present.iter().map(|s| s.to_string()));
                    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                    run_apt(bin, &argv)?;
                }
                changed = true;
            }
        }
        STATE_LATEST => {
            if check_mode {
                // Without running `apt-get install`, we can't know
                // post-versions cheaply. Conservative: report
                // `changed=true` whenever any requested package isn't
                // currently installed at all. v2 should parse
                // `apt-cache policy` to distinguish "already at
                // candidate" from "would upgrade". TODO: see
                // TODO.md — package(apt) STATE_LATEST check-mode
                // precision.
                let pre = probe_installed(dpkg, &op.names)?;
                if op.names.iter().any(|n| !pre.contains_key(n.as_str())) {
                    changed = true;
                }
                // For all-installed-but-maybe-outdated, we don't know
                // without policy parsing; err on the side of "would
                // change" only when we have evidence (missing pkg).
            } else {
                // Capture pre-versions for everything (including not-installed),
                // run install, capture post-versions, compare.
                let pre = probe_installed(dpkg, &op.names)?;
                let mut args: Vec<String> = vec!["install".into(), "-y".into()];
                push_install_flags(&mut args, op);
                args.extend(op.names.iter().cloned());
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                run_apt(bin, &argv)?;
                let post = probe_installed(dpkg, &op.names)?;
                for n in &op.names {
                    let pre_v = pre.get(n.as_str()).cloned().unwrap_or_default();
                    let post_v = post.get(n.as_str()).cloned().unwrap_or_default();
                    if pre_v != post_v {
                        changed = true;
                        break;
                    }
                }
            }
        }
        other => {
            return Err(PackageError::BadRequest(format!(
                "package(apt): unknown state byte {other}"
            )))
        }
    }

    // 3. autoremove last (so newly-orphaned packages get swept).
    if op.autoremove != 0 {
        if check_mode {
            // Without running `apt-get autoremove`, we don't know
            // whether anything would be removed. Conservative skip:
            // do not toggle `changed`; the operator can re-run for
            // real to see if there's actually work to do. (Mirrors
            // Ansible's behavior for autoremove under --check.)
        } else {
            // We can't easily tell whether autoremove was a no-op without
            // parsing apt output. Mark changed conservatively only if it
            // actually removed something — we approximate by capturing the
            // stdout and looking for "0 to remove" / "0 removed".
            let out = run_apt_capture(bin, &["autoremove", "-y"])?;
            // apt-get prints a summary line like "0 upgraded, 0 newly
            // installed, 0 to remove and N not upgraded." We treat absence
            // of "0 to remove" as "something was removed".
            if !out.contains("0 to remove") && !out.contains("0 removed") {
                // The line wasn't found at all, or removal happened.
                // Don't fail closed — only flip to `changed` if we see
                // evidence of removal.
                if out.contains("Removing ") {
                    changed = true;
                }
            }
        }
    }

    Ok(changed)
}

/// Build the apt-get install flag list shared by present + latest.
/// Ansible's default keeps recommends ON (we follow that); the only
/// extra flags we surface are `-t <release>` and
/// `--allow-unauthenticated`.
fn push_install_flags(args: &mut Vec<String>, op: &OpPackageOutput) {
    if !op.default_release.is_empty() {
        args.push("-t".into());
        args.push(op.default_release.clone());
    }
    if op.allow_unauthenticated != 0 {
        args.push("--allow-unauthenticated".into());
    }
}

/// Returns whether the apt-cache is stale enough to need an update.
/// `valid_seconds == 0` means "always run an update". Otherwise compare
/// the pkgcache mtime to `now` and skip when fresher than the window.
fn cache_update_needed(valid_seconds: u32) -> bool {
    if valid_seconds == 0 {
        return true;
    }
    let path = "/var/cache/apt/pkgcache.bin";
    let md = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return true, // no cache → must update
    };
    let mtime = match md.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };
    let age = SystemTime::now()
        .duration_since(mtime)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    age >= valid_seconds as u64
}

/// Run `apt-get <args>` with `DEBIAN_FRONTEND=noninteractive`. Errors
/// on non-zero exit with the captured stderr.
fn run_apt(bin: &str, args: &[&str]) -> Result<(), PackageError> {
    let out = spawn_apt_with_retry(bin, args)
        .map_err(|e| PackageError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(PackageError::Io(format!(
            "{bin} {args:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

/// Same as `run_apt` but returns the captured stdout for parsing.
fn run_apt_capture(bin: &str, args: &[&str]) -> Result<String, PackageError> {
    let out = spawn_apt_with_retry(bin, args)
        .map_err(|e| PackageError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(PackageError::Io(format!(
            "{bin} {args:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Apt's variant of the ETXTBSY retry: same idea as the shared helper
/// in modules::mod, but we need `DEBIAN_FRONTEND=noninteractive` on
/// every attempt, so we can't reuse the shared spawn function directly.
fn spawn_apt_with_retry(bin: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::io::ErrorKind;
    use std::time::Duration;
    let mut delay_ms = 5u64;
    let mut last_err = None;
    for _ in 0..6 {
        match Command::new(bin)
            .args(args)
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

/// `dpkg-query -W -f '${binary:Package} ${db:Status-Status} ${Version}\n' <pkgs...>`
/// returns one line per *known* package (installed or otherwise known to
/// dpkg). Unknown packages exit non-zero and don't appear on stdout — we
/// tolerate that. Output map: pkg → version string (empty if not installed).
fn probe_installed(dpkg: &str, names: &[String]) -> Result<BTreeMap<String, String>, PackageError> {
    if names.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut args: Vec<String> = vec![
        "-W".into(),
        "-f".into(),
        // db:Status-Status emits one of `installed|config-files|...`.
        // We only treat `installed` as "present".
        "${binary:Package} ${db:Status-Status} ${Version}\n".into(),
    ];
    args.extend(names.iter().cloned());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let argv_slice: Vec<&str> = argv.iter().copied().collect();
    let out = spawn_with_etxtbsy_retry(dpkg, &argv_slice)
        .map_err(|e| PackageError::Spawn(format!("spawn {dpkg} {argv:?}: {e}")))?;
    // dpkg-query exits non-zero when any requested package is unknown,
    // but the lines it could resolve are still printed. Don't error.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut map = BTreeMap::new();
    for line in stdout.lines() {
        let mut parts = line.splitn(3, ' ');
        let pkg = match parts.next() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let status = parts.next().unwrap_or("");
        let version = parts.next().unwrap_or("").trim();
        if status == "installed" {
            map.insert(pkg.to_string(), version.to_string());
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::msg::now_unix_ns;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// Stub pair: one apt-get and one dpkg-query script in a temp dir.
    /// The dpkg-query script reads a "DB" file with one line per
    /// installed pkg as `pkg version`; the apt-get script logs invocation
    /// and may rewrite the DB.
    struct Stub {
        dir: PathBuf,
        apt: PathBuf,
        dpkg: PathBuf,
    }

    impl Stub {
        fn new(label: &str, db: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-apt-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            // DB file: one line per installed pkg, `name version`.
            let db_text = db
                .iter()
                .map(|(n, v)| format!("{n} {v}"))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(dir.join("DB"), db_text).unwrap();
            // log file
            std::fs::write(dir.join("log"), "").unwrap();

            let apt = dir.join("apt-get");
            let dpkg = dir.join("dpkg-query");

            // apt-get stub: log argv, on `install <pkgs...>` add each
            // pkg to DB at version `installed-2`. On `remove`/`purge`
            // delete matching pkgs from DB. `update` and `autoremove`
            // are no-ops.
            let apt_script = format!(
                r#"#!/bin/sh
DB="{db}"
LOG="{log}"
echo "$@" >> "$LOG"
verb="$1"; shift
case "$verb" in
  update)
    ;;
  autoremove)
    ;;
  install)
    # skip -y / -t <rel> / --allow-unauthenticated
    while [ "${{1#-}}" != "$1" ]; do
      if [ "$1" = "-t" ]; then shift 2; else shift; fi
    done
    for pkg in "$@"; do
      grep -v "^$pkg " "$DB" > "$DB.tmp" || true
      echo "$pkg installed-2" >> "$DB.tmp"
      mv "$DB.tmp" "$DB"
    done
    ;;
  remove|purge)
    while [ "${{1#-}}" != "$1" ]; do shift; done
    for pkg in "$@"; do
      grep -v "^$pkg " "$DB" > "$DB.tmp" || true
      mv "$DB.tmp" "$DB"
    done
    ;;
esac
"#,
                db = dir.join("DB").display(),
                log = dir.join("log").display(),
            );

            // dpkg-query stub: only honors `-W -f '<fmt>' pkg1 pkg2 ...`
            // and emits "pkg installed version" if found in DB, nothing
            // otherwise.
            let dpkg_script = format!(
                r#"#!/bin/sh
DB="{db}"
# consume -W -f <fmt>
[ "$1" = "-W" ] && shift
[ "$1" = "-f" ] && shift 2
for pkg in "$@"; do
  ver=$(grep "^$pkg " "$DB" | head -n1 | cut -d' ' -f2)
  if [ -n "$ver" ]; then
    echo "$pkg installed $ver"
  fi
done
"#,
                db = dir.join("DB").display(),
            );

            for (path, body) in [(&apt, apt_script), (&dpkg, dpkg_script)] {
                use std::io::Write as _;
                {
                    let mut f = std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(path)
                        .unwrap();
                    f.write_all(body.as_bytes()).unwrap();
                    f.sync_all().unwrap();
                }
                let mut perms = std::fs::metadata(path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(path, perms).unwrap();
            }

            Stub { dir, apt, dpkg }
        }

        fn apt_path(&self) -> &Path {
            &self.apt
        }

        fn dpkg_path(&self) -> &Path {
            &self.dpkg
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }

        fn db(&self) -> String {
            std::fs::read_to_string(self.dir.join("DB")).unwrap_or_default()
        }
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn op(names: &[&str], state: u8) -> OpPackageOutput {
        OpPackageOutput {
            kind: 10,
            manager: 1, // apt
            names: names.iter().map(|s| s.to_string()).collect(),
            state,
            update_cache: 0,
            cache_valid_time: 0,
            purge: 0,
            autoremove: 0,
            default_release: String::new(),
            allow_unauthenticated: 0,
            virtualenv: String::new(),
            virtualenv_command: String::new(),
        }
    }

    fn run(stub: &Stub, op: &OpPackageOutput) -> Result<bool, PackageError> {
        apply_with_bins(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            op,
            false,
        )
    }

    #[test]
    fn present_installs_missing() {
        let stub = Stub::new("present-install", &[]);
        let changed = run(&stub, &op(&["nginx"], STATE_PRESENT)).unwrap();
        assert!(changed);
        assert!(stub.log().contains("install -y"), "log={:?}", stub.log());
        assert!(stub.db().contains("nginx installed-2"));
    }

    #[test]
    fn present_skips_when_installed() {
        let stub = Stub::new("present-noop", &[("nginx", "1.18.0-6")]);
        let changed = run(&stub, &op(&["nginx"], STATE_PRESENT)).unwrap();
        assert!(!changed);
        assert!(!stub.log().contains("install"), "log={:?}", stub.log());
    }

    #[test]
    fn present_installs_only_missing_in_batch() {
        let stub = Stub::new("present-batch", &[("curl", "7.85.0-1")]);
        let changed = run(&stub, &op(&["curl", "nginx"], STATE_PRESENT)).unwrap();
        assert!(changed);
        let log = stub.log();
        // Only nginx should be installed; curl should NOT appear.
        assert!(log.contains("install -y nginx"), "log={log:?}");
        assert!(!log.contains("install -y curl"), "log={log:?}");
    }

    #[test]
    fn absent_removes_installed() {
        let stub = Stub::new("absent-go", &[("nginx", "1.18.0-6")]);
        let changed = run(&stub, &op(&["nginx"], STATE_ABSENT)).unwrap();
        assert!(changed);
        assert!(stub.log().contains("remove -y nginx"), "log={:?}", stub.log());
        assert!(!stub.db().contains("nginx"));
    }

    #[test]
    fn absent_skips_when_not_installed() {
        let stub = Stub::new("absent-noop", &[]);
        let changed = run(&stub, &op(&["nginx"], STATE_ABSENT)).unwrap();
        assert!(!changed);
        assert!(!stub.log().contains("remove"), "log={:?}", stub.log());
    }

    #[test]
    fn absent_purge_uses_purge_verb() {
        let stub = Stub::new("absent-purge", &[("nginx", "1.18.0-6")]);
        let mut o = op(&["nginx"], STATE_ABSENT);
        o.purge = 1;
        let changed = run(&stub, &o).unwrap();
        assert!(changed);
        assert!(stub.log().contains("purge -y nginx"), "log={:?}", stub.log());
    }

    #[test]
    fn latest_install_when_missing_reports_changed() {
        let stub = Stub::new("latest-install", &[]);
        let changed = run(&stub, &op(&["nginx"], STATE_LATEST)).unwrap();
        assert!(changed);
        assert!(stub.log().contains("install -y"));
    }

    #[test]
    fn latest_when_version_unchanged_is_noop() {
        // Our apt stub always sets version to "installed-2" on install.
        // Pre-version is also "installed-2" → no change.
        let stub = Stub::new("latest-noop", &[("nginx", "installed-2")]);
        let changed = run(&stub, &op(&["nginx"], STATE_LATEST)).unwrap();
        assert!(!changed);
    }

    #[test]
    fn latest_when_version_changes_reports_changed() {
        let stub = Stub::new("latest-go", &[("nginx", "installed-1")]);
        let changed = run(&stub, &op(&["nginx"], STATE_LATEST)).unwrap();
        assert!(changed);
    }

    #[test]
    fn update_cache_runs_update_first() {
        let stub = Stub::new("update", &[]);
        let mut o = op(&["nginx"], STATE_PRESENT);
        o.update_cache = 1;
        o.cache_valid_time = 0;
        let _ = run(&stub, &o).unwrap();
        let log = stub.log();
        let update_pos = log.find("update").unwrap();
        let install_pos = log.find("install").unwrap();
        assert!(update_pos < install_pos, "log={log:?}");
    }

    #[test]
    fn default_release_passes_t_flag() {
        let stub = Stub::new("default-release", &[]);
        let mut o = op(&["nginx"], STATE_PRESENT);
        o.default_release = "bookworm-backports".into();
        let _ = run(&stub, &o).unwrap();
        assert!(stub.log().contains("-t bookworm-backports"), "log={:?}", stub.log());
    }

    #[test]
    fn empty_names_with_no_other_action_is_noop_in_apply() {
        // The dispatcher in package/mod.rs validates "need at least one
        // of [names, update_cache, autoremove]" before reaching the
        // backend. apply_with_bins itself doesn't crash but does nothing.
        let stub = Stub::new("empty", &[]);
        let changed = run(&stub, &op(&[], STATE_PRESENT)).unwrap();
        assert!(!changed);
    }
}
