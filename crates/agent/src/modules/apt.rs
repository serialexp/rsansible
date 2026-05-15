//! `OpApt` — Ansible's `apt` module (subset).
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

use std::collections::BTreeMap;
use std::process::Command;
use std::time::SystemTime;

use rsansible_wire::generated::OpAptOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;
const STATE_LATEST: u8 = 2;

pub async fn run(ctx: &Context, seq: u32, op: OpAptOutput) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    if op.names.is_empty() && op.update_cache == 0 && op.autoremove == 0 {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            "apt: need at least one of [name(s), update_cache, autoremove]",
        )
        .await;
        return Ok(());
    }

    let bin = std::env::var("RSANSIBLE_APT_GET").unwrap_or_else(|_| "apt-get".to_string());
    let dpkg = std::env::var("RSANSIBLE_DPKG_QUERY").unwrap_or_else(|_| "dpkg-query".to_string());
    let result = tokio::task::spawn_blocking(move || apply(&bin, &dpkg, &op))
        .await
        .map_err(|e| anyhow::anyhow!("apt join: {e}"))?;

    let changed = match result {
        Ok(c) => c,
        Err(AptError::Io(m)) => {
            emit_error(ctx, seq, err::IO, m).await;
            return Ok(());
        }
        Err(AptError::Spawn(m)) => {
            emit_error(ctx, seq, err::SPAWN_FAILED, m).await;
            return Ok(());
        }
        Err(AptError::BadRequest(m)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, m).await;
            return Ok(());
        }
    };

    let finished = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, started_unix_ns, finished))
        .await;
    Ok(())
}

#[derive(Debug)]
enum AptError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

fn apply(bin: &str, dpkg: &str, op: &OpAptOutput) -> Result<bool, AptError> {
    let mut changed = false;

    // 1. update_cache (with cache_valid_time gate).
    if op.update_cache != 0 && cache_update_needed(op.cache_valid_time) {
        run_apt(bin, &op, &["update"])?;
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
                let mut args: Vec<String> = vec!["install".into(), "-y".into()];
                push_install_flags(&mut args, op);
                args.extend(missing.iter().map(|s| s.to_string()));
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                run_apt(bin, &op, &argv)?;
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
                let verb = if op.purge != 0 { "purge" } else { "remove" };
                let mut args: Vec<String> = vec![verb.into(), "-y".into()];
                args.extend(present.iter().map(|s| s.to_string()));
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                run_apt(bin, &op, &argv)?;
                changed = true;
            }
        }
        STATE_LATEST => {
            // Capture pre-versions for everything (including not-installed),
            // run install, capture post-versions, compare.
            let pre = probe_installed(dpkg, &op.names)?;
            let mut args: Vec<String> = vec!["install".into(), "-y".into()];
            push_install_flags(&mut args, op);
            args.extend(op.names.iter().cloned());
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            run_apt(bin, &op, &argv)?;
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
        other => {
            return Err(AptError::BadRequest(format!(
                "apt: unknown state byte {other}"
            )))
        }
    }

    // 3. autoremove last (so newly-orphaned packages get swept).
    if op.autoremove != 0 {
        // We can't easily tell whether autoremove was a no-op without
        // parsing apt output. Mark changed conservatively only if it
        // actually removed something — we approximate by capturing the
        // stdout and looking for "0 to remove" / "0 removed".
        let out = run_apt_capture(bin, &op, &["autoremove", "-y"])?;
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

    Ok(changed)
}

/// Build the apt-get install flag list shared by present + latest.
/// Ansible's default keeps recommends ON (we follow that); the only
/// extra flags we surface are `-t <release>` and
/// `--allow-unauthenticated`.
fn push_install_flags(args: &mut Vec<String>, op: &OpAptOutput) {
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
fn run_apt(bin: &str, _op: &OpAptOutput, args: &[&str]) -> Result<(), AptError> {
    let out = Command::new(bin)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|e| AptError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(AptError::Io(format!(
            "{bin} {args:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

/// Same as `run_apt` but returns the captured stdout for parsing.
fn run_apt_capture(bin: &str, _op: &OpAptOutput, args: &[&str]) -> Result<String, AptError> {
    let out = Command::new(bin)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|e| AptError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(AptError::Io(format!(
            "{bin} {args:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `dpkg-query -W -f '${binary:Package} ${db:Status-Status} ${Version}\n' <pkgs...>`
/// returns one line per *known* package (installed or otherwise known to
/// dpkg). Unknown packages exit non-zero and don't appear on stdout — we
/// tolerate that. Output map: pkg → version string (empty if not installed).
fn probe_installed(dpkg: &str, names: &[String]) -> Result<BTreeMap<String, String>, AptError> {
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
    let out = Command::new(dpkg)
        .args(&argv)
        .output()
        .map_err(|e| AptError::Spawn(format!("spawn {dpkg} {argv:?}: {e}")))?;
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
            // pkg to DB at version `installed-1`. On `remove`/`purge`
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

    fn op(names: &[&str], state: u8) -> OpAptOutput {
        OpAptOutput {
            kind: 10,
            names: names.iter().map(|s| s.to_string()).collect(),
            state,
            update_cache: 0,
            cache_valid_time: 0,
            purge: 0,
            autoremove: 0,
            default_release: String::new(),
            allow_unauthenticated: 0,
        }
    }

    #[test]
    fn present_installs_missing() {
        let stub = Stub::new("present-install", &[]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["nginx"], STATE_PRESENT),
        )
        .unwrap();
        assert!(changed);
        assert!(stub.log().contains("install -y"), "log={:?}", stub.log());
        assert!(stub.db().contains("nginx installed-2"));
    }

    #[test]
    fn present_skips_when_installed() {
        let stub = Stub::new("present-noop", &[("nginx", "1.18.0-6")]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["nginx"], STATE_PRESENT),
        )
        .unwrap();
        assert!(!changed);
        assert!(!stub.log().contains("install"), "log={:?}", stub.log());
    }

    #[test]
    fn present_installs_only_missing_in_batch() {
        let stub = Stub::new("present-batch", &[("curl", "7.85.0-1")]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["curl", "nginx"], STATE_PRESENT),
        )
        .unwrap();
        assert!(changed);
        let log = stub.log();
        // Only nginx should be installed; curl should NOT appear.
        assert!(log.contains("install -y nginx"), "log={log:?}");
        assert!(!log.contains("install -y curl"), "log={log:?}");
    }

    #[test]
    fn absent_removes_installed() {
        let stub = Stub::new("absent-go", &[("nginx", "1.18.0-6")]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["nginx"], STATE_ABSENT),
        )
        .unwrap();
        assert!(changed);
        assert!(stub.log().contains("remove -y nginx"), "log={:?}", stub.log());
        assert!(!stub.db().contains("nginx"));
    }

    #[test]
    fn absent_skips_when_not_installed() {
        let stub = Stub::new("absent-noop", &[]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["nginx"], STATE_ABSENT),
        )
        .unwrap();
        assert!(!changed);
        assert!(!stub.log().contains("remove"), "log={:?}", stub.log());
    }

    #[test]
    fn absent_purge_uses_purge_verb() {
        let stub = Stub::new("absent-purge", &[("nginx", "1.18.0-6")]);
        let mut o = op(&["nginx"], STATE_ABSENT);
        o.purge = 1;
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &o,
        )
        .unwrap();
        assert!(changed);
        assert!(stub.log().contains("purge -y nginx"), "log={:?}", stub.log());
    }

    #[test]
    fn latest_install_when_missing_reports_changed() {
        let stub = Stub::new("latest-install", &[]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["nginx"], STATE_LATEST),
        )
        .unwrap();
        assert!(changed);
        assert!(stub.log().contains("install -y"));
    }

    #[test]
    fn latest_when_version_unchanged_is_noop() {
        // Our apt stub always sets version to "installed-2" on install.
        // Pre-version is also "installed-2" → no change.
        let stub = Stub::new("latest-noop", &[("nginx", "installed-2")]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["nginx"], STATE_LATEST),
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn latest_when_version_changes_reports_changed() {
        let stub = Stub::new("latest-go", &[("nginx", "installed-1")]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&["nginx"], STATE_LATEST),
        )
        .unwrap();
        assert!(changed);
    }

    #[test]
    fn update_cache_runs_update_first() {
        let stub = Stub::new("update", &[]);
        let mut o = op(&["nginx"], STATE_PRESENT);
        o.update_cache = 1;
        o.cache_valid_time = 0;
        let _ = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &o,
        )
        .unwrap();
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
        let _ = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &o,
        )
        .unwrap();
        assert!(stub.log().contains("-t bookworm-backports"), "log={:?}", stub.log());
    }

    #[test]
    fn empty_names_with_no_other_action_rejected() {
        // run() validates this; apply() doesn't crash but does nothing.
        let stub = Stub::new("empty", &[]);
        let changed = apply(
            stub.apt_path().to_str().unwrap(),
            stub.dpkg_path().to_str().unwrap(),
            &op(&[], STATE_PRESENT),
        )
        .unwrap();
        assert!(!changed);
    }
}
