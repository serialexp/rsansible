//! `OpTimezone` — set the system timezone.
//!
//! Strategy: read current timezone → no-op if equal → else mutate.
//! Mutation: prefer `timedatectl set-timezone <name>` (handles
//! `/etc/localtime`, `/etc/timezone`, and the kernel time-of-day state
//! in one call). Fall back to symlinking `/etc/localtime` ->
//! `/usr/share/zoneinfo/<name>` and writing `/etc/timezone` if
//! timedatectl isn't on PATH (non-systemd hosts).

use std::path::{Path, PathBuf};
use std::process::Command;

use rsansible_wire::generated::OpTimezoneOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpTimezoneOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    if op.name.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "timezone: empty `name`").await;
        return Ok(());
    }

    let result = tokio::task::spawn_blocking(move || apply(&op, check_mode))
        .await
        .map_err(|e| anyhow::anyhow!("timezone join: {e}"))?;

    match result {
        Ok(changed) => {
            ctx.emit(msg::task_done(
                seq,
                0,
                changed,
                false,
                started_unix_ns,
                now_unix_ns(),
            ))
            .await;
        }
        Err(TimezoneError::BadRequest(m)) => emit_error(ctx, seq, err::BAD_REQUEST, m).await,
        Err(TimezoneError::Io(m)) => emit_error(ctx, seq, err::IO, m).await,
        Err(TimezoneError::Spawn(m)) => emit_error(ctx, seq, err::SPAWN_FAILED, m).await,
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum TimezoneError {
    BadRequest(String),
    Io(String),
    Spawn(String),
}

pub(crate) struct Bins {
    pub timedatectl: String,
    pub etc_localtime: PathBuf,
    pub etc_timezone: PathBuf,
    pub zoneinfo_dir: PathBuf,
}

impl Bins {
    pub fn from_env() -> Self {
        Self {
            timedatectl: std::env::var("RSANSIBLE_TIMEDATECTL")
                .unwrap_or_else(|_| "timedatectl".into()),
            etc_localtime: std::env::var_os("RSANSIBLE_ETC_LOCALTIME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/etc/localtime")),
            etc_timezone: std::env::var_os("RSANSIBLE_ETC_TIMEZONE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/etc/timezone")),
            zoneinfo_dir: std::env::var_os("RSANSIBLE_ZONEINFO_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/share/zoneinfo")),
        }
    }
}

pub(crate) fn apply(op: &OpTimezoneOutput, check_mode: bool) -> Result<bool, TimezoneError> {
    apply_with_bins(&Bins::from_env(), op, check_mode)
}

pub(crate) fn apply_with_bins(
    bins: &Bins,
    op: &OpTimezoneOutput,
    check_mode: bool,
) -> Result<bool, TimezoneError> {
    let current = current_timezone(bins).unwrap_or_default();
    if current == op.name {
        return Ok(false);
    }
    if check_mode {
        return Ok(true);
    }
    set_timezone(bins, &op.name)?;
    Ok(true)
}

fn current_timezone(bins: &Bins) -> Option<String> {
    // Prefer `timedatectl show --property=Timezone --value` (single
    // line, no parsing pain). Fall back to reading the /etc/localtime
    // symlink target, which timedatectl writes anyway. /etc/timezone
    // is Debian/Ubuntu-specific so use it only as a last resort.
    if which(&bins.timedatectl) {
        if let Ok(out) = Command::new(&bins.timedatectl)
            .args(["show", "--property=Timezone", "--value"])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    if let Ok(target) = std::fs::read_link(&bins.etc_localtime) {
        // /etc/localtime → /usr/share/zoneinfo/<name>; strip the prefix.
        let zi = bins.zoneinfo_dir.as_path();
        if let Ok(rel) = target.strip_prefix(zi) {
            return Some(rel.to_string_lossy().into_owned());
        }
        // The link may be relative — `../usr/share/zoneinfo/<name>`.
        // Strip everything up to (and including) "zoneinfo/".
        let s = target.to_string_lossy();
        if let Some(idx) = s.find("zoneinfo/") {
            return Some(s[idx + "zoneinfo/".len()..].to_string());
        }
    }
    if let Ok(s) = std::fs::read_to_string(&bins.etc_timezone) {
        let t = s.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

fn set_timezone(bins: &Bins, name: &str) -> Result<(), TimezoneError> {
    // Validate the zone exists in /usr/share/zoneinfo before we touch
    // anything — both timedatectl and the symlink fallback would
    // produce a confusing error otherwise.
    let zi_file = bins.zoneinfo_dir.join(name);
    if !zi_file.is_file() {
        return Err(TimezoneError::BadRequest(format!(
            "timezone: zoneinfo entry not found: {}",
            zi_file.display()
        )));
    }

    // Prefer timedatectl — single call handles /etc/localtime,
    // /etc/timezone (where present), and the kernel time-of-day state.
    if which(&bins.timedatectl) {
        let out = Command::new(&bins.timedatectl)
            .args(["set-timezone", name])
            .output()
            .map_err(|e| TimezoneError::Spawn(format!("spawn {}: {e}", bins.timedatectl)))?;
        if !out.status.success() {
            return Err(TimezoneError::Io(format!(
                "{} set-timezone {name}: exit {:?} stderr={:?}",
                bins.timedatectl,
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        return Ok(());
    }

    // Fallback: rewrite /etc/localtime as a symlink to the zoneinfo
    // file, and write /etc/timezone. Replace atomically by removing
    // any existing /etc/localtime first; `symlink` errors out if the
    // path already exists.
    if bins.etc_localtime.exists() || bins.etc_localtime.symlink_metadata().is_ok() {
        std::fs::remove_file(&bins.etc_localtime).map_err(|e| {
            TimezoneError::Io(format!(
                "remove {}: {e}",
                bins.etc_localtime.display()
            ))
        })?;
    }
    std::os::unix::fs::symlink(&zi_file, &bins.etc_localtime).map_err(|e| {
        TimezoneError::Io(format!(
            "symlink {} -> {}: {e}",
            bins.etc_localtime.display(),
            zi_file.display()
        ))
    })?;
    std::fs::write(&bins.etc_timezone, format!("{name}\n")).map_err(|e| {
        TimezoneError::Io(format!("write {}: {e}", bins.etc_timezone.display()))
    })?;
    Ok(())
}

fn which(bin: &str) -> bool {
    if bin.starts_with('/') {
        return Path::new(bin).is_file();
    }
    Command::new("sh")
        .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Stub {
        dir: PathBuf,
        bins: Bins,
    }
    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    impl Stub {
        /// `initial` is the timezone reported by the stub timedatectl
        /// (and written into the synthetic /etc/timezone). `with_ctl`
        /// toggles whether the timedatectl stub is installed.
        fn new(label: &str, initial: &str, with_ctl: bool) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-timezone-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let zoneinfo_dir = dir.join("zoneinfo");
            std::fs::create_dir_all(&zoneinfo_dir).unwrap();
            // Pre-create a couple of zoneinfo files used by the tests.
            for z in ["UTC", "Europe/Amsterdam", "Etc/UTC"] {
                let p = zoneinfo_dir.join(z);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"zoneinfo data\n").unwrap();
            }
            let etc_timezone = dir.join("timezone-file");
            std::fs::write(&etc_timezone, format!("{initial}\n")).unwrap();
            let etc_localtime = dir.join("localtime");
            let log = dir.join("log");
            std::fs::write(&log, "").unwrap();

            let timedatectl_path = if with_ctl {
                let p = dir.join("timedatectl");
                let script = format!(
                    r#"#!/bin/sh
F="{etc}"
L="{log}"
case "$1" in
  show)
    cat "$F"
    ;;
  set-timezone)
    echo "timedatectl set-timezone $2" >> "$L"
    echo "$2" > "$F"
    ;;
  *)
    exit 1
    ;;
esac
"#,
                    etc = etc_timezone.display(),
                    log = log.display()
                );
                write_script(&p, &script);
                p
            } else {
                dir.join("no-timedatectl-here")
            };

            let bins = Bins {
                timedatectl: timedatectl_path.to_string_lossy().into_owned(),
                etc_localtime,
                etc_timezone,
                zoneinfo_dir,
            };
            Stub { dir, bins }
        }
        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }
        fn etc(&self) -> String {
            std::fs::read_to_string(&self.bins.etc_timezone).unwrap_or_default()
        }
    }

    fn write_script(p: &Path, body: &str) {
        std::fs::write(p, body.as_bytes()).unwrap();
        let mut perms = std::fs::metadata(p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(p, perms).unwrap();
    }

    fn op(name: &str) -> OpTimezoneOutput {
        OpTimezoneOutput { kind: 27, name: name.into() }
    }

    #[test]
    fn noop_when_already_matches() {
        let stub = Stub::new("noop", "UTC", true);
        let changed = apply_with_bins(&stub.bins, &op("UTC"), false).unwrap();
        assert!(!changed);
        assert!(stub.log().is_empty());
    }

    #[test]
    fn changes_via_timedatectl_when_present() {
        let stub = Stub::new("ctl", "Etc/UTC", true);
        let changed = apply_with_bins(&stub.bins, &op("Europe/Amsterdam"), false).unwrap();
        assert!(changed);
        assert!(
            stub.log().contains("timedatectl set-timezone Europe/Amsterdam"),
            "log: {:?}",
            stub.log()
        );
        assert_eq!(stub.etc().trim(), "Europe/Amsterdam");
    }

    #[test]
    fn changes_via_symlink_fallback_when_no_timedatectl() {
        let stub = Stub::new("nofall", "Etc/UTC", false);
        let changed = apply_with_bins(&stub.bins, &op("Europe/Amsterdam"), false).unwrap();
        assert!(changed);
        // /etc/localtime should be a symlink to zoneinfo/Europe/Amsterdam
        let link = std::fs::read_link(&stub.bins.etc_localtime).unwrap();
        assert!(
            link.ends_with("Europe/Amsterdam"),
            "link: {:?}",
            link
        );
        assert_eq!(stub.etc().trim(), "Europe/Amsterdam");
    }

    #[test]
    fn rejects_unknown_zone() {
        let stub = Stub::new("bad", "Etc/UTC", true);
        let err = apply_with_bins(&stub.bins, &op("Mars/Olympus"), false).unwrap_err();
        assert!(
            matches!(err, TimezoneError::BadRequest(ref m) if m.contains("not found")),
            "got: {err:?}"
        );
    }

    #[test]
    fn check_mode_reports_changed_without_writing() {
        let stub = Stub::new("check", "Etc/UTC", true);
        let changed = apply_with_bins(&stub.bins, &op("Europe/Amsterdam"), true).unwrap();
        assert!(changed);
        assert!(stub.log().is_empty());
        assert_eq!(stub.etc().trim(), "Etc/UTC");
    }
}
