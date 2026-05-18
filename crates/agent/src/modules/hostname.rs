//! `OpHostname` — set the system hostname.
//!
//! Strategy: read current hostname → no-op if equal → else mutate.
//! Mutation: prefer `hostnamectl set-hostname <name>` (handles
//! `/etc/hostname`, kernel name, and pretty/static aliases in one
//! call). Fall back to writing `/etc/hostname` and calling the
//! `hostname` binary if hostnamectl isn't on PATH (non-systemd hosts).

use std::path::Path;
use std::process::Command;

use rsansible_wire::generated::OpHostnameOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpHostnameOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    if op.name.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "hostname: empty `name`").await;
        return Ok(());
    }

    let result = tokio::task::spawn_blocking(move || apply(&op, check_mode))
        .await
        .map_err(|e| anyhow::anyhow!("hostname join: {e}"))?;

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
        Err(HostnameError::Io(m)) => emit_error(ctx, seq, err::IO, m).await,
        Err(HostnameError::Spawn(m)) => emit_error(ctx, seq, err::SPAWN_FAILED, m).await,
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum HostnameError {
    Io(String),
    Spawn(String),
}

pub(crate) struct Bins {
    pub hostname: String,
    pub hostnamectl: String,
    pub etc_hostname: String,
}

impl Bins {
    pub fn from_env() -> Self {
        Self {
            hostname: std::env::var("RSANSIBLE_HOSTNAME_BIN").unwrap_or_else(|_| "hostname".into()),
            hostnamectl: std::env::var("RSANSIBLE_HOSTNAMECTL")
                .unwrap_or_else(|_| "hostnamectl".into()),
            etc_hostname: std::env::var("RSANSIBLE_ETC_HOSTNAME")
                .unwrap_or_else(|_| "/etc/hostname".into()),
        }
    }
}

pub(crate) fn apply(op: &OpHostnameOutput, check_mode: bool) -> Result<bool, HostnameError> {
    apply_with_bins(&Bins::from_env(), op, check_mode)
}

pub(crate) fn apply_with_bins(
    bins: &Bins,
    op: &OpHostnameOutput,
    check_mode: bool,
) -> Result<bool, HostnameError> {
    let current = current_hostname(bins)?;
    if current == op.name {
        return Ok(false);
    }
    if check_mode {
        return Ok(true);
    }
    set_hostname(bins, &op.name)?;
    Ok(true)
}

fn current_hostname(bins: &Bins) -> Result<String, HostnameError> {
    // Prefer reading /etc/hostname (matches what hostnamectl writes,
    // survives a reboot, doesn't depend on which init system is up).
    // Fall back to the `hostname` binary if the file is absent or empty
    // (e.g. fresh installs where systemd-firstboot hasn't run yet).
    if Path::new(&bins.etc_hostname).exists() {
        match std::fs::read_to_string(&bins.etc_hostname) {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if !trimmed.is_empty() {
                    return Ok(trimmed);
                }
            }
            Err(e) => {
                return Err(HostnameError::Io(format!(
                    "read {}: {e}",
                    bins.etc_hostname
                )))
            }
        }
    }
    let out = Command::new(&bins.hostname)
        .output()
        .map_err(|e| HostnameError::Spawn(format!("spawn {}: {e}", bins.hostname)))?;
    if !out.status.success() {
        return Err(HostnameError::Io(format!(
            "{} failed ({:?}): stderr={:?}",
            bins.hostname,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn set_hostname(bins: &Bins, name: &str) -> Result<(), HostnameError> {
    // Prefer hostnamectl — single call handles /etc/hostname + kernel
    // name + (where supported) pretty/static names.
    if which(&bins.hostnamectl) {
        let out = Command::new(&bins.hostnamectl)
            .args(["set-hostname", name])
            .output()
            .map_err(|e| HostnameError::Spawn(format!("spawn {}: {e}", bins.hostnamectl)))?;
        if !out.status.success() {
            return Err(HostnameError::Io(format!(
                "{} set-hostname {name}: exit {:?} stderr={:?}",
                bins.hostnamectl,
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        return Ok(());
    }
    // Fallback: write /etc/hostname and update the kernel value via
    // the `hostname` binary so the change takes effect immediately.
    std::fs::write(&bins.etc_hostname, format!("{name}\n"))
        .map_err(|e| HostnameError::Io(format!("write {}: {e}", bins.etc_hostname)))?;
    let out = Command::new(&bins.hostname)
        .arg(name)
        .output()
        .map_err(|e| HostnameError::Spawn(format!("spawn {}: {e}", bins.hostname)))?;
    if !out.status.success() {
        return Err(HostnameError::Io(format!(
            "{} {name}: exit {:?} stderr={:?}",
            bins.hostname,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn which(bin: &str) -> bool {
    // If `bin` is an absolute path, test directly. Otherwise probe via
    // `command -v` so the agent's stub harness can override PATH or
    // pin the binary to an absolute path inside its tempdir.
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
        fn new(label: &str, initial: &str, with_ctl: bool) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-hostname-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let etc_hostname = dir.join("hostname-file");
            std::fs::write(&etc_hostname, format!("{initial}\n")).unwrap();
            let log = dir.join("log");
            std::fs::write(&log, "").unwrap();

            // `hostname` binary: with no args echoes /etc/hostname; with
            // an arg writes to log + updates the file (simulating the
            // running kernel value being persisted).
            let hostname_bin = dir.join("hostname");
            let script = format!(
                r#"#!/bin/sh
F="{etc}"
L="{log}"
if [ $# -eq 0 ]; then
  cat "$F"
else
  echo "hostname $1" >> "$L"
  echo "$1" > "$F"
fi
"#,
                etc = etc_hostname.display(),
                log = log.display()
            );
            write_script(&hostname_bin, &script);

            // hostnamectl: if requested, behaves as on systemd hosts.
            let hostnamectl_path = if with_ctl {
                let p = dir.join("hostnamectl");
                let ctl_script = format!(
                    r#"#!/bin/sh
F="{etc}"
L="{log}"
[ "$1" = "set-hostname" ] || exit 1
echo "hostnamectl $1 $2" >> "$L"
echo "$2" > "$F"
"#,
                    etc = etc_hostname.display(),
                    log = log.display()
                );
                write_script(&p, &ctl_script);
                p
            } else {
                // Point at a nonexistent path; which() returns false.
                dir.join("no-hostnamectl-here")
            };

            let bins = Bins {
                hostname: hostname_bin.to_string_lossy().into_owned(),
                hostnamectl: hostnamectl_path.to_string_lossy().into_owned(),
                etc_hostname: etc_hostname.to_string_lossy().into_owned(),
            };
            Stub { dir, bins }
        }
        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }
        fn etc(&self) -> String {
            std::fs::read_to_string(&self.bins.etc_hostname).unwrap_or_default()
        }
    }

    fn write_script(p: &Path, body: &str) {
        std::fs::write(p, body.as_bytes()).unwrap();
        let mut perms = std::fs::metadata(p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(p, perms).unwrap();
    }

    fn op(name: &str) -> OpHostnameOutput {
        OpHostnameOutput { kind: 26, name: name.into() }
    }

    #[test]
    fn noop_when_already_matches() {
        let stub = Stub::new("noop", "pg1", true);
        let changed = apply_with_bins(&stub.bins, &op("pg1"), false).unwrap();
        assert!(!changed);
        assert!(stub.log().is_empty());
    }

    #[test]
    fn changes_via_hostnamectl_when_present() {
        let stub = Stub::new("ctl", "old", true);
        let changed = apply_with_bins(&stub.bins, &op("pg1"), false).unwrap();
        assert!(changed);
        assert!(stub.log().contains("hostnamectl set-hostname pg1"));
        assert_eq!(stub.etc().trim(), "pg1");
    }

    #[test]
    fn changes_via_file_fallback_when_no_hostnamectl() {
        let stub = Stub::new("nofall", "old", false);
        let changed = apply_with_bins(&stub.bins, &op("pg1"), false).unwrap();
        assert!(changed);
        assert!(stub.log().contains("hostname pg1"));
        assert_eq!(stub.etc().trim(), "pg1");
    }

    #[test]
    fn check_mode_reports_changed_without_writing() {
        let stub = Stub::new("check", "old", true);
        let changed = apply_with_bins(&stub.bins, &op("pg1"), true).unwrap();
        assert!(changed);
        assert!(stub.log().is_empty());
        assert_eq!(stub.etc().trim(), "old");
    }
}
