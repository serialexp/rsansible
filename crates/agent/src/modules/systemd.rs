//! `OpSystemd` — Ansible's `systemd_service` / `service` module.
//!
//! Subset semantics:
//!   * `state` — `started`/`stopped`/`restarted`/`reloaded`/(unset).
//!   * `enabled` — bool, optional.
//!   * `masked`  — bool, optional.
//!   * `daemon_reload` — bool, run `systemctl daemon-reload` first.
//!   * `no_block` — bool, pass `--no-block` to start/stop/restart.
//!
//! Order:
//!   1. daemon-reload (if requested)
//!   2. mask / unmask (if requested) — re-probes after to know whether
//!      the next steps need to do anything.
//!   3. enable / disable (if requested) — idempotent via `is-enabled`
//!      probe.
//!   4. state transition — idempotent via `is-active` probe; restarted
//!      and reloaded are unconditionally treated as changed (Ansible's
//!      contract).
//!
//! Failure semantics: if any systemctl invocation returns a non-zero
//! exit code (other than the probes whose non-zero values carry status
//! meaning), the module sends TaskError(IO) with the captured stderr
//! and aborts.
//!
//! `RSANSIBLE_SYSTEMCTL` env var overrides the systemctl binary used
//! (defaults to `systemctl`). The override is exposed so the e2e test
//! can drop a stub in PATH without depending on a systemd-on-container
//! environment; production deployments leave it unset.

use std::process::Command;

use rsansible_wire::generated::OpSystemdOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_NONE: u8 = 0;
const STATE_STARTED: u8 = 1;
const STATE_STOPPED: u8 = 2;
const STATE_RESTARTED: u8 = 3;
const STATE_RELOADED: u8 = 4;

pub async fn run(ctx: &Context, seq: u32, op: OpSystemdOutput) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    if op.name.trim().is_empty() {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            "systemd: `name` is required",
        )
        .await;
        return Ok(());
    }

    let bin = std::env::var("RSANSIBLE_SYSTEMCTL").unwrap_or_else(|_| "systemctl".to_string());
    let result = tokio::task::spawn_blocking(move || apply(&bin, &op))
        .await
        .map_err(|e| anyhow::anyhow!("systemd join: {e}"))?;

    let changed = match result {
        Ok(c) => c,
        Err(SystemdError::Io(msg)) => {
            emit_error(ctx, seq, err::IO, msg).await;
            return Ok(());
        }
        Err(SystemdError::Spawn(msg)) => {
            emit_error(ctx, seq, err::SPAWN_FAILED, msg).await;
            return Ok(());
        }
        Err(SystemdError::BadRequest(msg)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, msg).await;
            return Ok(());
        }
    };

    let finished = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, started_unix_ns, finished))
        .await;
    Ok(())
}

#[derive(Debug)]
enum SystemdError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

fn apply(bin: &str, op: &OpSystemdOutput) -> Result<bool, SystemdError> {
    let name = op.name.as_str();
    let mut changed = false;

    if op.daemon_reload != 0 {
        run_systemctl(bin, &["daemon-reload"])?;
        // daemon-reload itself counts as changed per Ansible.
        changed = true;
    }

    // mask / unmask
    if op.has_masked != 0 {
        let want_masked = op.masked != 0;
        let cur = probe_is_enabled(&bin, name)?;
        let is_masked = cur == "masked";
        if want_masked && !is_masked {
            run_systemctl(bin, &["mask", name])?;
            changed = true;
        } else if !want_masked && is_masked {
            run_systemctl(bin, &["unmask", name])?;
            changed = true;
        }
    }

    // enable / disable
    if op.has_enabled != 0 {
        let want_enabled = op.enabled != 0;
        let cur = probe_is_enabled(&bin, name)?;
        // `enabled` and `enabled-runtime` both count as enabled.
        // `static` is enabled-by-presence-only; treat it as "no action
        // needed" — `systemctl enable` on a static unit is a no-op
        // anyway.
        let is_enabled = matches!(cur.as_str(), "enabled" | "enabled-runtime" | "alias" | "static");
        if want_enabled && !is_enabled {
            run_systemctl(bin, &["enable", name])?;
            changed = true;
        } else if !want_enabled && is_enabled && cur != "static" {
            run_systemctl(bin, &["disable", name])?;
            changed = true;
        }
    }

    // state
    match op.state {
        STATE_NONE => {}
        STATE_STARTED => {
            if !probe_is_active(&bin, name)? {
                let mut args = vec!["start"];
                if op.no_block != 0 {
                    args.insert(0, "--no-block");
                }
                args.push(name);
                run_systemctl(bin, &args)?;
                changed = true;
            }
        }
        STATE_STOPPED => {
            if probe_is_active(&bin, name)? {
                let mut args = vec!["stop"];
                if op.no_block != 0 {
                    args.insert(0, "--no-block");
                }
                args.push(name);
                run_systemctl(bin, &args)?;
                changed = true;
            }
        }
        STATE_RESTARTED => {
            let mut args = vec!["restart"];
            if op.no_block != 0 {
                args.insert(0, "--no-block");
            }
            args.push(name);
            run_systemctl(bin, &args)?;
            changed = true;
        }
        STATE_RELOADED => {
            run_systemctl(bin, &["reload", name])?;
            changed = true;
        }
        other => {
            return Err(SystemdError::BadRequest(format!(
                "systemd: unknown state byte {other}"
            )))
        }
    }

    Ok(changed)
}

/// Run `systemctl <args>`, returning the captured stdout on success or
/// SystemdError::Io on non-zero exit / stderr.
fn run_systemctl(bin: &str, args: &[&str]) -> Result<String, SystemdError> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| SystemdError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        return Err(SystemdError::Io(format!(
            "{bin} {args:?} failed ({:?}): stdout={stdout:?} stderr={stderr:?}",
            out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `systemctl is-active <unit>` — exits 0 + prints "active" when up.
/// Anything else (inactive, failed, activating) returns Ok(false).
fn probe_is_active(bin: &str, name: &str) -> Result<bool, SystemdError> {
    let out = Command::new(bin)
        .args(["is-active", name])
        .output()
        .map_err(|e| SystemdError::Spawn(format!("spawn {bin} is-active {name}: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout.trim() == "active")
}

/// `systemctl is-enabled <unit>` — returns the unit's enable state as a
/// string ("enabled", "disabled", "masked", "static", …). The exit
/// code carries the same info but the stdout string is more
/// informative; we use it.
fn probe_is_enabled(bin: &str, name: &str) -> Result<String, SystemdError> {
    let out = Command::new(bin)
        .args(["is-enabled", name])
        .output()
        .map_err(|e| SystemdError::Spawn(format!("spawn {bin} is-enabled {name}: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// Per-test stub directory + binary. Each test creates its own
    /// directory under /tmp; no shared env-var state, so tests can run
    /// in parallel.
    struct Stub {
        dir: PathBuf,
        bin: PathBuf,
    }

    impl Stub {
        fn new(label: &str, active: Option<&str>, enabled: Option<&str>) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-systemd-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(s) = active {
                std::fs::write(dir.join("ACTIVE"), s).unwrap();
            }
            if let Some(s) = enabled {
                std::fs::write(dir.join("ENABLED"), s).unwrap();
            }
            let bin = dir.join("systemctl");
            let script = format!(
                r#"#!/bin/sh
LOG="{log}"
ACTIVE_FILE="{active}"
ENABLED_FILE="{enabled}"
echo "$@" >> "$LOG"
case "$1" in
  is-active)
    if [ -f "$ACTIVE_FILE" ]; then cat "$ACTIVE_FILE"; else echo inactive; fi
    ;;
  is-enabled)
    if [ -f "$ENABLED_FILE" ]; then cat "$ENABLED_FILE"; else echo disabled; fi
    ;;
  *) ;;
esac
"#,
                log = dir.join("log").display(),
                active = dir.join("ACTIVE").display(),
                enabled = dir.join("ENABLED").display(),
            );
            // Use OpenOptions + write + sync_all rather than fs::write to
            // ensure the file descriptor is closed before we mark
            // executable + exec it. Without this, kernel sometimes
            // returns ETXTBSY ("Text file busy") on the subsequent
            // exec — flaky under parallel-test load.
            use std::io::Write as _;
            {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&bin)
                    .unwrap();
                f.write_all(script.as_bytes()).unwrap();
                f.sync_all().unwrap();
            }
            let mut perms = std::fs::metadata(&bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin, perms).unwrap();
            Stub { dir, bin }
        }

        fn path(&self) -> &Path {
            &self.bin
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn op(name: &str, state: u8) -> OpSystemdOutput {
        OpSystemdOutput {
            kind: 9,
            name: name.into(),
            state,
            has_enabled: 0,
            enabled: 0,
            has_masked: 0,
            masked: 0,
            daemon_reload: 0,
            no_block: 0,
        }
    }

    #[test]
    fn started_when_already_active_is_noop() {
        let stub = Stub::new("started-noop", Some("active\n"), None);
        let changed = apply(stub.path().to_str().unwrap(), &op("nginx.service", STATE_STARTED)).unwrap();
        assert!(!changed);
        let log = stub.log();
        assert!(log.contains("is-active nginx.service"), "log={log:?}");
        assert!(!log.contains("start "), "log={log:?}");
    }

    #[test]
    fn started_when_inactive_triggers_start() {
        let stub = Stub::new("started-go", None, None);
        let changed = apply(stub.path().to_str().unwrap(), &op("foo.service", STATE_STARTED)).unwrap();
        assert!(changed);
        let log = stub.log();
        assert!(log.contains("start foo.service"), "log={log:?}");
    }

    #[test]
    fn stopped_when_active_triggers_stop() {
        let stub = Stub::new("stopped-go", Some("active\n"), None);
        let changed = apply(stub.path().to_str().unwrap(), &op("foo.service", STATE_STOPPED)).unwrap();
        assert!(changed);
        let log = stub.log();
        assert!(log.contains("stop foo.service"), "log={log:?}");
    }

    #[test]
    fn stopped_when_already_inactive_is_noop() {
        let stub = Stub::new("stopped-noop", None, None);
        let changed = apply(stub.path().to_str().unwrap(), &op("foo.service", STATE_STOPPED)).unwrap();
        assert!(!changed);
        let log = stub.log();
        assert!(!log.contains("stop "), "log={log:?}");
    }

    #[test]
    fn restarted_always_runs_and_reports_changed() {
        let stub = Stub::new("restarted", Some("active\n"), None);
        let changed = apply(stub.path().to_str().unwrap(), &op("foo.service", STATE_RESTARTED)).unwrap();
        assert!(changed);
        let log = stub.log();
        assert!(log.contains("restart foo.service"), "log={log:?}");
    }

    #[test]
    fn enable_when_disabled_triggers_enable() {
        let stub = Stub::new("enable", None, None);
        let mut o = op("foo.service", STATE_NONE);
        o.has_enabled = 1;
        o.enabled = 1;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        let log = stub.log();
        assert!(log.contains("is-enabled foo.service"), "log={log:?}");
        assert!(log.contains("enable foo.service"), "log={log:?}");
    }

    #[test]
    fn enable_when_already_enabled_is_noop() {
        let stub = Stub::new("enable-noop", None, Some("enabled\n"));
        let mut o = op("foo.service", STATE_NONE);
        o.has_enabled = 1;
        o.enabled = 1;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(!changed);
        let log = stub.log();
        assert!(!log.contains("\nenable foo.service\n"), "log={log:?}");
    }

    #[test]
    fn daemon_reload_runs_first_then_start() {
        let stub = Stub::new("dr", None, None);
        let mut o = op("foo.service", STATE_STARTED);
        o.daemon_reload = 1;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        let log = stub.log();
        let dr_pos = log.find("daemon-reload").unwrap();
        let start_pos = log.find("start foo.service").unwrap();
        assert!(dr_pos < start_pos, "daemon-reload must come first: {log}");
    }

    #[test]
    fn no_block_inserted_before_subcommand() {
        let stub = Stub::new("noblock", None, None);
        let mut o = op("foo.service", STATE_STARTED);
        o.no_block = 1;
        let _ = apply(stub.path().to_str().unwrap(), &o).unwrap();
        let log = stub.log();
        assert!(
            log.contains("--no-block start foo.service"),
            "log={log:?}"
        );
    }

    #[test]
    fn mask_when_not_masked_triggers_mask() {
        let stub = Stub::new("mask", None, None);
        let mut o = op("foo.service", STATE_NONE);
        o.has_masked = 1;
        o.masked = 1;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        let log = stub.log();
        assert!(log.contains("mask foo.service"), "log={log:?}");
    }

    #[test]
    fn mask_when_already_masked_is_noop() {
        let stub = Stub::new("mask-noop", None, Some("masked\n"));
        let mut o = op("foo.service", STATE_NONE);
        o.has_masked = 1;
        o.masked = 1;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(!changed);
        let log = stub.log();
        assert!(!log.contains("\nmask foo.service\n"), "log={log:?}");
    }
}
