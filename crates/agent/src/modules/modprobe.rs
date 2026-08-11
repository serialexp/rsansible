//! `OpModprobe` — load or unload a Linux kernel module.
//!
//! Strategy: read `/proc/modules` → no-op if already in the desired
//! state → else shell out to `modprobe` (load) or `modprobe -r` (unload).
//!
//! Name normalisation matters here. The kernel reports module names with
//! underscores, but `modprobe` accepts either spelling and playbooks
//! write both — `kvm-amd` and `kvm_amd` are the same module. Comparing
//! the raw strings would make every `-`-spelled task report changed
//! forever and re-run `modprobe` on each play. We normalise both sides
//! before comparing.
//!
//! What this deliberately does NOT do:
//!
//! - **Reconcile `params` against an already-loaded module.** Parameters
//!   only apply at load time, and the only way to change them is to
//!   unload and reload. For the modules this exists to serve (kvm_amd,
//!   loop) that would yank the floor out from under a running VM or a
//!   mounted loop device. A loaded module is left alone.
//! - **Persist across reboots.** The controller rejects `persistent:` at
//!   parse time; write `/etc/modules-load.d/*.conf` explicitly.
//!
//! See ANSIBLE_COMPAT.md §13 for the full rationale.

use std::path::PathBuf;
use std::process::Command;

use rsansible_wire::generated::OpModprobeOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

/// Wire `state` bytes — mirrors `msg::modprobe_state`.
const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpModprobeOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    if op.name.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "modprobe: empty `name`").await;
        return Ok(());
    }
    if op.state != STATE_PRESENT && op.state != STATE_ABSENT {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            format!("modprobe: unknown state byte {}", op.state),
        )
        .await;
        return Ok(());
    }

    let result = tokio::task::spawn_blocking(move || apply(&op, check_mode))
        .await
        .map_err(|e| anyhow::anyhow!("modprobe join: {e}"))?;

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
        Err(ModprobeError::Io(m)) => emit_error(ctx, seq, err::IO, m).await,
        Err(ModprobeError::Spawn(m)) => emit_error(ctx, seq, err::SPAWN_FAILED, m).await,
    }
    Ok(())
}

/// Failure modes of [`apply`].
///
/// No `BadRequest` variant: the only malformed-input checks (empty
/// `name`, unknown `state` byte) happen in [`run`] before we get here, so
/// everything below is an environment failure rather than a caller error.
/// An unloadable or misspelled module surfaces as `Io` carrying
/// `modprobe`'s own stderr, which says more than we could.
#[derive(Debug)]
pub(crate) enum ModprobeError {
    Io(String),
    Spawn(String),
}

pub(crate) struct Bins {
    pub modprobe: String,
    pub proc_modules: PathBuf,
}

impl Bins {
    pub fn from_env() -> Self {
        Self {
            modprobe: std::env::var("RSANSIBLE_MODPROBE").unwrap_or_else(|_| "modprobe".into()),
            proc_modules: std::env::var_os("RSANSIBLE_PROC_MODULES")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/proc/modules")),
        }
    }
}

/// The kernel spells module names with underscores; `modprobe` accepts
/// hyphens and normalises them. Compare on the normalised form so
/// `kvm-amd` and `kvm_amd` are recognised as the same module.
fn normalize(name: &str) -> String {
    name.trim().replace('-', "_")
}

pub(crate) fn apply(op: &OpModprobeOutput, check_mode: bool) -> Result<bool, ModprobeError> {
    apply_with_bins(&Bins::from_env(), op, check_mode)
}

pub(crate) fn apply_with_bins(
    bins: &Bins,
    op: &OpModprobeOutput,
    check_mode: bool,
) -> Result<bool, ModprobeError> {
    let loaded = is_loaded(bins, &op.name)?;
    let want_loaded = op.state == STATE_PRESENT;
    if loaded == want_loaded {
        return Ok(false);
    }
    if check_mode {
        return Ok(true);
    }
    if want_loaded {
        load(bins, &op.name, &op.params)?;
    } else {
        unload(bins, &op.name)?;
    }
    Ok(true)
}

/// Whether `name` appears in `/proc/modules`.
///
/// Each line is `name size refcount deps state offset`; we only need the
/// first field.
fn is_loaded(bins: &Bins, name: &str) -> Result<bool, ModprobeError> {
    let want = normalize(name);
    let contents = std::fs::read_to_string(&bins.proc_modules)
        .map_err(|e| ModprobeError::Io(format!("read {}: {e}", bins.proc_modules.display())))?;
    Ok(contents
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|m| normalize(m) == want))
}

fn load(bins: &Bins, name: &str, params: &str) -> Result<(), ModprobeError> {
    let mut cmd = Command::new(&bins.modprobe);
    cmd.arg(name);
    // Parameters are space-separated `key=value` tokens; pass each as its
    // own argv entry so we never hand a shell anything to re-split.
    for p in params.split_whitespace() {
        cmd.arg(p);
    }
    let out = cmd
        .output()
        .map_err(|e| ModprobeError::Spawn(format!("spawn {}: {e}", bins.modprobe)))?;
    if !out.status.success() {
        return Err(ModprobeError::Io(format!(
            "{} {name}: exit {:?} stderr={:?}",
            bins.modprobe,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn unload(bins: &Bins, name: &str) -> Result<(), ModprobeError> {
    let out = Command::new(&bins.modprobe)
        .args(["-r", name])
        .output()
        .map_err(|e| ModprobeError::Spawn(format!("spawn {}: {e}", bins.modprobe)))?;
    if !out.status.success() {
        // The common failure is "Module ... is in use" — surface the
        // kernel's own words rather than a generic exit code, because
        // that's the difference between "typo" and "something is
        // actively using this".
        return Err(ModprobeError::Io(format!(
            "{} -r {name}: exit {:?} stderr={:?}",
            bins.modprobe,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
        /// `loaded` seeds the synthetic /proc/modules. The stub
        /// `modprobe` appends its argv to a log and mutates that file so
        /// idempotency can be observed across calls.
        fn new(label: &str, loaded: &[&str]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-modprobe-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let proc_modules = dir.join("modules");
            let body: String = loaded
                .iter()
                .map(|m| format!("{m} 16384 0 - Live 0x0000000000000000\n"))
                .collect();
            std::fs::write(&proc_modules, body).unwrap();
            let log = dir.join("log");
            std::fs::write(&log, "").unwrap();

            let mp = dir.join("modprobe");
            let script = format!(
                r#"#!/bin/sh
LOG="{log}"
MODS="{mods}"
echo "modprobe $*" >> "$LOG"
if [ "$1" = "-r" ]; then
  grep -v "^$2 " "$MODS" > "$MODS.tmp" || true
  mv "$MODS.tmp" "$MODS"
else
  echo "$1 16384 0 - Live 0x0000000000000000" >> "$MODS"
fi
exit 0
"#,
                log = log.display(),
                mods = proc_modules.display()
            );
            std::fs::write(&mp, script).unwrap();
            let mut perms = std::fs::metadata(&mp).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&mp, perms).unwrap();

            let bins = Bins {
                modprobe: mp.to_string_lossy().into_owned(),
                proc_modules,
            };
            Stub { dir, bins }
        }
        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }
        fn modules(&self) -> String {
            std::fs::read_to_string(&self.bins.proc_modules).unwrap_or_default()
        }
    }

    fn op(name: &str, state: u8, params: &str) -> OpModprobeOutput {
        OpModprobeOutput {
            kind: 29,
            name: name.into(),
            state,
            params: params.into(),
        }
    }

    #[test]
    fn noop_when_already_loaded() {
        let stub = Stub::new("noop", &["kvm_amd", "loop"]);
        let changed =
            apply_with_bins(&stub.bins, &op("kvm_amd", STATE_PRESENT, ""), false).unwrap();
        assert!(!changed);
        assert!(
            stub.log().is_empty(),
            "modprobe must not run: {:?}",
            stub.log()
        );
    }

    /// The bug this normalisation exists to prevent: `kvm-amd` in the
    /// playbook vs `kvm_amd` in /proc/modules would otherwise report
    /// changed on every single run.
    #[test]
    fn noop_across_hyphen_underscore_spelling() {
        let stub = Stub::new("dash", &["kvm_amd"]);
        let changed =
            apply_with_bins(&stub.bins, &op("kvm-amd", STATE_PRESENT, ""), false).unwrap();
        assert!(!changed, "kvm-amd and kvm_amd are the same module");
        assert!(stub.log().is_empty());
    }

    #[test]
    fn loads_when_absent() {
        let stub = Stub::new("load", &["loop"]);
        let changed =
            apply_with_bins(&stub.bins, &op("kvm_amd", STATE_PRESENT, ""), false).unwrap();
        assert!(changed);
        assert!(
            stub.log().contains("modprobe kvm_amd"),
            "log: {:?}",
            stub.log()
        );
        // And a second run is a no-op — real idempotency, not just a flag.
        let changed =
            apply_with_bins(&stub.bins, &op("kvm_amd", STATE_PRESENT, ""), false).unwrap();
        assert!(!changed, "second apply must be a no-op");
    }

    #[test]
    fn passes_params_as_separate_args() {
        let stub = Stub::new("params", &[]);
        let changed = apply_with_bins(
            &stub.bins,
            &op(
                "nf_conntrack",
                STATE_PRESENT,
                "nf_conntrack_max=65536 hashsize=8192",
            ),
            false,
        )
        .unwrap();
        assert!(changed);
        assert!(
            stub.log()
                .contains("modprobe nf_conntrack nf_conntrack_max=65536 hashsize=8192"),
            "log: {:?}",
            stub.log()
        );
    }

    #[test]
    fn unloads_when_present() {
        let stub = Stub::new("unload", &["loop", "kvm_amd"]);
        let changed = apply_with_bins(&stub.bins, &op("loop", STATE_ABSENT, ""), false).unwrap();
        assert!(changed);
        assert!(
            stub.log().contains("modprobe -r loop"),
            "log: {:?}",
            stub.log()
        );
        assert!(
            !stub.modules().contains("loop "),
            "modules: {:?}",
            stub.modules()
        );
    }

    #[test]
    fn noop_when_already_absent() {
        let stub = Stub::new("gone", &["kvm_amd"]);
        let changed = apply_with_bins(&stub.bins, &op("loop", STATE_ABSENT, ""), false).unwrap();
        assert!(!changed);
        assert!(stub.log().is_empty());
    }

    #[test]
    fn check_mode_reports_without_running() {
        let stub = Stub::new("check", &[]);
        let changed = apply_with_bins(&stub.bins, &op("kvm_amd", STATE_PRESENT, ""), true).unwrap();
        assert!(changed);
        assert!(stub.log().is_empty(), "check mode must not shell out");
        assert!(!stub.modules().contains("kvm_amd"));
    }

    /// A substring match would call `loop` loaded when only `loopback`
    /// is — /proc/modules is field-delimited, so parse it that way.
    #[test]
    fn does_not_substring_match_other_modules() {
        let stub = Stub::new("substr", &["loopback_target"]);
        let changed = apply_with_bins(&stub.bins, &op("loop", STATE_PRESENT, ""), false).unwrap();
        assert!(changed, "loopback_target must not satisfy `loop`");
        assert!(stub.log().contains("modprobe loop"));
    }

    #[test]
    fn surfaces_modprobe_failure() {
        let stub = Stub::new("fail", &[]);
        // Point at a binary that doesn't exist -> spawn error.
        let bins = Bins {
            modprobe: stub.dir.join("nope").to_string_lossy().into_owned(),
            proc_modules: stub.bins.proc_modules.clone(),
        };
        let err = apply_with_bins(&bins, &op("kvm_amd", STATE_PRESENT, ""), false).unwrap_err();
        assert!(matches!(err, ModprobeError::Spawn(_)), "got: {err:?}");
    }
}
