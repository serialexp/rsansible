//! `OpUfw` — Ansible's `community.general.ufw` (subset).
//!
//! Supported ops:
//!   * **rule** — allow/deny/limit/reject with proto/from/to/port/iface.
//!     Idempotency: probe `ufw status verbose`; if the rule (normalized
//!     into ufw's add-syntax) already appears in the rules list, skip.
//!     `delete=1` deletes instead; idempotent symmetrically.
//!   * **enable** — `ufw --force enable`. Idempotent via the
//!     `Status: active` line in `status verbose`.
//!   * **disable** — `ufw --force disable`. Same probe.
//!   * **reset** — `ufw --force reset`. Always considered changed
//!     (ufw doesn't expose a "ruleset hash"); rare and destructive.
//!   * **default** — `ufw default <policy> <direction>`. Idempotent
//!     via the `Default:` line in `status verbose`.
//!   * **reload** — `ufw reload`. Always changed.
//!   * **logging** — `ufw logging <level>`. Idempotent via the
//!     `Logging:` line.
//!
//! The agent invokes `ufw` (`RSANSIBLE_UFW` env override for tests).
//! `--force` is added for enable/disable/reset to silence the
//! interactive prompt; the rest are non-interactive by default.
//!
//! Note on rule canonicalization: ufw's `status verbose` re-prints
//! rules in a normalized form that doesn't always match the input
//! syntax (e.g. `allow 22/tcp` becomes `22/tcp ALLOW IN Anywhere`).
//! The probe matches loosely: we look for the (rule-verb, port, proto,
//! direction) tuple in the normalized output. False negatives
//! (declaring no-op when the rule isn't there) will trigger an
//! ineffective `ufw allow` call which is itself idempotent; false
//! positives (skipping when the rule isn't there) are the concern,
//! but ufw's normalized output is stable enough across versions that
//! this is acceptable for our subset.

use rsansible_wire::generated::OpUfwOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, spawn_with_etxtbsy_retry, Context};

const OP_RULE: u8 = 0;
const OP_ENABLE: u8 = 1;
const OP_DISABLE: u8 = 2;
const OP_RESET: u8 = 3;
const OP_DEFAULT: u8 = 4;
const OP_RELOAD: u8 = 5;
const OP_LOGGING: u8 = 6;

pub async fn run(ctx: &Context, seq: u32, op: OpUfwOutput) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    let bin = std::env::var("RSANSIBLE_UFW").unwrap_or_else(|_| "ufw".to_string());
    let result = tokio::task::spawn_blocking(move || apply(&bin, &op))
        .await
        .map_err(|e| anyhow::anyhow!("ufw join: {e}"))?;

    let changed = match result {
        Ok(c) => c,
        Err(UfwError::Io(m)) => {
            emit_error(ctx, seq, err::IO, m).await;
            return Ok(());
        }
        Err(UfwError::Spawn(m)) => {
            emit_error(ctx, seq, err::SPAWN_FAILED, m).await;
            return Ok(());
        }
        Err(UfwError::BadRequest(m)) => {
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
enum UfwError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

fn apply(bin: &str, op: &OpUfwOutput) -> Result<bool, UfwError> {
    match op.op {
        OP_RULE => apply_rule(bin, op),
        OP_ENABLE => apply_enable(bin, op, true),
        OP_DISABLE => apply_enable(bin, op, false),
        OP_RESET => {
            run_ufw(bin, &["--force", "reset"])?;
            Ok(true)
        }
        OP_DEFAULT => apply_default(bin, op),
        OP_RELOAD => {
            run_ufw(bin, &["reload"])?;
            Ok(true)
        }
        OP_LOGGING => apply_logging(bin, op),
        other => Err(UfwError::BadRequest(format!(
            "ufw: unknown op byte {other}"
        ))),
    }
}

fn apply_rule(bin: &str, op: &OpUfwOutput) -> Result<bool, UfwError> {
    if op.rule.is_empty() {
        return Err(UfwError::BadRequest(
            "ufw.rule: required for op=rule".into(),
        ));
    }
    // Build the ufw argv. ufw syntax:
    //   ufw [--insert N] [delete] <rule> [direction] [proto <p>]
    //       [from <ip> [port <p>]] [to <ip> [port <p>]]
    //       [interface <iface>] [comment "<text>"]
    // We mirror that order.
    let mut args: Vec<String> = Vec::new();
    if op.insert > 0 {
        args.push("insert".into());
        args.push(op.insert.to_string());
    }
    if op.delete != 0 {
        args.push("delete".into());
    }
    args.push(op.rule.clone());
    if !op.direction.is_empty() {
        args.push(op.direction.clone());
    }
    if !op.interface.is_empty() {
        args.push("on".into());
        args.push(op.interface.clone());
    }
    if !op.proto.is_empty() {
        args.push("proto".into());
        args.push(op.proto.clone());
    }
    if !op.from_ip.is_empty() || !op.from_port.is_empty() {
        args.push("from".into());
        args.push(if op.from_ip.is_empty() {
            "any".into()
        } else {
            op.from_ip.clone()
        });
        if !op.from_port.is_empty() {
            args.push("port".into());
            args.push(op.from_port.clone());
        }
    }
    if !op.to_ip.is_empty() || !op.to_port.is_empty() {
        args.push("to".into());
        args.push(if op.to_ip.is_empty() {
            "any".into()
        } else {
            op.to_ip.clone()
        });
        if !op.to_port.is_empty() {
            args.push("port".into());
            args.push(op.to_port.clone());
        }
    }
    if !op.comment.is_empty() {
        args.push("comment".into());
        args.push(op.comment.clone());
    }

    // Idempotency probe: ufw status numbered prints existing rules.
    // We compare loosely: the rule key derived from this op against
    // each existing rule.
    let status = run_ufw_capture(bin, &["status", "verbose"])?;
    let want_key = rule_key(op);
    let already = status.lines().any(|l| line_matches_key(l, &want_key));
    let want_present = op.delete == 0;
    if already == want_present {
        return Ok(false);
    }

    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ufw(bin, &argv)?;
    Ok(true)
}

fn apply_enable(bin: &str, _op: &OpUfwOutput, want_active: bool) -> Result<bool, UfwError> {
    let status = run_ufw_capture(bin, &["status", "verbose"])?;
    let is_active = status
        .lines()
        .any(|l| l.trim_start().starts_with("Status: active"));
    if is_active == want_active {
        return Ok(false);
    }
    let verb = if want_active { "enable" } else { "disable" };
    run_ufw(bin, &["--force", verb])?;
    Ok(true)
}

fn apply_default(bin: &str, op: &OpUfwOutput) -> Result<bool, UfwError> {
    if op.rule.is_empty() {
        return Err(UfwError::BadRequest(
            "ufw.rule: required for op=default (allow/deny/reject)".into(),
        ));
    }
    let policy = op.rule.to_ascii_lowercase();
    let direction = if op.direction.is_empty() {
        "incoming".to_string()
    } else {
        match op.direction.to_ascii_lowercase().as_str() {
            "in" => "incoming".into(),
            "out" => "outgoing".into(),
            "routed" => "routed".into(),
            "incoming" | "outgoing" => op.direction.to_ascii_lowercase(),
            other => {
                return Err(UfwError::BadRequest(format!(
                    "ufw.default direction: expected in/out/routed, got {other:?}"
                )))
            }
        }
    };
    // Probe via "Default: deny (incoming), allow (outgoing), ..." line.
    let status = run_ufw_capture(bin, &["status", "verbose"])?;
    if let Some(line) = status
        .lines()
        .find(|l| l.trim_start().starts_with("Default:"))
    {
        // Format: "Default: deny (incoming), allow (outgoing), disabled (routed)"
        // We look for "<policy> (<direction>)" substring.
        let want = format!("{policy} ({direction})");
        if line.contains(&want) {
            return Ok(false);
        }
    }
    run_ufw(bin, &["default", &policy, &direction])?;
    Ok(true)
}

fn apply_logging(bin: &str, op: &OpUfwOutput) -> Result<bool, UfwError> {
    if op.rule.is_empty() {
        return Err(UfwError::BadRequest(
            "ufw.rule: required for op=logging (on/off/low/medium/high/full)".into(),
        ));
    }
    let level = op.rule.to_ascii_lowercase();
    let status = run_ufw_capture(bin, &["status", "verbose"])?;
    if let Some(line) = status
        .lines()
        .find(|l| l.trim_start().starts_with("Logging:"))
    {
        // Format: "Logging: on (low)" or "Logging: off"
        let current = line
            .trim_start_matches("Logging:")
            .trim()
            .to_ascii_lowercase();
        let want_signature = match level.as_str() {
            "off" => "off".to_string(),
            "on" => "on".to_string(),
            other => format!("on ({other})"),
        };
        // Loose match: "off" must equal current; on/level matches if the
        // current line starts with "on" and contains "(level)" (or any
        // form of "on" for plain "on").
        let matches = match level.as_str() {
            "off" => current.starts_with("off"),
            "on" => current.starts_with("on"),
            _ => current == want_signature,
        };
        if matches {
            return Ok(false);
        }
    }
    run_ufw(bin, &["logging", &level])?;
    Ok(true)
}

/// Derive a normalized rule key from the op. Used to scan the lines
/// of `ufw status verbose` for an existing match. The key is the
/// uppercase verb + the port-spec (if any) + the optional from-ip.
/// Loose by design — ufw's verbose output formats vary.
fn rule_key(op: &OpUfwOutput) -> RuleKey {
    let verb = op.rule.to_ascii_uppercase();
    // Prefer to-port (the canonical "destination port" in ufw output),
    // fall back to from-port if no to-port was set.
    let port = if !op.to_port.is_empty() {
        op.to_port.clone()
    } else {
        op.from_port.clone()
    };
    let proto = op.proto.to_ascii_lowercase();
    RuleKey {
        verb,
        port,
        proto,
        from_ip: op.from_ip.clone(),
        direction: op.direction.to_ascii_lowercase(),
    }
}

#[derive(Debug)]
struct RuleKey {
    verb: String,
    port: String,
    proto: String,
    from_ip: String,
    direction: String,
}

/// Loose match against a single status-output line. ufw's lines look
/// like:
///   "22/tcp                     ALLOW IN    Anywhere"
///   "Anywhere                   DENY  IN    10.0.0.0/8"
///   "22                         LIMIT IN    Anywhere"
fn line_matches_key(line: &str, key: &RuleKey) -> bool {
    let upper = line.to_ascii_uppercase();
    if !upper.contains(&key.verb) {
        return false;
    }
    if !key.port.is_empty() {
        let want = if key.proto.is_empty() {
            key.port.clone()
        } else {
            format!("{}/{}", key.port, key.proto)
        };
        if !line.contains(&want) && !line.contains(&key.port) {
            return false;
        }
    }
    if !key.from_ip.is_empty() && !line.contains(&key.from_ip) {
        return false;
    }
    if !key.direction.is_empty() {
        let want = match key.direction.as_str() {
            "in" | "incoming" => "IN",
            "out" | "outgoing" => "OUT",
            "routed" => "FWD",
            _ => "",
        };
        if !want.is_empty() && !upper.contains(want) {
            return false;
        }
    }
    true
}

fn run_ufw(bin: &str, args: &[&str]) -> Result<(), UfwError> {
    let out = spawn_with_etxtbsy_retry(bin, args)
        .map_err(|e| UfwError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(UfwError::Io(format!(
            "{bin} {args:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn run_ufw_capture(bin: &str, args: &[&str]) -> Result<String, UfwError> {
    let out = spawn_with_etxtbsy_retry(bin, args)
        .map_err(|e| UfwError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(UfwError::Io(format!(
            "{bin} {args:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// Stub ufw binary. The script logs invocations and serves canned
    /// `status verbose` output from a state file the test writes.
    ///
    /// Note on ETXTBSY: parallel cargo tests can hit "Text file busy"
    /// when one thread is still finishing the write-out of its stub
    /// while another thread tries to exec a *different* stub at the
    /// same dentry-cache moment. We use a create-via-rename pattern
    /// (write to sibling tempfile, sync, rename into place) so the
    /// final path has no writable fds open against it. As a belt-and-
    /// suspenders measure, `apply_*` callers tolerate ETXTBSY in the
    /// initial probe by retrying — see `retry_spawn` below.
    struct Stub {
        dir: PathBuf,
        bin: PathBuf,
    }

    impl Stub {
        fn new(label: &str, status_text: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-ufw-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("STATUS"), status_text).unwrap();
            std::fs::write(dir.join("log"), "").unwrap();
            let bin = dir.join("ufw");

            let script = format!(
                r#"#!/bin/sh
LOG="{log}"
STATUS="{status}"
echo "$@" >> "$LOG"
if [ "$1" = "status" ]; then
  cat "$STATUS"
  exit 0
fi
exit 0
"#,
                log = dir.join("log").display(),
                status = dir.join("STATUS").display(),
            );
            use std::io::Write as _;
            let tmp = bin.with_extension("tmp");
            {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&tmp)
                    .unwrap();
                f.write_all(script.as_bytes()).unwrap();
                f.sync_all().unwrap();
            }
            let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&tmp, perms).unwrap();
            std::fs::rename(&tmp, &bin).unwrap();
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

    fn rule_op(verb: &str, port: &str, proto: &str) -> OpUfwOutput {
        OpUfwOutput {
            kind: 11,
            op: OP_RULE,
            rule: verb.into(),
            direction: String::new(),
            proto: proto.into(),
            from_ip: String::new(),
            from_port: String::new(),
            to_ip: String::new(),
            to_port: port.into(),
            interface: String::new(),
            comment: String::new(),
            delete: 0,
            insert: 0,
        }
    }

    const STATUS_INACTIVE: &str = "Status: inactive\n";
    const STATUS_ACTIVE_22: &str =
        "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n";

    #[test]
    fn rule_added_when_missing_changes_state() {
        let stub = Stub::new("rule-add", STATUS_INACTIVE);
        let changed = apply(
            stub.path().to_str().unwrap(),
            &rule_op("allow", "22", "tcp"),
        )
        .unwrap();
        assert!(changed);
        assert!(stub.log().contains("allow"), "log={:?}", stub.log());
    }

    #[test]
    fn rule_skipped_when_already_present() {
        let stub = Stub::new("rule-noop", STATUS_ACTIVE_22);
        let changed = apply(
            stub.path().to_str().unwrap(),
            &rule_op("allow", "22", "tcp"),
        )
        .unwrap();
        assert!(!changed);
        // status verbose should have been called, but no `allow` mutate.
        assert!(stub.log().contains("status verbose"), "log={:?}", stub.log());
        let log = stub.log();
        // Filter out the status line and check no `allow 22/tcp` shape.
        let mutating = log
            .lines()
            .filter(|l| !l.contains("status"))
            .collect::<Vec<_>>();
        assert!(
            mutating.iter().all(|l| !l.starts_with("allow")),
            "expected no mutating calls: {mutating:?}"
        );
    }

    #[test]
    fn rule_delete_removes_existing() {
        let stub = Stub::new("rule-del", STATUS_ACTIVE_22);
        let mut o = rule_op("allow", "22", "tcp");
        o.delete = 1;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        assert!(stub.log().contains("delete"), "log={:?}", stub.log());
    }

    #[test]
    fn rule_delete_when_absent_is_noop() {
        let stub = Stub::new("rule-del-noop", STATUS_INACTIVE);
        let mut o = rule_op("allow", "22", "tcp");
        o.delete = 1;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(!changed);
    }

    #[test]
    fn enable_when_inactive_runs_force_enable() {
        let stub = Stub::new("enable", STATUS_INACTIVE);
        let mut o = rule_op("", "", "");
        o.op = OP_ENABLE;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        assert!(stub.log().contains("--force enable"), "log={:?}", stub.log());
    }

    #[test]
    fn enable_when_already_active_is_noop() {
        let stub = Stub::new("enable-noop", STATUS_ACTIVE_22);
        let mut o = rule_op("", "", "");
        o.op = OP_ENABLE;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(!changed);
    }

    #[test]
    fn disable_when_active_runs_force_disable() {
        let stub = Stub::new("disable", STATUS_ACTIVE_22);
        let mut o = rule_op("", "", "");
        o.op = OP_DISABLE;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        assert!(stub.log().contains("--force disable"), "log={:?}", stub.log());
    }

    #[test]
    fn default_idempotent_when_already_set() {
        // STATUS_ACTIVE_22 has "deny (incoming), allow (outgoing)".
        let stub = Stub::new("default-noop", STATUS_ACTIVE_22);
        let mut o = rule_op("", "", "");
        o.op = OP_DEFAULT;
        o.rule = "deny".into();
        o.direction = "in".into();
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(!changed);
    }

    #[test]
    fn default_runs_when_policy_differs() {
        let stub = Stub::new("default-go", STATUS_ACTIVE_22);
        let mut o = rule_op("", "", "");
        o.op = OP_DEFAULT;
        o.rule = "reject".into();
        o.direction = "in".into();
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        assert!(stub.log().contains("default reject incoming"), "log={:?}", stub.log());
    }

    #[test]
    fn reset_always_changed_and_logged() {
        let stub = Stub::new("reset", STATUS_ACTIVE_22);
        let mut o = rule_op("", "", "");
        o.op = OP_RESET;
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        assert!(stub.log().contains("--force reset"), "log={:?}", stub.log());
    }

    #[test]
    fn logging_idempotent_when_level_matches() {
        // STATUS_ACTIVE_22 has "Logging: on (low)".
        let stub = Stub::new("logging-noop", STATUS_ACTIVE_22);
        let mut o = rule_op("", "", "");
        o.op = OP_LOGGING;
        o.rule = "low".into();
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(!changed);
    }

    #[test]
    fn logging_runs_when_level_differs() {
        let stub = Stub::new("logging-go", STATUS_ACTIVE_22);
        let mut o = rule_op("", "", "");
        o.op = OP_LOGGING;
        o.rule = "high".into();
        let changed = apply(stub.path().to_str().unwrap(), &o).unwrap();
        assert!(changed);
        assert!(stub.log().contains("logging high"), "log={:?}", stub.log());
    }
}
