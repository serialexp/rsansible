//! `OpIptables` — Ansible's `ansible.builtin.iptables` (subset).
//!
//! Manages a single iptables (or ip6tables) rule, identified by the
//! tuple of chain + table + match args. Idempotency comes from
//! `iptables -C`: we ask the kernel "would this rule match an
//! existing entry?" before doing anything. If `-C` exits 0 the rule
//! is already in the requested state (present), if it exits 1 the
//! rule is absent. Any other exit code is an iptables error and
//! propagates as `TaskError`.
//!
//! Argv construction order follows what `iptables -L` would print:
//! `-t <table> -A/I/D/C <chain> [-p <proto>] [-s <src>] [-d <dst>]
//! [--sport <p>] [--dport <p>] [-i <if>] [-o <if>]
//! [-m conntrack --ctstate <s>] [-m comment --comment "<text>"]
//! -j <target>`. Empty string knobs are omitted (no flag emitted).
//!
//! The agent does NOT do any sudo wrapping here — the caller is
//! expected to be running as a user with iptables permissions. In
//! rsansible's case that's the `BecomeKey::As("root")` agent slot,
//! spawned by the controller's per-host pool.
//!
//! Envelope on success: the `iptables -A/-I/-D` invocation's stdout
//! (usually empty) is included for diagnostics; `changed` is 0 when
//! `-C` reported the rule was already in the requested state.

use rsansible_wire::generated::OpIptablesOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, spawn_with_etxtbsy_retry, Context};

const ACTION_APPEND: u8 = 0;
const ACTION_INSERT: u8 = 1;

const STATE_ABSENT: u8 = 0;
const STATE_PRESENT: u8 = 1;

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpIptablesOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    let bin = pick_binary(&op);
    let result =
        tokio::task::spawn_blocking(move || apply(&bin, &op, check_mode))
            .await
            .map_err(|e| anyhow::anyhow!("iptables join: {e}"))?;

    let changed = match result {
        Ok(c) => c,
        Err(IptablesError::BadRequest(m)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, m).await;
            return Ok(());
        }
        Err(IptablesError::Spawn(m)) => {
            emit_error(ctx, seq, err::SPAWN_FAILED, m).await;
            return Ok(());
        }
        Err(IptablesError::Io(m)) => {
            emit_error(ctx, seq, err::IO, m).await;
            return Ok(());
        }
    };

    let finished = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        changed,
        false,
        started_unix_ns,
        finished,
    ))
    .await;
    Ok(())
}

#[derive(Debug)]
enum IptablesError {
    /// Malformed input — operator bug, not a runtime condition.
    BadRequest(String),
    /// Couldn't spawn the iptables binary at all.
    Spawn(String),
    /// iptables ran but exited non-zero in a way that wasn't "rule
    /// not found" — e.g. malformed args the agent built, kernel
    /// permission denied, table doesn't exist.
    Io(String),
}

fn pick_binary(op: &OpIptablesOutput) -> String {
    // `RSANSIBLE_IPTABLES` / `RSANSIBLE_IP6TABLES` override the binary
    // path so unit tests can swap in a stub without touching $PATH.
    match op.ip_version {
        6 => std::env::var("RSANSIBLE_IP6TABLES").unwrap_or_else(|_| "ip6tables".into()),
        // ip_version=0 is treated as the default (IPv4). The schema
        // doc says 4 or 6, but accepting 0 keeps "field unset" → "use
        // default" working at the wire layer.
        _ => std::env::var("RSANSIBLE_IPTABLES").unwrap_or_else(|_| "iptables".into()),
    }
}

fn apply(bin: &str, op: &OpIptablesOutput, check_mode: bool) -> Result<bool, IptablesError> {
    if op.chain.is_empty() {
        return Err(IptablesError::BadRequest("iptables.chain: required".into()));
    }
    let action = match op.action {
        ACTION_APPEND => 'A',
        ACTION_INSERT => 'I',
        other => {
            return Err(IptablesError::BadRequest(format!(
                "iptables.action: expected 0 (append) or 1 (insert), got {other}"
            )))
        }
    };
    let want_present = match op.rule_state {
        STATE_ABSENT => false,
        STATE_PRESENT => true,
        other => {
            return Err(IptablesError::BadRequest(format!(
                "iptables.rule_state: expected 0 (absent) or 1 (present), got {other}"
            )))
        }
    };

    // Idempotency probe: -C exits 0 if a matching rule exists, 1 if
    // not. Any other exit is treated as a real iptables error.
    let probe_args = build_rule_argv(op, 'C')?;
    let exists = run_check(bin, &probe_args)?;
    if exists == want_present {
        return Ok(false);
    }
    if check_mode {
        // Would change but didn't — Ansible treats this as changed=1
        // under --check, but our `changed` here is the modify-actually-
        // happened flag. The orchestrator overlays check-mode semantics
        // upstream; here we just report what we did.
        return Ok(true);
    }

    // Apply the change. For state=present we honor `action` (A/I); for
    // state=absent we always use D.
    let verb = if want_present { action } else { 'D' };
    let mutate_args = build_rule_argv(op, verb)?;
    run_mutate(bin, &mutate_args)?;
    Ok(true)
}

/// Build the argv list for `iptables -<verb> <chain> ...`. Empty
/// string knobs are skipped — `-p ""` would be a hard iptables error.
fn build_rule_argv(op: &OpIptablesOutput, verb: char) -> Result<Vec<String>, IptablesError> {
    let mut args: Vec<String> = Vec::new();
    // `-t <table>` MUST come before `-<verb>` per iptables's argv
    // parser. Empty table → don't pass `-t`; iptables defaults to filter.
    if !op.table.is_empty() {
        args.push("-t".into());
        args.push(op.table.clone());
    }
    args.push(format!("-{verb}"));
    args.push(op.chain.clone());
    if !op.protocol.is_empty() {
        args.push("-p".into());
        args.push(op.protocol.clone());
    }
    if !op.source.is_empty() {
        args.push("-s".into());
        args.push(op.source.clone());
    }
    if !op.destination.is_empty() {
        args.push("-d".into());
        args.push(op.destination.clone());
    }
    if !op.in_interface.is_empty() {
        args.push("-i".into());
        args.push(op.in_interface.clone());
    }
    if !op.out_interface.is_empty() {
        args.push("-o".into());
        args.push(op.out_interface.clone());
    }
    // Port matches require `-p <proto>` to be in effect — iptables's
    // `--sport` / `--dport` are module extensions of tcp/udp/sctp/etc.
    // Reject the ambiguous case here rather than surfacing iptables's
    // less-friendly error.
    if (!op.source_port.is_empty() || !op.destination_port.is_empty()) && op.protocol.is_empty() {
        return Err(IptablesError::BadRequest(
            "iptables: source_port/destination_port require protocol (tcp/udp/sctp)".into(),
        ));
    }
    if !op.source_port.is_empty() {
        args.push("--sport".into());
        args.push(op.source_port.clone());
    }
    if !op.destination_port.is_empty() {
        args.push("--dport".into());
        args.push(op.destination_port.clone());
    }
    if !op.ctstate.is_empty() {
        args.push("-m".into());
        args.push("conntrack".into());
        args.push("--ctstate".into());
        args.push(op.ctstate.clone());
    }
    if !op.comment.is_empty() {
        args.push("-m".into());
        args.push("comment".into());
        args.push("--comment".into());
        args.push(op.comment.clone());
    }
    if !op.jump.is_empty() {
        args.push("-j".into());
        args.push(op.jump.clone());
    }
    Ok(args)
}

/// Run `iptables -C` and translate exit code into a bool:
///   exit 0 → rule exists
///   exit 1 → rule absent (the documented "no match" exit)
///   anything else → propagate as Io error
fn run_check(bin: &str, args: &[String]) -> Result<bool, IptablesError> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = spawn_with_etxtbsy_retry(bin, &argv)
        .map_err(|e| IptablesError::Spawn(format!("spawn {bin} {argv:?}: {e}")))?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(other) => Err(IptablesError::Io(format!(
            "{bin} {argv:?} probe exited {other}: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        ))),
        None => Err(IptablesError::Io(format!(
            "{bin} {argv:?} probe terminated by signal: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        ))),
    }
}

fn run_mutate(bin: &str, args: &[String]) -> Result<(), IptablesError> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = spawn_with_etxtbsy_retry(bin, &argv)
        .map_err(|e| IptablesError::Spawn(format!("spawn {bin} {argv:?}: {e}")))?;
    if !out.status.success() {
        return Err(IptablesError::Io(format!(
            "{bin} {argv:?} failed ({:?}): stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Stub iptables binary. The script records every invocation to
    /// a log file the test can inspect; the probe exit code is read
    /// from a `PROBE_EXIT` file so each test can simulate "rule
    /// already exists" (0) vs. "rule absent" (1).
    struct Stub {
        dir: PathBuf,
        bin: PathBuf,
    }

    impl Stub {
        fn new(label: &str, probe_exit: i32) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-iptables-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("PROBE_EXIT"), probe_exit.to_string()).unwrap();
            std::fs::write(dir.join("log"), "").unwrap();
            let bin = dir.join("iptables");
            let script = format!(
                r#"#!/bin/sh
LOG="{log}"
PROBE_EXIT="{probe_exit}"
# Log the full argv, one invocation per line.
printf '%s\n' "$*" >> "$LOG"
# Detect a probe call (-C anywhere in the argv).
for a in "$@"; do
  if [ "$a" = "-C" ]; then
    exit "$(cat "$PROBE_EXIT")"
  fi
done
exit 0
"#,
                log = dir.join("log").display(),
                probe_exit = dir.join("PROBE_EXIT").display(),
            );
            use std::io::Write as _;
            let tmp = bin.with_extension("tmp");
            {
                let mut f = std::fs::File::create(&tmp).unwrap();
                f.write_all(script.as_bytes()).unwrap();
                f.sync_all().unwrap();
            }
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(&tmp, &bin).unwrap();
            Self { dir, bin }
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }

        fn set_probe_exit(&self, code: i32) {
            std::fs::write(self.dir.join("PROBE_EXIT"), code.to_string()).unwrap();
        }
    }

    fn base_op() -> OpIptablesOutput {
        OpIptablesOutput {
            kind: 20,
            table: "".into(),
            chain: "OUTPUT".into(),
            protocol: "tcp".into(),
            source: "".into(),
            destination: "10.0.0.1".into(),
            source_port: "".into(),
            destination_port: "2379".into(),
            in_interface: "".into(),
            out_interface: "".into(),
            jump: "DROP".into(),
            ctstate: "".into(),
            comment: "test-drill".into(),
            ip_version: 4,
            action: ACTION_INSERT,
            rule_state: STATE_PRESENT,
        }
    }

    #[test]
    fn insert_present_when_absent_inserts() {
        let stub = Stub::new("ins-present-abs", 1); // probe says absent
        let bin = stub.bin.to_str().unwrap().to_string();
        let changed = apply(&bin, &base_op(), false).unwrap();
        assert!(changed, "expected changed=true on insert");
        let log = stub.log();
        // Two invocations: one -C probe, one -I mutate.
        assert_eq!(log.lines().count(), 2, "log: {log}");
        assert!(log.lines().next().unwrap().contains("-C OUTPUT"));
        assert!(log.lines().nth(1).unwrap().contains("-I OUTPUT"));
        assert!(log.contains("-d 10.0.0.1"));
        assert!(log.contains("--dport 2379"));
        assert!(log.contains("-j DROP"));
        assert!(log.contains("--comment test-drill"));
    }

    #[test]
    fn present_when_already_present_is_noop() {
        let stub = Stub::new("present-noop", 0); // probe says exists
        let bin = stub.bin.to_str().unwrap().to_string();
        let changed = apply(&bin, &base_op(), false).unwrap();
        assert!(!changed, "expected changed=false on no-op present");
        // Only the probe should have run.
        let log = stub.log();
        assert_eq!(log.lines().count(), 1, "log: {log}");
        assert!(log.contains("-C OUTPUT"));
    }

    #[test]
    fn absent_when_present_deletes() {
        let stub = Stub::new("abs-del", 0); // probe says exists
        let bin = stub.bin.to_str().unwrap().to_string();
        let mut op = base_op();
        op.rule_state = STATE_ABSENT;
        let changed = apply(&bin, &op, false).unwrap();
        assert!(changed);
        let log = stub.log();
        assert_eq!(log.lines().count(), 2);
        assert!(log.lines().nth(1).unwrap().contains("-D OUTPUT"));
    }

    #[test]
    fn absent_when_already_absent_is_noop() {
        let stub = Stub::new("abs-noop", 1); // probe says missing
        let bin = stub.bin.to_str().unwrap().to_string();
        let mut op = base_op();
        op.rule_state = STATE_ABSENT;
        let changed = apply(&bin, &op, false).unwrap();
        assert!(!changed);
        assert_eq!(stub.log().lines().count(), 1);
    }

    #[test]
    fn append_action_uses_dash_A() {
        let stub = Stub::new("append", 1);
        let bin = stub.bin.to_str().unwrap().to_string();
        let mut op = base_op();
        op.action = ACTION_APPEND;
        let _ = apply(&bin, &op, false).unwrap();
        let log = stub.log();
        assert!(log.lines().nth(1).unwrap().contains("-A OUTPUT"), "log: {log}");
    }

    #[test]
    fn table_flag_precedes_verb() {
        let stub = Stub::new("table", 1);
        let bin = stub.bin.to_str().unwrap().to_string();
        let mut op = base_op();
        op.table = "nat".into();
        let _ = apply(&bin, &op, false).unwrap();
        // iptables expects `-t nat -I OUTPUT ...`; verify ordering.
        let log = stub.log();
        let first = log.lines().next().unwrap();
        let t_idx = first.find("-t nat").expect("no -t nat");
        let verb_idx = first.find("-C OUTPUT").expect("no -C");
        assert!(t_idx < verb_idx, "expected -t before -C; line: {first}");
    }

    #[test]
    fn empty_chain_rejected() {
        let stub = Stub::new("empty-chain", 1);
        let bin = stub.bin.to_str().unwrap().to_string();
        let mut op = base_op();
        op.chain = "".into();
        let err = apply(&bin, &op, false).unwrap_err();
        match err {
            IptablesError::BadRequest(m) => assert!(m.contains("chain")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn port_without_protocol_rejected() {
        let stub = Stub::new("port-no-proto", 1);
        let bin = stub.bin.to_str().unwrap().to_string();
        let mut op = base_op();
        op.protocol = "".into();
        op.destination_port = "2379".into();
        let err = apply(&bin, &op, false).unwrap_err();
        match err {
            IptablesError::BadRequest(m) => {
                assert!(m.contains("protocol"), "msg: {m}");
            }
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn probe_unknown_exit_propagates_as_io() {
        let stub = Stub::new("probe-bad", 2); // bizarre exit code from iptables
        let bin = stub.bin.to_str().unwrap().to_string();
        let err = apply(&bin, &base_op(), false).unwrap_err();
        match err {
            IptablesError::Io(m) => assert!(m.contains("exited 2"), "msg: {m}"),
            _ => panic!("expected Io, got {err:?}"),
        }
    }

    #[test]
    fn check_mode_short_circuits_after_probe() {
        let stub = Stub::new("check-mode", 1); // probe: absent → would insert
        let bin = stub.bin.to_str().unwrap().to_string();
        let changed = apply(&bin, &base_op(), true).unwrap();
        assert!(changed, "check_mode should still report would-change");
        // No mutate invocation should have happened.
        assert_eq!(stub.log().lines().count(), 1);
    }
}
