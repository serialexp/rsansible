//! `OpWaitFor` — wait for a TCP port to be reachable OR for a path to
//! appear/disappear. Ansible's `wait_for` module.
//!
//! Mutually-exclusive modes (validated controller-side, re-checked here
//! for defense-in-depth):
//!   - port > 0 + non-empty host → TCP probe
//!   - port == 0 + non-empty path → path-existence probe
//!
//! `state`:
//!   - present (0): wait for it to come up / appear (default)
//!   - absent  (1): wait for it to go away / disappear
//!
//! Timing:
//!   - delay_ms: initial sleep BEFORE the first check
//!   - sleep_ms: interval between checks
//!   - timeout_ms: overall wall-clock cap on the loop (delay included)
//!
//! Outcomes:
//!   - condition met within timeout → TaskDone(0, changed=0)
//!   - timeout reached              → TaskError(TIMEOUT)
//!   - bad mode (both/neither set)  → TaskError(BAD_REQUEST)
//!
//! TCP probe semantics: a successful `connect()` (followed by immediate
//! close) within a 1-second per-attempt timeout counts as "reachable".
//! No protocol-level handshake — Ansible's wait_for does the same.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

use rsansible_wire::generated::OpWaitForOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

/// Per-attempt TCP connect deadline. Independent of the user-supplied
/// `sleep_ms` so a slow refusal/RST doesn't eat the full poll cycle.
const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(1_000);

pub async fn run(ctx: &Context, seq: u32, op: OpWaitForOutput, _check_mode: bool) -> anyhow::Result<()> {
    // wait_for is a read-only probe — it never mutates host state, so
    // it runs unchanged under `--check`. Surfacing a missing dependency
    // is the whole point of dry-run, so we intentionally do NOT skip
    // the wait. `_check_mode` is accepted for plumbing uniformity.
    let started_unix_ns = now_unix_ns();

    let mode = match classify(&op) {
        Ok(m) => m,
        Err(msg) => {
            emit_error(ctx, seq, err::BAD_REQUEST, msg).await;
            return Ok(());
        }
    };

    let want_present = match op.state {
        STATE_PRESENT => true,
        STATE_ABSENT => false,
        other => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("wait_for: unknown state byte {other}"),
            )
            .await;
            return Ok(());
        }
    };

    let timeout = Duration::from_millis(op.timeout_ms.max(1) as u64);
    let sleep = Duration::from_millis(op.sleep_ms.max(50) as u64);
    let delay = Duration::from_millis(op.delay_ms as u64);

    // The loop is sync (TcpStream::connect_timeout / std::fs::metadata
    // are blocking syscalls). Park it on a blocking task so we don't
    // wedge the agent's tokio runtime.
    let outcome = tokio::task::spawn_blocking(move || {
        wait_loop(&op, mode, want_present, delay, sleep, timeout)
    })
    .await
    .map_err(|e| anyhow::anyhow!("wait_for join: {e}"))?;

    match outcome {
        Outcome::Met => {
            let finished_unix_ns = now_unix_ns();
            ctx.emit(msg::task_done(seq, 0, false, false, started_unix_ns, finished_unix_ns))
                .await;
        }
        Outcome::Timeout(detail) => {
            emit_error(ctx, seq, err::TIMEOUT, detail).await;
        }
        Outcome::Io(detail) => {
            emit_error(ctx, seq, err::IO, detail).await;
        }
    }
    Ok(())
}

#[derive(Debug)]
enum Mode {
    Tcp,
    Path,
    /// "Just sleep" form — no host/port/path given. Matches Ansible's
    /// behavior: sleep for `delay` seconds and report success. `sleep`
    /// and `timeout` have no meaning here (nothing to probe).
    Sleep,
}

fn classify(op: &OpWaitForOutput) -> Result<Mode, String> {
    let has_tcp = op.port > 0;
    let has_path = !op.path.is_empty();
    match (has_tcp, has_path) {
        (true, false) => {
            if op.host.is_empty() {
                Err("wait_for: TCP mode requires a non-empty host".to_string())
            } else {
                Ok(Mode::Tcp)
            }
        }
        (false, true) => Ok(Mode::Path),
        (true, true) => Err("wait_for: host+port and path are mutually exclusive".to_string()),
        (false, false) => Ok(Mode::Sleep),
    }
}

enum Outcome {
    Met,
    Timeout(String),
    Io(String),
}

fn wait_loop(
    op: &OpWaitForOutput,
    mode: Mode,
    want_present: bool,
    delay: Duration,
    sleep: Duration,
    timeout: Duration,
) -> Outcome {
    // "Just sleep" mode: pure delay, then success. Nothing to probe,
    // so `timeout` and `sleep` are inert. Matches Ansible exactly.
    if matches!(mode, Mode::Sleep) {
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        return Outcome::Met;
    }
    let deadline = Instant::now() + timeout;
    if !delay.is_zero() {
        std::thread::sleep(delay.min(timeout));
    }
    loop {
        let observed_present = match &mode {
            Mode::Tcp => probe_tcp(&op.host, op.port),
            Mode::Path => Ok(Path::new(&op.path).exists()),
            Mode::Sleep => unreachable!("Sleep handled above"),
        };
        match observed_present {
            Ok(present) if present == want_present => return Outcome::Met,
            Ok(_) => {}
            Err(e) => {
                // Hard error from the probe (e.g. DNS lookup blew up).
                // Don't loop on this — surface it.
                return Outcome::Io(format!("wait_for probe: {e}"));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Outcome::Timeout(describe_timeout(op, &mode, want_present, timeout));
        }
        let remaining = deadline - now;
        std::thread::sleep(sleep.min(remaining));
    }
}

fn describe_timeout(op: &OpWaitForOutput, mode: &Mode, want_present: bool, total: Duration) -> String {
    let action = if want_present { "appear" } else { "disappear" };
    match mode {
        Mode::Tcp => format!(
            "wait_for: timed out after {}ms waiting for {}:{} to {action}",
            total.as_millis(),
            op.host,
            op.port,
        ),
        Mode::Path => format!(
            "wait_for: timed out after {}ms waiting for {} to {action}",
            total.as_millis(),
            op.path,
        ),
        // Sleep mode never reaches timeout — wait_loop returns Met
        // immediately after the delay sleep. This arm exists only to
        // make the match exhaustive.
        Mode::Sleep => format!(
            "wait_for: sleep-only mode timed out after {}ms (this is a bug — Sleep should never time out)",
            total.as_millis(),
        ),
    }
}

/// Attempt a single TCP connect with a short per-attempt deadline.
/// Returns Ok(true) if the connect succeeded; Ok(false) for any
/// transient error (refused, no route, timed out, unreachable) so the
/// caller can keep polling. Returns Err only for unrecoverable issues
/// (e.g. DNS resolver gave up with a system error).
fn probe_tcp(host: &str, port: u32) -> io::Result<bool> {
    // Resolve once per attempt. Use to_socket_addrs to handle IPv4/IPv6
    // and DNS uniformly.
    let target = format!("{host}:{port}");
    let addrs = match target.to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => {
            // Resolver failures are transient (e.g. systemd-resolved
            // not yet up). Treat as "not reachable yet" rather than
            // surfacing the error.
            if e.kind() == io::ErrorKind::Other || e.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(e);
        }
    };
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TCP_PROBE_TIMEOUT) {
            Ok(_stream) => return Ok(true),
            Err(_) => continue,
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn op_for_tcp(host: &str, port: u32, state: u8, timeout_ms: u32, sleep_ms: u32) -> OpWaitForOutput {
        OpWaitForOutput {
            kind: 6,
            host: host.into(),
            port,
            path: String::new(),
            state,
            timeout_ms,
            delay_ms: 0,
            sleep_ms,
        }
    }

    fn op_for_path(path: &str, state: u8, timeout_ms: u32, sleep_ms: u32) -> OpWaitForOutput {
        OpWaitForOutput {
            kind: 6,
            host: String::new(),
            port: 0,
            path: path.into(),
            state,
            timeout_ms,
            delay_ms: 0,
            sleep_ms,
        }
    }

    #[test]
    fn classify_rejects_both_modes() {
        let mut op = op_for_tcp("a", 1, 0, 0, 0);
        op.path = "/x".into();
        let err = classify(&op).unwrap_err();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    /// Regression: bare wait_for (no host/port/path) classifies as
    /// Sleep mode rather than failing. Matches Ansible's "just sleep"
    /// shape and unblocks playbooks that use wait_for as a placeholder
    /// or controlled pause.
    #[test]
    fn classify_no_target_is_sleep_mode() {
        let op = OpWaitForOutput {
            kind: 6,
            host: String::new(),
            port: 0,
            path: String::new(),
            state: 0,
            timeout_ms: 1000,
            delay_ms: 0,
            sleep_ms: 0,
        };
        let mode = classify(&op).expect("bare wait_for must classify");
        assert!(matches!(mode, Mode::Sleep));
    }

    #[test]
    fn sleep_mode_returns_met_immediately_when_delay_zero() {
        let op = OpWaitForOutput {
            kind: 6,
            host: String::new(),
            port: 0,
            path: String::new(),
            state: STATE_PRESENT,
            timeout_ms: 60_000,
            delay_ms: 0,
            sleep_ms: 1000,
        };
        let start = Instant::now();
        let out = wait_loop(
            &op,
            Mode::Sleep,
            true,
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(60),
        );
        assert!(matches!(out, Outcome::Met));
        // Should not have slept its 60s timeout — sleep mode returns
        // immediately when delay is zero.
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn sleep_mode_honors_delay() {
        let op = OpWaitForOutput {
            kind: 6,
            host: String::new(),
            port: 0,
            path: String::new(),
            state: STATE_PRESENT,
            timeout_ms: 60_000,
            delay_ms: 150,
            sleep_ms: 1000,
        };
        let start = Instant::now();
        let out = wait_loop(
            &op,
            Mode::Sleep,
            true,
            Duration::from_millis(150),
            Duration::from_secs(1),
            Duration::from_secs(60),
        );
        assert!(matches!(out, Outcome::Met));
        // Must have slept ~150ms (allow generous slack for CI jitter).
        assert!(start.elapsed() >= Duration::from_millis(140));
        assert!(start.elapsed() < Duration::from_millis(2000));
    }

    #[test]
    fn tcp_reachable_returns_met_fast() {
        // Bind a listener on a free port; wait_for(present) should
        // succeed on the first probe.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port() as u32;
        let op = op_for_tcp("127.0.0.1", port, STATE_PRESENT, 5_000, 100);
        let start = Instant::now();
        let out = wait_loop(
            &op,
            Mode::Tcp,
            true,
            Duration::ZERO,
            Duration::from_millis(100),
            Duration::from_secs(5),
        );
        assert!(matches!(out, Outcome::Met), "expected Met");
        assert!(start.elapsed() < Duration::from_millis(500), "should resolve fast");
        drop(l);
    }

    #[test]
    fn tcp_unreachable_times_out() {
        // 127.0.0.2:1 should be closed (refused) — wait_for(present)
        // times out.
        let op = op_for_tcp("127.0.0.1", 1, STATE_PRESENT, 300, 50);
        let out = wait_loop(
            &op,
            Mode::Tcp,
            true,
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_millis(300),
        );
        match out {
            Outcome::Timeout(m) => assert!(m.contains("appear"), "got: {m}"),
            other => panic!("expected Timeout, got {:?}", match other {
                Outcome::Met => "Met",
                Outcome::Io(_) => "Io",
                _ => "?",
            }),
        }
    }

    #[test]
    fn tcp_absent_returns_immediately_for_closed_port() {
        let op = op_for_tcp("127.0.0.1", 1, STATE_ABSENT, 1_000, 50);
        let out = wait_loop(
            &op,
            Mode::Tcp,
            false,
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_secs(1),
        );
        assert!(matches!(out, Outcome::Met));
    }

    #[test]
    fn path_present_returns_immediately_for_existing_path() {
        let p = std::env::temp_dir().join(format!(
            "rsansible-wait-test-{}-{}",
            std::process::id(),
            now_unix_ns()
        ));
        std::fs::write(&p, b"x").unwrap();
        let op = op_for_path(p.to_str().unwrap(), STATE_PRESENT, 1_000, 50);
        let out = wait_loop(
            &op,
            Mode::Path,
            true,
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_secs(1),
        );
        assert!(matches!(out, Outcome::Met));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn path_present_picks_up_late_creation() {
        let p = std::env::temp_dir().join(format!(
            "rsansible-wait-test-late-{}-{}",
            std::process::id(),
            now_unix_ns()
        ));
        let p_owned = p.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            std::fs::write(&p_owned, b"x").unwrap();
        });
        let op = op_for_path(p.to_str().unwrap(), STATE_PRESENT, 2_000, 50);
        let out = wait_loop(
            &op,
            Mode::Path,
            true,
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_secs(2),
        );
        assert!(matches!(out, Outcome::Met));
        handle.join().unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn path_absent_returns_immediately_for_missing() {
        let op = op_for_path("/definitely/not/here/rsansible", STATE_ABSENT, 500, 50);
        let out = wait_loop(
            &op,
            Mode::Path,
            false,
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_millis(500),
        );
        assert!(matches!(out, Outcome::Met));
    }
}
