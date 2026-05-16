//! `OpGatherFacts` — collect a small set of `ansible_*` facts about the host.
//!
//! Output is a JSON object written to stdout via a single TaskProgress chunk,
//! followed by TaskDone(exit_code=0). The controller parses the stdout and
//! lifts the keys into `HostCtx.facts`. Failures inside individual fact
//! collectors are non-fatal: the corresponding key is simply omitted from
//! the output. Only a hard error (channel closed, JSON serialization) breaks
//! the task.
//!
//! Keys emitted (all best-effort):
//!   - `ansible_hostname`              — uname().nodename
//!   - `ansible_distribution`          — /etc/os-release `ID`, title-cased
//!   - `ansible_distribution_release`  — /etc/os-release `VERSION_CODENAME`
//!   - `ansible_date_time`             — { iso8601, date, time, epoch }
//!   - `ansible_default_ipv4`          — { address: "10.0.0.5" } if known

use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use rsansible_wire::msg::{self, now_unix_ns};
use serde_json::{json, Value};

use super::Context;

pub async fn run(ctx: &Context, seq: u32, _check_mode: bool) -> anyhow::Result<()> {
    // gather_facts is read-only: it only reads /proc, /etc/os-release,
    // and asks the kernel which local address it would route to 1.1.1.1.
    // No state changes; `_check_mode` is accepted for plumbing
    // uniformity and ignored.
    let started_unix_ns = now_unix_ns();
    let facts = collect_facts();
    let bytes = serde_json::to_vec(&facts)?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;
    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, false, false, started_unix_ns, finished_unix_ns)).await;
    Ok(())
}

/// Collect facts. Anything that can fail is wrapped so the entire fact set
/// is best-effort — Ansible's `gather_facts` behaves the same.
pub(crate) fn collect_facts() -> BTreeMap<String, Value> {
    let mut out: BTreeMap<String, Value> = BTreeMap::new();

    if let Some(name) = hostname() {
        out.insert("ansible_hostname".into(), Value::String(name));
    }

    if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
        if let Some(id) = parse_os_release(&release, "ID") {
            out.insert(
                "ansible_distribution".into(),
                Value::String(title_case(&id)),
            );
        }
        if let Some(codename) = parse_os_release(&release, "VERSION_CODENAME") {
            out.insert(
                "ansible_distribution_release".into(),
                Value::String(codename),
            );
        }
    }

    out.insert("ansible_date_time".into(), date_time_json());

    if let Some(addr) = default_ipv4_address() {
        out.insert(
            "ansible_default_ipv4".into(),
            json!({ "address": addr }),
        );
    }

    out
}

fn hostname() -> Option<String> {
    let uts = rustix::system::uname();
    let bytes = uts.nodename().to_bytes();
    if bytes.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Parse a `KEY=value` line from os-release. Values may be quoted with `"` or
/// `'`. We strip a single layer of matching quotes; nothing fancier (no
/// escape sequences — os-release values in practice don't use them).
fn parse_os_release(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        if k != key {
            continue;
        }
        let v = v.trim();
        if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            return Some(v[1..v.len() - 1].to_string());
        }
        return Some(v.to_string());
    }
    None
}

fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase(),
    }
}

/// Format the current system time as a small JSON object matching the subset
/// of Ansible's `ansible_date_time` that gothab and similar playbooks rely on.
/// `iso8601` is the field commonly templated; the others are cheap extras.
fn date_time_json() -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let epoch = now.as_secs();
    let (year, month, day, hour, minute, second) = decompose_utc(epoch);
    let iso = format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    );
    let date = format!("{year:04}-{month:02}-{day:02}");
    let time = format!("{hour:02}:{minute:02}:{second:02}");
    json!({
        "iso8601": iso,
        "date": date,
        "time": time,
        "epoch": epoch.to_string(),
    })
}

/// Convert a Unix epoch (seconds since 1970-01-01 UTC) into broken-down UTC
/// components. Pure arithmetic — no external dependency required for the
/// handful of fields we need. Valid for 1970-01-01 .. 9999-12-31, plenty.
fn decompose_utc(epoch: u64) -> (u32, u32, u32, u32, u32, u32) {
    let secs_per_day: u64 = 86_400;
    let days_since_epoch = (epoch / secs_per_day) as i64;
    let rem = epoch % secs_per_day;
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;

    // Days since 1970-01-01 → civil date via Hinnant's algorithm.
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp.wrapping_sub(9) };
    let year = (y + if m <= 2 { 1 } else { 0 }) as u32;
    (year, m as u32, d as u32, hour, minute, second)
}

/// Best-effort default-route source address. Opens a UDP socket and asks the
/// kernel which local address it would use to reach `1.1.1.1:53` — no packets
/// are actually sent. Returns `None` if the lookup fails (no network, etc.).
fn default_ipv4_address() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:53").ok()?;
    let local = sock.local_addr().ok()?;
    Some(local.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_release_unquoted() {
        let text = "NAME=Ubuntu\nID=ubuntu\nVERSION_CODENAME=jammy\n";
        assert_eq!(parse_os_release(text, "ID").as_deref(), Some("ubuntu"));
        assert_eq!(
            parse_os_release(text, "VERSION_CODENAME").as_deref(),
            Some("jammy")
        );
        assert_eq!(parse_os_release(text, "MISSING"), None);
    }

    #[test]
    fn parses_os_release_quoted() {
        let text = "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 22.04\"\n";
        assert_eq!(parse_os_release(text, "NAME").as_deref(), Some("Ubuntu"));
        assert_eq!(
            parse_os_release(text, "PRETTY_NAME").as_deref(),
            Some("Ubuntu 22.04")
        );
    }

    #[test]
    fn title_case_handles_empty_and_short() {
        assert_eq!(title_case(""), "");
        assert_eq!(title_case("u"), "U");
        assert_eq!(title_case("ubuntu"), "Ubuntu");
        assert_eq!(title_case("UBUNTU"), "Ubuntu");
    }

    #[test]
    fn decompose_utc_known_dates() {
        // 1970-01-01T00:00:00Z
        assert_eq!(decompose_utc(0), (1970, 1, 1, 0, 0, 0));
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(decompose_utc(946_684_800), (2000, 1, 1, 0, 0, 0));
        // 2024-02-29T12:24:56Z = 1709209496 (verified by hand:
        // 19782 days × 86400 + 12×3600 + 24×60 + 56 = 1709209496).
        // Confirms leap-year handling of Feb 29.
        assert_eq!(decompose_utc(1_709_209_496), (2024, 2, 29, 12, 24, 56));
    }

    /// Print how long `collect_facts` takes locally — pure agent-side
    /// cost, no wire. Run with `cargo test -p rsansible-agent --lib
    /// bench_collect_facts -- --nocapture`.
    #[test]
    fn bench_collect_facts() {
        use std::time::Instant;
        // Warm up the page cache for /etc/os-release etc.
        let _ = collect_facts();
        let iters = 100;
        let started = Instant::now();
        for _ in 0..iters {
            let _ = std::hint::black_box(collect_facts());
        }
        let elapsed = started.elapsed();
        let per = elapsed / iters;
        eprintln!(
            "collect_facts: {iters} iters in {:?} ({:?} per call, {} keys)",
            elapsed,
            per,
            collect_facts().len()
        );
    }

    #[test]
    fn collect_facts_includes_date_time() {
        let facts = collect_facts();
        let dt = facts.get("ansible_date_time").expect("date_time present");
        let iso = dt
            .as_object()
            .and_then(|m| m.get("iso8601"))
            .and_then(Value::as_str)
            .expect("iso8601 string");
        assert!(iso.len() == "YYYY-MM-DDTHH:MM:SSZ".len(), "got {iso:?}");
        assert!(iso.ends_with('Z'), "expected UTC marker, got {iso:?}");
    }
}
