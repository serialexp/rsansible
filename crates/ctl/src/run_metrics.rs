//! Run-level timing aggregator.
//!
//! Every wire round-trip (controller dispatches an `Op` to the agent and
//! reads back a `TaskDone`) produces four timestamps:
//!
//! - controller dispatched the frame
//! - agent started its module
//! - agent finished its module
//! - controller received `TaskDone`
//!
//! Per-task these are emitted as a `tracing::debug` line under the
//! `rsansible::timing` target. Per-run we want totals: how much time was
//! spent doing real work on the agent vs. spent on the wire / in
//! controller-side framing. This module collects those totals via a
//! single shared `RunMetrics` accumulator, updated once per wire
//! dispatch, snapshotted into the final `RunReport`.
//!
//! Concurrency: `RunMetrics` uses lock-free atomics so per-host walkers
//! running in parallel can record without contending. Updates are
//! `Relaxed` because aggregate timing has no causal-ordering
//! requirement — we just need the totals to be correct when read at
//! end-of-run, after every walker has joined.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

/// Per-op-type running totals: how many times this op fired across all
/// hosts, and how many ns the agents spent actually running it. Read
/// at end-of-run to answer "where did the agents spend their time?".
#[derive(Debug, Default, Clone, Copy)]
struct PerOpAccum {
    count: u64,
    /// Sum of `agent_finished - agent_started` for this op. The
    /// authoritative measure of "real work the agent did" — same
    /// clock both endpoints so skew-immune.
    agent_ns: u64,
    /// Sum of `controller_received - controller_dispatched` for this
    /// op. Includes the wire RTT; comparing to `agent_ns` shows how
    /// much of the wall time was wire vs. real work per op type.
    wall_ns: u64,
}

/// Shared per-run timing accumulator. Threaded through every `HostCtx`
/// (`Arc<RunMetrics>` field; cheap clone), updated by
/// `orchestrator::run_op_body` once per completed wire round-trip.
#[derive(Debug, Default)]
pub struct RunMetrics {
    /// Number of wire round-trips recorded. Includes idempotency probes
    /// (e.g. `creates:`/`removes:` stat checks) and any other
    /// orchestrator-internal probes, because those are real
    /// dispatch-overhead cost the operator pays.
    op_count: AtomicU64,
    /// Sum across all recorded ops of `agent_finished_unix_ns -
    /// agent_started_unix_ns`, in nanoseconds. Skew-immune — the
    /// agent measured both endpoints on its own clock.
    agent_ns_total: AtomicU64,
    /// Sum across all recorded ops of `controller_received_unix_ns -
    /// controller_dispatched_unix_ns`, in nanoseconds. Controller-
    /// observed end-to-end; this is what a stopwatch would show if it
    /// could see each op individually. Note this is NOT the run's
    /// wall-clock duration — tasks on different hosts overlap.
    wall_ns_total: AtomicU64,
    /// Sum across all recorded ops of skew-corrected outbound time:
    /// (agent_started - clock_offset) - controller_dispatched. Signed
    /// because the Ping/Pong offset has residual error; a slightly
    /// negative sum is normal on a low-latency network.
    outbound_ns_total: AtomicI64,
    /// Sum across all recorded ops of skew-corrected inbound time:
    /// controller_received - (agent_finished - clock_offset). Same
    /// signedness caveat.
    inbound_ns_total: AtomicI64,
    /// Per-op-type breakdown: key is the static op name (see
    /// `wire::Op::name()`), value is the running count + agent ns +
    /// wall ns for that op type. Wrapped in a `Mutex` rather than
    /// per-key atomics because the variant set is small and the
    /// per-record overhead is dwarfed by the wire round-trip we're
    /// already paying — uncontended mutex acquire is ~50ns, op
    /// dispatch is hundreds of µs minimum.
    per_op: Mutex<BTreeMap<&'static str, PerOpAccum>>,
}

impl RunMetrics {
    /// Compute the four deltas from raw timestamps and accumulate them.
    /// Called once per wire round-trip from `orchestrator::run_op_body`
    /// alongside `emit_timing_trace` — same data, two consumers.
    pub fn record(
        &self,
        agent_started_unix_ns: u64,
        agent_finished_unix_ns: u64,
        ctl_dispatched_unix_ns: u64,
        ctl_received_unix_ns: u64,
        agent_clock_offset_ns: i64,
        op_name: &'static str,
    ) {
        let agent_ns = agent_finished_unix_ns.saturating_sub(agent_started_unix_ns);
        let wall_ns = ctl_received_unix_ns.saturating_sub(ctl_dispatched_unix_ns);
        // Skew-correct the agent's wall-clock samples into the
        // controller's reference frame, then compute outbound /
        // inbound. i128 avoids overflow on the intermediate subtract;
        // we narrow back to i64 (saturating) before the atomic add.
        let offset = agent_clock_offset_ns as i128;
        let agent_started_corrected = (agent_started_unix_ns as i128) - offset;
        let agent_finished_corrected = (agent_finished_unix_ns as i128) - offset;
        let outbound_ns = agent_started_corrected - (ctl_dispatched_unix_ns as i128);
        let inbound_ns = (ctl_received_unix_ns as i128) - agent_finished_corrected;

        self.op_count.fetch_add(1, Ordering::Relaxed);
        self.agent_ns_total.fetch_add(agent_ns, Ordering::Relaxed);
        self.wall_ns_total.fetch_add(wall_ns, Ordering::Relaxed);
        self.outbound_ns_total
            .fetch_add(saturating_i64_from_i128(outbound_ns), Ordering::Relaxed);
        self.inbound_ns_total
            .fetch_add(saturating_i64_from_i128(inbound_ns), Ordering::Relaxed);
        // Per-op-type bucket. `&'static str` key means no allocation
        // on insert; the variant set is small (~30 entries) so the
        // BTreeMap stays tiny and lookup is O(log N) on short keys.
        // Lock contention is negligible — at most one acquire per
        // wire round-trip, which already costs hundreds of µs.
        if let Ok(mut map) = self.per_op.lock() {
            let entry = map.entry(op_name).or_default();
            entry.count = entry.count.saturating_add(1);
            entry.agent_ns = entry.agent_ns.saturating_add(agent_ns);
            entry.wall_ns = entry.wall_ns.saturating_add(wall_ns);
        }
    }

    /// Read all atomics into a plain-old-data snapshot. Call once at
    /// end-of-run when no walker is still recording.
    pub fn snapshot(&self) -> RunMetricsSnapshot {
        let per_op = self
            .per_op
            .lock()
            .map(|m| {
                m.iter()
                    .map(|(name, acc)| PerOpStat {
                        op: (*name).to_string(),
                        count: acc.count,
                        agent_ns: acc.agent_ns,
                        wall_ns: acc.wall_ns,
                    })
                    .collect()
            })
            .unwrap_or_default();
        RunMetricsSnapshot {
            op_count: self.op_count.load(Ordering::Relaxed),
            agent_ns_total: self.agent_ns_total.load(Ordering::Relaxed),
            wall_ns_total: self.wall_ns_total.load(Ordering::Relaxed),
            outbound_ns_total: self.outbound_ns_total.load(Ordering::Relaxed),
            inbound_ns_total: self.inbound_ns_total.load(Ordering::Relaxed),
            per_op,
        }
    }
}

/// Per-op-type stat row in the serializable snapshot. Keyed by the
/// op name from `wire::Op::name()`.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerOpStat {
    pub op: String,
    pub count: u64,
    /// Agent-side wall time spent on this op type. Sum of
    /// `agent_finished - agent_started` per dispatch — same clock
    /// at both endpoints, so skew-immune. This is the authoritative
    /// "what did the targets actually spend time on" measurement.
    pub agent_ns: u64,
    /// Controller-observed wall time for this op type (includes
    /// wire RTT). The difference `wall_ns - agent_ns` per op is the
    /// fraction of dispatch cost that was bits moving, not work
    /// happening — useful when comparing forward-mode (in-DC) vs.
    /// laptop-direct (WAN) runs.
    pub wall_ns: u64,
}

/// Plain-old-data snapshot of `RunMetrics` for inclusion in `RunReport`.
///
/// Was `Copy` before per-op breakdown was added; now `Clone`-only
/// because `per_op` owns a heap `Vec`. Read-once at end-of-run so
/// the lost-`Copy`-ness doesn't ripple anywhere hot.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct RunMetricsSnapshot {
    pub op_count: u64,
    pub agent_ns_total: u64,
    pub wall_ns_total: u64,
    pub outbound_ns_total: i64,
    pub inbound_ns_total: i64,
    /// Per-op-type breakdown. Empty `Vec` for legacy snapshots
    /// from before this field existed (serde `default`). Order is
    /// not stable — callers should sort by whatever dimension they
    /// want to display.
    #[serde(default)]
    pub per_op: Vec<PerOpStat>,
}

impl RunMetricsSnapshot {
    /// Sum of skew-corrected outbound + inbound time across all ops.
    /// This is what we mean by "round-trip overhead" — time the
    /// operator spent waiting for bits to move, not for the agent to
    /// do work. Returns a signed value because the per-op components
    /// are signed (residual skew error); negative magnitudes are
    /// expected to be small.
    pub fn round_trip_ns_total(&self) -> i64 {
        self.outbound_ns_total
            .saturating_add(self.inbound_ns_total)
    }

    /// Pretty-printed per-op-type table sorted by descending agent
    /// time. Each row shows count, total agent ns spent, share of
    /// the global agent total as a percent, and the controller-side
    /// wall total for the same op (so the operator can compare
    /// agent-vs-wire per op type at a glance). Returns an empty
    /// string when no per-op buckets exist (legacy snapshots,
    /// 0-op runs).
    ///
    /// Format example:
    /// ```text
    /// agent-side per-op breakdown:
    ///   systemd          n=47   agent=12.30s ( 51.2%)  wall=14.10s
    ///   package          n= 3   agent= 8.50s ( 35.4%)  wall= 9.20s
    ///   ...
    /// ```
    pub fn per_op_breakdown(&self) -> String {
        if self.per_op.is_empty() {
            return String::new();
        }
        let mut rows: Vec<&PerOpStat> = self.per_op.iter().collect();
        rows.sort_by(|a, b| b.agent_ns.cmp(&a.agent_ns));
        let agent_total = self.agent_ns_total.max(1) as f64;
        let name_w = rows.iter().map(|r| r.op.len()).max().unwrap_or(8).max(8);
        let mut out = String::from("agent-side per-op breakdown:\n");
        for r in rows {
            let agent_s = r.agent_ns as f64 / 1e9;
            let wall_s = r.wall_ns as f64 / 1e9;
            let pct = (r.agent_ns as f64 / agent_total) * 100.0;
            out.push_str(&format!(
                "  {name:<name_w$}  n={count:>4}   agent={agent:>6.2}s ({pct:>5.1}%)  wall={wall:>6.2}s\n",
                name = r.op,
                count = r.count,
                agent = agent_s,
                pct = pct,
                wall = wall_s,
            ));
        }
        out
    }
}

fn saturating_i64_from_i128(v: i128) -> i64 {
    if v > i64::MAX as i128 {
        i64::MAX
    } else if v < i64::MIN as i128 {
        i64::MIN
    } else {
        v as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The aggregator must sum agent and wall durations across multiple
    /// ops and produce the same totals regardless of recording order.
    /// `agent_ns` accumulates only the work the agent reported; `wall_ns`
    /// accumulates only what the controller observed; outbound/inbound
    /// chip away at the gap (wall = agent + outbound + inbound modulo
    /// skew error).
    #[test]
    fn record_sums_per_op_deltas_into_totals() {
        let m = RunMetrics::default();
        // op #1: agent worked 10ms, wall was 14ms, dispatched at T=100,
        // started at T=102 (offset 0), finished at T=112, received at
        // T=114. Outbound 2ms, inbound 2ms.
        m.record(
            102_000_000, // agent started
            112_000_000, // agent finished
            100_000_000, // ctl dispatched
            114_000_000, // ctl received
            0,           // offset
            "exec",
        );
        // op #2: agent worked 5ms, wall 7ms, perfect offset of 0.
        m.record(
            201_000_000,
            206_000_000,
            200_000_000,
            207_000_000,
            0,
            "shell",
        );
        let s = m.snapshot();
        assert_eq!(s.op_count, 2);
        assert_eq!(s.agent_ns_total, 15_000_000);
        assert_eq!(s.wall_ns_total, 21_000_000);
        assert_eq!(s.outbound_ns_total, 3_000_000);
        assert_eq!(s.inbound_ns_total, 3_000_000);
        assert_eq!(s.round_trip_ns_total(), 6_000_000);
        assert_eq!(
            s.agent_ns_total as i64 + s.round_trip_ns_total(),
            s.wall_ns_total as i64,
            "agent + round-trip = wall (within skew tolerance)"
        );
    }

    /// Clock-offset correction: if the agent's wall clock is 50ms ahead
    /// of the controller, the raw `(agent_started - ctl_dispatched)`
    /// looks like 52ms outbound. Skew correction subtracts 50ms,
    /// yielding the true 2ms wire time.
    #[test]
    fn record_applies_clock_offset_correction() {
        let m = RunMetrics::default();
        // Agent clock 50ms ahead. Dispatched at T=0, agent claims it
        // started at T=52ms (=2ms real + 50ms skew), finished at
        // T=62ms (=12ms real + 50ms skew), controller received at
        // T=14ms.
        m.record(
            52_000_000, // agent started (agent clock)
            62_000_000, // agent finished (agent clock)
            0,          // ctl dispatched
            14_000_000, // ctl received
            50_000_000, // offset: agent is 50ms ahead
            "exec",
        );
        let s = m.snapshot();
        assert_eq!(s.op_count, 1);
        assert_eq!(s.agent_ns_total, 10_000_000, "agent-local duration is skew-immune");
        assert_eq!(s.wall_ns_total, 14_000_000, "wall is purely controller-side");
        assert_eq!(s.outbound_ns_total, 2_000_000, "outbound is skew-corrected");
        assert_eq!(s.inbound_ns_total, 2_000_000, "inbound is skew-corrected");
    }

    /// Residual skew error can make outbound/inbound mildly negative.
    /// The aggregator must not panic on overflow and must preserve sign.
    #[test]
    fn record_tolerates_negative_skew_corrected_components() {
        let m = RunMetrics::default();
        // Offset is over-estimated by 1ms: outbound looks like -1ms.
        m.record(
            10_000_000_000, // agent started
            20_000_000_000, // agent finished
            10_000_000_000, // ctl dispatched (same as agent started under perfect skew)
            20_000_000_000, // ctl received (same as agent finished under perfect skew)
            1_000_000,      // offset over-estimated by 1ms
            "exec",
        );
        let s = m.snapshot();
        assert_eq!(s.outbound_ns_total, -1_000_000);
        assert_eq!(s.inbound_ns_total, 1_000_000);
        assert_eq!(s.round_trip_ns_total(), 0);
    }

    /// Per-op-type bucketing: repeated calls with the same op name
    /// accumulate into the same bucket; distinct names get their
    /// own buckets; the snapshot exposes each bucket so the run
    /// summary can sort by agent_ns and surface the dominant
    /// op types.
    #[test]
    fn record_buckets_per_op_type() {
        let m = RunMetrics::default();
        // Two systemd ops: 10ms + 30ms agent, 14ms + 34ms wall.
        m.record(102_000_000, 112_000_000, 100_000_000, 114_000_000, 0, "systemd");
        m.record(202_000_000, 232_000_000, 200_000_000, 234_000_000, 0, "systemd");
        // One package op: 50ms agent, 54ms wall.
        m.record(302_000_000, 352_000_000, 300_000_000, 354_000_000, 0, "package");
        let s = m.snapshot();
        assert_eq!(s.per_op.len(), 2, "two distinct op buckets");
        let systemd = s.per_op.iter().find(|p| p.op == "systemd").expect("systemd bucket");
        assert_eq!(systemd.count, 2);
        assert_eq!(systemd.agent_ns, 40_000_000);
        assert_eq!(systemd.wall_ns, 48_000_000);
        let pkg = s.per_op.iter().find(|p| p.op == "package").expect("package bucket");
        assert_eq!(pkg.count, 1);
        assert_eq!(pkg.agent_ns, 50_000_000);
        assert_eq!(pkg.wall_ns, 54_000_000);
        // Per-bucket agent totals must sum to the global total.
        let bucket_sum: u64 = s.per_op.iter().map(|p| p.agent_ns).sum();
        assert_eq!(bucket_sum, s.agent_ns_total);
    }
}
