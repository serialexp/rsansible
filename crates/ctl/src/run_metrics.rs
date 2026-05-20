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

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

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
    }

    /// Read all atomics into a plain-old-data snapshot. Call once at
    /// end-of-run when no walker is still recording.
    pub fn snapshot(&self) -> RunMetricsSnapshot {
        RunMetricsSnapshot {
            op_count: self.op_count.load(Ordering::Relaxed),
            agent_ns_total: self.agent_ns_total.load(Ordering::Relaxed),
            wall_ns_total: self.wall_ns_total.load(Ordering::Relaxed),
            outbound_ns_total: self.outbound_ns_total.load(Ordering::Relaxed),
            inbound_ns_total: self.inbound_ns_total.load(Ordering::Relaxed),
        }
    }
}

/// Plain-old-data snapshot of `RunMetrics` for inclusion in `RunReport`.
#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct RunMetricsSnapshot {
    pub op_count: u64,
    pub agent_ns_total: u64,
    pub wall_ns_total: u64,
    pub outbound_ns_total: i64,
    pub inbound_ns_total: i64,
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
        );
        // op #2: agent worked 5ms, wall 7ms, perfect offset of 0.
        m.record(201_000_000, 206_000_000, 200_000_000, 207_000_000, 0);
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
        );
        let s = m.snapshot();
        assert_eq!(s.outbound_ns_total, -1_000_000);
        assert_eq!(s.inbound_ns_total, 1_000_000);
        assert_eq!(s.round_trip_ns_total(), 0);
    }
}
