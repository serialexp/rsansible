//! Run-scoped phase-level timing collector.
//!
//! The existing [`RunMetrics`] aggregator (see `run_metrics.rs`) times
//! per-op agent dispatch wall: from the moment we hand a wire op to the
//! pool conn until the response comes back. That's the right window
//! for understanding `agent vs rtt` ratios, but it's blind to anything
//! the controller does between dispatches — rendering template args,
//! resolving become / delegate_to / pool slots, evaluating `when:`,
//! merging hostvars across hosts, applying registers.
//!
//! Live-drill data showed those "between" phases add up: a forward-mode
//! db-1 run that dispatched 171 wire ops in 8.05s of agent+rtt actually
//! took 54.3s of per-task barrier wall, with 46s of that **outside the
//! agent-dispatch window**. This collector attributes that 46s.
//!
//! ## Design
//!
//! - **Lock-free atomic counters.** Each phase is an `AtomicU64` of
//!   accumulated nanoseconds. `fetch_add(_, Relaxed)` is ~30ns on
//!   modern x86 (cache-line atomic increment); for the orchestrator's
//!   per-task rate this is well below noise.
//! - **Always on.** Collection runs unconditionally — the `--timing`
//!   CLI flag only controls *display* of the breakdown. This means
//!   you can't accidentally compare two runs where one had
//!   instrumentation and the other didn't.
//! - **Phase list is flat.** No nested totals ("body_dispatch is
//!   render + agent + bind"); each phase is its own bucket. Hierarchy
//!   makes diffing two runs harder than it needs to be.
//! - **Per-phase counters too.** `body_dispatch_count` answers "how
//!   many wire ops did we issue" — useful when comparing two
//!   playbook shapes, since per-phase ms alone doesn't tell you
//!   "rendered 2× more times" vs. "each render got slower."
//!
//! ## Adding a new phase
//!
//! 1. Add a field to [`TaskTimingAggregator`] (AtomicU64).
//! 2. Add the same name to [`TimingBreakdown`] as `<phase>_ms: f64`.
//! 3. In [`TaskTimingAggregator::summary`] map the ns → ms.
//! 4. In [`format_breakdown`] include it under the right header.
//! 5. At the orchestrator call site:
//!    ```ignore
//!    let t = Instant::now();
//!    do_the_thing();
//!    timing.add(&timing.your_phase_ns, t.elapsed());
//!    ```
//!
//! ## Why not `tracing`?
//!
//! tracing spans are great for single-event introspection ("what
//! happened on this one task?") but their default subscribers print
//! per-event, not aggregated. We want aggregated *because* the
//! interesting question is "where did 46 seconds go across 200 tasks,"
//! not "how long did task #57 take." For per-event timing we already
//! have `tracing::info!(took_ms = ...)` in the orchestrator; this
//! collector is the run-level rollup.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Run-scoped timing aggregator. One instance per `orchestrator::run`,
/// shared via `Arc` to every per-task and per-host walker.
///
/// All counters are nanoseconds. Convert to f64 milliseconds at
/// snapshot time ([`Self::summary`]) — keeping ns internally avoids
/// floating-point accumulation drift.
#[derive(Debug)]
pub struct TaskTimingAggregator {
    // ----- Per-task barrier work (run_play_per_task / run_play_per_play) -----
    /// `merge_dynamic_hostvars` — rebuild the per-task hostvars
    /// snapshot from every host's current ctx. Cheap in practice
    /// (microseconds) but the natural first suspect, so we measure it.
    pub merge_hostvars_ns: AtomicU64,

    // ----- Inside run_task_fanout (controller, not in agent dispatch) -----
    /// JoinSet allocation + per-host spawn loop + RunOnceCoord
    /// allocation. Everything between "decided to dispatch" and the
    /// per-host async tasks actually running.
    pub fanout_setup_ns: AtomicU64,
    /// `apply_per_host_result` — bind register, mark outcome, propagate
    /// failure flags. Runs once per host per task on the controller
    /// after the per-host async completes.
    pub apply_per_host_result_ns: AtomicU64,

    // ----- Inside run_task_on_one_host (per-host, per-task) -----
    /// `apply_task_vars` — render and bind task-scoped `vars:`.
    pub task_vars_ns: AtomicU64,
    /// `eval_when` — render `when:` and parse truthiness.
    pub eval_when_ns: AtomicU64,
    /// `resolve_loop_items` — render `loop:` source to a Vec<JsonValue>.
    pub resolve_loop_items_ns: AtomicU64,
    /// `resolve_target!` block — `become_::effective` + (optional)
    /// `delegate_to` render + `pool.get_or_spawn`. Per loop iteration
    /// when looped.
    pub resolve_target_ns: AtomicU64,
    /// `run_body_with_retries` — agent op dispatch including any
    /// retry-loop delays. Includes the `RunMetrics` agent+rtt window,
    /// so this is NOT controller overhead in isolation. Subtract
    /// `RunMetrics.wall_ns_total` to get controller-side overhead
    /// inside the body call.
    pub body_dispatch_ns: AtomicU64,
    /// Inside `run_op_body`: `render_op` — controller-side Jinja
    /// templating of every task argument (paths, content, sql,
    /// env values, etc.). Builds a fresh template ctx each call,
    /// which clones `WorldVars` including the `hostvars` snapshot.
    pub render_op_ns: AtomicU64,
    /// Subset of `render_op_ns`: time spent in `build_template_ctx`
    /// flattening the per-host variable layers into a BTreeMap.
    pub render_op_build_ctx_ns: AtomicU64,
    /// Subset of `render_op_ns`: time spent in
    /// `resolve_view_var_templates` (the var-of-var fixpoint).
    pub render_op_resolve_ns: AtomicU64,
    /// Subset of `render_op_ns`: everything else — the per-field
    /// `render_str_resolved` calls plus the op-shape match.
    pub render_op_fields_ns: AtomicU64,
    /// Inside `run_op_body`: the actual `run_one_task_op` call —
    /// hand wire op to agent, await response. Should ~match
    /// `RunMetrics.wall_ns_total` for non-composite ops.
    pub wire_dispatch_ns: AtomicU64,
    /// `enqueue_notifies` — render notify names against the current
    /// ctx (handler names are templated).
    pub notify_enqueue_ns: AtomicU64,

    // ----- Counters -----
    /// Tasks that crossed the per-task barrier (incl. when:-false,
    /// no-live-hosts skips, controller-only tasks). Tag-skipped
    /// tasks DO NOT count — they exit before the barrier.
    pub task_barrier_count: AtomicU64,
    /// Per-host task entries — sum over all tasks of `live.len()`.
    /// `host_task_count / task_barrier_count` is the average hosts
    /// per task; useful when comparing the same playbook against
    /// different host counts.
    pub host_task_count: AtomicU64,
    /// Times `run_body_with_retries` was invoked. For non-looped
    /// tasks: == host_task_count. For looped tasks: × loop length.
    pub body_dispatch_count: AtomicU64,
    /// Tasks where `when:` evaluated to false. Useful for "is this
    /// playbook spending most of its time on no-op evals?"
    pub when_false_count: AtomicU64,
}

impl TaskTimingAggregator {
    /// Allocate a fresh aggregator with all counters at zero. Wrap in
    /// `Arc` so per-host walkers can cheaply clone the handle.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            merge_hostvars_ns: AtomicU64::new(0),
            fanout_setup_ns: AtomicU64::new(0),
            apply_per_host_result_ns: AtomicU64::new(0),
            task_vars_ns: AtomicU64::new(0),
            eval_when_ns: AtomicU64::new(0),
            resolve_loop_items_ns: AtomicU64::new(0),
            resolve_target_ns: AtomicU64::new(0),
            body_dispatch_ns: AtomicU64::new(0),
            render_op_ns: AtomicU64::new(0),
            render_op_build_ctx_ns: AtomicU64::new(0),
            render_op_resolve_ns: AtomicU64::new(0),
            render_op_fields_ns: AtomicU64::new(0),
            wire_dispatch_ns: AtomicU64::new(0),
            notify_enqueue_ns: AtomicU64::new(0),
            task_barrier_count: AtomicU64::new(0),
            host_task_count: AtomicU64::new(0),
            body_dispatch_count: AtomicU64::new(0),
            when_false_count: AtomicU64::new(0),
        })
    }

    /// Add a measured duration to a phase counter. `Relaxed` ordering
    /// is sufficient: counters are independent and the only consumer
    /// (`summary`) reads them after the run has fully completed (and
    /// thus after a happens-before via the run's top-level join).
    #[inline]
    pub fn add(&self, field: &AtomicU64, d: Duration) {
        field.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Increment a counter by 1.
    #[inline]
    pub fn incr(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the current counters into a `TimingBreakdown`. Call
    /// after the orchestrator's join — concurrent reads are safe but
    /// won't be self-consistent if invoked mid-run.
    pub fn summary(&self) -> TimingBreakdown {
        let ms = |ns: &AtomicU64| ns.load(Ordering::Relaxed) as f64 / 1e6;
        let count = |c: &AtomicU64| c.load(Ordering::Relaxed);
        TimingBreakdown {
            merge_hostvars_ms: ms(&self.merge_hostvars_ns),
            fanout_setup_ms: ms(&self.fanout_setup_ns),
            apply_per_host_result_ms: ms(&self.apply_per_host_result_ns),
            task_vars_ms: ms(&self.task_vars_ns),
            eval_when_ms: ms(&self.eval_when_ns),
            resolve_loop_items_ms: ms(&self.resolve_loop_items_ns),
            resolve_target_ms: ms(&self.resolve_target_ns),
            body_dispatch_ms: ms(&self.body_dispatch_ns),
            render_op_ms: ms(&self.render_op_ns),
            render_op_build_ctx_ms: ms(&self.render_op_build_ctx_ns),
            render_op_resolve_ms: ms(&self.render_op_resolve_ns),
            render_op_fields_ms: ms(&self.render_op_fields_ns),
            wire_dispatch_ms: ms(&self.wire_dispatch_ns),
            notify_enqueue_ms: ms(&self.notify_enqueue_ns),
            task_barrier_count: count(&self.task_barrier_count),
            host_task_count: count(&self.host_task_count),
            body_dispatch_count: count(&self.body_dispatch_count),
            when_false_count: count(&self.when_false_count),
        }
    }
}

/// Serializable snapshot of [`TaskTimingAggregator`]. Carried on
/// [`crate::orchestrator::RunReport`] so forward-mode runs can ship
/// the remote-side breakdown back to the laptop for display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingBreakdown {
    pub merge_hostvars_ms: f64,
    pub fanout_setup_ms: f64,
    pub apply_per_host_result_ms: f64,
    pub task_vars_ms: f64,
    pub eval_when_ms: f64,
    pub resolve_loop_items_ms: f64,
    pub resolve_target_ms: f64,
    pub body_dispatch_ms: f64,
    pub render_op_ms: f64,
    pub render_op_build_ctx_ms: f64,
    pub render_op_resolve_ms: f64,
    pub render_op_fields_ms: f64,
    pub wire_dispatch_ms: f64,
    pub notify_enqueue_ms: f64,
    pub task_barrier_count: u64,
    pub host_task_count: u64,
    pub body_dispatch_count: u64,
    pub when_false_count: u64,
}

impl TimingBreakdown {
    /// Sum of controller-side phases (everything except `body_dispatch`,
    /// which contains the agent wall already accounted for in
    /// `RunMetrics`). Useful as a single "controller overhead" number
    /// when comparing tuning iterations.
    pub fn controller_ms(&self) -> f64 {
        self.merge_hostvars_ms
            + self.fanout_setup_ms
            + self.apply_per_host_result_ms
            + self.task_vars_ms
            + self.eval_when_ms
            + self.resolve_loop_items_ms
            + self.resolve_target_ms
            + self.notify_enqueue_ms
    }

    /// Render the breakdown to a multi-line human string. Used by the
    /// CLI when `--timing` is passed.
    pub fn format(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "  tasks={tb} host_tasks={ht} body_dispatches={bd} when_false={wf}\n",
            tb = self.task_barrier_count,
            ht = self.host_task_count,
            bd = self.body_dispatch_count,
            wf = self.when_false_count,
        ));
        out.push_str("  per-task barrier:\n");
        out.push_str(&format!("    merge_hostvars        {:>9.2} ms\n", self.merge_hostvars_ms));
        out.push_str(&format!("    fanout_setup          {:>9.2} ms\n", self.fanout_setup_ms));
        out.push_str(&format!("    apply_per_host_result {:>9.2} ms\n", self.apply_per_host_result_ms));
        out.push_str("  per host-task (inside fanout):\n");
        out.push_str(&format!("    task_vars             {:>9.2} ms\n", self.task_vars_ms));
        out.push_str(&format!("    eval_when             {:>9.2} ms\n", self.eval_when_ms));
        out.push_str(&format!("    resolve_loop_items    {:>9.2} ms\n", self.resolve_loop_items_ms));
        out.push_str(&format!("    resolve_target        {:>9.2} ms\n", self.resolve_target_ms));
        out.push_str(&format!("    body_dispatch         {:>9.2} ms  (= render_op + wire_dispatch + composite/post)\n", self.body_dispatch_ms));
        out.push_str(&format!("      render_op           {:>9.2} ms  (controller Jinja)\n", self.render_op_ms));
        out.push_str(&format!("        build_ctx         {:>9.2} ms  (flatten layers + clone cached JSON)\n", self.render_op_build_ctx_ms));
        out.push_str(&format!("        resolve           {:>9.2} ms  (var-of-var fixpoint)\n", self.render_op_resolve_ms));
        out.push_str(&format!("        fields            {:>9.2} ms  (per-field render_str)\n", self.render_op_fields_ms));
        out.push_str(&format!("      wire_dispatch       {:>9.2} ms  (~ RunMetrics agent+rtt)\n", self.wire_dispatch_ms));
        out.push_str(&format!("    notify_enqueue        {:>9.2} ms\n", self.notify_enqueue_ms));
        out.push_str(&format!(
            "  controller-side overhead total: {:.2} ms\n",
            self.controller_ms(),
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_accumulates_and_summary_converts_to_ms() {
        let agg = TaskTimingAggregator::new();
        agg.add(&agg.merge_hostvars_ns, Duration::from_micros(1500));
        agg.add(&agg.merge_hostvars_ns, Duration::from_micros(2500));
        let s = agg.summary();
        // 4000 us = 4 ms.
        assert!((s.merge_hostvars_ms - 4.0).abs() < 1e-6);
    }

    #[test]
    fn counters_increment() {
        let agg = TaskTimingAggregator::new();
        for _ in 0..5 {
            agg.incr(&agg.task_barrier_count);
        }
        assert_eq!(agg.summary().task_barrier_count, 5);
    }

    #[test]
    fn controller_ms_excludes_body_dispatch() {
        let agg = TaskTimingAggregator::new();
        agg.add(&agg.merge_hostvars_ns, Duration::from_millis(1));
        agg.add(&agg.body_dispatch_ns, Duration::from_millis(100));
        agg.add(&agg.resolve_target_ns, Duration::from_millis(2));
        let s = agg.summary();
        // body_dispatch_ms (100) must NOT be in controller_ms.
        assert!((s.controller_ms() - 3.0).abs() < 1e-6);
    }

    #[test]
    fn format_includes_all_phases() {
        let agg = TaskTimingAggregator::new();
        agg.add(&agg.merge_hostvars_ns, Duration::from_millis(1));
        let s = agg.summary().format();
        for needle in [
            "merge_hostvars",
            "fanout_setup",
            "apply_per_host_result",
            "task_vars",
            "eval_when",
            "resolve_loop_items",
            "resolve_target",
            "body_dispatch",
            "notify_enqueue",
            "controller-side overhead total",
        ] {
            assert!(s.contains(needle), "missing phase {needle} in:\n{s}");
        }
    }
}
