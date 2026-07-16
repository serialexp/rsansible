//! Structured run reporting.
//!
//! rsansible historically only produced human-formatted stderr output plus an
//! aggregate [`crate::orchestrator::RunReport`] (per-host outcome + counters).
//! This module adds a per-(host, task) structured event stream so a run can be
//! persisted, uploaded, or streamed to an external consumer (e.g. a Gothab
//! operation-run view) without scraping stderr.
//!
//! The seam is the [`Reporter`] trait: the orchestrator emits one
//! [`TaskReport`] per task-on-host as it completes (via `on_task`) and a final
//! [`RunOutcome`] at end-of-run (via `finish`). Two impls ship here — a no-op
//! [`NullReporter`] (the default, so behaviour is unchanged unless a reporter
//! is requested) and a newline-delimited-JSON [`JsonReporter`]. The trait is
//! deliberately object-safe and `Send + Sync`: it rides on `HostCtx` the same
//! way the timing aggregator does, and a later phase can add a reporter impl
//! that streams events over HTTP to Gothab without touching the orchestrator.
//!
//! Field vocabulary mirrors Ansible on purpose (`ok`/`changed`/`skipped`/
//! `failed`/`unreachable`, `rc`, a `{before, after}`-shaped diff) so the data
//! reads the same to anyone who knows Ansible. See `ANSIBLE_COMPAT.md`.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Ansible-vocabulary status for one (host, task) result.
///
/// `Ok` vs `Changed` is the usual Ansible split (a task that ran but reported
/// no change vs one that mutated state / would mutate under `--check`).
/// `Skipped` covers both `when: false` and a check-mode module that declined
/// to act. `Failed`/`Unreachable` mirror Ansible's terminal host states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Ok,
    Changed,
    Skipped,
    Failed,
    Unreachable,
}

/// Lightweight per-task module result, captured on `HostCtx` as each task
/// completes and folded into a [`TaskReport`] at the emission funnel. Kept
/// separate from the full [`crate::exec_ctx::RegisterValue`] so we don't clone
/// (potentially large) stdout/stderr into the reporting path.
#[derive(Debug, Clone, Default)]
pub struct TaskRunSummary {
    /// Module exit code. For looped tasks, the last iteration's rc.
    pub rc: i32,
    /// Wall time attributed to the task body. For looped tasks, the sum of
    /// per-iteration durations.
    pub duration_ms: u64,
    /// Serialized diff payload for a changed file, in Ansible's `{before,
    /// after, before_header, after_header}` JSON shape (or a JSON array of
    /// those for a looped task with several changed files). Populated when the
    /// run requested `--diff` and a diffing module (write_file / copy) changed
    /// a file; `None` otherwise. Owned by rsansible — the consumer stores it
    /// verbatim (gothab) and can render a unified diff from it (see
    /// [`crate::diff_render`]).
    pub diff: Option<String>,
}

/// One structured (host, task) result event.
#[derive(Debug, Clone, Serialize)]
pub struct TaskReport {
    /// The `name:` of the play this task ran under.
    pub play: String,
    /// Inventory hostname the task ran against.
    pub host: String,
    /// The task's `name:` (empty string if the task was unnamed).
    pub task: String,
    pub status: TaskStatus,
    /// Convenience mirror: `true` iff `status == Changed`. Kept as an explicit
    /// field so consumers grouping/filtering don't have to special-case the
    /// enum.
    pub changed: bool,
    /// Whether this task ran under `--check` (dry-run). A `changed` under check
    /// means "would change".
    pub check_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rc: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    /// Failure reason, present only for `Failed`/`Unreachable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Terminal per-host state for the run-end record. Mirrors
/// [`crate::orchestrator::HostOutcome`] but lives here so the [`Reporter`]
/// trait has no dependency back on the orchestrator (keeps the module graph
/// acyclic).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostState {
    Ok,
    Failed { task: String, reason: String },
    Unreachable { reason: String },
    NotTargeted,
}

/// Run-end summary handed to [`Reporter::finish`].
#[derive(Debug, Clone, Serialize)]
pub struct RunOutcome {
    pub check_mode: bool,
    pub stopped_early: bool,
    pub tasks_ok: u64,
    pub tasks_changed: u64,
    pub tasks_skipped: u64,
    pub hosts: BTreeMap<String, HostState>,
}

/// Sink for structured run events. Object-safe and `Send + Sync` so it can
/// ride on `HostCtx` (shared `Arc`) and be called from the async dispatch
/// path. Both methods default to no-ops so an impl can opt into only the
/// events it cares about.
pub trait Reporter: Send + Sync {
    /// Called once per task-on-host as it completes, in the order results are
    /// reaped by the orchestrator (serialized — never concurrently).
    fn on_task(&self, _report: &TaskReport) {}
    /// Called once at end-of-run with the aggregate outcome.
    fn finish(&self, _outcome: &RunOutcome) {}
}

/// `Arc<dyn Reporter>` is stored on `HostCtx`, which derives `Debug`; give the
/// trait object a trivial `Debug` so that derive keeps working without leaking
/// reporter internals.
impl std::fmt::Debug for dyn Reporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<reporter>")
    }
}

/// The default reporter: does nothing. Installed unless the caller requests a
/// real one, so a run with no `--report` behaves exactly as before.
pub struct NullReporter;
impl Reporter for NullReporter {}

/// A tagged wrapper so each NDJSON line carries a discriminator without the
/// consumer having to infer the record kind from its shape.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record<'a> {
    Task(&'a TaskReport),
    Run(&'a RunOutcome),
}

/// Newline-delimited-JSON reporter. Emits one object per line — `{"type":
/// "task", …}` per task as it finishes, then a final `{"type": "run", …}`.
/// Streaming per line (rather than buffering a single array) means a run that
/// dies mid-flight still leaves a partial, valid-per-line artifact — the same
/// checkpoint property the eventual push path wants.
pub struct JsonReporter {
    w: Mutex<Box<dyn Write + Send>>,
}

impl JsonReporter {
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            w: Mutex::new(writer),
        }
    }

    /// Build a reporter writing to `path`, or to stdout when `path` is `-`.
    pub fn to_path(path: &std::path::Path) -> std::io::Result<Self> {
        let writer: Box<dyn Write + Send> = if path.as_os_str() == "-" {
            Box::new(std::io::stdout())
        } else {
            Box::new(std::io::BufWriter::new(std::fs::File::create(path)?))
        };
        Ok(Self::new(writer))
    }

    fn write_record(&self, rec: &Record<'_>) {
        let Ok(mut w) = self.w.lock() else {
            return;
        };
        // A reporting-path IO error must not abort the run — surface it once on
        // stderr and carry on. Losing a report line is strictly better than
        // failing an otherwise-successful converge because a log file filled up.
        let res = serde_json::to_writer(&mut *w, rec)
            .map_err(std::io::Error::from)
            .and_then(|()| {
                w.write_all(b"\n")?;
                w.flush()
            });
        if let Err(e) = res {
            eprintln!("report: failed to write JSON record: {e}");
        }
    }
}

impl Reporter for JsonReporter {
    fn on_task(&self, report: &TaskReport) {
        self.write_record(&Record::Task(report));
    }
    fn finish(&self, outcome: &RunOutcome) {
        self.write_record(&Record::Run(outcome));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A reporter that captures events in memory, for tests.
    #[derive(Default)]
    struct CapturingReporter {
        tasks: Mutex<Vec<TaskReport>>,
        finished: Mutex<Option<RunOutcome>>,
    }
    impl Reporter for CapturingReporter {
        fn on_task(&self, report: &TaskReport) {
            self.tasks.lock().unwrap().push(report.clone());
        }
        fn finish(&self, outcome: &RunOutcome) {
            *self.finished.lock().unwrap() = Some(outcome.clone());
        }
    }

    fn sample_task() -> TaskReport {
        TaskReport {
            play: "converge".into(),
            host: "db-1".into(),
            task: "install patroni".into(),
            status: TaskStatus::Changed,
            changed: true,
            check_mode: false,
            rc: Some(0),
            duration_ms: Some(41),
            diff: None,
            reason: None,
        }
    }

    #[test]
    fn task_json_uses_ansible_vocabulary_and_omits_empty_options() {
        let t = sample_task();
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["status"], "changed");
        assert_eq!(v["changed"], true);
        assert_eq!(v["rc"], 0);
        assert_eq!(v["duration_ms"], 41);
        // None-valued options are omitted, not rendered as null.
        assert!(v.get("diff").is_none());
        assert!(v.get("reason").is_none());
    }

    #[test]
    fn ndjson_reporter_writes_one_tagged_line_per_event() {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        // A Write shim over the shared buffer so we can inspect it after.
        struct Shim(Arc<Mutex<Vec<u8>>>);
        impl Write for Shim {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let reporter = JsonReporter::new(Box::new(Shim(buf.clone())));
        reporter.on_task(&sample_task());
        reporter.finish(&RunOutcome {
            check_mode: false,
            stopped_early: false,
            tasks_ok: 1,
            tasks_changed: 1,
            tasks_skipped: 0,
            hosts: BTreeMap::from([("db-1".to_string(), HostState::Ok)]),
        });

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "one line per event, got: {out:?}");
        let l0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(l0["type"], "task");
        assert_eq!(l0["host"], "db-1");
        let l1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(l1["type"], "run");
        assert_eq!(l1["hosts"]["db-1"]["state"], "ok");
    }

    #[test]
    fn null_reporter_is_inert() {
        let r = NullReporter;
        r.on_task(&sample_task());
        r.finish(&RunOutcome {
            check_mode: true,
            stopped_early: false,
            tasks_ok: 0,
            tasks_changed: 0,
            tasks_skipped: 0,
            hosts: BTreeMap::new(),
        });
        // Nothing to assert beyond "does not panic"; the trait defaults are
        // genuine no-ops.
    }

    #[test]
    fn capturing_reporter_roundtrips_via_trait_object() {
        let cap = Arc::new(CapturingReporter::default());
        let dyn_reporter: Arc<dyn Reporter> = cap.clone();
        dyn_reporter.on_task(&sample_task());
        assert_eq!(cap.tasks.lock().unwrap().len(), 1);
        assert_eq!(cap.tasks.lock().unwrap()[0].host, "db-1");
    }
}
