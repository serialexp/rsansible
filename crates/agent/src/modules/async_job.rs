//! `OpAsyncStart` + `OpAsyncStatus` — fire-and-forget jobs and polling.
//!
//! Maps Ansible's `async: N, poll: M` pattern. `OpAsyncStart` wraps an
//! inner `Op`, spawns it on a background task, and returns immediately
//! with an envelope carrying the `ansible_job_id`. The controller later
//! issues `OpAsyncStatus { job_id }` to harvest results.
//!
//! Lifetime: the job table is purely in-memory on the agent process. If
//! the agent disconnects, every job goes away with it. That's
//! intentional — rsansible's agent is push-and-execute, not a daemon,
//! so we don't need durable async semantics. The controller must finish
//! polling before it disconnects.
//!
//! Capture model: the inner op runs against a "virtual" Sender backed
//! by an mpsc channel. As the inner module emits TaskProgress /
//! TaskDone / TaskError, the spawned watcher task stashes the bytes
//! into a `JobEntry`. On the eventual `OpAsyncStatus` we serialize the
//! entry into the response envelope.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rsansible_wire::generated::{OpAsyncStartOutput, OpAsyncStatusOutput};
use rsansible_wire::msg::{self, err, now_unix_ns, stream as wire_stream};
use rsansible_wire::{Message, Op};
use serde_json::{Map, Value};
use tokio::sync::mpsc;

use super::{dispatch, emit_error, Context};
use crate::writer::Sender;

#[derive(Default, Debug, Clone)]
pub struct JobEntryInner {
    #[allow(dead_code)]
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub rc: Option<i32>,
    pub changed: bool,
    pub skipped: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub error: Option<(u8, String)>,
}

#[derive(Clone, Default)]
pub struct JobTable(Arc<Mutex<HashMap<u32, Arc<Mutex<JobEntryInner>>>>>);

impl JobTable {
    pub fn new() -> Self {
        Self::default()
    }

    fn create(&self, job_id: u32, started_at: u64) -> Arc<Mutex<JobEntryInner>> {
        let e = Arc::new(Mutex::new(JobEntryInner {
            started_at,
            ..Default::default()
        }));
        self.0.lock().unwrap().insert(job_id, e.clone());
        e
    }

    fn get(&self, job_id: u32) -> Option<Arc<Mutex<JobEntryInner>>> {
        self.0.lock().unwrap().get(&job_id).cloned()
    }
}

pub async fn run_start(
    ctx: &Context,
    seq: u32,
    op: OpAsyncStartOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    let inner: Op = *op.inner;
    let timeout_ms = op.timeout_ms;
    let table = ctx.jobs.clone();
    let entry = table.create(seq, started_unix_ns);

    if !check_mode {
        // Inner ctx: capturing writer + shared job table.
        let (tx, mut rx) = mpsc::channel::<Message>(64);
        let inner_ctx = Context {
            writer: Sender(tx),
            jobs: table.clone(),
        };
        let entry_for_task = entry.clone();
        tokio::spawn(async move {
            // `dispatch` returns a `Pin<Box<dyn Future + Send>>` so the
            // recursive edge (dispatch → run_start → spawn(dispatch))
            // has a concrete Send return type. `tokio::pin!` lets us
            // poll it via `&mut` inside the select.
            let mut dispatch_fut = dispatch(&inner_ctx, seq, inner, false);

            // Per-iter sleep future so the select! has a third arm when
            // `timeout_ms == 0` (then we wait forever on `pending`).
            let deadline = if timeout_ms > 0 {
                Some(
                    tokio::time::Instant::now()
                        + std::time::Duration::from_millis(timeout_ms as u64),
                )
            } else {
                None
            };

            loop {
                tokio::select! {
                    biased;
                    maybe_msg = rx.recv() => {
                        if let Some(m) = maybe_msg {
                            stash_message(&entry_for_task, m);
                        }
                        // None means inner ctx's tx clone dropped; the
                        // dispatch future is about to resolve. Fall
                        // through to the dispatch arm next iteration.
                    }
                    res = &mut dispatch_fut => {
                        // Drain anything queued before the close.
                        while let Ok(m) = rx.try_recv() {
                            stash_message(&entry_for_task, m);
                        }
                        let mut g = entry_for_task.lock().unwrap();
                        if g.finished_at.is_none() {
                            g.finished_at = Some(now_unix_ns());
                        }
                        if g.rc.is_none() && g.error.is_none() {
                            // Dispatch returned without emitting either
                            // TaskDone or TaskError — that's an internal
                            // contract violation.
                            g.error = Some((
                                err::INTERNAL,
                                format!(
                                    "async inner dispatch returned without terminal: {res:?}"
                                ),
                            ));
                        }
                        return;
                    }
                    _ = async {
                        match deadline {
                            Some(d) => tokio::time::sleep_until(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        let mut g = entry_for_task.lock().unwrap();
                        g.finished_at = Some(now_unix_ns());
                        g.error = Some((
                            err::TIMEOUT,
                            format!("async job exceeded timeout_ms={timeout_ms}"),
                        ));
                        return;
                    }
                }
            }
        });
    } else {
        // Check mode: don't actually run anything. Mark as finished
        // immediately with a synthetic OK so a follow-up status poll
        // returns something sensible.
        let mut g = entry.lock().unwrap();
        g.finished_at = Some(started_unix_ns);
        g.rc = Some(0);
        g.skipped = true;
    }

    // Synthesize the start envelope.
    let mut envelope = Map::new();
    envelope.insert("ansible_job_id".into(), Value::from(seq));
    envelope.insert("started".into(), Value::from(1));
    envelope.insert("finished".into(), Value::from(0));
    envelope.insert("results_file".into(), Value::String(String::new()));
    let bytes = serde_json::to_vec(&Value::Object(envelope))?;
    ctx.emit(msg::task_progress(seq, wire_stream::STDOUT, bytes))
        .await;
    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        false,
        check_mode,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

fn stash_message(entry: &Arc<Mutex<JobEntryInner>>, m: Message) {
    let mut g = entry.lock().unwrap();
    match m {
        Message::TaskProgress(p) => match p.stream {
            x if x == wire_stream::STDOUT => g.stdout.extend_from_slice(&p.chunk),
            x if x == wire_stream::STDERR => g.stderr.extend_from_slice(&p.chunk),
            _ => {}
        },
        Message::TaskDone(d) => {
            g.rc = Some(d.exit_code);
            g.changed = d.changed != 0;
            g.skipped = d.skipped != 0;
            if g.finished_at.is_none() {
                g.finished_at = Some(d.finished_unix_ns);
            }
        }
        Message::TaskError(e) => {
            g.error = Some((e.code, e.message));
            if g.finished_at.is_none() {
                g.finished_at = Some(now_unix_ns());
            }
        }
        _ => {}
    }
}

pub async fn run_status(
    ctx: &Context,
    seq: u32,
    op: OpAsyncStatusOutput,
    _check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    let Some(entry) = ctx.jobs.get(op.job_id) else {
        emit_error(
            ctx,
            seq,
            err::NOT_FOUND,
            format!("unknown ansible_job_id {}", op.job_id),
        )
        .await;
        return Ok(());
    };
    let g = entry.lock().unwrap().clone();
    drop(entry);

    let finished = g.finished_at.is_some();
    let mut envelope = Map::new();
    envelope.insert("ansible_job_id".into(), Value::from(op.job_id));
    envelope.insert("started".into(), Value::from(1));
    envelope.insert(
        "finished".into(),
        Value::from(if finished { 1 } else { 0 }),
    );

    if finished {
        envelope.insert("rc".into(), Value::from(g.rc.unwrap_or(-1)));
        envelope.insert("changed".into(), Value::Bool(g.changed));
        if let Some((code, message)) = &g.error {
            envelope.insert("failed".into(), Value::Bool(true));
            envelope.insert("error_code".into(), Value::from(*code));
            envelope.insert("msg".into(), Value::String(message.clone()));
        }
        // Lift inner envelope keys (if the inner module emitted a single
        // JSON object on stdout). Use `entry().or_insert` so our own
        // top-level keys (ansible_job_id, rc, changed, …) shadow any
        // collisions from the inner envelope.
        if !g.stdout.is_empty() {
            let trimmed = trim_to_json(&g.stdout);
            if let Ok(Value::Object(inner)) = serde_json::from_str::<Value>(trimmed) {
                for (k, v) in inner {
                    envelope.entry(k).or_insert(v);
                }
            } else {
                envelope.insert(
                    "stdout".into(),
                    Value::String(String::from_utf8_lossy(&g.stdout).into_owned()),
                );
            }
        }
        if !g.stderr.is_empty() {
            envelope.insert(
                "stderr".into(),
                Value::String(String::from_utf8_lossy(&g.stderr).into_owned()),
            );
        }
    }

    let changed = finished && g.changed;
    let bytes = serde_json::to_vec(&Value::Object(envelope))?;
    ctx.emit(msg::task_progress(seq, wire_stream::STDOUT, bytes))
        .await;
    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        changed,
        false,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

fn trim_to_json(bytes: &[u8]) -> &str {
    // Inner stdout is typically a single JSON envelope, possibly with
    // trailing whitespace. UTF-8-decode lossily? No, just bail to "" so
    // the parser fails and we fall back to the stdout-as-string path.
    std::str::from_utf8(bytes).map(|s| s.trim()).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_table_round_trip() {
        let t = JobTable::new();
        let e = t.create(7, 100);
        e.lock().unwrap().rc = Some(0);
        assert_eq!(t.get(7).unwrap().lock().unwrap().rc, Some(0));
        assert!(t.get(8).is_none());
    }

    #[test]
    fn stash_progress_and_done_into_entry() {
        let t = JobTable::new();
        let e = t.create(1, 50);
        stash_message(
            &e,
            msg::task_progress(1, wire_stream::STDOUT, b"hello".to_vec()),
        );
        stash_message(
            &e,
            msg::task_progress(1, wire_stream::STDERR, b"warn".to_vec()),
        );
        stash_message(&e, msg::task_done(1, 0, true, false, 50, 60));
        let g = e.lock().unwrap();
        assert_eq!(g.stdout, b"hello");
        assert_eq!(g.stderr, b"warn");
        assert_eq!(g.rc, Some(0));
        assert!(g.changed);
        assert_eq!(g.finished_at, Some(60));
    }

    /// End-to-end: dispatch OpAsyncStart wrapping a shell op, then poll
    /// OpAsyncStatus until we see finished=1 and rc=0.
    #[tokio::test]
    async fn start_then_status_round_trip_runs_inner_shell() {
        use rsansible_wire::msg as wmsg;
        use rsansible_wire::Message;
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<Message>(128);
        let ctx = Context::new(crate::writer::Sender(tx));

        // Inner: `sh -c 'echo hi'`. Fast — no real timing dependency.
        let inner = wmsg::op_shell("echo hi".into(), 0);
        let start_op = match wmsg::op_async_start(0, inner) {
            Op::OpAsyncStart(s) => s,
            _ => unreachable!(),
        };
        // Run start; this emits the "started" envelope and spawns the
        // inner task.
        run_start(&ctx, 7, start_op, false).await.unwrap();

        // Poll until finished.
        let mut got_finished = false;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let status_op = match wmsg::op_async_status(7) {
                Op::OpAsyncStatus(s) => s,
                _ => unreachable!(),
            };
            run_status(&ctx, 100, status_op, false).await.unwrap();
            // Drain anything emitted so we can inspect the latest envelope.
            let mut latest = None;
            while let Ok(m) = rx.try_recv() {
                if let Message::TaskProgress(p) = m {
                    if p.seq == 100 {
                        latest = Some(serde_json::from_slice::<Value>(&p.chunk).unwrap());
                    }
                }
            }
            if let Some(env) = latest {
                if env["finished"] == 1 {
                    assert_eq!(env["ansible_job_id"], 7);
                    assert_eq!(env["rc"], 0);
                    // Inner shell op emits its own envelope on stdout
                    // (exit_code + stdout). The lift folds those in.
                    got_finished = true;
                    break;
                }
            }
        }
        assert!(got_finished, "async job did not finish within budget");
    }

    #[test]
    fn stash_error_records_code_and_message() {
        let t = JobTable::new();
        let e = t.create(2, 0);
        stash_message(&e, msg::task_error(2, err::TIMEOUT, "boom".into()));
        let g = e.lock().unwrap();
        assert_eq!(g.error.as_ref().map(|(c, _)| *c), Some(err::TIMEOUT));
        assert!(g.finished_at.is_some());
    }
}
