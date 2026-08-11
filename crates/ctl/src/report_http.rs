//! HTTP push-sink reporter.
//!
//! A [`crate::report::Reporter`] impl that streams a run's per-`(host, task)`
//! results to a **generic HTTP ingestion endpoint** as tasks finish, so a
//! long run is observable live and a controller that dies mid-run leaves a
//! persisted *partial* on the server (the checkpoint property).
//!
//! This module is deliberately **vendor-neutral**: it speaks a small,
//! documented JSON protocol (see `PUSH_PROTOCOL.md`) and knows nothing about
//! any particular server. Any service that implements the four endpoints —
//! `open`, `items`, `finalize`, `renew` — can consume rsansible runs.
//!
//! ## Shape
//!
//! - [`HttpReporter::open`] performs the `POST {base}/runs` handshake up front
//!   (async, before the converge) so a bad URL / token / scope fails the run
//!   fast, then spawns a background **worker** task.
//! - [`Reporter::on_task`] (sync, called serially by the orchestrator) maps the
//!   [`crate::report::TaskReport`] to a wire [`Item`], stamps a monotonic
//!   `sequence`, and hands it to the worker over an unbounded channel — it never
//!   blocks the converge on network I/O.
//! - The worker batches items, `POST`s them under the per-run **lease token**
//!   with bounded retry + backoff (buffer retained on transient failure so a
//!   network blip doesn't lose the run), and renews the lease on a timer.
//! - [`Reporter::finish`] stashes the [`crate::report::RunOutcome`] and signals
//!   the worker to flush + `POST {base}/runs/{id}/finalize`.
//! - [`HttpReporter::join`] (awaited by `main` after the run) drains the worker
//!   so the process never exits with unsent results. A reporting failure is
//!   logged, never fatal — losing a report line must not flip an otherwise
//!   successful converge's exit code (same posture as `JsonReporter`).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::report::{Reporter, RunOutcome, TaskReport, TaskStatus};

// ── Wire protocol types (the contract; see PUSH_PROTOCOL.md) ───────────────

/// Run mode. `apply` is a real converge; `check` is a dry run (`--check`),
/// stored identically but flagged so "what would the last preview have
/// changed?" is answerable from history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Apply,
    Check,
}

/// `POST {base}/runs` request body — opens a run and identifies which
/// project/stack it belongs to on the server. Authenticated with the operator
/// token as a `Bearer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRequest {
    /// Owning namespace/org on the server.
    pub namespace: String,
    /// Project = the playbook/repo scope.
    pub project: String,
    /// Stack = the target environment/inventory (e.g. `prod`).
    pub stack: String,
    pub mode: RunMode,
    /// Playbook file name, for display. Best-effort.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbook: Option<String>,
    /// Inventory name/path, for display. Best-effort.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory: Option<String>,
}

/// `POST {base}/runs` response — the opaque run id and the lease that
/// authorizes all subsequent streaming writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenResponse {
    pub run_id: String,
    pub lease_token: String,
    /// RFC3339 lease expiry (informational; the client renews on
    /// `renew_interval_secs`, not by parsing this).
    #[serde(default)]
    pub lease_expires_at: Option<String>,
    /// How often the client should `POST …/renew`, in seconds. The server
    /// picks a value comfortably inside the lease window.
    pub renew_interval_secs: u64,
}

/// The `dimensions` map of an item — the pivotable coordinates of one
/// `(task, host)` atom. `host` and `task` are always present; `play`/`role`
/// when known. Kept as explicit fields (not a free `Map`) so the wire shape is
/// stable and self-documenting; the server stores it as an opaque JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dimensions {
    pub host: String,
    pub task: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub play: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// One `(host, task)` result on the wire. Mirrors [`TaskReport`] but is the
/// server-facing shape: a monotonic `sequence`, the pivot `dimensions`, and an
/// inline `diff` the server splits into its event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    /// Monotonic dispatch order within the run. Also the sequence the server
    /// assigns to this item's diff event, if any.
    pub sequence: u32,
    pub dimensions: Dimensions,
    /// Display label (the task name; empty if unnamed).
    pub name: String,
    pub status: TaskStatus,
    pub changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rc: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Ansible-shaped `{before, after, before_header, after_header}` diff (or a
    /// JSON array of those for a looped task), serialized as a string exactly as
    /// rsansible computed it. The server stores it verbatim in its event stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

/// `POST {base}/runs/{id}/items` request body — a batch of item upserts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemsRequest {
    pub items: Vec<Item>,
}

/// Terminal run status for finalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Succeeded,
    Failed,
}

/// Aggregate per-status counts sent on finalize.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunSummary {
    pub ok: u64,
    pub changed: u64,
    pub skipped: u64,
    pub failed: u64,
    pub unreachable: u64,
}

/// `POST {base}/runs/{id}/finalize` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeRequest {
    pub status: RunStatus,
    pub summary: RunSummary,
    pub stopped_early: bool,
}

/// `POST {base}/runs/{id}/renew` response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewResponse {
    #[serde(default)]
    pub lease_expires_at: Option<String>,
}

// ── Configuration ──────────────────────────────────────────────────────────

/// Everything the push sink needs, assembled from the CLI flags in `main`.
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// Base ingestion URL; the client appends `/runs`, `/runs/{id}/items`, …
    pub base_url: String,
    /// Operator bearer token for the `open` handshake.
    pub token: String,
    pub namespace: String,
    pub project: String,
    pub stack: String,
    pub mode: RunMode,
    pub playbook: Option<String>,
    pub inventory: Option<String>,
}

// ── Worker protocol ─────────────────────────────────────────────────────────

/// Messages the sync reporter methods hand to the async worker.
enum Msg {
    Item(Box<Item>),
    /// End of run: flush remaining items, then POST finalize.
    Finalize(Box<FinalizeRequest>),
}

/// Flush the item buffer whenever it reaches this many entries, so a big run
/// doesn't grow an unbounded in-memory backlog between timer ticks.
const BATCH_MAX: usize = 64;
/// Otherwise flush at least this often, so a slow trickle of tasks still lands
/// promptly.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
/// Bounded retry attempts for a single POST before giving up on that batch (the
/// items stay buffered and are retried on the next flush regardless).
const MAX_RETRIES: u32 = 4;

// ── HttpReporter ────────────────────────────────────────────────────────────

/// The push-sink reporter. Cloneable handle over the worker channel.
pub struct HttpReporter {
    tx: UnboundedSender<Msg>,
    seq: AtomicU32,
    /// The spawned worker; taken by [`Self::join`].
    worker: Mutex<Option<JoinHandle<()>>>,
    run_id: String,
}

impl HttpReporter {
    /// Perform the `open` handshake and spawn the worker. Async because the
    /// handshake is a real request — a bad URL/token/scope fails here, before
    /// the converge starts.
    pub async fn open(cfg: PushConfig) -> Result<Arc<Self>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("build HTTP client for --report-url")?;

        let base = cfg.base_url.trim_end_matches('/').to_string();
        let open_body = OpenRequest {
            namespace: cfg.namespace.clone(),
            project: cfg.project.clone(),
            stack: cfg.stack.clone(),
            mode: cfg.mode,
            playbook: cfg.playbook.clone(),
            inventory: cfg.inventory.clone(),
        };

        let resp = client
            .post(format!("{base}/runs"))
            .bearer_auth(&cfg.token)
            .json(&open_body)
            .send()
            .await
            .with_context(|| format!("open run at {base}/runs"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("open run failed: HTTP {status}: {body}");
        }
        let open: OpenResponse = resp.json().await.context("decode open-run response")?;

        let (tx, rx) = unbounded_channel::<Msg>();
        let worker = Worker {
            client,
            base,
            run_id: open.run_id.clone(),
            lease_token: open.lease_token,
            renew_interval: Duration::from_secs(open.renew_interval_secs.max(1)),
        };
        let handle = tokio::spawn(worker.run(rx));

        Ok(Arc::new(Self {
            tx,
            seq: AtomicU32::new(0),
            worker: Mutex::new(Some(handle)),
            run_id: open.run_id,
        }))
    }

    /// The server-assigned run id (useful for a "view your run at …" hint).
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Close the channel and await the worker so no results are lost on exit.
    /// Called by `main` after `orchestrator::run` returns. Never propagates a
    /// reporting error as a run failure — logs and moves on.
    pub async fn join(&self) {
        // Dropping the sender signals the worker's recv loop to drain and exit.
        // We can't move `tx` out of `&self`, so rely on `finish` having sent the
        // Finalize marker; the worker exits after handling it. If `finish` was
        // never called (run panicked before end), the channel closes when the
        // last `Arc<HttpReporter>` drops.
        let handle = self.worker.lock().await.take();
        if let Some(handle) = handle {
            if let Err(e) = handle.await {
                tracing::warn!("report push worker panicked: {e}");
            }
        }
    }
}

impl Reporter for HttpReporter {
    fn on_task(&self, report: &TaskReport) {
        let sequence = self.seq.fetch_add(1, Ordering::Relaxed);
        let item = Item {
            sequence,
            dimensions: Dimensions {
                host: report.host.clone(),
                task: report.task.clone(),
                play: (!report.play.is_empty()).then(|| report.play.clone()),
                role: None,
            },
            name: report.task.clone(),
            status: report.status,
            changed: report.changed,
            // rsansible carries skew-immune wall times on the wire but the
            // reporter surfaces only a duration today; timestamps are optional
            // in the protocol and filled once the reporter threads them through.
            started_at: None,
            finished_at: None,
            rc: report.rc,
            error: report.reason.clone(),
            diff: report.diff.clone(),
        };
        // Unbounded send never blocks; a closed channel (worker gone) is a
        // dropped line, which is acceptable for the reporting path.
        let _ = self.tx.send(Msg::Item(Box::new(item)));
    }

    fn finish(&self, outcome: &RunOutcome) {
        let status = if outcome.stopped_early || host_failed(outcome) {
            RunStatus::Failed
        } else {
            RunStatus::Succeeded
        };
        let summary = RunSummary {
            ok: outcome.tasks_ok,
            changed: outcome.tasks_changed,
            skipped: outcome.tasks_skipped,
            // The RunOutcome aggregates task counts for ok/changed/skipped and
            // per-host terminal state for failed/unreachable; derive host-level
            // failure/unreachable counts from the hosts map.
            failed: outcome
                .hosts
                .values()
                .filter(|h| matches!(h, crate::report::HostState::Failed { .. }))
                .count() as u64,
            unreachable: outcome
                .hosts
                .values()
                .filter(|h| matches!(h, crate::report::HostState::Unreachable { .. }))
                .count() as u64,
        };
        let fin = FinalizeRequest {
            status,
            summary,
            stopped_early: outcome.stopped_early,
        };
        let _ = self.tx.send(Msg::Finalize(Box::new(fin)));
    }
}

/// True iff any host ended in a terminal failure/unreachable state.
fn host_failed(outcome: &RunOutcome) -> bool {
    outcome.hosts.values().any(|h| {
        matches!(
            h,
            crate::report::HostState::Failed { .. } | crate::report::HostState::Unreachable { .. }
        )
    })
}

impl std::fmt::Debug for HttpReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpReporter")
            .field("run_id", &self.run_id)
            .finish_non_exhaustive()
    }
}

// ── Worker ──────────────────────────────────────────────────────────────────

struct Worker {
    client: reqwest::Client,
    base: String,
    run_id: String,
    lease_token: String,
    renew_interval: Duration,
}

impl Worker {
    /// Drain the channel: batch items, flush on size/interval, renew the lease
    /// on a timer, and on the Finalize marker flush the tail then POST finalize.
    async fn run(self, mut rx: tokio::sync::mpsc::UnboundedReceiver<Msg>) {
        let mut buf: Vec<Item> = Vec::new();
        let mut flush_timer = tokio::time::interval(FLUSH_INTERVAL);
        flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut renew_timer = tokio::time::interval(self.renew_interval);
        // The first tick of each interval fires immediately; skip it so we
        // don't renew/flush before there's anything to do.
        renew_timer.tick().await;
        flush_timer.tick().await;

        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(Msg::Item(item)) => {
                        buf.push(*item);
                        if buf.len() >= BATCH_MAX {
                            self.flush_items(&mut buf).await;
                        }
                    }
                    Some(Msg::Finalize(fin)) => {
                        // Flush everything still buffered, then finalize.
                        self.flush_items(&mut buf).await;
                        self.finalize(&fin).await;
                        return;
                    }
                    None => {
                        // Sender dropped without a Finalize (run aborted). Best
                        // effort: flush what we have and leave the run open on
                        // the server — the lease reaper times it out, exactly
                        // the "crashed run leaves a partial" property we want.
                        self.flush_items(&mut buf).await;
                        return;
                    }
                },
                _ = flush_timer.tick() => {
                    self.flush_items(&mut buf).await;
                }
                _ = renew_timer.tick() => {
                    self.renew().await;
                }
            }
        }
    }

    /// POST the buffered items with bounded retry. On success the buffer is
    /// cleared; on persistent failure the items stay buffered and are retried on
    /// the next flush (so a transient blip never loses a run).
    async fn flush_items(&self, buf: &mut Vec<Item>) {
        if buf.is_empty() {
            return;
        }
        let body = ItemsRequest { items: buf.clone() };
        let url = format!("{}/runs/{}/items", self.base, self.run_id);
        if self.post_with_retry(&url, &body).await {
            buf.clear();
        } else {
            tracing::warn!(
                "report push: {} item(s) could not be delivered after {} retries; retained for next flush",
                buf.len(),
                MAX_RETRIES
            );
        }
    }

    async fn finalize(&self, fin: &FinalizeRequest) {
        let url = format!("{}/runs/{}/finalize", self.base, self.run_id);
        if !self.post_with_retry(&url, fin).await {
            tracing::warn!("report push: finalize could not be delivered");
        }
    }

    async fn renew(&self) {
        let url = format!("{}/runs/{}/renew", self.base, self.run_id);
        // A single attempt per tick is enough; the next tick retries.
        let res = self
            .client
            .post(&url)
            .bearer_auth(&self.lease_token)
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => tracing::warn!("report push: renew lease HTTP {}", r.status()),
            Err(e) => tracing::warn!("report push: renew lease failed: {e}"),
        }
    }

    /// POST `body` under the lease token, retrying transient failures with
    /// exponential backoff. Returns whether it ultimately succeeded. A 4xx
    /// (other than 429) is treated as permanent — retrying a rejected payload
    /// won't help.
    async fn post_with_retry<T: Serialize>(&self, url: &str, body: &T) -> bool {
        let mut backoff = Duration::from_millis(200);
        for attempt in 0..=MAX_RETRIES {
            let res = self
                .client
                .post(url)
                .bearer_auth(&self.lease_token)
                .json(body)
                .send()
                .await;
            match res {
                Ok(r) if r.status().is_success() => return true,
                Ok(r)
                    if r.status().is_client_error()
                        && r.status() != reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    tracing::warn!(
                        "report push: {url} rejected with HTTP {} (permanent)",
                        r.status()
                    );
                    return false;
                }
                Ok(r) => {
                    tracing::debug!("report push: {url} HTTP {} (attempt {attempt})", r.status())
                }
                Err(e) => tracing::debug!("report push: {url} error (attempt {attempt}): {e}"),
            }
            if attempt < MAX_RETRIES {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
        false
    }
}

// ── MultiReporter ────────────────────────────────────────────────────────────

/// Fan a run's events out to several reporters, so `--report <file>` and
/// `--report-url` can be active at once.
pub struct MultiReporter {
    reporters: Vec<Arc<dyn Reporter>>,
}

impl MultiReporter {
    pub fn new(reporters: Vec<Arc<dyn Reporter>>) -> Self {
        Self { reporters }
    }
}

impl Reporter for MultiReporter {
    fn on_task(&self, report: &TaskReport) {
        for r in &self.reporters {
            r.on_task(report);
        }
    }
    fn finish(&self, outcome: &RunOutcome) {
        for r in &self.reporters {
            r.finish(outcome);
        }
    }
}

#[cfg(test)]
mod tests;
