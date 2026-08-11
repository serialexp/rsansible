//! Tests for the HTTP push sink, driven against an in-process `axum` mock that
//! implements the push protocol and records what the client sent. No live
//! server, no network beyond loopback.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use tokio::sync::Mutex;

use super::*;
use crate::report::{HostState, RunOutcome, TaskReport, TaskStatus};

/// Everything the mock server observed, for post-hoc assertions.
#[derive(Default)]
struct Recorded {
    open_auth: Vec<String>,
    open_bodies: Vec<OpenRequest>,
    item_auth: Vec<String>,
    item_batches: Vec<ItemsRequest>,
    finalize_auth: Vec<String>,
    finalizes: Vec<FinalizeRequest>,
    renews: usize,
}

struct MockState {
    rec: Mutex<Recorded>,
    /// Number of times the `items` endpoint should still reply 500 before it
    /// starts replying 200 (drives the retry test).
    fail_items_remaining: AtomicUsize,
    renew_interval_secs: u64,
}

fn bearer(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string()
}

async fn open_handler(
    State(st): State<Arc<MockState>>,
    headers: HeaderMap,
    Json(body): Json<OpenRequest>,
) -> Json<OpenResponse> {
    let mut rec = st.rec.lock().await;
    rec.open_auth.push(bearer(&headers));
    rec.open_bodies.push(body);
    Json(OpenResponse {
        run_id: "run-123".to_string(),
        lease_token: "lease-abc".to_string(),
        lease_expires_at: Some("2026-07-16T12:05:00Z".to_string()),
        renew_interval_secs: st.renew_interval_secs,
    })
}

async fn items_handler(
    State(st): State<Arc<MockState>>,
    headers: HeaderMap,
    Json(body): Json<ItemsRequest>,
) -> StatusCode {
    // Fail the first N attempts to exercise the client's retry/buffer path.
    if st.fail_items_remaining.load(Ordering::SeqCst) > 0 {
        st.fail_items_remaining.fetch_sub(1, Ordering::SeqCst);
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let mut rec = st.rec.lock().await;
    rec.item_auth.push(bearer(&headers));
    rec.item_batches.push(body);
    StatusCode::OK
}

async fn finalize_handler(
    State(st): State<Arc<MockState>>,
    headers: HeaderMap,
    Json(body): Json<FinalizeRequest>,
) -> StatusCode {
    let mut rec = st.rec.lock().await;
    rec.finalize_auth.push(bearer(&headers));
    rec.finalizes.push(body);
    StatusCode::OK
}

async fn renew_handler(State(st): State<Arc<MockState>>) -> Json<RenewResponse> {
    st.rec.lock().await.renews += 1;
    Json(RenewResponse {
        lease_expires_at: Some("2026-07-16T12:09:00Z".to_string()),
    })
}

/// Bind a mock server on an ephemeral loopback port; return its base URL and the
/// shared state. The server task runs until the test process exits.
async fn spawn_mock(fail_items: usize, renew_interval_secs: u64) -> (String, Arc<MockState>) {
    let st = Arc::new(MockState {
        rec: Mutex::new(Recorded::default()),
        fail_items_remaining: AtomicUsize::new(fail_items),
        renew_interval_secs,
    });
    let app = Router::new()
        .route("/runs", post(open_handler))
        .route("/runs/:run_id/items", post(items_handler))
        .route("/runs/:run_id/finalize", post(finalize_handler))
        .route("/runs/:run_id/renew", post(renew_handler))
        .with_state(st.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), st)
}

fn cfg(base_url: String) -> PushConfig {
    PushConfig {
        base_url,
        token: "operator-pat".to_string(),
        namespace: "acme".to_string(),
        project: "site".to_string(),
        stack: "prod".to_string(),
        mode: RunMode::Apply,
        playbook: Some("site.yml".to_string()),
        inventory: None,
    }
}

fn task(host: &str, name: &str, status: TaskStatus, diff: Option<&str>) -> TaskReport {
    TaskReport {
        play: "converge".to_string(),
        host: host.to_string(),
        task: name.to_string(),
        status,
        changed: status == TaskStatus::Changed,
        check_mode: false,
        rc: Some(0),
        duration_ms: Some(5),
        diff: diff.map(|d| d.to_string()),
        reason: None,
    }
}

fn ok_outcome() -> RunOutcome {
    RunOutcome {
        check_mode: false,
        stopped_early: false,
        tasks_ok: 1,
        tasks_changed: 1,
        tasks_skipped: 0,
        hosts: BTreeMap::from([("db-1".to_string(), HostState::Ok)]),
    }
}

#[tokio::test]
async fn open_items_finalize_happy_path() {
    let (base, st) = spawn_mock(0, 3600).await;
    let reporter = HttpReporter::open(cfg(base)).await.expect("open");

    reporter.on_task(&task(
        "db-1",
        "install",
        TaskStatus::Changed,
        Some("{\"before\":\"a\",\"after\":\"b\"}"),
    ));
    reporter.on_task(&task("db-2", "gather", TaskStatus::Ok, None));
    reporter.finish(&ok_outcome());
    reporter.join().await;

    let rec = st.rec.lock().await;
    // Open used the operator token; the JSON body carried the identity + mode.
    assert_eq!(rec.open_auth, vec!["operator-pat".to_string()]);
    assert_eq!(rec.open_bodies.len(), 1);
    assert_eq!(rec.open_bodies[0].project, "site");
    assert!(matches!(rec.open_bodies[0].mode, RunMode::Apply));

    // All items arrived, under the lease token (never the operator token).
    let items: Vec<&Item> = rec.item_batches.iter().flat_map(|b| &b.items).collect();
    assert_eq!(items.len(), 2, "both tasks pushed");
    assert!(
        rec.item_auth.iter().all(|a| a == "lease-abc"),
        "writes use the lease"
    );
    // Monotonic sequences + pivot dimensions + inline diff preserved.
    assert_eq!(items[0].sequence, 0);
    assert_eq!(items[0].dimensions.host, "db-1");
    assert_eq!(items[0].dimensions.play.as_deref(), Some("converge"));
    assert!(items[0].diff.is_some());
    assert_eq!(items[1].sequence, 1);
    assert_eq!(items[1].dimensions.host, "db-2");

    // Finalize arrived under the lease, with the terminal status + counts.
    assert_eq!(rec.finalize_auth, vec!["lease-abc".to_string()]);
    assert_eq!(rec.finalizes.len(), 1);
    assert!(matches!(rec.finalizes[0].status, RunStatus::Succeeded));
    assert_eq!(rec.finalizes[0].summary.ok, 1);
    assert_eq!(rec.finalizes[0].summary.changed, 1);
}

#[tokio::test]
async fn items_are_retried_after_transient_500() {
    // Server 500s the first two item POSTs, then succeeds. The client must
    // retain the buffer and re-send, so no item is lost.
    let (base, st) = spawn_mock(2, 3600).await;
    let reporter = HttpReporter::open(cfg(base)).await.expect("open");

    reporter.on_task(&task("db-1", "install", TaskStatus::Changed, None));
    reporter.finish(&ok_outcome());
    reporter.join().await;

    let rec = st.rec.lock().await;
    let items: Vec<&Item> = rec.item_batches.iter().flat_map(|b| &b.items).collect();
    assert_eq!(items.len(), 1, "the item survived two transient failures");
    assert_eq!(items[0].dimensions.task, "install");
    assert_eq!(rec.finalizes.len(), 1, "finalize still delivered");
}

#[tokio::test]
async fn finalize_reports_failure_when_a_host_failed() {
    let (base, st) = spawn_mock(0, 3600).await;
    let reporter = HttpReporter::open(cfg(base)).await.expect("open");

    reporter.on_task(&task("db-1", "start", TaskStatus::Failed, None));
    reporter.finish(&RunOutcome {
        check_mode: false,
        stopped_early: false,
        tasks_ok: 0,
        tasks_changed: 0,
        tasks_skipped: 0,
        hosts: BTreeMap::from([(
            "db-1".to_string(),
            HostState::Failed {
                task: "start".to_string(),
                reason: "boom".to_string(),
            },
        )]),
    });
    reporter.join().await;

    let rec = st.rec.lock().await;
    assert_eq!(rec.finalizes.len(), 1);
    assert!(matches!(rec.finalizes[0].status, RunStatus::Failed));
    assert_eq!(rec.finalizes[0].summary.failed, 1);
}

#[tokio::test]
async fn lease_is_renewed_on_the_server_interval() {
    // renew_interval_secs=1 so a couple of ticks land within a short real-time
    // wait. A long run outlives the lease window, so renewal is load-bearing.
    let (base, st) = spawn_mock(0, 1).await;
    let reporter = HttpReporter::open(cfg(base)).await.expect("open");

    reporter.on_task(&task("db-1", "slow", TaskStatus::Ok, None));
    // Let the renew timer tick at least twice.
    tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
    reporter.finish(&ok_outcome());
    reporter.join().await;

    let rec = st.rec.lock().await;
    assert!(
        rec.renews >= 2,
        "expected >=2 lease renewals, got {}",
        rec.renews
    );
}

/// The committed `protocol_fixture.json` deserializes cleanly into the wire
/// types and re-serializes to equal JSON. gothab asserts the *same* fixture on
/// its side, so any contract drift breaks one repo's test.
#[test]
fn protocol_fixture_round_trips() {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("../../protocol_fixture.json")).unwrap();

    let open_req: OpenRequest = serde_json::from_value(raw["open_request"].clone()).unwrap();
    assert_eq!(open_req.namespace, "acme");
    assert!(matches!(open_req.mode, RunMode::Apply));

    let open_resp: OpenResponse = serde_json::from_value(raw["open_response"].clone()).unwrap();
    assert_eq!(open_resp.renew_interval_secs, 240);

    let items: ItemsRequest = serde_json::from_value(raw["items_request"].clone()).unwrap();
    assert_eq!(items.items.len(), 3);
    assert!(matches!(items.items[0].status, TaskStatus::Changed));
    assert!(items.items[0].diff.is_some());
    assert_eq!(items.items[2].dimensions.host, "db-2");
    assert!(matches!(items.items[2].status, TaskStatus::Failed));

    let fin: FinalizeRequest = serde_json::from_value(raw["finalize_request"].clone()).unwrap();
    assert!(matches!(fin.status, RunStatus::Failed));
    assert_eq!(fin.summary.failed, 1);

    let _renew: RenewResponse = serde_json::from_value(raw["renew_response"].clone()).unwrap();

    // Re-serialize one representative type and confirm it matches the fixture
    // value (field names/casing are the contract).
    let reser = serde_json::to_value(&items.items[1]).unwrap();
    assert_eq!(reser, raw["items_request"]["items"][1]);
}
