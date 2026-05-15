//! `OpUri` — HTTP client. Ansible's `uri:` module.
//!
//! The agent builds a request from the wire spec, executes it via reqwest
//! (rustls-tls, no OpenSSL), and ships a JSON envelope on stdout that the
//! controller lifts into the register's top-level keys
//! (`register.status`, `register.url`, `register.json.<body-field>`, …).
//!
//! Result categories:
//!
//!   * **Response received** (any status): TaskDone with `exit_code=0` if
//!     the status is in `op.status_codes`, else `exit_code=1`. The
//!     envelope ships in both cases so the register is populated even
//!     under `ignore_errors:`. `changed=1` iff exit_code=0 and the
//!     method is mutating (POST/PUT/PATCH/DELETE) — Ansible's contract:
//!     mutating verbs report changed because the server's idempotency
//!     isn't observable from here.
//!
//!   * **Pre-status failure** (DNS, connect refused, TLS handshake,
//!     timeout): TaskError with the relevant code (TIMEOUT for the
//!     timeout case, BAD_REQUEST otherwise). No envelope is shipped —
//!     there's nothing to populate the register with.
//!
//! Headers on the response are normalised to lowercase keys with values
//! joined by `, ` for multi-valued headers, matching Ansible.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rsansible_wire::generated::OpUriOutput;
use rsansible_wire::msg::{self, err, now_unix_ns, uri_body_format, uri_follow, uri_method};
use serde_json::{Map, Value};

use super::{emit_error, Context};

pub async fn run(ctx: &Context, seq: u32, op: OpUriOutput) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    // Parse the method byte first. Bad method = controller bug; surface
    // as BAD_REQUEST so the operator sees a real complaint rather than a
    // silent fallback.
    let method = match map_method(op.method) {
        Some(m) => m,
        None => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("unknown method byte: {}", op.method),
            )
            .await;
            return Ok(());
        }
    };

    // Build the reqwest Client. We pay a one-Client-per-call cost so we
    // can wire per-request `validate_certs` / `follow_redirects` without
    // a global pool. Agent ops are serial; this is fine.
    let client = match build_client(&op, method.clone()) {
        Ok(c) => c,
        Err(msg) => {
            emit_error(ctx, seq, err::BAD_REQUEST, msg).await;
            return Ok(());
        }
    };

    // Assemble the request.
    let req = match build_request(&client, method, &op) {
        Ok(r) => r,
        Err(msg) => {
            emit_error(ctx, seq, err::BAD_REQUEST, msg).await;
            return Ok(());
        }
    };

    let original_url = op.url.clone();
    let started_wall = Instant::now();
    let resp = match client.execute(req).await {
        Ok(r) => r,
        Err(e) => {
            let code = if e.is_timeout() {
                err::TIMEOUT
            } else {
                err::BAD_REQUEST
            };
            emit_error(ctx, seq, code, format!("{e}")).await;
            return Ok(());
        }
    };

    // Capture status + headers + final URL before consuming body.
    let status_u16 = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers_map = normalize_headers(resp.headers());
    let content_type = headers_map
        .get("content-type")
        .cloned()
        .unwrap_or_default();

    // Body bytes. reqwest's gzip decode is automatic when the gzip
    // feature is on and the server advertised it.
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                err::IO,
                format!("reading response body: {e}"),
            )
            .await;
            return Ok(());
        }
    };
    let elapsed_ms = started_wall.elapsed().as_millis() as u64;
    let content_length = body_bytes.len();

    // Try to parse the body as UTF-8 once; reused for `content` and
    // `json` extraction below. Non-UTF-8 → `content` becomes a lossy
    // string (matching Ansible's behaviour: it'll only set content if
    // return_content is true, so binary bodies just won't round-trip
    // through templates), `json` stays absent.
    let body_str = String::from_utf8_lossy(&body_bytes).into_owned();
    let parsed_json = if content_type_indicates_json(&content_type) {
        serde_json::from_slice::<Value>(&body_bytes).ok()
    } else {
        None
    };

    // Envelope. Insert optional fields only when populated — keeps the
    // controller's lift block simple (no null-checking).
    let mut envelope = Map::new();
    envelope.insert("status".into(), Value::from(status_u16));
    envelope.insert("url".into(), Value::String(final_url.clone()));
    envelope.insert(
        "headers".into(),
        Value::Object(
            headers_map
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
        ),
    );
    envelope.insert("content_length".into(), Value::from(content_length));
    envelope.insert("content_type".into(), Value::String(content_type));
    envelope.insert("elapsed_ms".into(), Value::from(elapsed_ms));
    envelope.insert(
        "redirected".into(),
        Value::Bool(final_url != original_url),
    );
    if op.return_content != 0 {
        envelope.insert("content".into(), Value::String(body_str));
    }
    if let Some(j) = parsed_json {
        envelope.insert("json".into(), j);
    }

    // Status validation.
    let status_ok = op.status_codes.iter().any(|&c| c == status_u16);
    let exit_code: i32 = if status_ok { 0 } else { 1 };
    // Ansible's mutating-verbs-are-changed contract. GET/HEAD never
    // claim changed; failed requests never claim changed regardless of
    // verb (the server may have rejected outright).
    let changed_flag = status_ok && method_is_mutating(op.method);

    let bytes = serde_json::to_vec(&Value::Object(envelope))?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;
    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        exit_code,
        changed_flag,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn map_method(b: u8) -> Option<reqwest::Method> {
    match b {
        uri_method::GET => Some(reqwest::Method::GET),
        uri_method::POST => Some(reqwest::Method::POST),
        uri_method::PUT => Some(reqwest::Method::PUT),
        uri_method::PATCH => Some(reqwest::Method::PATCH),
        uri_method::DELETE => Some(reqwest::Method::DELETE),
        uri_method::HEAD => Some(reqwest::Method::HEAD),
        _ => None,
    }
}

fn method_is_mutating(b: u8) -> bool {
    !matches!(b, uri_method::GET | uri_method::HEAD)
}

fn content_type_indicates_json(ct: &str) -> bool {
    // Accept `application/json`, `application/something+json`, and the
    // suffix variant with parameters like `; charset=utf-8`. Lowercased
    // already by `normalize_headers`.
    let head = ct.split(';').next().unwrap_or("").trim();
    head == "application/json"
        || head == "text/json"
        || head.ends_with("+json")
}

fn build_client(op: &OpUriOutput, original_method: reqwest::Method) -> Result<reqwest::Client, String> {
    use reqwest::redirect::Policy;

    let policy = match op.follow_redirects {
        uri_follow::NONE => Policy::none(),
        uri_follow::ALL => Policy::limited(10),
        uri_follow::SAFE => {
            // "safe" = follow only when the *original* request method was
            // GET or HEAD. reqwest's Attempt API doesn't expose the
            // method directly, but the closure can close over the
            // original_method we captured at build time.
            let safe_for_method = matches!(
                original_method,
                reqwest::Method::GET | reqwest::Method::HEAD
            );
            Policy::custom(move |attempt| {
                if !safe_for_method {
                    attempt.stop()
                } else if attempt.previous().len() >= 10 {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            })
        }
        other => {
            return Err(format!("unknown follow_redirects byte: {other}"));
        }
    };

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(op.timeout_ms.max(1) as u64))
        .redirect(policy);
    if op.validate_certs == 0 {
        builder = builder.danger_accept_invalid_certs(true);
    }

    // mTLS / custom-CA wiring. All three fields are length-prefixed bytes;
    // empty = absent. The controller reads the PEM files at playbook load
    // time and embeds the bytes here, so the agent never touches the
    // controller filesystem. reqwest's `Identity::from_pem` wants the
    // client cert and key concatenated into one PEM bundle.
    if !op.ca_bundle_pem.is_empty() {
        let cert = reqwest::Certificate::from_pem(&op.ca_bundle_pem)
            .map_err(|e| format!("parsing ca_bundle_pem: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    if !op.client_cert_pem.is_empty() {
        if op.client_key_pem.is_empty() {
            return Err("client_cert_pem set but client_key_pem is empty".into());
        }
        // Concatenate cert + key into a single PEM bundle. Tolerate a
        // missing trailing newline on the cert so consumers can pass
        // either form.
        let mut bundle = Vec::with_capacity(op.client_cert_pem.len() + op.client_key_pem.len() + 1);
        bundle.extend_from_slice(&op.client_cert_pem);
        if !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        bundle.extend_from_slice(&op.client_key_pem);
        let id = reqwest::Identity::from_pem(&bundle)
            .map_err(|e| format!("parsing client cert/key: {e}"))?;
        builder = builder.identity(id);
    } else if !op.client_key_pem.is_empty() {
        return Err("client_key_pem set but client_cert_pem is empty".into());
    }

    builder
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

fn build_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    op: &OpUriOutput,
) -> Result<reqwest::Request, String> {
    use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE};

    let url = reqwest::Url::parse(&op.url).map_err(|e| format!("parsing url {:?}: {e}", op.url))?;
    let mut req = client.request(method.clone(), url);

    // The wire schema guarantees the keys/values arrays are the same
    // length (the controller builds them in lockstep), but defense in
    // depth: bail if they ever drift.
    if op.header_keys.len() != op.header_values.len() {
        return Err(format!(
            "header_keys.len({}) != header_values.len({})",
            op.header_keys.len(),
            op.header_values.len()
        ));
    }
    let mut caller_set_ct = false;
    for (k, v) in op.header_keys.iter().zip(op.header_values.iter()) {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| format!("invalid header name {k:?}: {e}"))?;
        let val = HeaderValue::from_str(v)
            .map_err(|e| format!("invalid header value for {k:?}: {e}"))?;
        if name == CONTENT_TYPE {
            caller_set_ct = true;
        }
        req = req.header(name, val);
    }

    // Apply body + body_format. RAW: ship verbatim, don't touch
    // Content-Type. JSON/FORM: ship verbatim AND auto-set Content-Type
    // when the caller didn't.
    match op.body_format {
        uri_body_format::RAW => {
            if !op.body.is_empty() {
                req = req.body(op.body.clone());
            }
        }
        uri_body_format::JSON => {
            if !caller_set_ct {
                req = req.header(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            if !op.body.is_empty() {
                req = req.body(op.body.clone());
            }
        }
        uri_body_format::FORM => {
            if !caller_set_ct {
                req = req.header(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
            }
            if !op.body.is_empty() {
                req = req.body(op.body.clone());
            }
        }
        other => return Err(format!("unknown body_format byte: {other}")),
    }

    req.build().map_err(|e| format!("building request: {e}"))
}

fn normalize_headers(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    // Ansible lowercases response-header keys and joins multi-valued
    // headers with `, ` (Set-Cookie excepted in Ansible, but we don't
    // need that special case for the gothab consumers). We follow the
    // same shape.
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_lowercase();
        let val = v.to_str().unwrap_or("").to_string();
        out.entry(key)
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(&val);
            })
            .or_insert(val);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_mapping() {
        assert_eq!(map_method(0).unwrap(), reqwest::Method::GET);
        assert_eq!(map_method(1).unwrap(), reqwest::Method::POST);
        assert_eq!(map_method(5).unwrap(), reqwest::Method::HEAD);
        assert!(map_method(99).is_none());
    }

    #[test]
    fn method_mutating_classification() {
        assert!(!method_is_mutating(uri_method::GET));
        assert!(!method_is_mutating(uri_method::HEAD));
        assert!(method_is_mutating(uri_method::POST));
        assert!(method_is_mutating(uri_method::PUT));
        assert!(method_is_mutating(uri_method::PATCH));
        assert!(method_is_mutating(uri_method::DELETE));
    }

    #[test]
    fn content_type_json_detection() {
        assert!(content_type_indicates_json("application/json"));
        assert!(content_type_indicates_json("application/json; charset=utf-8"));
        assert!(content_type_indicates_json("application/vnd.api+json"));
        assert!(content_type_indicates_json("text/json"));
        assert!(!content_type_indicates_json("text/html"));
        assert!(!content_type_indicates_json(""));
        assert!(!content_type_indicates_json("application/xml"));
    }

    #[test]
    fn headers_normalized_lowercase() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert("Content-Type", HeaderValue::from_static("application/json"));
        h.insert("X-Custom", HeaderValue::from_static("v1"));
        let m = normalize_headers(&h);
        assert_eq!(m.get("content-type").unwrap(), "application/json");
        assert_eq!(m.get("x-custom").unwrap(), "v1");
        assert!(m.get("Content-Type").is_none(), "keys must be lowercased");
    }

    #[test]
    fn headers_multivalued_join() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.append("X-Multi", HeaderValue::from_static("a"));
        h.append("X-Multi", HeaderValue::from_static("b"));
        let m = normalize_headers(&h);
        assert_eq!(m.get("x-multi").unwrap(), "a, b");
    }

    // Integration-style tests: spin up an in-process axum server and
    // exercise the agent module against it. These live under cfg(test)
    // because axum is a dev-dep.

    use axum::body::Bytes;
    use axum::extract::{Path as AxumPath, Query, Request};
    use axum::http::{header, HeaderMap as AxumHeaderMap, Method as AxumMethod, StatusCode};
    use axum::response::{IntoResponse, Redirect, Response};
    use axum::routing::{any, get};
    use axum::Router;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    /// Drains envelope JSON from the writer channel after an op runs.
    /// Returns the parsed envelope plus whether TaskDone exit_code was
    /// 0 plus whether `changed` was set.
    struct OpResult {
        envelope: Option<Value>,
        exit_code: i32,
        changed: bool,
        error: Option<(u8, String)>,
    }

    async fn drain(mut rx: tokio::sync::mpsc::Receiver<rsansible_wire::Message>) -> OpResult {
        let mut envelope = None;
        let mut exit_code = 0;
        let mut changed = false;
        let mut error: Option<(u8, String)> = None;
        while let Some(m) = rx.recv().await {
            match m {
                rsansible_wire::Message::TaskProgress(p) => {
                    if p.stream == 0 {
                        envelope = Some(serde_json::from_slice(&p.chunk).expect("envelope JSON"));
                    }
                }
                rsansible_wire::Message::TaskDone(d) => {
                    exit_code = d.exit_code;
                    changed = d.changed != 0;
                }
                rsansible_wire::Message::TaskError(e) => {
                    error = Some((e.code, e.message));
                }
                _ => {}
            }
        }
        OpResult { envelope, exit_code, changed, error }
    }

    /// Boot an axum router on `127.0.0.1:0` and return the bound port.
    async fn boot(router: Router) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        port
    }

    fn op_for(url: &str) -> OpUriOutput {
        OpUriOutput {
            kind: 12,
            method: uri_method::GET,
            url: url.to_string(),
            header_keys: vec![],
            header_values: vec![],
            body: vec![],
            body_format: uri_body_format::RAW,
            status_codes: vec![200],
            timeout_ms: 5_000,
            return_content: 0,
            validate_certs: 1,
            follow_redirects: uri_follow::SAFE,
            client_cert_pem: vec![],
            client_key_pem: vec![],
            ca_bundle_pem: vec![],
        }
    }

    async fn run_op(op: OpUriOutput) -> OpResult {
        let (tx, rx) = mpsc::channel::<rsansible_wire::Message>(64);
        let ctx = Context::new(crate::writer::Sender(tx));
        run(&ctx, 1, op).await.unwrap();
        drop(ctx);
        drain(rx).await
    }

    #[tokio::test]
    async fn get_200_json_envelope_basics() {
        let app = Router::new().route(
            "/echo",
            get(|| async {
                ([(header::CONTENT_TYPE, "application/json")], r#"{"foo":"bar"}"#)
            }),
        );
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/echo"));
        op.return_content = 1;
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 0);
        assert!(!r.changed, "GET never reports changed");
        let env = r.envelope.expect("envelope present");
        assert_eq!(env["status"], 200);
        assert_eq!(env["content"], "{\"foo\":\"bar\"}");
        assert_eq!(env["content_type"], "application/json");
        assert_eq!(env["json"]["foo"], "bar");
        assert_eq!(env["redirected"], false);
    }

    #[tokio::test]
    async fn get_404_with_expected_only_200_marks_failure() {
        let app = Router::new().route(
            "/nope",
            get(|| async { (StatusCode::NOT_FOUND, "missing") }),
        );
        let port = boot(app).await;

        let op = op_for(&format!("http://127.0.0.1:{port}/nope"));
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 1, "404 not in [200] → exit_code=1");
        assert!(!r.changed);
        let env = r.envelope.expect("envelope still present on failure");
        assert_eq!(env["status"], 404);
    }

    #[tokio::test]
    async fn get_404_allowed_via_status_codes() {
        let app = Router::new().route(
            "/nope",
            get(|| async { (StatusCode::NOT_FOUND, "missing") }),
        );
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/nope"));
        op.status_codes = vec![200, 404];
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 0);
        let env = r.envelope.unwrap();
        assert_eq!(env["status"], 404);
    }

    #[tokio::test]
    async fn post_json_body_with_content_type_default() {
        // Server captures the Content-Type and the body. axum-side echo
        // back what we received so the client side can assert.
        let app = Router::new().route(
            "/echo",
            any(|req: Request| async move {
                let (parts, body) = req.into_parts();
                let ct = parts
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap();
                let body_str = String::from_utf8_lossy(&bytes).to_string();
                let resp = serde_json::json!({"ct": ct, "body": body_str}).to_string();
                (
                    StatusCode::CREATED,
                    [(header::CONTENT_TYPE, "application/json")],
                    resp,
                )
            }),
        );
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/echo"));
        op.method = uri_method::POST;
        op.body = br#"{"x":1}"#.to_vec();
        op.body_format = uri_body_format::JSON;
        op.status_codes = vec![201];
        op.return_content = 1;
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 0);
        assert!(r.changed, "POST success reports changed=1");
        let env = r.envelope.unwrap();
        assert_eq!(env["status"], 201);
        assert_eq!(env["json"]["ct"], "application/json");
        assert_eq!(env["json"]["body"], r#"{"x":1}"#);
    }

    #[tokio::test]
    async fn post_explicit_content_type_takes_precedence() {
        let app = Router::new().route(
            "/echo",
            any(|req: Request| async move {
                let ct = req
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                (StatusCode::OK, ct)
            }),
        );
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/echo"));
        op.method = uri_method::POST;
        op.body = b"{}".to_vec();
        op.body_format = uri_body_format::JSON;
        op.header_keys = vec!["Content-Type".into()];
        op.header_values = vec!["application/vnd.custom+json".into()];
        op.return_content = 1;
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 0);
        let env = r.envelope.unwrap();
        assert_eq!(env["content"], "application/vnd.custom+json");
    }

    #[tokio::test]
    async fn put_form_body_sets_form_content_type() {
        let app = Router::new().route(
            "/form",
            any(|req: Request| async move {
                let ct = req
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let (_, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, 1024).await.unwrap();
                (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], format!("{ct}|{}", String::from_utf8_lossy(&bytes)))
            }),
        );
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/form"));
        op.method = uri_method::PUT;
        op.body = b"a=1&b=two".to_vec();
        op.body_format = uri_body_format::FORM;
        op.return_content = 1;
        let r = run_op(op).await;

        let env = r.envelope.unwrap();
        let content = env["content"].as_str().unwrap();
        assert!(content.starts_with("application/x-www-form-urlencoded|"));
        assert!(content.ends_with("|a=1&b=two"));
    }

    #[tokio::test]
    async fn safe_redirect_follows_get() {
        let app = Router::new()
            .route("/start", get(|| async { Redirect::to("/end") }))
            .route("/end", get(|| async { (StatusCode::OK, "done") }));
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/start"));
        op.return_content = 1;
        op.follow_redirects = uri_follow::SAFE;
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 0);
        let env = r.envelope.unwrap();
        assert_eq!(env["status"], 200);
        assert_eq!(env["content"], "done");
        assert_eq!(env["redirected"], true);
        assert!(env["url"].as_str().unwrap().ends_with("/end"));
    }

    #[tokio::test]
    async fn safe_redirect_does_not_follow_post() {
        // /start returns a 302 with Location: /end. With follow=safe and
        // method=POST, the client should NOT follow — status comes back
        // as 302.
        let app = Router::new()
            .route(
                "/start",
                any(|| async {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, "/end")],
                        "",
                    )
                }),
            )
            .route("/end", any(|| async { (StatusCode::OK, "done") }));
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/start"));
        op.method = uri_method::POST;
        op.status_codes = vec![302];
        op.follow_redirects = uri_follow::SAFE;
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 0, "302 was in status_codes, success");
        let env = r.envelope.unwrap();
        assert_eq!(env["status"], 302);
        assert_eq!(env["redirected"], false);
    }

    #[tokio::test]
    async fn none_redirect_surfaces_3xx() {
        let app = Router::new()
            .route("/start", get(|| async { Redirect::to("/end") }))
            .route("/end", get(|| async { (StatusCode::OK, "done") }));
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/start"));
        op.status_codes = vec![303, 302, 307, 308];
        op.follow_redirects = uri_follow::NONE;
        let r = run_op(op).await;

        assert_eq!(r.exit_code, 0);
        let env = r.envelope.unwrap();
        let st = env["status"].as_u64().unwrap();
        assert!((300..400).contains(&st), "got status {st}");
        assert_eq!(env["redirected"], false);
    }

    #[tokio::test]
    async fn connect_refused_emits_bad_request() {
        // 127.0.0.1 with an unbound port; in practice this returns
        // ECONNREFUSED fast.
        let op = op_for("http://127.0.0.1:1/nope");
        let r = run_op(op).await;

        assert!(r.envelope.is_none());
        let (code, msg) = r.error.expect("error emitted");
        assert_eq!(code, err::BAD_REQUEST);
        assert!(!msg.is_empty());
    }

    #[tokio::test]
    async fn timeout_emits_timeout_error() {
        // Server holds the connection past the client's timeout.
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                "late"
            }),
        );
        let port = boot(app).await;

        let mut op = op_for(&format!("http://127.0.0.1:{port}/slow"));
        op.timeout_ms = 100;
        let r = run_op(op).await;

        assert!(r.envelope.is_none());
        let (code, _) = r.error.expect("error emitted");
        assert_eq!(code, err::TIMEOUT);
    }

    #[tokio::test]
    async fn elapsed_ms_populated() {
        let app = Router::new().route("/echo", get(|| async { "ok" }));
        let port = boot(app).await;

        let op = op_for(&format!("http://127.0.0.1:{port}/echo"));
        let r = run_op(op).await;
        let env = r.envelope.unwrap();
        // Elapsed should be a non-negative integer; can't be too strict
        // about an upper bound in CI, but it shouldn't be wildly missing.
        assert!(env["elapsed_ms"].is_number());
        let ms = env["elapsed_ms"].as_u64().unwrap();
        assert!(ms < 30_000, "elapsed_ms {ms} should be small");
    }

    // unused but silenced — keep the path import alive in case future
    // tests want axum::extract::Path.
    #[allow(dead_code)]
    fn _silence(_: AxumPath<()>, _: Query<HashMap<String, String>>, _: AxumHeaderMap, _: AxumMethod, _: Bytes, _: SocketAddr) -> Response<axum::body::Body> {
        ().into_response()
    }
}
