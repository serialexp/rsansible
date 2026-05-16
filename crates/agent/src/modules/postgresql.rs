//! `OpPostgresqlQuery` + `OpPostgresqlExt` — PostgreSQL ops.
//!
//! Both ops share connection-config plumbing: UNIX socket via
//! `login_unix_socket` (Patroni clusters listen on `/var/run/postgresql`)
//! or TCP to `login_host:login_port`. When `login_user` is empty we let
//! the libpq-style "peer auth" default kick in — under `become: postgres`
//! the controller wraps the entire agent invocation in `sudo -u postgres`
//! so the UNIX-socket connection authenticates as postgres without a
//! password.
//!
//! ## OpPostgresqlQuery
//!
//! The controller classifies the SQL at compile time (read-only vs
//! mutating) and ships the verdict in the `read_only` byte. That byte
//! controls:
//!
//! 1. **Check-mode behaviour.** Under `check_mode=1` the controller
//!    already skips dispatch for mutating SQL outright; this module
//!    still defends — if a mutating op arrives with `check_mode=1`, we
//!    emit `skipped=true` and return without touching the database.
//! 2. **`changed` reporting.** Read-only SQL never sets `changed`;
//!    mutating SQL always does (even if the row count is zero — same
//!    contract as Ansible's `community.postgresql.postgresql_query`,
//!    which can't introspect what an arbitrary DML statement did).
//!
//! Row encoding: when `positional_args` is empty we use
//! `simple_query` — values come back as text strings, every column type
//! works, and we get the real `statusmessage` (the PostgreSQL command
//! tag like `SELECT 3` or `INSERT 0 1`). When parameters are present we
//! fall through to the typed `query` path which knows a fixed set of
//! oids (int/float/bool/text/bytea/json) and stringifies unknowns. That
//! split keeps the common case faithful without hand-implementing
//! every pg type.
//!
//! Envelope shape (stdout):
//! ```json
//! {
//!   "query_result": [ {col_name: value, ...}, ... ],
//!   "rowcount": <uint>,
//!   "statusmessage": "<server command tag>"
//! }
//! ```
//!
//! ## OpPostgresqlExt
//!
//! Probes `pg_extension` first; only runs DDL if state diverges. Version
//! upgrades (ALTER EXTENSION ... UPDATE TO) are intentionally **not**
//! implemented in v1 — if the caller supplies `version` and the
//! extension is already present with a different version, we report
//! `changed=false` and surface the prior_version in the envelope so the
//! caller can decide whether to handle it themselves. Document this.
//!
//! Envelope shape:
//! ```json
//! { "extension": "<name>", "state": "present"|"absent",
//!   "prior_version": "<str>"|null, "version": "<str>"|null }
//! ```

use base64::Engine as _;
use rsansible_wire::generated::{OpPostgresqlExtOutput, OpPostgresqlQueryOutput};
use rsansible_wire::msg::{self, err, now_unix_ns, postgresql_ext_state};
use serde_json::{Map, Value};
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::{Client, Config, NoTls, SimpleQueryMessage};

use super::{emit_error, Context};

// ── OpPostgresqlQuery ───────────────────────────────────────────────

pub async fn run_query(
    ctx: &Context,
    seq: u32,
    op: OpPostgresqlQueryOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    // Defence in depth: the controller's SQL classifier already skips
    // mutating SQL under --check before dispatch. If a mutating op
    // still arrives with check_mode=1, it means the classifier missed
    // or someone bypassed it — either way, don't touch the DB.
    if check_mode && op.read_only == 0 {
        let finished_unix_ns = now_unix_ns();
        ctx.emit(msg::task_done(
            seq,
            0,
            false,
            /*skipped=*/ true,
            started_unix_ns,
            finished_unix_ns,
        ))
        .await;
        return Ok(());
    }

    let mut client = match connect(
        &op.db,
        &op.login_user,
        &op.login_password,
        &op.login_unix_socket,
        &op.login_host,
        op.login_port,
    )
    .await
    {
        Ok(c) => c,
        Err(msg) => {
            emit_error(ctx, seq, err::IO, msg).await;
            return Ok(());
        }
    };

    let read_only = op.read_only != 0;
    let autocommit = op.autocommit != 0;

    let result = if op.positional_args.is_empty() {
        execute_simple(&client, &op.query, autocommit).await
    } else {
        execute_typed(&mut client, &op.query, &op.positional_args, autocommit).await
    };

    let envelope = match result {
        Ok(env) => env,
        Err(msg) => {
            emit_error(ctx, seq, err::BAD_REQUEST, msg).await;
            return Ok(());
        }
    };

    let bytes = serde_json::to_vec(&envelope)?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;

    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        /*changed=*/ !read_only,
        /*skipped=*/ false,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

/// Execute a query with no parameters via `simple_query` — text mode,
/// every column type works, real `statusmessage` from the server.
async fn execute_simple(
    client: &Client,
    query: &str,
    autocommit: bool,
) -> Result<Value, String> {
    let wrapped: String;
    let to_run = if autocommit {
        query
    } else {
        wrapped = format!("BEGIN;\n{}\nCOMMIT;", query.trim_end_matches(';'));
        &wrapped
    };

    let messages = client
        .simple_query(to_run)
        .await
        .map_err(|e| format!("postgres error: {e}"))?;

    let mut rows = Vec::new();
    let mut statusmessage = String::new();
    // simple_query returns a flat list; we only surface the LAST
    // statement's rows (matches Ansible's "single-statement is the
    // primary use case" pattern). If a BEGIN/COMMIT wrapper is added
    // we naturally skip those CommandComplete entries.
    let mut current_columns: Vec<String> = Vec::new();
    let mut current_rows: Vec<Map<String, Value>> = Vec::new();
    for msg in messages {
        match msg {
            SimpleQueryMessage::RowDescription(cols) => {
                current_columns = cols.iter().map(|c| c.name().to_string()).collect();
                current_rows.clear();
            }
            SimpleQueryMessage::Row(r) => {
                let mut obj = Map::with_capacity(current_columns.len());
                for (i, name) in current_columns.iter().enumerate() {
                    let v = match r.get(i) {
                        Some(s) => Value::String(s.to_string()),
                        None => Value::Null,
                    };
                    obj.insert(name.clone(), v);
                }
                current_rows.push(obj);
            }
            SimpleQueryMessage::CommandComplete(n) => {
                // The text "command tag" isn't exposed by
                // SimpleQueryMessage — tokio-postgres parses it into the
                // u64 count. Synthesise a tag from what we know:
                // SELECT N when this result set had columns, OK N
                // otherwise (DML / DDL).
                statusmessage = if !current_columns.is_empty() {
                    format!("SELECT {}", current_rows.len())
                } else {
                    format!("OK {n}")
                };
                // Treat each CommandComplete as the end of a result set;
                // the LAST one becomes the final answer (matches the
                // single-statement common case + ignores BEGIN/COMMIT
                // wrappers we added).
                rows = std::mem::take(&mut current_rows);
                current_columns.clear();
            }
            _ => {}
        }
    }

    Ok(envelope_query(rows, statusmessage))
}

/// Execute a query WITH parameters via the typed `query` path. Types
/// are limited to the common cases; unknown column types stringify.
async fn execute_typed(
    client: &mut Client,
    query: &str,
    positional_args: &[String],
    autocommit: bool,
) -> Result<Value, String> {
    let args: Vec<&(dyn ToSql + Sync)> = positional_args
        .iter()
        .map(|s| s as &(dyn ToSql + Sync))
        .collect();

    let (rows, rowcount) = if autocommit {
        // execute returns rowcount for non-row-returning; query returns
        // rows. We pessimistically use query (works for both — returns
        // empty for DML without RETURNING).
        let rows = client
            .query(query, &args)
            .await
            .map_err(|e| format!("postgres error: {e}"))?;
        let n = rows.len();
        (rows, n as u64)
    } else {
        let tx = client
            .transaction()
            .await
            .map_err(|e| format!("postgres error: {e}"))?;
        let rows = tx
            .query(query, &args)
            .await
            .map_err(|e| format!("postgres error: {e}"))?;
        let n = rows.len();
        tx.commit()
            .await
            .map_err(|e| format!("postgres error: {e}"))?;
        (rows, n as u64)
    };

    let mut result_rows = Vec::with_capacity(rows.len());
    for row in &rows {
        let mut obj = Map::with_capacity(row.columns().len());
        for (i, col) in row.columns().iter().enumerate() {
            obj.insert(col.name().to_string(), pg_typed_to_json(row, i, col.type_()));
        }
        result_rows.push(Value::Object(obj));
    }

    let statusmessage = if !rows.is_empty() {
        format!("SELECT {}", rowcount)
    } else {
        format!("OK {}", rowcount)
    };
    Ok(envelope_query(
        result_rows
            .into_iter()
            .map(|v| match v {
                Value::Object(o) => o,
                _ => Map::new(),
            })
            .collect(),
        statusmessage,
    ))
}

fn envelope_query(rows: Vec<Map<String, Value>>, statusmessage: String) -> Value {
    let rowcount = rows.len();
    let mut env = Map::new();
    env.insert(
        "query_result".into(),
        Value::Array(rows.into_iter().map(Value::Object).collect()),
    );
    env.insert("rowcount".into(), Value::from(rowcount));
    env.insert("statusmessage".into(), Value::String(statusmessage));
    Value::Object(env)
}

fn pg_typed_to_json(row: &tokio_postgres::Row, idx: usize, ty: &Type) -> Value {
    match *ty {
        Type::BOOL => row
            .try_get::<_, Option<bool>>(idx)
            .ok()
            .flatten()
            .map(Value::Bool)
            .unwrap_or(Value::Null),
        Type::INT2 => row
            .try_get::<_, Option<i16>>(idx)
            .ok()
            .flatten()
            .map(|v| Value::from(v as i64))
            .unwrap_or(Value::Null),
        Type::INT4 => row
            .try_get::<_, Option<i32>>(idx)
            .ok()
            .flatten()
            .map(|v| Value::from(v as i64))
            .unwrap_or(Value::Null),
        Type::INT8 => row
            .try_get::<_, Option<i64>>(idx)
            .ok()
            .flatten()
            .map(Value::from)
            .unwrap_or(Value::Null),
        Type::FLOAT4 => row
            .try_get::<_, Option<f32>>(idx)
            .ok()
            .flatten()
            .and_then(|v| serde_json::Number::from_f64(v as f64).map(Value::Number))
            .unwrap_or(Value::Null),
        Type::FLOAT8 => row
            .try_get::<_, Option<f64>>(idx)
            .ok()
            .flatten()
            .and_then(|v| serde_json::Number::from_f64(v).map(Value::Number))
            .unwrap_or(Value::Null),
        Type::TEXT | Type::VARCHAR | Type::NAME | Type::BPCHAR => row
            .try_get::<_, Option<String>>(idx)
            .ok()
            .flatten()
            .map(Value::String)
            .unwrap_or(Value::Null),
        Type::BYTEA => row
            .try_get::<_, Option<Vec<u8>>>(idx)
            .ok()
            .flatten()
            .map(|b| Value::String(base64::engine::general_purpose::STANDARD.encode(b)))
            .unwrap_or(Value::Null),
        Type::JSON | Type::JSONB => row
            .try_get::<_, Option<Value>>(idx)
            .ok()
            .flatten()
            .unwrap_or(Value::Null),
        _ => {
            // Unknown type — try a String fallback (works for many
            // text-castable types). Failing that, null.
            row.try_get::<_, Option<String>>(idx)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null)
        }
    }
}

// ── OpPostgresqlExt ─────────────────────────────────────────────────

pub async fn run_ext(
    ctx: &Context,
    seq: u32,
    op: OpPostgresqlExtOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    let client = match connect(
        &op.db,
        &op.login_user,
        &op.login_password,
        &op.login_unix_socket,
        &op.login_host,
        op.login_port,
    )
    .await
    {
        Ok(c) => c,
        Err(msg) => {
            emit_error(ctx, seq, err::IO, msg).await;
            return Ok(());
        }
    };

    // Probe: is the extension already installed? Use simple_query for
    // a plain string result.
    let probe_sql = format!(
        "SELECT extversion FROM pg_extension WHERE extname = '{}'",
        escape_sql_literal(&op.name)
    );
    let probe_messages = match client.simple_query(&probe_sql).await {
        Ok(m) => m,
        Err(e) => {
            emit_error(ctx, seq, err::IO, format!("probing pg_extension: {e}")).await;
            return Ok(());
        }
    };
    let prior_version = extract_probe_version(&probe_messages);
    let currently_present = prior_version.is_some();
    let want_present = op.state == postgresql_ext_state::PRESENT;
    let needs_change = currently_present != want_present;

    let target_version: Option<String> = if op.version.is_empty() {
        None
    } else {
        Some(op.version.clone())
    };

    if !needs_change {
        // Already in the desired state. Build the envelope and return
        // changed=false (no DDL).
        let bytes = serde_json::to_vec(&envelope_ext(&op.name, want_present, prior_version.clone(), prior_version))?;
        ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
            .await;
        let finished_unix_ns = now_unix_ns();
        ctx.emit(msg::task_done(
            seq,
            0,
            false,
            false,
            started_unix_ns,
            finished_unix_ns,
        ))
        .await;
        return Ok(());
    }

    // We need to mutate. Under check_mode the controller already skipped
    // dispatch — defence in depth.
    if check_mode {
        let bytes = serde_json::to_vec(&envelope_ext(
            &op.name,
            want_present,
            prior_version.clone(),
            target_version.clone().or(prior_version),
        ))?;
        ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
            .await;
        let finished_unix_ns = now_unix_ns();
        ctx.emit(msg::task_done(
            seq,
            0,
            /*changed=*/ true,
            /*skipped=*/ true,
            started_unix_ns,
            finished_unix_ns,
        ))
        .await;
        return Ok(());
    }

    let ddl = if want_present {
        build_create_ext_sql(&op.name, &op.ext_schema, &op.version, op.cascade != 0)
    } else {
        build_drop_ext_sql(&op.name, op.cascade != 0)
    };

    if let Err(e) = client.simple_query(&ddl).await {
        emit_error(ctx, seq, err::BAD_REQUEST, format!("DDL failed: {e}")).await;
        return Ok(());
    }

    // Probe again for the post-state version.
    let post_version = if want_present {
        match client.simple_query(&probe_sql).await {
            Ok(m) => extract_probe_version(&m),
            Err(_) => target_version.clone(),
        }
    } else {
        None
    };

    let bytes = serde_json::to_vec(&envelope_ext(&op.name, want_present, prior_version, post_version))?;
    ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
        .await;

    let finished_unix_ns = now_unix_ns();
    ctx.emit(msg::task_done(
        seq,
        0,
        /*changed=*/ true,
        /*skipped=*/ false,
        started_unix_ns,
        finished_unix_ns,
    ))
    .await;
    Ok(())
}

fn extract_probe_version(messages: &[SimpleQueryMessage]) -> Option<String> {
    for m in messages {
        if let SimpleQueryMessage::Row(r) = m {
            return r.get(0).map(|s| s.to_string());
        }
    }
    None
}

fn envelope_ext(name: &str, present: bool, prior: Option<String>, current: Option<String>) -> Value {
    let mut env = Map::new();
    env.insert("extension".into(), Value::String(name.to_string()));
    env.insert(
        "state".into(),
        Value::String(if present { "present" } else { "absent" }.into()),
    );
    env.insert(
        "prior_version".into(),
        prior.map(Value::String).unwrap_or(Value::Null),
    );
    env.insert(
        "version".into(),
        current.map(Value::String).unwrap_or(Value::Null),
    );
    Value::Object(env)
}

fn build_create_ext_sql(name: &str, schema: &str, version: &str, cascade: bool) -> String {
    let mut sql = format!("CREATE EXTENSION IF NOT EXISTS \"{}\"", escape_ident(name));
    if !schema.is_empty() {
        sql.push_str(&format!(" WITH SCHEMA \"{}\"", escape_ident(schema)));
    }
    if !version.is_empty() {
        sql.push_str(&format!(" VERSION '{}'", escape_sql_literal(version)));
    }
    if cascade {
        sql.push_str(" CASCADE");
    }
    sql
}

fn build_drop_ext_sql(name: &str, cascade: bool) -> String {
    let mut sql = format!("DROP EXTENSION IF EXISTS \"{}\"", escape_ident(name));
    if cascade {
        sql.push_str(" CASCADE");
    }
    sql
}

/// Escape a SQL string literal — double up single quotes. The wider
/// SQL-injection surface is mitigated by the caller validating the
/// extension/schema name as an identifier (`escape_ident`).
fn escape_sql_literal(s: &str) -> String {
    s.replace('\'', "''")
}

/// Escape a SQL identifier (extension/schema name) — double up
/// double quotes. We wrap the result in double-quotes in the DDL.
fn escape_ident(s: &str) -> String {
    s.replace('"', "\"\"")
}

// ── Connection ──────────────────────────────────────────────────────

async fn connect(
    db: &str,
    user: &str,
    password: &str,
    unix_socket: &str,
    host: &str,
    port: u16,
) -> Result<Client, String> {
    let mut cfg = Config::new();
    if !unix_socket.is_empty() {
        cfg.host_path(unix_socket);
    } else if !host.is_empty() {
        cfg.host(host);
    } else {
        cfg.host("localhost");
    }
    cfg.port(if port == 0 { 5432 } else { port });
    if !user.is_empty() {
        cfg.user(user);
    } else {
        // libpq defaults to the OS username; tokio-postgres does NOT
        // — explicitly populate from getuid so peer auth Just Works.
        let uid = rustix::process::getuid();
        // Fallback to "postgres" when we can't get the username; this
        // matches the common deployment posture.
        let user = whoami_for_uid(uid.as_raw()).unwrap_or_else(|| "postgres".into());
        cfg.user(&user);
    }
    if !password.is_empty() {
        cfg.password(password);
    }
    if db.is_empty() {
        cfg.dbname("postgres");
    } else {
        cfg.dbname(db);
    }

    let (client, conn) = cfg
        .connect(NoTls)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    // tokio-postgres requires the connection future to be driven on a
    // task. It owns the actual socket I/O; the Client is just a handle
    // that queues requests against it.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::warn!(error = %e, "postgres connection terminated");
        }
    });
    Ok(client)
}

fn whoami_for_uid(uid: u32) -> Option<String> {
    // Cheap /etc/passwd lookup. We don't pull in `users` or `nix` just
    // for this — peer auth only cares about the uid bytes anyway, but
    // libpq-style configs key on the username string. A failure here
    // just means we fall back to "postgres" in the caller.
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.splitn(7, ':');
        let user = fields.next()?;
        fields.next()?; // password placeholder
        let line_uid: u32 = fields.next()?.parse().ok()?;
        if line_uid == uid {
            return Some(user.to_string());
        }
    }
    None
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ext_sql_basic() {
        let s = build_create_ext_sql("pg_stat_statements", "", "", false);
        assert_eq!(s, r#"CREATE EXTENSION IF NOT EXISTS "pg_stat_statements""#);
    }

    #[test]
    fn create_ext_sql_with_schema_and_version() {
        let s = build_create_ext_sql("hstore", "public", "1.8", false);
        assert_eq!(
            s,
            r#"CREATE EXTENSION IF NOT EXISTS "hstore" WITH SCHEMA "public" VERSION '1.8'"#
        );
    }

    #[test]
    fn create_ext_sql_cascade() {
        let s = build_create_ext_sql("postgis", "", "", true);
        assert_eq!(s, r#"CREATE EXTENSION IF NOT EXISTS "postgis" CASCADE"#);
    }

    #[test]
    fn drop_ext_sql() {
        assert_eq!(
            build_drop_ext_sql("hstore", false),
            r#"DROP EXTENSION IF EXISTS "hstore""#
        );
        assert_eq!(
            build_drop_ext_sql("hstore", true),
            r#"DROP EXTENSION IF EXISTS "hstore" CASCADE"#
        );
    }

    #[test]
    fn escape_ident_doubles_quotes() {
        assert_eq!(escape_ident(r#"weird"name"#), r#"weird""name"#);
    }

    #[test]
    fn escape_literal_doubles_apos() {
        assert_eq!(escape_sql_literal("O'Brien"), "O''Brien");
    }
}
