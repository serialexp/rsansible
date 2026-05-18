//! `OpGetent` — single-key NSS database lookup.
//!
//! Shells out to `getent <database> <key>` and parses the result.
//! Read-only: never reports `changed=1`. Envelope shape:
//!   - `database`: echoed back
//!   - `<key>`: list-of-strings (fields after the lookup key), or `null`
//!              when `fail_key=0` and the lookup missed.
//!
//! On a miss with `fail_key=1` we emit `TaskError BAD_REQUEST` with a
//! message naming the database + key — matches Ansible's surfacing of
//! "Key '<k>' not found in <db>" so vendored playbooks see the same
//! failure shape.
//!
//! `split` chooses the field separator (Ansible's `split:`):
//!   - empty string → database-derived default (`:` for passwd/group/
//!     shadow/services, whitespace for hosts/aliases/networks/protocols)
//!   - explicit string → that exact character (single byte) is used.
//!     Multi-character splits aren't supported; we error at parse
//!     time on the controller side.
//!
//! `getent` itself is part of glibc and present on every system we
//! support; if it's missing we surface SPAWN_FAILED rather than a
//! cryptic "command not found".
//!
//! Exit-code contract from `getent` (man getent):
//!   0 — found
//!   1 — missing database (we map to BAD_REQUEST)
//!   2 — key not found (the interesting case)
//!   3 — `enumeration not supported` (we treat as BAD_REQUEST)
//!   other — surfaced as IO with stderr attached.

use std::process::Command;

use rsansible_wire::generated::OpGetentOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};
use serde_json::{json, Value};

use super::{emit_error, Context};

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpGetentOutput,
    _check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    if op.database.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "getent: empty `database`").await;
        return Ok(());
    }
    if op.key.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "getent: empty `key`").await;
        return Ok(());
    }

    let result = tokio::task::spawn_blocking(move || apply(&op))
        .await
        .map_err(|e| anyhow::anyhow!("getent join: {e}"))?;

    match result {
        Ok(value) => {
            let bytes = serde_json::to_vec(&value)?;
            ctx.emit(msg::task_progress(seq, msg::stream::STDOUT, bytes))
                .await;
            ctx.emit(msg::task_done(
                seq,
                0,
                false,
                false,
                started_unix_ns,
                now_unix_ns(),
            ))
            .await;
        }
        Err(GetentError::Io(m)) => emit_error(ctx, seq, err::IO, m).await,
        Err(GetentError::Spawn(m)) => emit_error(ctx, seq, err::SPAWN_FAILED, m).await,
        Err(GetentError::BadRequest(m)) => emit_error(ctx, seq, err::BAD_REQUEST, m).await,
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum GetentError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

pub(crate) fn apply(op: &OpGetentOutput) -> Result<Value, GetentError> {
    let getent = std::env::var("RSANSIBLE_GETENT").unwrap_or_else(|_| "getent".into());
    apply_with_bin(&getent, op)
}

pub(crate) fn apply_with_bin(getent: &str, op: &OpGetentOutput) -> Result<Value, GetentError> {
    let split = resolve_split(&op.database, &op.split)?;

    let out = Command::new(getent)
        .args([&op.database, &op.key])
        .output()
        .map_err(|e| GetentError::Spawn(format!("spawn {getent}: {e}")))?;

    match out.status.code() {
        Some(0) => {
            let line = String::from_utf8_lossy(&out.stdout);
            let line = line.trim_end_matches('\n');
            let fields = split_line(line, &split);
            Ok(json!({
                "database": op.database,
                op.key.clone(): fields,
            }))
        }
        Some(2) => {
            if op.fail_key != 0 {
                Err(GetentError::BadRequest(format!(
                    "getent: key {:?} not found in {:?}",
                    op.key, op.database
                )))
            } else {
                Ok(json!({
                    "database": op.database,
                    op.key.clone(): Value::Null,
                }))
            }
        }
        Some(1) | Some(3) => Err(GetentError::BadRequest(format!(
            "getent: unsupported database {:?} (exit {})",
            op.database,
            out.status.code().unwrap()
        ))),
        Some(code) => Err(GetentError::Io(format!(
            "{getent} {} {}: exit {code} stderr={:?}",
            op.database,
            op.key,
            String::from_utf8_lossy(&out.stderr)
        ))),
        None => Err(GetentError::Io(format!(
            "{getent} {} {}: killed by signal",
            op.database, op.key
        ))),
    }
}

/// Pick the field separator. If `op_split` is empty, derive from the
/// database name. We accept the Ansible split-character set without
/// validation: empty → default, any non-empty single character → use
/// it verbatim.
fn resolve_split(database: &str, op_split: &str) -> Result<SplitSpec, GetentError> {
    if op_split.is_empty() {
        Ok(default_split_for(database))
    } else {
        Ok(SplitSpec::Char(op_split.to_string()))
    }
}

fn default_split_for(database: &str) -> SplitSpec {
    match database {
        // colon-separated entries
        "passwd" | "group" | "shadow" | "gshadow" | "services" => SplitSpec::Char(":".into()),
        // whitespace-separated
        "hosts" | "aliases" | "networks" | "protocols" | "rpc" | "ethers" => SplitSpec::Whitespace,
        // unknown — default to colon (matches Ansible's getent fallback)
        _ => SplitSpec::Char(":".into()),
    }
}

#[derive(Debug, Clone)]
enum SplitSpec {
    Char(String),
    Whitespace,
}

/// Split a single result line on the chosen separator. Drops the first
/// field (the lookup key) so the envelope's `<key>: [...]` matches
/// Ansible's `getent_<db>[key] = [field1, field2, ...]` shape.
fn split_line(line: &str, split: &SplitSpec) -> Vec<String> {
    let parts: Vec<String> = match split {
        SplitSpec::Char(s) => line.split(s.as_str()).map(|s| s.to_string()).collect(),
        SplitSpec::Whitespace => line.split_whitespace().map(|s| s.to_string()).collect(),
    };
    // Drop the first field (the lookup key itself).
    if parts.is_empty() {
        parts
    } else {
        parts[1..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Stub {
        dir: PathBuf,
        bin: PathBuf,
    }
    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    impl Stub {
        fn new(label: &str, db_lines: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-getent-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            // db file format: "<database> <line>" — the stub greps for
            // the first column matching $1 and matching the requested key.
            let db = dir.join("db");
            let mut s = String::new();
            for (database, line) in db_lines {
                s.push_str(&format!("{database}\t{line}\n"));
            }
            std::fs::write(&db, s).unwrap();

            let bin = dir.join("getent");
            let script = format!(
                r#"#!/bin/sh
DB="{db}"
db="$1"
key="$2"
# match: lines starting with "<db>\t" whose key (1st field after tab,
# colon- or whitespace-separated) equals $key.
awk -v db="$db" -v key="$key" '
$1 == db {{
    rest = substr($0, length($1) + 2)
    # try colon-split first
    n = split(rest, fs, ":")
    if (n > 1 && fs[1] == key) {{ print rest; found = 1; exit 0 }}
    # then whitespace-split
    n = split(rest, fs, /[[:space:]]+/)
    if (fs[1] == key) {{ print rest; found = 1; exit 0 }}
}}
END {{ if (!found) exit 2 }}
' "$DB"
"#,
                db = db.display()
            );
            std::fs::write(&bin, script.as_bytes()).unwrap();
            let mut perms = std::fs::metadata(&bin).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin, perms).unwrap();

            Stub { dir, bin }
        }
    }

    fn op(database: &str, key: &str, fail_key: bool) -> OpGetentOutput {
        OpGetentOutput {
            kind: 25,
            database: database.into(),
            key: key.into(),
            fail_key: if fail_key { 1 } else { 0 },
            split: String::new(),
        }
    }

    #[test]
    fn parses_passwd_line() {
        let stub = Stub::new(
            "pw",
            &[("passwd", "postgres:x:1000:1000::/var/lib/postgresql:/bin/bash")],
        );
        let out = apply_with_bin(stub.bin.to_str().unwrap(), &op("passwd", "postgres", true))
            .unwrap();
        let pg = out.get("postgres").unwrap().as_array().unwrap();
        // First field after lookup key is the password placeholder.
        assert_eq!(pg[0], "x");
        assert_eq!(pg[5], "/bin/bash");
        assert_eq!(out["database"], "passwd");
    }

    #[test]
    fn miss_with_fail_key_errors() {
        let stub = Stub::new("miss", &[]);
        let e = apply_with_bin(stub.bin.to_str().unwrap(), &op("passwd", "nobody", true))
            .unwrap_err();
        match e {
            GetentError::BadRequest(m) => assert!(m.contains("not found"), "got: {m}"),
            other => panic!("expected BadRequest, got: {other:?}"),
        }
    }

    #[test]
    fn miss_without_fail_key_returns_null() {
        let stub = Stub::new("miss-noflag", &[]);
        let out = apply_with_bin(stub.bin.to_str().unwrap(), &op("passwd", "nobody", false))
            .unwrap();
        assert!(out.get("nobody").unwrap().is_null());
    }

    #[test]
    fn whitespace_db_splits_on_whitespace() {
        let stub = Stub::new("hosts", &[("hosts", "10.0.0.1 pg1.local pg1")]);
        let out = apply_with_bin(stub.bin.to_str().unwrap(), &op("hosts", "10.0.0.1", true))
            .unwrap();
        let fields = out.get("10.0.0.1").unwrap().as_array().unwrap();
        // First field after the IP (the lookup key) is the canonical name.
        assert_eq!(fields[0], "pg1.local");
        assert_eq!(fields[1], "pg1");
    }
}
