//! `postgresql_query:` / `postgresql_ext:` task bodies, plus the
//! controller-side SQL read-only classifier they share.
//!
//! The classifier lives here rather than `shared.rs` because it's only
//! used by these two ops; if anything else needs SQL classification
//! later we can lift it.

use super::shared::{
    take_optional_ansible_bool, take_optional_field_string,
};
use rsansible_wire::msg::postgresql_ext_state;
use serde::{de::Error as _, Deserialize, Deserializer};

/// `postgresql_query:` parsed form. Mirrors
/// `community.postgresql.postgresql_query` (subset).
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlQueryOp {
    /// SQL to execute. Jinja-templatable.
    pub query: String,
    /// Database name. Empty = "postgres" (server default).
    pub db: String,
    /// Login user. Empty = peer auth using the agent process uid.
    pub login_user: String,
    /// Login password. Empty = no password (peer/trust auth).
    pub login_password: String,
    /// UNIX socket path (e.g. `/var/run/postgresql`). Empty = use TCP.
    pub login_unix_socket: String,
    /// TCP host (only consulted if `login_unix_socket` is empty).
    /// Empty = `localhost`.
    pub login_host: String,
    /// TCP port. 0 = 5432.
    pub login_port: u16,
    /// `autocommit=true` runs the query outside any transaction
    /// (required for VACUUM, CREATE INDEX CONCURRENTLY, etc.).
    /// Default false → wrapped in BEGIN/COMMIT.
    pub autocommit: bool,
    /// Positional parameters as text. The agent binds these as text and
    /// relies on server-side casts (`WHERE id = $1::int`).
    pub positional_args: Vec<String>,
    /// Controller-classified: true if the SQL is read-only
    /// (SELECT/SHOW/EXPLAIN/VALUES/WITH/TABLE). Drives check-mode skip
    /// and `changed` reporting downstream.
    pub read_only: bool,
}

/// `postgresql_ext:` parsed form. Mirrors
/// `community.postgresql.postgresql_ext` (subset). Version updates
/// not implemented in v1.
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlExtOp {
    /// Extension name (e.g. `pg_stat_statements`).
    pub name: String,
    /// Target state. 0=present, 1=absent — matches the wire byte.
    pub state: u8,
    /// Pinned extension version. Empty = server default.
    pub version: String,
    /// Schema to install into. Empty = default. Field-named
    /// `ext_schema` on the wire to avoid colliding with the SQL
    /// reserved word `schema`.
    pub ext_schema: String,
    /// Add CASCADE to CREATE/DROP EXTENSION.
    pub cascade: bool,
    pub db: String,
    pub login_user: String,
    pub login_password: String,
    pub login_unix_socket: String,
    pub login_host: String,
    pub login_port: u16,
}

/// `postgresql_user:` parsed form. Maps Ansible's
/// `community.postgresql.postgresql_user` (subset).
///
/// Implemented as a controller-side composite that dispatches one or
/// two `OpPostgresqlQuery` wire ops per task: a `SELECT … FROM
/// pg_authid` probe (always), followed by a CREATE/ALTER/DROP ROLE on
/// divergence only. Idempotent re-runs cost one roundtrip; mutating
/// runs cost two. See `crates/ctl/src/orchestrator.rs::run_postgresql_user_composite`
/// for the dispatch logic and `TODO.md` for the "collapse to one
/// wire-dispatch" follow-up.
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlUserOp {
    /// Role name. Jinja-templatable. Quoted as an identifier in the
    /// emitted SQL — no `;` injection risk.
    pub name: String,
    /// Password to set on the role. Empty means "do not touch the
    /// password" (matches Ansible). Jinja-templatable. Treated as
    /// secret: never logged in plaintext; masked from `register.queries`.
    pub password: String,
    /// `role_attr_flags:` — comma-separated list like
    /// `"LOGIN,NOSUPERUSER,NOCREATEROLE,NOCREATEDB"`. Each bool attr
    /// in this list participates in idempotency; attrs not mentioned
    /// keep their current server-side value. Jinja-templatable.
    pub role_attr_flags: String,
    /// Target state. 0=present (default), 1=absent.
    pub state: u8,
    /// `no_password_changes: true` skips the ALTER ROLE … WITH
    /// PASSWORD path even when `password:` is set, but the password
    /// is still used at CREATE time for absent → present runs.
    pub no_password_changes: bool,
    /// `conn_limit:` — connection limit attr.
    /// `i32::MIN` (sentinel) = field not set; -1 = unlimited; >=0 =
    /// max concurrent connections. Default sentinel.
    pub conn_limit: i32,
    /// `db:` / `login_db:` — database to connect to for executing the
    /// SQL. Empty = server default ("postgres").
    pub db: String,
    pub login_user: String,
    pub login_password: String,
    pub login_unix_socket: String,
    pub login_host: String,
    pub login_port: u16,
}

/// Sentinel for "conn_limit: was not set in the playbook." `i32::MIN`
/// is unmistakably outside any reasonable user value (-1 is the
/// "unlimited" sentinel postgres itself uses).
pub const CONN_LIMIT_UNSET: i32 = i32::MIN;

/// `postgresql_db:` parsed form. Maps Ansible's
/// `community.postgresql.postgresql_db` (subset).
///
/// Same controller-side composite shape as `postgresql_user`: probe
/// `pg_database`, then conditionally CREATE/DROP/ALTER OWNER. Encoding
/// / collation can't be changed post-CREATE — a divergence between
/// requested and existing produces a hard error rather than a silent
/// no-op.
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlDbOp {
    /// Database name. Jinja-templatable. Quoted as identifier.
    pub name: String,
    /// Owner role. Jinja-templatable. Empty = no ALTER OWNER on
    /// existing DB; absent + create = postgres defaults the owner to
    /// the connecting user.
    pub owner: String,
    /// `encoding:` — locale-encoding name (e.g. "UTF8"). Empty =
    /// server-default. CREATE-only; mismatch on existing DB errors.
    pub encoding: String,
    /// `lc_collate:` — collation locale. Empty = server-default.
    /// CREATE-only; mismatch errors.
    pub lc_collate: String,
    /// `lc_ctype:` — character classification locale. Empty =
    /// server-default. CREATE-only; mismatch errors.
    pub lc_ctype: String,
    /// `template:` — template database to clone (default `template1`,
    /// `template0` lets you specify a different collation/encoding).
    /// Empty = postgres default. CREATE-only.
    pub template: String,
    /// Target state. 0=present, 1=absent.
    pub state: u8,
    pub login_user: String,
    pub login_password: String,
    pub login_unix_socket: String,
    pub login_host: String,
    pub login_port: u16,
}

/// `postgresql_membership:` parsed form. Maps Ansible's
/// `community.postgresql.postgresql_membership` (subset).
///
/// Controller-side composite: probe `pg_auth_members` for each
/// (group, target_role) pair, then GRANT or REVOKE on divergence.
/// Idempotent re-runs cost one probe roundtrip per pair.
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlMembershipOp {
    /// One or more group roles. Accepts `group:` (singular) or
    /// `groups:` (list). Jinja-templatable per item.
    pub groups: Vec<String>,
    /// One or more target roles (the roles being added to / removed
    /// from the groups). Accepts `target_role:` or `target_roles:`.
    /// Jinja-templatable per item.
    pub target_roles: Vec<String>,
    /// Target state. 0=present (grant), 1=absent (revoke).
    pub state: u8,
    /// `fail_on_role: false` lets the task succeed when the group or
    /// target role doesn't exist (mirrors Ansible). Default true.
    pub fail_on_role: bool,
    pub db: String,
    pub login_user: String,
    pub login_password: String,
    pub login_unix_socket: String,
    pub login_host: String,
    pub login_port: u16,
}

/// Classify a SQL statement as read-only or potentially-mutating, used
/// by `--check` to decide whether to dispatch the task or skip it
/// outright on the controller. Heuristic — not a full SQL parser — but
/// sufficient for the well-formed SQL acme issues:
///
/// 1. Strip leading whitespace, `-- line comments`, and `/* block */`
///    comments (with nesting; postgres supports nested `/* */`).
/// 2. Look at the first identifier token.
/// 3. SELECT, SHOW, VALUES, TABLE → read-only.
///    EXPLAIN → read-only unless the option list / leading bareword
///    options include `ANALYZE` (or `EXECUTE` with non-EXPLAIN payload).
///    `EXPLAIN ANALYZE` runs the wrapped statement; we treat such a
///    body as a fresh sub-statement and recurse.
///    WITH → scan every parenthesised CTE body and the trailing
///    statement; if any of those contain a mutating keyword token
///    (INSERT/UPDATE/DELETE/MERGE/TRUNCATE/CREATE/DROP/…) at top level
///    of their respective sub-expression, the whole WITH is mutating.
///    Everything else → mutating.
///
/// When the SQL contains multiple statements separated by semicolons,
/// classify each; only return true if *every* statement is read-only.
///
/// Remaining caveats (documented; not blocking):
/// - The keyword scanner is identifier-aware (skips string literals,
///   dollar-quoted bodies, and double-quoted identifiers) so column /
///   table names that happen to spell `insert_ts` etc. don't trip it.
/// - We don't try to follow `EXECUTE` of a prepared statement; if a
///   caller uses `EXPLAIN ANALYZE EXECUTE foo`, we treat it as
///   mutating (conservative).
pub fn classify_sql_readonly(sql: &str) -> bool {
    let stripped = strip_sql_comments(sql);
    let statements = split_sql_statements(&stripped);
    if statements.is_empty() {
        // Empty / whitespace-only query: no mutation possible.
        return true;
    }
    statements.iter().all(|s| classify_one_statement_readonly(s))
}

/// Decide whether a single, comment-stripped statement is read-only.
fn classify_one_statement_readonly(stmt: &str) -> bool {
    match first_sql_keyword(stmt).as_deref() {
        Some("SELECT") | Some("SHOW") | Some("VALUES") | Some("TABLE") => true,
        Some("EXPLAIN") => explain_is_readonly(stmt),
        Some("WITH") => with_is_readonly(stmt),
        _ => false,
    }
}

/// Returns true if the EXPLAIN body executes its inner statement.
/// `EXPLAIN ANALYZE …` runs the inner; `EXPLAIN (ANALYZE) …` runs it;
/// `EXPLAIN (ANALYZE false) …` does not. Without ANALYZE the inner is
/// never executed regardless of what it contains.
fn explain_is_readonly(stmt: &str) -> bool {
    if !explain_options_include_analyze(stmt) {
        return true;
    }
    // ANALYZE is on — the wrapped statement runs. Strip the EXPLAIN
    // header (keyword + options block / bareword options) and classify
    // whatever's left as its own statement.
    let inner = strip_explain_header(stmt);
    classify_one_statement_readonly(inner)
}

/// Returns true if a `WITH …` statement is read-only — i.e. every CTE
/// body and the trailing statement use only read verbs.
fn with_is_readonly(stmt: &str) -> bool {
    // Conservative: if any mutating keyword token appears anywhere in
    // the WITH (outside string literals / dollar-quoted bodies /
    // quoted identifiers), call the whole thing mutating. This catches
    // both `WITH x AS (DELETE …) SELECT …` and the trailing-DML form
    // `WITH x AS (SELECT …) DELETE FROM t USING x`.
    !contains_mutating_keyword_token(stmt)
}

/// Mutating keywords we recognise as standalone identifiers. Lowercase
/// inputs are normalised by `next_identifier_token`'s `to_ascii_uppercase`.
const MUTATING_KEYWORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "CREATE", "DROP", "ALTER", "GRANT",
    "REVOKE", "CLUSTER", "REINDEX", "VACUUM", "REFRESH", "COPY", "CALL", "EXECUTE", "DO",
    "LISTEN", "UNLISTEN", "NOTIFY", "LOCK", "PREPARE", "DEALLOCATE", "SET", "RESET",
    "DISCARD", "SECURITY",
];

/// True if any identifier token in `s` (skipping string/identifier/dollar
/// literals) matches one of the mutating keywords.
fn contains_mutating_keyword_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(skip_to) = skip_literal(bytes, i) {
            i = skip_to;
            continue;
        }
        if let Some((tok, next)) = next_identifier_token(bytes, i) {
            i = next;
            if MUTATING_KEYWORDS.iter().any(|k| *k == tok) {
                return true;
            }
            continue;
        }
        i += 1;
    }
    false
}

/// True if the EXPLAIN options preceding the wrapped statement include
/// `ANALYZE` (legacy bareword) or `ANALYZE [TRUE|ON|1]` inside the
/// parenthesised options list. `ANALYZE FALSE` etc. don't count.
fn explain_options_include_analyze(stmt: &str) -> bool {
    let bytes = stmt.as_bytes();
    // Skip "EXPLAIN" keyword.
    let mut i = skip_one_keyword(bytes, 0, "EXPLAIN");
    i = skip_whitespace(bytes, i);
    // Parenthesised options form?
    if bytes.get(i).copied() == Some(b'(') {
        // Find matching ')'.
        let end = find_matching_paren(bytes, i).unwrap_or(bytes.len());
        let opts = &stmt[i + 1..end];
        return options_block_has_analyze_on(opts);
    }
    // Legacy bareword form: scan tokens until we hit something that
    // isn't ANALYZE/VERBOSE.
    let mut j = i;
    while j < bytes.len() {
        j = skip_whitespace(bytes, j);
        let Some((tok, next)) = next_identifier_token(bytes, j) else { return false };
        match tok.as_str() {
            "ANALYZE" => return true,
            "VERBOSE" => {
                j = next;
                continue;
            }
            _ => return false,
        }
    }
    false
}

/// True if a comma-separated EXPLAIN options block (e.g.
/// `ANALYZE, BUFFERS true`) sets ANALYZE to a truthy value (or leaves
/// it bare — defaults to ON).
fn options_block_has_analyze_on(opts: &str) -> bool {
    for opt in opts.split(',') {
        let mut parts = opt.split_ascii_whitespace();
        let Some(name) = parts.next() else { continue };
        if name.eq_ignore_ascii_case("ANALYZE") {
            // ANALYZE alone is ON; ANALYZE TRUE/ON/1 is ON.
            match parts.next() {
                None => return true,
                Some(v) => {
                    let v = v.to_ascii_uppercase();
                    if matches!(v.as_str(), "TRUE" | "ON" | "1") {
                        return true;
                    }
                    if matches!(v.as_str(), "FALSE" | "OFF" | "0") {
                        return false;
                    }
                    // Anything else (e.g. malformed) — conservative ON.
                    return true;
                }
            }
        }
    }
    false
}

/// Strip the `EXPLAIN [(...)] [ANALYZE] [VERBOSE]` header from a
/// statement; return the remaining wrapped statement. Used when ANALYZE
/// is on and we need to recurse on the inner statement.
fn strip_explain_header(stmt: &str) -> &str {
    let bytes = stmt.as_bytes();
    let mut i = skip_one_keyword(bytes, 0, "EXPLAIN");
    i = skip_whitespace(bytes, i);
    if bytes.get(i).copied() == Some(b'(') {
        let end = find_matching_paren(bytes, i).unwrap_or(bytes.len());
        i = end + 1;
        i = skip_whitespace(bytes, i);
    } else {
        // Legacy bareword options.
        while let Some((tok, next)) = next_identifier_token(bytes, i) {
            if matches!(tok.as_str(), "ANALYZE" | "VERBOSE") {
                i = next;
                i = skip_whitespace(bytes, i);
            } else {
                break;
            }
        }
    }
    &stmt[i..]
}

/// If the byte at `start` opens a string literal, identifier-literal, or
/// dollar-quoted body, return the index just past the closing delimiter.
/// Otherwise None.
fn skip_literal(bytes: &[u8], start: usize) -> Option<usize> {
    let b = *bytes.get(start)?;
    match b {
        b'\'' => {
            let mut i = start + 1;
            while i < bytes.len() {
                let c = bytes[i];
                i += 1;
                if c == b'\'' {
                    if bytes.get(i).copied() == Some(b'\'') {
                        i += 1;
                        continue;
                    }
                    return Some(i);
                }
            }
            Some(bytes.len())
        }
        b'"' => {
            let mut i = start + 1;
            while i < bytes.len() {
                let c = bytes[i];
                i += 1;
                if c == b'"' {
                    if bytes.get(i).copied() == Some(b'"') {
                        i += 1;
                        continue;
                    }
                    return Some(i);
                }
            }
            Some(bytes.len())
        }
        b'$' => {
            // Dollar-quoted body: $tag$ ... $tag$. tag may be empty.
            let mut j = start + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if bytes.get(j).copied() != Some(b'$') {
                return None;
            }
            let tag = &bytes[start + 1..j];
            let mut needle = Vec::with_capacity(tag.len() + 2);
            needle.push(b'$');
            needle.extend_from_slice(tag);
            needle.push(b'$');
            let body_start = j + 1;
            if let Some(off) = find_subslice(&bytes[body_start..], &needle) {
                Some(body_start + off + needle.len())
            } else {
                Some(bytes.len())
            }
        }
        _ => None,
    }
}

/// Return the next identifier token starting at `start` (skipping
/// leading whitespace), uppercased, plus the index just past it.
fn next_identifier_token(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = skip_whitespace(bytes, start);
    let token_start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        i += 1;
    }
    // Allow trailing digits/underscores once at least one alpha char has
    // been seen — but to keep keyword matching strict, stop at the first
    // non-alpha-underscore for now (keywords don't contain digits).
    if i == token_start {
        return None;
    }
    let tok = std::str::from_utf8(&bytes[token_start..i])
        .ok()?
        .to_ascii_uppercase();
    Some((tok, i))
}

fn skip_whitespace(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Skip the literal keyword `kw` if it appears at `start` (case
/// insensitive); otherwise return `start` unchanged.
fn skip_one_keyword(bytes: &[u8], start: usize, kw: &str) -> usize {
    let s = skip_whitespace(bytes, start);
    if s + kw.len() <= bytes.len()
        && bytes[s..s + kw.len()].eq_ignore_ascii_case(kw.as_bytes())
        && bytes
            .get(s + kw.len())
            .map(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
            .unwrap_or(true)
    {
        s + kw.len()
    } else {
        start
    }
}

/// Given an index pointing at `(`, find the matching `)`, respecting
/// nested parens and string/dollar/identifier literals inside.
fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 1i32;
    let mut i = open + 1;
    while i < bytes.len() {
        if let Some(skip_to) = skip_literal(bytes, i) {
            i = skip_to;
            continue;
        }
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    (0..=last).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Strip `-- line` and `/* nested */` comments from a SQL string.
/// Preserves string literals and dollar-quoted bodies verbatim — a `--`
/// inside a literal is not a comment.
fn strip_sql_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        match (b, next) {
            (b'-', Some(b'-')) => {
                // Line comment to EOL.
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                // Block comment; postgres supports nesting.
                let mut depth = 1u32;
                i += 2;
                while i + 1 < bytes.len() && depth > 0 {
                    match (bytes[i], bytes[i + 1]) {
                        (b'/', b'*') => {
                            depth += 1;
                            i += 2;
                        }
                        (b'*', b'/') => {
                            depth -= 1;
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
            }
            (b'\'', _) => {
                // Single-quoted literal — copy through, watching for '' escape.
                out.push(b as char);
                i += 1;
                while i < bytes.len() {
                    let c = bytes[i];
                    out.push(c as char);
                    i += 1;
                    if c == b'\'' {
                        // doubled? skip the second one.
                        if bytes.get(i).copied() == Some(b'\'') {
                            out.push('\'');
                            i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// Split a SQL body on unquoted `;`. Returns the trimmed, non-empty
/// statements.
fn split_sql_statements(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' => {
                cur.push(b as char);
                i += 1;
                while i < bytes.len() {
                    let c = bytes[i];
                    cur.push(c as char);
                    i += 1;
                    if c == b'\'' {
                        if bytes.get(i).copied() == Some(b'\'') {
                            cur.push('\'');
                            i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
            b';' => {
                let trimmed = cur.trim().to_string();
                if !trimmed.is_empty() {
                    out.push(trimmed);
                }
                cur.clear();
                i += 1;
            }
            _ => {
                cur.push(b as char);
                i += 1;
            }
        }
    }
    let last = cur.trim().to_string();
    if !last.is_empty() {
        out.push(last);
    }
    out
}

/// Return the first identifier in the statement, uppercased.
fn first_sql_keyword(stmt: &str) -> Option<String> {
    let bytes = stmt.as_bytes();
    let mut i = 0;
    // skip whitespace and any leading `(` from things like
    // `( SELECT ... )`
    while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'(') {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        i += 1;
    }
    if i == start {
        return None;
    }
    Some(stmt[start..i].to_ascii_uppercase())
}

/// `db:` and `login_db:` are aliases in Ansible's
/// `community.postgresql.*` modules. Accept either spelling; if both
/// are set with the same value, that's fine; if both are set with
/// *different* values, the YAML is ambiguous and we reject. Returns
/// the resolved db name or empty string if neither is present.
fn resolve_db_alias<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    module: &str,
) -> Result<String, E> {
    let a = take_optional_field_string::<E>(map, "db")?;
    let b = take_optional_field_string::<E>(map, "login_db")?;
    match (a, b) {
        (Some(x), Some(y)) if x == y => Ok(x),
        (Some(_), Some(_)) => Err(E::custom(format!(
            "{module}: both `db:` and `login_db:` set with different values \
             — they're aliases; pick one"
        ))),
        (Some(x), None) | (None, Some(x)) => Ok(x),
        (None, None) => Ok(String::new()),
    }
}

/// Shared deserialization of `login_user` / `login_password` /
/// `login_unix_socket` / `login_host` / `login_port` for every
/// postgresql_* task. Mutates `map` to consume the fields it
/// recognises; caller checks `map.is_empty()` afterward.
fn take_pg_login_fields<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    module: &str,
) -> Result<(String, String, String, String, u16), E> {
    let login_user = take_optional_field_string(map, "login_user")?.unwrap_or_default();
    let login_password =
        take_optional_field_string(map, "login_password")?.unwrap_or_default();
    let login_unix_socket =
        take_optional_field_string(map, "login_unix_socket")?.unwrap_or_default();
    let login_host = take_optional_field_string(map, "login_host")?.unwrap_or_default();
    let login_port = match map.remove("login_port") {
        None | Some(serde_yaml::Value::Null) => 0u16,
        Some(serde_yaml::Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| {
                E::custom(format!(
                    "{module}.login_port: expected uint16, got: {n}"
                ))
            })?,
        Some(serde_yaml::Value::String(s)) => {
            // Allow port as string (Jinja-rendered numerics arrive
            // here as strings after templating; defer parsing to
            // render arm via the empty/numeric heuristic if needed).
            if s.is_empty() {
                0u16
            } else {
                s.parse::<u16>().map_err(|e| {
                    E::custom(format!(
                        "{module}.login_port: expected uint16, got {s:?}: {e}"
                    ))
                })?
            }
        }
        Some(other) => {
            return Err(E::custom(format!(
                "{module}.login_port: expected integer, got: {other:?}"
            )))
        }
    };
    Ok((login_user, login_password, login_unix_socket, login_host, login_port))
}

impl<'de> Deserialize<'de> for PostgresqlUserOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let name = match map.remove("name") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::missing_field("name")),
            Some(other) => return Err(D::Error::custom(format!(
                "postgresql_user.name: expected non-empty string, got: {other:?}"
            ))),
        };
        let password = take_optional_field_string(&mut map, "password")?.unwrap_or_default();
        let role_attr_flags =
            take_optional_field_string(&mut map, "role_attr_flags")?.unwrap_or_default();
        // Reject unknown attr flags at parse time IFF the string isn't
        // Jinja-templated — otherwise defer to dispatch (we render
        // role_attr_flags through Jinja same as name/password).
        if !super::shared::string_is_jinja(&role_attr_flags) && !role_attr_flags.is_empty() {
            for raw in role_attr_flags.split(',') {
                let tok = raw.trim();
                if tok.is_empty() {
                    continue;
                }
                if normalize_role_attr_token(tok).is_none() {
                    return Err(D::Error::custom(format!(
                        "postgresql_user.role_attr_flags: unknown attr {tok:?}; \
                         supported (each with NO… counterpart): LOGIN, SUPERUSER, \
                         CREATEDB, CREATEROLE, INHERIT, REPLICATION, BYPASSRLS"
                    )));
                }
            }
        }
        let state = match map.remove("state") {
            None | Some(serde_yaml::Value::Null) => 0u8,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => 0u8,
                "absent" => 1u8,
                other => {
                    return Err(D::Error::custom(format!(
                        "postgresql_user.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_user.state: expected string, got: {other:?}"
                )))
            }
        };
        let no_password_changes =
            take_optional_ansible_bool(&mut map, "no_password_changes")?.unwrap_or(false);
        let conn_limit = match map.remove("conn_limit") {
            None | Some(serde_yaml::Value::Null) => CONN_LIMIT_UNSET,
            Some(serde_yaml::Value::Number(n)) => n
                .as_i64()
                .and_then(|v| i32::try_from(v).ok())
                .filter(|v| *v >= -1)
                .ok_or_else(|| {
                    D::Error::custom(format!(
                        "postgresql_user.conn_limit: expected int >= -1, got: {n}"
                    ))
                })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_user.conn_limit: expected integer, got: {other:?}"
                )))
            }
        };
        let db = resolve_db_alias::<D::Error>(&mut map, "postgresql_user")?;
        let (login_user, login_password, login_unix_socket, login_host, login_port) =
            take_pg_login_fields::<D::Error>(&mut map, "postgresql_user")?;

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "postgresql_user: unknown field(s): {unknown:?}; expected one of \
                 [name, password, role_attr_flags, state, no_password_changes, \
                 conn_limit, db, login_db, login_user, login_password, \
                 login_unix_socket, login_host, login_port]"
            )));
        }

        Ok(PostgresqlUserOp {
            name,
            password,
            role_attr_flags,
            state,
            no_password_changes,
            conn_limit,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
        })
    }
}

/// Map a single role-attr token (case-insensitive) to a canonical
/// (attr_name, value) tuple. Returns None for tokens we don't
/// recognise so the caller can produce a useful error.
///
/// The canonical attr name matches the pg_authid column suffix:
/// `super`, `createrole`, `createdb`, `canlogin`, `inherit`,
/// `replication`, `bypassrls`. The yes/no spelling in Ansible
/// (LOGIN vs NOLOGIN) collapses to a bool: LOGIN → ("canlogin", true),
/// NOLOGIN → ("canlogin", false), etc.
pub(crate) fn normalize_role_attr_token(tok: &str) -> Option<(&'static str, bool)> {
    let upper = tok.to_ascii_uppercase();
    let (name, want) = if let Some(rest) = upper.strip_prefix("NO") {
        (rest, false)
    } else {
        (upper.as_str(), true)
    };
    let canonical: &'static str = match name {
        "LOGIN" => "canlogin",
        "SUPERUSER" => "super",
        "CREATEDB" => "createdb",
        "CREATEROLE" => "createrole",
        "INHERIT" => "inherit",
        "REPLICATION" => "replication",
        "BYPASSRLS" => "bypassrls",
        _ => return None,
    };
    Some((canonical, want))
}

impl<'de> Deserialize<'de> for PostgresqlDbOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let name = match map.remove("name") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::missing_field("name")),
            Some(other) => return Err(D::Error::custom(format!(
                "postgresql_db.name: expected non-empty string, got: {other:?}"
            ))),
        };
        let owner = take_optional_field_string(&mut map, "owner")?.unwrap_or_default();
        let encoding = take_optional_field_string(&mut map, "encoding")?.unwrap_or_default();
        let lc_collate =
            take_optional_field_string(&mut map, "lc_collate")?.unwrap_or_default();
        let lc_ctype = take_optional_field_string(&mut map, "lc_ctype")?.unwrap_or_default();
        let template = take_optional_field_string(&mut map, "template")?.unwrap_or_default();
        let state = match map.remove("state") {
            None | Some(serde_yaml::Value::Null) => 0u8,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => 0u8,
                "absent" => 1u8,
                other => {
                    return Err(D::Error::custom(format!(
                        "postgresql_db.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_db.state: expected string, got: {other:?}"
                )))
            }
        };
        let (login_user, login_password, login_unix_socket, login_host, login_port) =
            take_pg_login_fields::<D::Error>(&mut map, "postgresql_db")?;

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "postgresql_db: unknown field(s): {unknown:?}; expected one of \
                 [name, owner, encoding, lc_collate, lc_ctype, template, state, \
                 login_user, login_password, login_unix_socket, login_host, login_port]"
            )));
        }

        Ok(PostgresqlDbOp {
            name,
            owner,
            encoding,
            lc_collate,
            lc_ctype,
            template,
            state,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
        })
    }
}

/// Accept a YAML field that's either a single string or a list of
/// strings, normalising to `Vec<String>`. Used for
/// postgresql_membership's `group:` / `groups:` and
/// `target_role:` / `target_roles:` pairs (singular/plural aliases).
fn take_string_or_list<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    singular: &str,
    plural: &str,
    module: &str,
) -> Result<Vec<String>, E> {
    let pull = |map: &mut serde_yaml::Mapping, key: &str| -> Result<Option<Vec<String>>, E> {
        match map.remove(key) {
            None | Some(serde_yaml::Value::Null) => Ok(None),
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => Ok(Some(vec![s])),
            Some(serde_yaml::Value::String(_)) => Ok(Some(vec![])),
            Some(serde_yaml::Value::Sequence(seq)) => {
                let mut out = Vec::with_capacity(seq.len());
                for v in seq {
                    match v {
                        serde_yaml::Value::String(s) => out.push(s),
                        other => {
                            return Err(E::custom(format!(
                                "{module}.{key} item: expected string, got: {other:?}"
                            )))
                        }
                    }
                }
                Ok(Some(out))
            }
            Some(other) => Err(E::custom(format!(
                "{module}.{key}: expected string or list of strings, got: {other:?}"
            ))),
        }
    };
    let s = pull(map, singular)?;
    let p = pull(map, plural)?;
    match (s, p) {
        (Some(_), Some(_)) => Err(E::custom(format!(
            "{module}: set either `{singular}:` or `{plural}:`, not both"
        ))),
        (Some(v), None) | (None, Some(v)) => {
            if v.is_empty() {
                Err(E::custom(format!(
                    "{module}: `{singular}` / `{plural}` is empty; pick at least one"
                )))
            } else {
                Ok(v)
            }
        }
        (None, None) => Err(E::custom(format!(
            "{module}: missing required field `{singular}` (or its alias `{plural}`)"
        ))),
    }
}

impl<'de> Deserialize<'de> for PostgresqlMembershipOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let groups = take_string_or_list::<D::Error>(
            &mut map,
            "group",
            "groups",
            "postgresql_membership",
        )?;
        let target_roles = take_string_or_list::<D::Error>(
            &mut map,
            "target_role",
            "target_roles",
            "postgresql_membership",
        )?;
        let state = match map.remove("state") {
            None | Some(serde_yaml::Value::Null) => 0u8,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => 0u8,
                "absent" => 1u8,
                other => {
                    return Err(D::Error::custom(format!(
                        "postgresql_membership.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_membership.state: expected string, got: {other:?}"
                )))
            }
        };
        let fail_on_role =
            take_optional_ansible_bool(&mut map, "fail_on_role")?.unwrap_or(true);
        let db = resolve_db_alias::<D::Error>(&mut map, "postgresql_membership")?;
        let (login_user, login_password, login_unix_socket, login_host, login_port) =
            take_pg_login_fields::<D::Error>(&mut map, "postgresql_membership")?;

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "postgresql_membership: unknown field(s): {unknown:?}; expected one of \
                 [group, groups, target_role, target_roles, state, fail_on_role, \
                 db, login_db, login_user, login_password, login_unix_socket, \
                 login_host, login_port]"
            )));
        }

        Ok(PostgresqlMembershipOp {
            groups,
            target_roles,
            state,
            fail_on_role,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
        })
    }
}

impl<'de> Deserialize<'de> for PostgresqlQueryOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let query = match map.remove("query") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::missing_field("query")),
            Some(other) => return Err(D::Error::custom(format!(
                "postgresql_query.query: expected non-empty string, got: {other:?}"
            ))),
        };
        let db = resolve_db_alias::<D::Error>(&mut map, "postgresql_query")?;
        let login_user = take_optional_field_string(&mut map, "login_user")?.unwrap_or_default();
        let login_password =
            take_optional_field_string(&mut map, "login_password")?.unwrap_or_default();
        let login_unix_socket =
            take_optional_field_string(&mut map, "login_unix_socket")?.unwrap_or_default();
        let login_host = take_optional_field_string(&mut map, "login_host")?.unwrap_or_default();
        let login_port = match map.remove("login_port") {
            None | Some(serde_yaml::Value::Null) => 0u16,
            Some(serde_yaml::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .ok_or_else(|| {
                    D::Error::custom(format!(
                        "postgresql_query.login_port: expected uint16, got: {n}"
                    ))
                })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_query.login_port: expected integer, got: {other:?}"
                )))
            }
        };
        let autocommit =
            take_optional_ansible_bool(&mut map, "autocommit")?.unwrap_or(false);
        let positional_args: Vec<String> = match map.remove("positional_args") {
            None | Some(serde_yaml::Value::Null) => Vec::new(),
            Some(serde_yaml::Value::Sequence(seq)) => {
                let mut out = Vec::with_capacity(seq.len());
                for v in seq {
                    let s = match v {
                        serde_yaml::Value::String(s) => s,
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        serde_yaml::Value::Null => String::new(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "postgresql_query.positional_args item: expected scalar, got: {other:?}"
                            )))
                        }
                    };
                    out.push(s);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_query.positional_args: expected a list, got: {other:?}"
                )))
            }
        };

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "postgresql_query: unknown field(s): {unknown:?}; expected one of \
                 [query, db, login_user, login_password, login_unix_socket, \
                 login_host, login_port, autocommit, positional_args]"
            )));
        }

        let read_only = classify_sql_readonly(&query);
        Ok(PostgresqlQueryOp {
            query,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
            autocommit,
            positional_args,
            read_only,
        })
    }
}

impl<'de> Deserialize<'de> for PostgresqlExtOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let name = match map.remove("name") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::missing_field("name")),
            Some(other) => return Err(D::Error::custom(format!(
                "postgresql_ext.name: expected non-empty string, got: {other:?}"
            ))),
        };
        let state = match map.remove("state") {
            None | Some(serde_yaml::Value::Null) => postgresql_ext_state::PRESENT,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => postgresql_ext_state::PRESENT,
                "absent" => postgresql_ext_state::ABSENT,
                other => {
                    return Err(D::Error::custom(format!(
                        "postgresql_ext.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_ext.state: expected string, got: {other:?}"
                )))
            }
        };
        let version = take_optional_field_string(&mut map, "version")?.unwrap_or_default();
        let ext_schema = take_optional_field_string(&mut map, "schema")?.unwrap_or_default();
        let cascade = take_optional_ansible_bool(&mut map, "cascade")?.unwrap_or(false);
        let db = resolve_db_alias::<D::Error>(&mut map, "postgresql_ext")?;
        let login_user = take_optional_field_string(&mut map, "login_user")?.unwrap_or_default();
        let login_password =
            take_optional_field_string(&mut map, "login_password")?.unwrap_or_default();
        let login_unix_socket =
            take_optional_field_string(&mut map, "login_unix_socket")?.unwrap_or_default();
        let login_host = take_optional_field_string(&mut map, "login_host")?.unwrap_or_default();
        let login_port = match map.remove("login_port") {
            None | Some(serde_yaml::Value::Null) => 0u16,
            Some(serde_yaml::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .ok_or_else(|| {
                    D::Error::custom(format!(
                        "postgresql_ext.login_port: expected uint16, got: {n}"
                    ))
                })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "postgresql_ext.login_port: expected integer, got: {other:?}"
                )))
            }
        };

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "postgresql_ext: unknown field(s): {unknown:?}; expected one of \
                 [name, state, version, schema, cascade, db, login_user, \
                 login_password, login_unix_socket, login_host, login_port]"
            )));
        }

        Ok(PostgresqlExtOp {
            name,
            state,
            version,
            ext_schema,
            cascade,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task, try_parse_task_for_test as try_parse_task};
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{TaskBody, TaskOp};

    #[test]
    fn classify_sql_select_is_readonly() {
        assert!(classify_sql_readonly("SELECT 1"));
        assert!(classify_sql_readonly("select pid FROM pg_stat_activity"));
        assert!(classify_sql_readonly("  \n\tSELECT 1"));
        assert!(classify_sql_readonly("SHOW server_version"));
        assert!(classify_sql_readonly("EXPLAIN SELECT 1"));
        assert!(classify_sql_readonly("VALUES (1), (2)"));
        assert!(classify_sql_readonly("WITH x AS (SELECT 1) SELECT * FROM x"));
        assert!(classify_sql_readonly("TABLE pg_class"));
    }

    #[test]
    fn classify_sql_dml_is_mutating() {
        assert!(!classify_sql_readonly("INSERT INTO t VALUES (1)"));
        assert!(!classify_sql_readonly("UPDATE t SET x = 1"));
        assert!(!classify_sql_readonly("DELETE FROM t"));
        assert!(!classify_sql_readonly("CREATE TABLE t (x int)"));
        assert!(!classify_sql_readonly("DROP TABLE t"));
        assert!(!classify_sql_readonly("ALTER SYSTEM SET work_mem = '64MB'"));
        assert!(!classify_sql_readonly("TRUNCATE t"));
        assert!(!classify_sql_readonly("VACUUM"));
        assert!(!classify_sql_readonly("CREATE EXTENSION pg_stat_statements"));
    }

    #[test]
    fn classify_sql_strips_comments_before_classify() {
        assert!(classify_sql_readonly("-- a comment\nSELECT 1"));
        assert!(classify_sql_readonly("/* leading block */ SELECT 1"));
        assert!(!classify_sql_readonly("-- still mutates\nDELETE FROM t"));
        // nested block comments — postgres supports nesting
        assert!(classify_sql_readonly("/* outer /* inner */ outer */ SELECT 1"));
    }

    #[test]
    fn classify_sql_multistmt_any_mutating_is_mutating() {
        assert!(classify_sql_readonly("SELECT 1; SELECT 2"));
        assert!(!classify_sql_readonly("SELECT 1; INSERT INTO t VALUES (1)"));
        assert!(!classify_sql_readonly("INSERT INTO t VALUES (1); SELECT 1"));
    }

    #[test]
    fn classify_sql_semicolons_in_literals_dont_split() {
        // The literal 'INSERT INTO t' should NOT be classified as a
        // mutating statement — it's just a string.
        assert!(classify_sql_readonly(
            "SELECT 'INSERT INTO t VALUES (1)'::text"
        ));
    }

    #[test]
    fn classify_sql_empty_or_whitespace_is_readonly() {
        assert!(classify_sql_readonly(""));
        assert!(classify_sql_readonly("   \n  \t  "));
        assert!(classify_sql_readonly("-- just a comment\n"));
    }

    #[test]
    fn classify_sql_explain_without_analyze_is_readonly() {
        assert!(classify_sql_readonly("EXPLAIN SELECT 1"));
        assert!(classify_sql_readonly("EXPLAIN INSERT INTO t VALUES (1)"));
        assert!(classify_sql_readonly("EXPLAIN VERBOSE INSERT INTO t VALUES (1)"));
        assert!(classify_sql_readonly("EXPLAIN (VERBOSE, BUFFERS) DELETE FROM t"));
        assert!(classify_sql_readonly("EXPLAIN (ANALYZE FALSE) DELETE FROM t"));
        assert!(classify_sql_readonly("EXPLAIN (ANALYZE OFF) DELETE FROM t"));
    }

    #[test]
    fn classify_sql_explain_analyze_dml_is_mutating() {
        // Legacy bareword form.
        assert!(!classify_sql_readonly("EXPLAIN ANALYZE INSERT INTO t VALUES (1)"));
        assert!(!classify_sql_readonly("explain analyze delete from t"));
        assert!(!classify_sql_readonly(
            "EXPLAIN ANALYZE VERBOSE UPDATE t SET x = 1"
        ));
        // Parenthesised options form.
        assert!(!classify_sql_readonly(
            "EXPLAIN (ANALYZE) INSERT INTO t VALUES (1)"
        ));
        assert!(!classify_sql_readonly(
            "EXPLAIN (ANALYZE TRUE, BUFFERS) UPDATE t SET x = 1"
        ));
        assert!(!classify_sql_readonly(
            "EXPLAIN (ANALYZE ON) DELETE FROM t"
        ));
        assert!(!classify_sql_readonly(
            "EXPLAIN (BUFFERS, ANALYZE 1) MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET x = 1"
        ));
        // ANALYZE wrapping a benign SELECT — still read-only because
        // the inner statement is read-only.
        assert!(classify_sql_readonly("EXPLAIN ANALYZE SELECT 1"));
    }

    #[test]
    fn classify_sql_with_data_modifying_cte_is_mutating() {
        assert!(!classify_sql_readonly(
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"
        ));
        assert!(!classify_sql_readonly(
            "WITH i AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM i"
        ));
        assert!(!classify_sql_readonly(
            "WITH u AS (UPDATE t SET x = 1 RETURNING *) SELECT * FROM u"
        ));
        // Trailing DML form.
        assert!(!classify_sql_readonly(
            "WITH x AS (SELECT id FROM s) DELETE FROM t USING x WHERE t.id = x.id"
        ));
        // Read-only WITH still passes.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT 1) SELECT * FROM x"
        ));
        // Multiple CTEs: any mutating CTE → mutating.
        assert!(!classify_sql_readonly(
            "WITH a AS (SELECT 1), b AS (DELETE FROM t RETURNING *) SELECT * FROM a, b"
        ));
    }

    #[test]
    fn classify_sql_with_literal_keywords_dont_trip() {
        // Identifier-aware scanner: 'INSERT INTO t' as a string literal
        // should not flag this WITH as mutating.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT 'INSERT INTO t' AS sql) SELECT * FROM x"
        ));
        // Quoted-identifier column called "delete" — still read-only.
        assert!(classify_sql_readonly(
            r#"WITH x AS (SELECT "delete" FROM t) SELECT * FROM x"#
        ));
        // Column called `update_at` — UPDATE_AT ≠ UPDATE, so not a hit.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT update_at FROM t) SELECT * FROM x"
        ));
        // Dollar-quoted body containing DML keyword — skipped.
        assert!(classify_sql_readonly(
            "WITH x AS (SELECT $body$DELETE FROM t$body$ AS sql) SELECT * FROM x"
        ));
    }

    #[test]
    fn parse_postgresql_query_minimal() {
        let t = parse_task(
            r#"
name: t
postgresql_query:
  query: SELECT 1
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlQuery(p)) => {
                assert_eq!(p.query, "SELECT 1");
                assert!(p.read_only);
                assert!(p.db.is_empty());
                assert!(p.login_unix_socket.is_empty());
                assert!(p.positional_args.is_empty());
                assert!(!p.autocommit);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_query_full() {
        let t = parse_task(
            r#"
name: t
postgresql_query:
  query: "INSERT INTO clients(name) VALUES ($1) RETURNING id"
  db: app
  login_user: app_writer
  login_unix_socket: /var/run/postgresql
  autocommit: true
  positional_args:
    - acme corp
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlQuery(p)) => {
                assert_eq!(p.db, "app");
                assert_eq!(p.login_user, "app_writer");
                assert_eq!(p.login_unix_socket, "/var/run/postgresql");
                assert!(p.autocommit);
                assert_eq!(p.positional_args, vec!["acme corp".to_string()]);
                // INSERT — classified mutating.
                assert!(!p.read_only);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_query_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
postgresql_query:
  query: SELECT 1
  named_args: { x: 1 }
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("named_args") || msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn parse_postgresql_ext_default_present() {
        let t = parse_task(
            r#"
name: t
postgresql_ext:
  name: pg_stat_statements
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlExt(p)) => {
                assert_eq!(p.name, "pg_stat_statements");
                assert_eq!(p.state, 0); // PRESENT
                assert!(p.version.is_empty());
                assert!(!p.cascade);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_ext_absent_cascade() {
        let t = parse_task(
            r#"
name: t
postgresql_ext:
  name: hstore
  state: absent
  cascade: yes
  db: app
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::PostgresqlExt(p)) => {
                assert_eq!(p.state, 1); // ABSENT
                assert!(p.cascade);
                assert_eq!(p.db, "app");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_postgresql_user_basic() {
        let t = parse_task(
            r#"
name: t
postgresql_user:
  name: acme
  password: secret123
  role_attr_flags: "LOGIN,NOSUPERUSER,NOCREATEROLE,NOCREATEDB"
  login_unix_socket: /var/run/postgresql
"#,
        );
        let TaskBody::Op(TaskOp::PostgresqlUser(u)) = t.body else { panic!() };
        assert_eq!(u.name, "acme");
        assert_eq!(u.password, "secret123");
        assert_eq!(u.role_attr_flags, "LOGIN,NOSUPERUSER,NOCREATEROLE,NOCREATEDB");
        assert_eq!(u.state, 0); // present
        assert_eq!(u.login_unix_socket, "/var/run/postgresql");
        assert!(!u.no_password_changes);
        assert_eq!(u.conn_limit, CONN_LIMIT_UNSET);
    }

    #[test]
    fn parse_postgresql_user_rejects_unknown_role_attr_flag() {
        // Catch typos at parse time when the flags string is a
        // literal (not Jinja-templated). NEEDNOTHING isn't an attr.
        let err = try_parse_task(
            r#"
name: t
postgresql_user:
  name: r
  role_attr_flags: "LOGIN,NEEDNOTHING"
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("NEEDNOTHING"), "got: {msg}");
    }

    #[test]
    fn parse_postgresql_user_defers_jinja_role_attr_flags() {
        // Templated role_attr_flags must not be rejected at parse;
        // dispatch-time resolves them post-render.
        let t = parse_task(
            r#"
name: t
postgresql_user:
  name: r
  role_attr_flags: "{{ pg_attr_set }}"
"#,
        );
        let TaskBody::Op(TaskOp::PostgresqlUser(u)) = t.body else { panic!() };
        assert_eq!(u.role_attr_flags, "{{ pg_attr_set }}");
    }

    #[test]
    fn parse_postgresql_user_state_absent() {
        let t = parse_task(
            r#"
name: t
postgresql_user:
  name: r
  state: absent
"#,
        );
        let TaskBody::Op(TaskOp::PostgresqlUser(u)) = t.body else { panic!() };
        assert_eq!(u.state, 1);
    }

    #[test]
    fn parse_postgresql_user_rejects_negative_conn_limit_below_minus_one() {
        let err = try_parse_task(
            r#"
name: t
postgresql_user:
  name: r
  conn_limit: -42
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("conn_limit") || msg.contains("-1"), "got: {msg}");
    }

    #[test]
    fn parse_postgresql_db_basic() {
        let t = parse_task(
            r#"
name: t
postgresql_db:
  name: acme
  owner: acme
  encoding: UTF8
  lc_collate: en_US.UTF-8
  lc_ctype: en_US.UTF-8
  template: template0
  login_unix_socket: /var/run/postgresql
"#,
        );
        let TaskBody::Op(TaskOp::PostgresqlDb(d)) = t.body else { panic!() };
        assert_eq!(d.name, "acme");
        assert_eq!(d.owner, "acme");
        assert_eq!(d.encoding, "UTF8");
        assert_eq!(d.lc_collate, "en_US.UTF-8");
        assert_eq!(d.lc_ctype, "en_US.UTF-8");
        assert_eq!(d.template, "template0");
        assert_eq!(d.state, 0);
        assert_eq!(d.login_unix_socket, "/var/run/postgresql");
    }

    #[test]
    fn parse_postgresql_db_state_absent_minimal() {
        let t = parse_task(
            r#"
name: t
postgresql_db:
  name: scratch
  state: absent
"#,
        );
        let TaskBody::Op(TaskOp::PostgresqlDb(d)) = t.body else { panic!() };
        assert_eq!(d.state, 1);
        assert!(d.owner.is_empty());
        assert!(d.encoding.is_empty());
    }

    #[test]
    fn parse_postgresql_user_to_wire_op_errors() {
        // Composite ops should refuse to_wire_op — they're intercepted
        // earlier in the dispatch pipeline.
        let t = parse_task(
            r#"
name: t
postgresql_user:
  name: x
"#,
        );
        let TaskBody::Op(op) = t.body else { panic!() };
        let err = op.to_wire_op().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("composite") || msg.contains("intercepted"), "got: {msg}");
    }

    #[test]
    fn parse_postgresql_membership_groups_and_target_roles_lists() {
        let t = parse_task(
            r#"
name: t
postgresql_membership:
  groups:
    - readers
    - writers
  target_roles:
    - alice
    - bob
"#,
        );
        let TaskBody::Op(TaskOp::PostgresqlMembership(m)) = t.body else { panic!() };
        assert_eq!(m.groups, vec!["readers", "writers"]);
        assert_eq!(m.target_roles, vec!["alice", "bob"]);
        assert_eq!(m.state, 0);
        assert!(m.fail_on_role);
    }

    #[test]
    fn parse_postgresql_membership_singular_aliases() {
        // `group:` (singular) and `target_role:` (singular) both
        // accept either a string or a one-element list.
        let t = parse_task(
            r#"
name: t
postgresql_membership:
  group: readers
  target_role: alice
  state: absent
  fail_on_role: false
"#,
        );
        let TaskBody::Op(TaskOp::PostgresqlMembership(m)) = t.body else { panic!() };
        assert_eq!(m.groups, vec!["readers"]);
        assert_eq!(m.target_roles, vec!["alice"]);
        assert_eq!(m.state, 1);
        assert!(!m.fail_on_role);
    }

    #[test]
    fn parse_postgresql_membership_rejects_missing_groups() {
        let err = try_parse_task(
            r#"
name: t
postgresql_membership:
  target_role: alice
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("group") || msg.contains("groups"),
            "got: {msg}"
        );
    }

    #[test]
    fn parse_postgresql_membership_to_wire_op_errors() {
        let t = parse_task(
            r#"
name: t
postgresql_membership:
  group: g
  target_role: t
"#,
        );
        let TaskBody::Op(op) = t.body else { panic!() };
        let err = op.to_wire_op().unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("composite") || msg.contains("intercepted"),
            "got: {msg}"
        );
    }

    #[test]
    fn parse_postgresql_db_to_wire_op_errors() {
        let t = parse_task(
            r#"
name: t
postgresql_db:
  name: scratch
"#,
        );
        let TaskBody::Op(op) = t.body else { panic!() };
        let err = op.to_wire_op().unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("composite") || msg.contains("intercepted"),
            "got: {msg}"
        );
    }

    #[test]
    fn parse_postgresql_ext_to_wire_op() {
        let t = parse_task(
            r#"
name: t
postgresql_ext:
  name: pg_trgm
  version: "1.6"
  schema: public
"#,
        );
        let TaskBody::Op(op) = t.body else { panic!() };
        let wire = op.to_wire_op().unwrap();
        let WireOp::OpPostgresqlExt(e) = wire else { panic!("got {wire:?}") };
        assert_eq!(e.kind, 14);
        assert_eq!(e.name, "pg_trgm");
        assert_eq!(e.version, "1.6");
        assert_eq!(e.ext_schema, "public");
    }
}
