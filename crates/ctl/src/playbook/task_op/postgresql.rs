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

/// Classify a SQL statement as read-only or potentially-mutating, used
/// by `--check` to decide whether to dispatch the task or skip it
/// outright on the controller. Heuristic — not a full SQL parser — but
/// sufficient for the well-formed SQL gothab issues:
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
        let db = take_optional_field_string(&mut map, "db")?.unwrap_or_default();
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
        let db = take_optional_field_string(&mut map, "db")?.unwrap_or_default();
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
