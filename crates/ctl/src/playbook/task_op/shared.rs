//! Shared helpers for the per-op parsers under `task_op/`.
//!
//! Everything in this module is `pub(super)` — these are internal
//! plumbing for the YAML deserialize impls, not part of the public
//! task_op surface. If you want to expose one of these, re-export it
//! explicitly from `mod.rs`.

use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

/// Pull an optional string out of a YAML mapping. None on absent/null;
/// errors on non-string. Used by per-op deserializers; the other
/// `take_optional_string` is the task-shell variant that also formats
/// the task name into errors.
pub(super) fn take_optional_field_string<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        Some(other) => Err(E::custom(format!(
            "{key}: expected a string, got: {other:?}"
        ))),
    }
}

/// Pull an optional Ansible-flavored bool out of a YAML mapping.
pub(super) fn take_optional_ansible_bool<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<bool>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" => Ok(Some(true)),
            "no" | "false" | "off" => Ok(Some(false)),
            other => Err(E::custom(format!(
                "{key}: expected bool (true/false/yes/no/on/off), got: {other:?}"
            ))),
        },
        Some(other) => Err(E::custom(format!(
            "{key}: expected bool, got: {other:?}"
        ))),
    }
}

/// Accept either a YAML integer (`port: 22`) or a string (`port:
/// "22:25"`, `port: "ssh"`) and return the string form. Ansible's port
/// fields accept both. Returns None on absent/null.
pub(super) fn take_optional_port<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        Some(serde_yaml::Value::Number(n)) => Ok(Some(n.to_string())),
        Some(other) => Err(E::custom(format!(
            "{key}: expected a port number or string, got: {other:?}"
        ))),
    }
}

/// Pull an optional Ansible-flavored mode out of a YAML mapping. Accepts
/// int (`0o755`) or string (`"0755"`/`"755"`/`"0o755"`).
pub(super) fn take_optional_mode<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<u32>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::Number(n)) => {
            let v = n.as_u64().ok_or_else(|| {
                E::custom(format!("{key}: expected non-negative integer, got: {n}"))
            })? as u32;
            if v & !0o7777 != 0 {
                return Err(E::custom(format!(
                    "{key}: only the low 12 bits are meaningful (got 0o{v:o})"
                )));
            }
            Ok(Some(v))
        }
        Some(serde_yaml::Value::String(s)) => {
            let v = parse_mode_str(&s).map_err(E::custom)?;
            if v & !0o7777 != 0 {
                return Err(E::custom(format!(
                    "{key}: only the low 12 bits are meaningful (got 0o{v:o})"
                )));
            }
            Ok(Some(v))
        }
        Some(other) => Err(E::custom(format!(
            "{key}: expected string or int, got: {other:?}"
        ))),
    }
}

/// Pull a task-level optional string out of a YAML mapping, formatting
/// the task name into error messages so the user can see which task is
/// at fault. Differs from `take_optional_field_string` in that we
/// reject any non-string value (including `null`) — used for fields
/// like `when:` / `register:` where ambiguity is a bug.
pub(super) fn take_optional_string<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
    task_name: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        // `register: my_name` and `when: x == 1` are always strings in
        // user-facing YAML. Be strict: reject numbers/bools to catch
        // `when: 1` style typos early.
        Some(other) => Err(E::custom(format!(
            "task {task_name:?}: `{key}` must be a string, got: {other:?}"
        ))),
    }
}

/// Accept either a non-negative integer or a string (typically a Jinja
/// expression). Returns `Some(String)` either way — integers are
/// stringified so the runtime has one type to template-render and parse.
///
/// Used by `retries:` and `delay:`, which Ansible accepts as either an
/// integer literal or a Jinja-templated value:
///
/// ```yaml
/// retries: 5
/// retries: "{{ (duration_s | int) // 5 }}"
/// ```
pub(super) fn take_int_or_template_string<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
    task_name: &str,
) -> Result<Option<String>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        Some(serde_yaml::Value::Number(n)) => {
            let v = n.as_u64().ok_or_else(|| {
                E::custom(format!(
                    "task {task_name:?}: `{key}` must be a non-negative integer or a Jinja string, got: {n:?}"
                ))
            })?;
            Ok(Some(v.to_string()))
        }
        Some(other) => Err(E::custom(format!(
            "task {task_name:?}: `{key}` must be a non-negative integer or a Jinja string, got: {other:?}"
        ))),
    }
}

/// Accept a YAML field that's either a single string or a list of
/// strings, returning `Option<Vec<String>>` (None on missing/null).
/// Used by openssl_csr_pipe's `subject_alt_name` / `key_usage` /
/// `extended_key_usage` which Ansible permits in both shapes.
pub(super) fn take_optional_string_list<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
) -> Result<Option<Vec<String>>, E> {
    match map.remove(key) {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(vec![s])),
        Some(serde_yaml::Value::Sequence(seq)) => {
            let mut out = Vec::with_capacity(seq.len());
            for (i, v) in seq.into_iter().enumerate() {
                match v {
                    serde_yaml::Value::String(s) => out.push(s),
                    other => return Err(E::custom(format!(
                        "{key}[{i}]: expected a string, got: {other:?}"
                    ))),
                }
            }
            Ok(Some(out))
        }
        Some(other) => Err(E::custom(format!(
            "{key}: expected a string or list of strings, got: {other:?}"
        ))),
    }
}

/// Accept `<key>: <seconds>` as int or numeric string; convert to ms.
/// Returns `default_ms` if absent.
pub(super) fn take_seconds_ms<E: serde::de::Error>(
    map: &mut serde_yaml::Mapping,
    key: &str,
    default_ms: u32,
) -> Result<u32, E> {
    match map.remove(key) {
        None => Ok(default_ms),
        Some(serde_yaml::Value::Number(n)) => {
            let s = n.as_f64().ok_or_else(|| {
                E::custom(format!("wait_for.{key}: invalid number {n}"))
            })?;
            if !s.is_finite() || s < 0.0 {
                return Err(E::custom(format!(
                    "wait_for.{key}: expected non-negative seconds, got {s}"
                )));
            }
            Ok((s * 1000.0) as u32)
        }
        Some(serde_yaml::Value::String(s)) => {
            let f = s.parse::<f64>().map_err(|e| {
                E::custom(format!("wait_for.{key}: invalid number {s:?}: {e}"))
            })?;
            if !f.is_finite() || f < 0.0 {
                return Err(E::custom(format!(
                    "wait_for.{key}: expected non-negative seconds, got {f}"
                )));
            }
            Ok((f * 1000.0) as u32)
        }
        Some(other) => Err(E::custom(format!(
            "wait_for.{key} must be a number or numeric string, got: {other:?}"
        ))),
    }
}

/// Parse `mode:` from either a string (`"0755"`, `"755"`, `"0o755"`)
/// or an int (e.g. `0o755` literal in YAML). Strings with a leading `0`
/// are treated as octal — Ansible's behavior. Returns the parsed value
/// or an error; `None` means the field was absent.
pub(super) fn deserialize_file_mode<'de, D>(d: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = match Option::<serde_yaml::Value>::deserialize(d)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let n = match v {
        serde_yaml::Value::Null => return Ok(None),
        serde_yaml::Value::Number(n) => {
            n.as_u64().ok_or_else(|| {
                D::Error::custom(format!("mode: expected non-negative integer, got: {n}"))
            })? as u32
        }
        serde_yaml::Value::String(s) => parse_mode_str(&s).map_err(D::Error::custom)?,
        other => {
            return Err(D::Error::custom(format!(
                "mode: expected string or int, got: {other:?}"
            )))
        }
    };
    if n & !0o7777 != 0 {
        return Err(D::Error::custom(format!(
            "mode: only the low 12 bits are meaningful (got 0o{n:o})"
        )));
    }
    Ok(Some(n))
}

/// Strings like `"0755"` and `"755"` → 0o755. `"0o755"` and `"0755"`
/// also accepted. No symbolic modes (`u=rwx,g=rx`) — gothab doesn't use
/// them.
pub(super) fn parse_mode_str(s: &str) -> Result<u32, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("mode: empty string".to_string());
    }
    let (body, radix) = if let Some(rest) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        (rest, 8u32)
    } else if t.starts_with('0') && t.len() > 1 {
        (t, 8u32)
    } else {
        (t, 8u32)
    };
    u32::from_str_radix(body, radix)
        .map_err(|e| format!("mode: invalid octal {s:?}: {e}"))
}

/// Accept Ansible-flavored booleans: `true`, `false`, `yes`, `no`, `on`,
/// `off` (case-insensitive). YAML 1.2 only accepts `true`/`false`, but
/// every gothab playbook uses `yes`/`no` so we widen.
pub(super) fn deserialize_ansible_bool<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = serde_yaml::Value::deserialize(d)?;
    match v {
        serde_yaml::Value::Bool(b) => Ok(b),
        serde_yaml::Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" => Ok(true),
            "no" | "false" | "off" => Ok(false),
            other => Err(D::Error::custom(format!(
                "expected bool (true/false/yes/no/on/off), got: {other:?}"
            ))),
        },
        other => Err(D::Error::custom(format!(
            "expected bool, got: {other:?}"
        ))),
    }
}

/// Ansible-compatible bool parsing. YAML's `yes`/`no` get quoted by
/// serde_yaml-0.9 (they live in the "schema" core but serde_yaml strips
/// them to strings), so accept the standard truthy/falsy spellings as
/// strings too.
pub(super) fn parse_ansible_bool<E: serde::de::Error>(
    v: Option<serde_yaml::Value>,
    field: &str,
    default: bool,
) -> Result<bool, E> {
    match v {
        None | Some(serde_yaml::Value::Null) => Ok(default),
        Some(serde_yaml::Value::Bool(b)) => Ok(b),
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" | "1" => Ok(true),
            "no" | "false" | "off" | "0" => Ok(false),
            other => Err(E::custom(format!(
                "{field}: expected bool (yes/no/true/false), got: {other:?}"
            ))),
        },
        Some(other) => Err(E::custom(format!(
            "{field}: expected bool, got: {other:?}"
        ))),
    }
}

pub(super) fn parse_octal_mode<E: serde::de::Error>(s: &str) -> Result<u32, E> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    let radix_stripped = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
        .unwrap_or(trimmed);
    u32::from_str_radix(radix_stripped, 8).map_err(|e| {
        E::custom(format!("expected octal mode string (e.g. \"0644\"), got {s:?}: {e}"))
    })
}

/// Accept `BTreeMap<String, scalar>` where scalar values may be strings,
/// numbers, or bools — return them all as `String`.
pub(super) fn deserialize_scalar_string_map<'de, D>(
    d: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let raw: BTreeMap<String, serde_yaml::Value> = BTreeMap::deserialize(d)?;
    raw.into_iter()
        .map(|(k, v)| {
            let s = match v {
                serde_yaml::Value::String(s) => s,
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::Bool(b) => b.to_string(),
                serde_yaml::Value::Null => String::new(),
                other => {
                    return Err(D::Error::custom(format!(
                        "env value for {k:?} must be a scalar (string/number/bool/null), got: {other:?}"
                    )))
                }
            };
            Ok((k, s))
        })
        .collect()
}


/// Read a PEM file from the controller filesystem at wire-emit time.
/// Empty path → empty bytes (= absent on the wire). The caller has
/// already rendered any Jinja in the path. Used by `OpUri` for
/// `client_cert` / `client_key` / `ca_path`. Errors are wrapped with
/// the field name so a missing `client_cert` surfaces as a clear
/// per-field message rather than a bare I/O error.
pub(super) fn read_pem_if_set(path: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context as _;
    if path.is_empty() {
        return Ok(Vec::new());
    }
    std::fs::read(path)
        .with_context(|| format!("uri.{field}: reading PEM from {path:?}"))
}
