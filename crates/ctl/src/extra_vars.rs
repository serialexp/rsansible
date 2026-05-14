//! `--extra-vars` (`-e`) CLI argument parsing.
//!
//! Mirrors Ansible's `-e` accepted forms:
//!
//!   * `key=value` — string assignment. The first `=` splits key from
//!     value; the value is taken verbatim as a string (no shell-style
//!     quoting; the surrounding shell already handled that).
//!   * `@path/to/file.yml` — load a YAML map from disk, merge top-level
//!     keys.
//!   * `{"json": "object"}` — parse as JSON (or YAML, since YAML is a
//!     superset) and merge top-level keys.
//!
//! Multiple `-e` flags accumulate; later occurrences overwrite earlier
//! ones on key collision (Ansible's behavior).
//!
//! The resulting `BTreeMap<String, JsonValue>` is fed into
//! `RunSpec.extra_vars` and seeded into each host's `HostCtx.extra_vars`
//! at run start. Layered at the top of `build_template_ctx`'s precedence
//! chain, so it cannot be overridden by anything inside the playbook.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::path::Path;

/// Parse a single `-e` / `--extra-vars` argument into a key→value map.
///
/// See the module-level docs for accepted forms. The returned map may
/// have more than one entry (when the argument is a JSON/YAML object
/// literal or an `@file` reference).
pub fn parse_one(arg: &str) -> Result<BTreeMap<String, JsonValue>> {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        bail!("empty --extra-vars value");
    }
    if let Some(path_str) = trimmed.strip_prefix('@') {
        return load_from_file(Path::new(path_str.trim()))
            .with_context(|| format!("loading --extra-vars from {path_str:?}"));
    }
    // A leading `{` or `[` flags a JSON/YAML literal. YAML's a superset
    // of JSON so we can route both through serde_yaml.
    let first = trimmed.chars().next().unwrap();
    if first == '{' || first == '[' {
        return parse_yaml_object(trimmed).with_context(|| {
            format!("parsing --extra-vars JSON/YAML literal")
        });
    }
    parse_key_value(trimmed)
}

/// Merge a sequence of `-e` arguments left-to-right. Later args overwrite
/// earlier ones on key collision.
pub fn parse_all<I, S>(args: I) -> Result<BTreeMap<String, JsonValue>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut acc: BTreeMap<String, JsonValue> = BTreeMap::new();
    for arg in args {
        let map = parse_one(arg.as_ref())?;
        for (k, v) in map {
            acc.insert(k, v);
        }
    }
    Ok(acc)
}

fn parse_key_value(arg: &str) -> Result<BTreeMap<String, JsonValue>> {
    let (key, value) = arg
        .split_once('=')
        .ok_or_else(|| anyhow!("`{arg}` is not in `key=value` form (or use `@file` / `{{json}}`)"))?;
    let key = key.trim();
    if key.is_empty() {
        bail!("empty key in `{arg}`");
    }
    if !is_valid_identifier(key) {
        bail!(
            "invalid extra-var key {key:?}: must be a Python-style identifier ([A-Za-z_][A-Za-z0-9_]*)"
        );
    }
    // Take the value verbatim. Note: we deliberately do NOT try to parse
    // it as JSON/YAML here — Ansible's `key=value` form always produces
    // a string. Users who want structured values use `-e {json}` or
    // `-e @file.yml`.
    let mut map = BTreeMap::new();
    map.insert(key.to_string(), JsonValue::String(value.to_string()));
    Ok(map)
}

fn parse_yaml_object(text: &str) -> Result<BTreeMap<String, JsonValue>> {
    let val: serde_yaml::Value = serde_yaml::from_str(text)
        .with_context(|| "couldn't parse as YAML/JSON")?;
    yaml_value_to_top_level_map(val)
}

fn load_from_file(path: &Path) -> Result<BTreeMap<String, JsonValue>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let val: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {} as YAML", path.display()))?;
    yaml_value_to_top_level_map(val)
}

fn yaml_value_to_top_level_map(val: serde_yaml::Value) -> Result<BTreeMap<String, JsonValue>> {
    let map = match val {
        serde_yaml::Value::Mapping(m) => m,
        serde_yaml::Value::Null => return Ok(BTreeMap::new()),
        other => bail!(
            "extra-vars source must be a top-level mapping (key: value), got: {other:?}"
        ),
    };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        let key = k
            .as_str()
            .ok_or_else(|| anyhow!("extra-vars key must be a string, got: {k:?}"))?
            .to_string();
        let json = yaml_to_json(v)?;
        out.insert(key, json);
    }
    Ok(out)
}

/// Lossless-ish YAML → JSON conversion. Used for both file and inline
/// JSON literal sources. Keeps numbers/bools/nulls intact; refuses
/// tag-based YAML constructs we don't support.
fn yaml_to_json(v: serde_yaml::Value) -> Result<JsonValue> {
    Ok(match v {
        serde_yaml::Value::Null => JsonValue::Null,
        serde_yaml::Value::Bool(b) => JsonValue::Bool(b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                JsonValue::from(i)
            } else if let Some(u) = n.as_u64() {
                JsonValue::from(u)
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(JsonValue::Number)
                    .unwrap_or(JsonValue::Null)
            } else {
                bail!("unsupported numeric value: {n:?}");
            }
        }
        serde_yaml::Value::String(s) => JsonValue::String(s),
        serde_yaml::Value::Sequence(s) => {
            JsonValue::Array(s.into_iter().map(yaml_to_json).collect::<Result<_>>()?)
        }
        serde_yaml::Value::Mapping(m) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in m {
                let key = k.as_str().ok_or_else(|| {
                    anyhow!("nested mapping key must be a string, got: {k:?}")
                })?;
                obj.insert(key.to_string(), yaml_to_json(v)?);
            }
            JsonValue::Object(obj)
        }
        serde_yaml::Value::Tagged(t) => {
            // !vault and friends — surface a clear error rather than
            // silently dropping the tag.
            bail!("YAML tags aren't supported in --extra-vars: {:?}", t.tag);
        }
    })
}

fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn key_value_simple_string() {
        let m = parse_one("svc=demo").unwrap();
        assert_eq!(m.get("svc"), Some(&json!("demo")));
    }

    #[test]
    fn key_value_value_can_contain_equals() {
        let m = parse_one("url=https://example.com/?a=1&b=2").unwrap();
        assert_eq!(
            m.get("url"),
            Some(&json!("https://example.com/?a=1&b=2"))
        );
    }

    #[test]
    fn key_value_always_yields_string_even_when_value_is_numeric() {
        // Ansible behavior: `-e count=3` makes a string, not a number.
        // Users who want structured types reach for `-e {json}` or
        // `-e @file.yml`.
        let m = parse_one("count=3").unwrap();
        assert_eq!(m.get("count"), Some(&json!("3")));
    }

    #[test]
    fn rejects_bare_value_without_equals() {
        let err = parse_one("just-a-value").unwrap_err();
        assert!(format!("{err}").contains("key=value"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_key_identifier() {
        let err = parse_one("bad-key=x").unwrap_err();
        assert!(format!("{err}").contains("identifier"), "got: {err}");
    }

    #[test]
    fn rejects_empty_value() {
        let err = parse_one("   ").unwrap_err();
        assert!(format!("{err}").contains("empty"), "got: {err}");
    }

    #[test]
    fn json_object_literal_yields_typed_values() {
        let m = parse_one(r#"{"port": 8080, "tls": true, "tags": ["a", "b"]}"#).unwrap();
        assert_eq!(m.get("port"), Some(&json!(8080)));
        assert_eq!(m.get("tls"), Some(&json!(true)));
        assert_eq!(m.get("tags"), Some(&json!(["a", "b"])));
    }

    #[test]
    fn json_top_level_array_is_rejected() {
        let err = parse_one("[1, 2, 3]").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("mapping"), "got: {msg}");
    }

    #[test]
    fn at_file_loads_yaml_map() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vars.yml");
        std::fs::write(
            &path,
            "service: demo\nport: 8080\nflags:\n  - a\n  - b\n",
        )
        .unwrap();
        let m = parse_one(&format!("@{}", path.display())).unwrap();
        assert_eq!(m.get("service"), Some(&json!("demo")));
        assert_eq!(m.get("port"), Some(&json!(8080)));
        assert_eq!(m.get("flags"), Some(&json!(["a", "b"])));
    }

    #[test]
    fn at_missing_file_surfaces_path_in_error() {
        let err = parse_one("@/no/such/file.yml").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("/no/such/file.yml"), "got: {msg}");
    }

    #[test]
    fn parse_all_later_wins() {
        let m = parse_all(&["svc=first", "svc=second", "port=8080"]).unwrap();
        assert_eq!(m.get("svc"), Some(&json!("second")));
        assert_eq!(m.get("port"), Some(&json!("8080")));
    }

    #[test]
    fn parse_all_mixes_key_value_and_json_literals() {
        let m = parse_all(&[
            "service=demo",
            r#"{"port": 8080, "tls": true}"#,
        ])
        .unwrap();
        assert_eq!(m.get("service"), Some(&json!("demo")));
        assert_eq!(m.get("port"), Some(&json!(8080)));
        assert_eq!(m.get("tls"), Some(&json!(true)));
    }

    #[test]
    fn yaml_tagged_values_rejected_with_clear_error() {
        // !vault tags would silently corrupt extra-vars otherwise. The
        // error message should mention "tags".
        let err = parse_one("{secret: !vault \"...\"}").unwrap_err();
        assert!(format!("{err:#}").contains("tags"), "got: {err:#}");
    }
}
