//! Per-host execution context.
//!
//! Threaded through every task dispatch alongside the `AgentConn`. Holds
//! variables that survive across tasks (and across plays): inventory vars
//! the host was configured with, set_facts accumulated during the run,
//! registers captured from completed tasks.
//!
//! Render targets (`when:`, `set_fact:` values, op argv/env/path/content,
//! `loop:` expressions, `assert.that:` expressions) all evaluate against
//! the merged view returned by `build_template_ctx`.

use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};

/// One host's state across the run.
#[derive(Debug, Clone)]
pub struct HostCtx {
    pub host_name: String,
    /// Static-ish vars from the inventory entry (host:, port:, user:, …).
    /// Lowest precedence in the template context.
    pub inventory_vars: BTreeMap<String, JsonValue>,
    /// `set_fact:` accumulated values. Persists across plays for this
    /// host (Ansible-faithful semantics).
    pub set_facts: BTreeMap<String, JsonValue>,
    /// Bound by tasks with `register:`. Keyed by the register name.
    pub registers: BTreeMap<String, RegisterValue>,
    /// True once a task on this host has failed in a way that should
    /// keep it from receiving further work (mark_host_failed policy, or
    /// a failed `assert:`/`fail:` under `on_failure: stop`).
    pub failed: bool,
    /// Transient loop-item value. Set just before evaluating a loop
    /// iteration's body and templates; consulted by `build_template_ctx`
    /// to expose `item` (or a renamed `loop_var`).
    pub iter_item: Option<(String, JsonValue)>,
    /// Handler names notified by tasks on this host but not yet flushed.
    /// Deduped naturally (BTreeSet). Drained at end-of-play or on
    /// `meta: flush_handlers`.
    pub pending_handlers: BTreeSet<String>,
}

impl HostCtx {
    pub fn new(host_name: String) -> Self {
        Self {
            host_name,
            inventory_vars: BTreeMap::new(),
            set_facts: BTreeMap::new(),
            registers: BTreeMap::new(),
            failed: false,
            iter_item: None,
            pending_handlers: BTreeSet::new(),
        }
    }

    /// Convenience: stash a register value.
    pub fn record_register(&mut self, name: &str, value: RegisterValue) {
        self.registers.insert(name.to_string(), value);
    }
}

/// What a `register:` captures from a completed (or skipped) task. Maps
/// roughly to Ansible's registered-result dict.
#[derive(Debug, Clone, Default)]
pub struct RegisterValue {
    pub changed: bool,
    pub rc: i32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_lines: Vec<String>,
    /// `Some(_)` iff `stdout` parses as JSON. Lets `register.json.field`
    /// work in `when:` clauses without an explicit `from_json` filter.
    pub json: Option<JsonValue>,
    pub took_ms: u64,
    pub skipped: bool,
    pub failed: bool,
    /// For tasks under `loop:`, the per-iteration results land here so
    /// `register: x` exposes `x.results = [...]`.
    pub results: Option<Vec<RegisterValue>>,
}

impl RegisterValue {
    /// Convert to the JSON form templates see.
    pub fn to_json(&self) -> JsonValue {
        let mut m = serde_json::Map::new();
        m.insert("changed".into(), JsonValue::Bool(self.changed));
        m.insert("rc".into(), JsonValue::from(self.rc));
        m.insert("stdout".into(), JsonValue::String(self.stdout.clone()));
        m.insert("stderr".into(), JsonValue::String(self.stderr.clone()));
        m.insert(
            "stdout_lines".into(),
            JsonValue::Array(
                self.stdout_lines
                    .iter()
                    .map(|s| JsonValue::String(s.clone()))
                    .collect(),
            ),
        );
        if let Some(j) = &self.json {
            m.insert("json".into(), j.clone());
        }
        m.insert("took_ms".into(), JsonValue::from(self.took_ms));
        m.insert("skipped".into(), JsonValue::Bool(self.skipped));
        m.insert("failed".into(), JsonValue::Bool(self.failed));
        if let Some(results) = &self.results {
            m.insert(
                "results".into(),
                JsonValue::Array(results.iter().map(|r| r.to_json()).collect()),
            );
        }
        JsonValue::Object(m)
    }

    /// Build from an executed task's wire response + the buffered output.
    pub fn from_exec(
        exit_code: i32,
        changed: bool,
        took_ms: u64,
        stdout_bytes: &[u8],
        stderr_bytes: &[u8],
    ) -> Self {
        let stdout = String::from_utf8_lossy(stdout_bytes).into_owned();
        let stderr = String::from_utf8_lossy(stderr_bytes).into_owned();
        let stdout_lines: Vec<String> = stdout
            .split('\n')
            .filter(|s| !s.is_empty() || stdout.ends_with('\n'))
            .map(|s| s.to_string())
            .collect();
        // strip the trailing empty from a final '\n' to match Ansible
        let stdout_lines = if stdout.ends_with('\n') {
            let mut v = stdout_lines;
            if v.last().map(|s| s.is_empty()).unwrap_or(false) {
                v.pop();
            }
            v
        } else {
            stdout_lines
        };
        let json = serde_json::from_str::<JsonValue>(stdout.trim()).ok();
        Self {
            changed,
            rc: exit_code,
            stdout,
            stderr,
            stdout_lines,
            json,
            took_ms,
            skipped: false,
            failed: exit_code != 0,
            results: None,
        }
    }

    /// A "this task was skipped on this host" placeholder.
    pub fn skipped_marker() -> Self {
        Self {
            skipped: true,
            ..Self::default()
        }
    }

    /// Synthetic register for controller-side bodies (set_fact, assert,
    /// fail) that don't produce wire-level output.
    pub fn synthetic_ok() -> Self {
        Self {
            changed: true,
            ..Self::default()
        }
    }
}

/// Build the template context view for a host at a particular moment.
///
/// Precedence (lowest → highest): inventory_vars → set_facts → registers.
/// Loop's `item` (or renamed via loop_control.loop_var) is layered on top
/// when present.
pub fn build_template_ctx(ctx: &HostCtx) -> BTreeMap<String, JsonValue> {
    let mut out: BTreeMap<String, JsonValue> = BTreeMap::new();
    for (k, v) in &ctx.inventory_vars {
        out.insert(k.clone(), v.clone());
    }
    for (k, v) in &ctx.set_facts {
        out.insert(k.clone(), v.clone());
    }
    for (k, v) in &ctx.registers {
        out.insert(k.clone(), v.to_json());
    }
    // Stable host identity, mirroring the most-asked Ansible vars.
    out.insert(
        "inventory_hostname".into(),
        JsonValue::String(ctx.host_name.clone()),
    );
    if let Some((name, val)) = &ctx.iter_item {
        out.insert(name.clone(), val.clone());
    }
    out
}

/// Convert a `serde_yaml::Value` to a `serde_json::Value`. Maps with
/// non-string keys are rejected; YAML scalars (bool/int/float/null/string)
/// map to their JSON counterparts.
pub fn yaml_to_json(v: serde_yaml::Value) -> anyhow::Result<JsonValue> {
    use anyhow::bail;
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
                JsonValue::Null
            }
        }
        serde_yaml::Value::String(s) => JsonValue::String(s),
        serde_yaml::Value::Sequence(seq) => JsonValue::Array(
            seq.into_iter()
                .map(yaml_to_json)
                .collect::<anyhow::Result<Vec<_>>>()?,
        ),
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    serde_yaml::Value::String(s) => s,
                    other => bail!("mapping key must be a string, got: {other:?}"),
                };
                out.insert(key, yaml_to_json(v)?);
            }
            JsonValue::Object(out)
        }
        serde_yaml::Value::Tagged(t) => yaml_to_json(t.value)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_ctx_layers_precedence() {
        let mut ctx = HostCtx::new("web1".into());
        ctx.inventory_vars.insert("greeting".into(), json!("hello"));
        ctx.set_facts.insert("greeting".into(), json!("hola"));
        let map = build_template_ctx(&ctx);
        assert_eq!(map.get("greeting"), Some(&json!("hola")));
        assert_eq!(map.get("inventory_hostname"), Some(&json!("web1")));
    }

    #[test]
    fn register_to_json_roundtrip_shape() {
        let rv = RegisterValue::from_exec(0, true, 12, b"hi\n", b"");
        let j = rv.to_json();
        assert_eq!(j["rc"], 0);
        assert_eq!(j["changed"], true);
        assert_eq!(j["stdout"], "hi\n");
        assert_eq!(j["stdout_lines"], json!(["hi"]));
        assert_eq!(j["failed"], false);
    }

    #[test]
    fn register_parses_json_stdout() {
        let rv = RegisterValue::from_exec(0, false, 1, b"{\"a\": 1}", b"");
        assert_eq!(rv.json, Some(json!({"a": 1})));
        let j = rv.to_json();
        assert_eq!(j["json"], json!({"a": 1}));
    }

    #[test]
    fn register_invalid_json_yields_none() {
        let rv = RegisterValue::from_exec(0, false, 1, b"not json", b"");
        assert!(rv.json.is_none());
        let j = rv.to_json();
        assert!(j.get("json").is_none());
    }

    #[test]
    fn iter_item_layered_on_top() {
        let mut ctx = HostCtx::new("web1".into());
        ctx.iter_item = Some(("name".into(), json!("alice")));
        let map = build_template_ctx(&ctx);
        assert_eq!(map.get("name"), Some(&json!("alice")));
    }

    #[test]
    fn yaml_to_json_scalars() {
        let v = serde_yaml::from_str::<serde_yaml::Value>("42").unwrap();
        assert_eq!(yaml_to_json(v).unwrap(), json!(42));
        let v = serde_yaml::from_str::<serde_yaml::Value>("true").unwrap();
        assert_eq!(yaml_to_json(v).unwrap(), json!(true));
        let v = serde_yaml::from_str::<serde_yaml::Value>("[1, 2, 3]").unwrap();
        assert_eq!(yaml_to_json(v).unwrap(), json!([1, 2, 3]));
    }

    #[test]
    fn skipped_marker_shape() {
        let rv = RegisterValue::skipped_marker();
        assert!(rv.skipped);
        assert!(!rv.failed);
        let j = rv.to_json();
        assert_eq!(j["skipped"], true);
    }
}
