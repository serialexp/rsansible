//! Exact-value redaction of vault-sourced secrets.
//!
//! # Why this can be exact
//!
//! rsansible renders `template:`/`copy:` bodies on the controller
//! (`orchestrator::render_str_resolved`), so at the moment a diff comes back
//! from an agent the same process still holds the variable map that produced
//! the `after` side — including values decrypted out of `$ANSIBLE_VAULT` files
//! by [`crate::vault`]. That means we do not have to *guess* which bytes are
//! secret from their shape: we know the literal strings, and can redact those
//! and only those.
//!
//! That is the whole reason this module exists rather than a pattern matcher.
//! A heuristic redactor ("blank anything under a key called `password`, or that
//! looks like a PEM block") fails silently on the first format nobody
//! anticipated, and — worse — gets advertised, so people enable diff reporting
//! believing they are covered. Exact-value redaction has no false positives at
//! all, and its false negatives are enumerable. They are enumerated below.
//!
//! # What this does NOT catch
//!
//! Read this list before treating the registry as a guarantee.
//!
//! - **Secrets not sourced from a vault file.** A password sitting in plaintext
//!   `group_vars/all.yml` is, as far as this code can tell, ordinary config.
//!   Vault-encrypt it, or mark the consuming task `no_log: true`.
//! - **Values shorter than [`MIN_SECRET_LEN`].** See that constant for why the
//!   floor has to exist. A four-character vault value goes through unredacted.
//! - **Non-string scalars.** `db_port: 54321` in a vault file parses as a JSON
//!   number, and numbers are not learned — a bare integer is far more likely to
//!   collide with innocent content (a size, a timestamp, a port) than to be the
//!   thing you meant to hide. Quote genuinely secret values in the vault file
//!   and they become strings.
//! - **Transformed secrets.** A value the playbook hashes, base64s, or splices
//!   before writing does not appear literally in the output, so there is
//!   nothing to match. `no_log: true` is the answer there.
//!
//! `no_log: true` remains the complete answer; this is defence in depth under
//! it, for the common case where somebody forgot.
//!
//! Ansible has no equivalent — a templated vault value appears verbatim in its
//! `--diff` output. See ANSIBLE_COMPAT.md §14.

use std::collections::BTreeSet;
use std::sync::RwLock;

use serde_json::Value as JsonValue;

/// Text substituted for a matched secret.
pub const REDACTED: &str = "<redacted: vault value>";

/// Shortest vault string treated as a secret.
///
/// A floor is not optional. Vault files hold ordinary config next to the
/// secrets — `postgres_version: "17"`, `env: "prod"`, `replicas: "3"` — and
/// substring-redacting a value like `"17"` would corrupt every diff that
/// contains those two characters anywhere, which is most of them. The output
/// would be unreadable and, being unreadable, would be turned off.
///
/// Ansible's own `no_log` substitution has no such floor, which is why
/// `no_log` on a short value is a well-known way to shred your output. We
/// harvest *every* string in a vault file rather than only values explicitly
/// marked secret, so the floor matters more here, not less.
///
/// Eight characters is short enough to catch any credential worth the name and
/// long enough that collisions with structural config are rare. The cost is
/// stated plainly in the module docs: shorter vault values are not redacted.
pub const MIN_SECRET_LEN: usize = 8;

/// The set of literal strings to redact from anything leaving the process.
///
/// Populated during inventory load (the only place that knows a value came out
/// of a vault file) and consulted at the reporting funnel. Interior mutability
/// so it can be threaded as a shared reference through the loader rather than
/// `&mut` up four call frames.
#[derive(Debug, Default)]
pub struct SecretRegistry {
    values: RwLock<BTreeSet<String>>,
}

impl SecretRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild a registry from previously-collected values.
    ///
    /// Used by the forwarder: in remote-run mode the laptop does the vault
    /// decryption and ships the resolved vars, so the forwarder never calls the
    /// loader and would otherwise have an empty registry — silently losing
    /// redaction for exactly the runs most likely to be reported.
    pub fn from_values<I: IntoIterator<Item = String>>(values: I) -> Self {
        let reg = Self::new();
        {
            let mut w = reg.values.write().expect("secret registry poisoned");
            for v in values {
                if Self::is_learnable(&v) {
                    w.insert(v);
                }
            }
        }
        reg
    }

    /// Snapshot the learned values, for transport to a forwarder.
    pub fn values(&self) -> Vec<String> {
        self.values
            .read()
            .expect("secret registry poisoned")
            .iter()
            .cloned()
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.values
            .read()
            .expect("secret registry poisoned")
            .is_empty()
    }

    pub fn len(&self) -> usize {
        self.values.read().expect("secret registry poisoned").len()
    }

    fn is_learnable(s: &str) -> bool {
        s.len() >= MIN_SECRET_LEN && !s.trim().is_empty()
    }

    /// Learn every string leaf of a vault-decrypted value.
    ///
    /// Called with the parsed contents of a file that `vault::is_vault`
    /// accepted, so the whole tree is secret-adjacent by provenance — we do not
    /// try to tell "the password" from "the version pin sitting next to it",
    /// because guessing that is exactly the failure mode this module avoids.
    /// [`MIN_SECRET_LEN`] is the only filter.
    pub fn learn(&self, value: &JsonValue) {
        let mut w = self.values.write().expect("secret registry poisoned");
        Self::walk(value, &mut w);
    }

    fn walk(value: &JsonValue, out: &mut BTreeSet<String>) {
        match value {
            JsonValue::String(s) => {
                if Self::is_learnable(s) {
                    out.insert(s.clone());
                }
            }
            JsonValue::Array(a) => a.iter().for_each(|v| Self::walk(v, out)),
            JsonValue::Object(o) => o.values().for_each(|v| Self::walk(v, out)),
            // Numbers, bools and null are deliberately not learned; see the
            // module docs.
            _ => {}
        }
    }

    /// Redact every known secret from a plain string.
    ///
    /// Longest-first so that a secret which contains another (a URL embedding a
    /// password, say) is replaced whole rather than leaving a mangled tail.
    pub fn redact_text(&self, text: &str) -> String {
        let values = self.values.read().expect("secret registry poisoned");
        if values.is_empty() {
            return text.to_string();
        }
        let mut ordered: Vec<&String> = values.iter().collect();
        ordered.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));

        let mut out = text.to_string();
        for secret in ordered {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        out
    }

    /// Redact a serialized-JSON payload (i.e. a diff).
    ///
    /// Parses and walks the structure rather than running the substring pass
    /// over the raw text, because a secret containing a quote, a backslash or a
    /// newline appears *escaped* inside serialized JSON — `"pa\"ss"` — and a
    /// raw substring match would sail straight past it. Walking the parsed
    /// value compares against the real string, then re-serializes with correct
    /// escaping.
    ///
    /// Shape-agnostic on purpose: it redacts every string leaf, so it keeps
    /// working if the diff payload grows a field. If the text is not valid JSON
    /// (it always is today — [`crate::report::TaskRunSummary::diff`] is built
    /// by `serde_json`), it falls back to the raw substring pass rather than
    /// passing the text through unredacted.
    pub fn redact_json_payload(&self, payload: &str) -> String {
        if self.is_empty() {
            return payload.to_string();
        }
        match serde_json::from_str::<JsonValue>(payload) {
            Ok(mut v) => {
                self.redact_value(&mut v);
                serde_json::to_string(&v).unwrap_or_else(|_| self.redact_text(payload))
            }
            Err(_) => self.redact_text(payload),
        }
    }

    fn redact_value(&self, value: &mut JsonValue) {
        match value {
            JsonValue::String(s) => {
                let red = self.redact_text(s);
                if &red != s {
                    *s = red;
                }
            }
            JsonValue::Array(a) => a.iter_mut().for_each(|v| self.redact_value(v)),
            JsonValue::Object(o) => o.values_mut().for_each(|v| self.redact_value(v)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reg(vals: &[&str]) -> SecretRegistry {
        SecretRegistry::from_values(vals.iter().map(|s| s.to_string()))
    }

    #[test]
    fn learns_string_leaves_from_a_nested_map() {
        let r = SecretRegistry::new();
        r.learn(&json!({
            "db": {"password": "sup3rsecretpw", "port": 5432},
            "peers": ["another-secret-value", "x"],
        }));
        let mut got = r.values();
        got.sort();
        assert_eq!(got, vec!["another-secret-value", "sup3rsecretpw"]);
    }

    #[test]
    fn ignores_values_below_the_length_floor() {
        // The floor is what stops `env: "prod"` from corrupting every diff.
        let r = SecretRegistry::new();
        r.learn(&json!({"env": "prod", "version": "17"}));
        assert!(r.is_empty());
    }

    #[test]
    fn ignores_non_string_scalars() {
        let r = SecretRegistry::new();
        r.learn(&json!({"port": 54321, "on": true, "nothing": null}));
        assert!(r.is_empty());
    }

    #[test]
    fn redacts_an_exact_match() {
        let r = reg(&["sup3rsecretpw"]);
        assert_eq!(
            r.redact_text("password = sup3rsecretpw\n"),
            format!("password = {REDACTED}\n")
        );
    }

    #[test]
    fn leaves_innocent_text_untouched() {
        let r = reg(&["sup3rsecretpw"]);
        assert_eq!(r.redact_text("listen = 0.0.0.0\n"), "listen = 0.0.0.0\n");
    }

    #[test]
    fn redacts_every_occurrence() {
        let r = reg(&["sup3rsecretpw"]);
        assert_eq!(
            r.redact_text("a=sup3rsecretpw b=sup3rsecretpw"),
            format!("a={REDACTED} b={REDACTED}")
        );
    }

    #[test]
    fn longest_match_wins() {
        // The long value embeds the short one. Replacing the short one first
        // would leave a mangled remnant of the long one in the output.
        let r = reg(&["hunter2pass", "postgres://u:hunter2pass@db/app"]);
        let out = r.redact_text("dsn: postgres://u:hunter2pass@db/app");
        assert_eq!(out, format!("dsn: {REDACTED}"));
    }

    #[test]
    fn redacts_inside_a_serialized_diff_payload() {
        let r = reg(&["sup3rsecretpw"]);
        let payload = serde_json::to_string(&json!({
            "before": "",
            "after": "password = sup3rsecretpw\n",
            "before_header": "/etc/app.conf",
            "after_header": "/etc/app.conf",
        }))
        .unwrap();
        let out = r.redact_json_payload(&payload);
        assert!(!out.contains("sup3rsecretpw"));
        assert!(out.contains(REDACTED));
        // Headers survive: you still learn which file changed.
        assert!(out.contains("/etc/app.conf"));
    }

    #[test]
    fn redacts_inside_an_array_payload() {
        // Looped tasks ship a JSON array of diffs.
        let r = reg(&["sup3rsecretpw"]);
        let payload = serde_json::to_string(&json!([
            {"after": "a"},
            {"after": "pw=sup3rsecretpw"},
        ]))
        .unwrap();
        assert!(!r.redact_json_payload(&payload).contains("sup3rsecretpw"));
    }

    #[test]
    fn catches_a_secret_that_json_escaping_would_hide_from_a_substring_pass() {
        // This is the case that motivates parsing instead of grepping: the
        // secret contains a quote and a newline, so in the serialized payload
        // it appears as `pa\"ss\nword` and a raw substring match misses it.
        let secret = "pa\"ss\nword-secret";
        let r = reg(&[secret]);
        let payload = serde_json::to_string(&json!({"after": format!("k={secret}\n")})).unwrap();
        assert!(
            !payload.contains(secret),
            "test is vacuous unless the raw payload really does hide the secret"
        );
        let out = r.redact_json_payload(&payload);
        let back: JsonValue = serde_json::from_str(&out).unwrap();
        assert!(!back["after"].as_str().unwrap().contains("word-secret"));
    }

    #[test]
    fn falls_back_to_substring_redaction_on_unparseable_input() {
        // Fail closed: if the payload is not JSON we still scrub it, rather
        // than treating "I could not parse this" as "this is safe".
        let r = reg(&["sup3rsecretpw"]);
        let out = r.redact_json_payload("not json at all: sup3rsecretpw");
        assert!(!out.contains("sup3rsecretpw"));
    }

    #[test]
    fn an_empty_registry_is_a_passthrough() {
        let r = SecretRegistry::new();
        assert_eq!(r.redact_text("anything"), "anything");
        assert_eq!(r.redact_json_payload("{\"a\":\"b\"}"), "{\"a\":\"b\"}");
    }

    #[test]
    fn from_values_applies_the_same_floor() {
        // Transport must not be a way to smuggle in a value the loader would
        // have rejected.
        let r = reg(&["short", "long-enough-value"]);
        assert_eq!(r.values(), vec!["long-enough-value"]);
    }
}
