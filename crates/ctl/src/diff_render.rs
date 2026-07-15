//! Human `--diff` rendering: turn the agent's serialized diff payload into a
//! unified diff for terminal output.
//!
//! The agent ships each changed file's diff as an Ansible-shaped
//! `{before, after, before_header, after_header}` JSON object (see the agent's
//! `modules::diff`). A looped task with several changed files ships a JSON
//! array of those objects. This module is the read side: it parses either
//! shape and renders a `diff -u`-style unified diff per file, which the
//! orchestrator prints to stderr when `--diff` is active.
//!
//! Rendering is display-only — the structured `--report` carries the raw JSON
//! payload verbatim; gothab renders its own view. Keeping the wire payload as
//! Ansible's field names (not a pre-rendered blob) means the same bytes serve
//! both the terminal diff here and a richer web view later.

use serde::Deserialize;
use similar::{ChangeTag, TextDiff};

/// One file's diff, matching Ansible's `diff` dict field names. `before`/
/// `after` are the (possibly binary-/size-guarded) file contents; the headers
/// default to the file path.
#[derive(Debug, Deserialize)]
struct FileDiff {
    #[serde(default)]
    before: String,
    #[serde(default)]
    after: String,
    #[serde(default)]
    before_header: String,
    #[serde(default)]
    after_header: String,
}

/// Parse a diff payload (a single object or an array of objects) and render a
/// unified diff for each file. Returns `None` when the payload is empty, isn't
/// valid JSON of the expected shape, or produces no textual changes (e.g. a
/// mode-only change that carried an empty payload). The returned string ends
/// with a trailing newline when non-empty.
pub fn render_diff_payload(payload: &str) -> Option<String> {
    let payload = payload.trim();
    if payload.is_empty() {
        return None;
    }

    // Accept both the single-file object and the looped-task array shape.
    let files: Vec<FileDiff> = match serde_json::from_str::<Vec<FileDiff>>(payload) {
        Ok(v) => v,
        Err(_) => match serde_json::from_str::<FileDiff>(payload) {
            Ok(one) => vec![one],
            Err(_) => return None,
        },
    };

    let mut out = String::new();
    for f in &files {
        if let Some(rendered) = render_one(f) {
            out.push_str(&rendered);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Render one file's unified diff with `--- before_header` / `+++ after_header`
/// banners. Returns `None` if `before == after` (no lines differ).
fn render_one(f: &FileDiff) -> Option<String> {
    if f.before == f.after {
        return None;
    }
    let before_label = if f.before_header.is_empty() {
        "before"
    } else {
        f.before_header.as_str()
    };
    let after_label = if f.after_header.is_empty() {
        "after"
    } else {
        f.after_header.as_str()
    };

    let diff = TextDiff::from_lines(&f.before, &f.after);
    let mut s = String::new();
    s.push_str(&format!("--- {before_label}\n"));
    s.push_str(&format!("+++ {after_label}\n"));
    // A single hunk covering the whole file keeps the output simple and
    // deterministic; config files (the common case) are small enough that
    // context-grouping buys little. `similar`'s unified_diff() with a large
    // context achieves the same, but iterating changes lets us control the
    // exact markers without depending on its header formatting.
    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => '-',
            ChangeTag::Insert => '+',
            ChangeTag::Equal => ' ',
        };
        s.push(sign);
        s.push_str(change.value());
        // `from_lines` keeps the line's own newline in `value()`; add one only
        // when the source line lacked a trailing newline (last line of file).
        if !change.value().ends_with('\n') {
            s.push('\n');
        }
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_object_renders_unified_diff() {
        let payload = serde_json::json!({
            "before": "alpha\nbeta\n",
            "after": "alpha\ngamma\n",
            "before_header": "/etc/x",
            "after_header": "/etc/x",
        })
        .to_string();
        let out = render_diff_payload(&payload).unwrap();
        assert!(out.contains("--- /etc/x"));
        assert!(out.contains("+++ /etc/x"));
        assert!(out.contains("-beta"));
        assert!(out.contains("+gamma"));
        assert!(out.contains(" alpha"));
    }

    #[test]
    fn new_file_shows_all_additions() {
        let payload = serde_json::json!({
            "before": "",
            "after": "one\ntwo\n",
            "before_header": "/etc/new",
            "after_header": "/etc/new",
        })
        .to_string();
        let out = render_diff_payload(&payload).unwrap();
        assert!(out.contains("+one"));
        assert!(out.contains("+two"));
        // No deletion lines (a `-` marker on a content line, distinct from the
        // `--- header` banner) for a brand-new file.
        assert!(!out
            .lines()
            .any(|l| l.starts_with('-') && !l.starts_with("---")));
    }

    #[test]
    fn array_payload_renders_each_file() {
        let payload = serde_json::json!([
            {"before": "a\n", "after": "b\n", "before_header": "/f1", "after_header": "/f1"},
            {"before": "c\n", "after": "d\n", "before_header": "/f2", "after_header": "/f2"},
        ])
        .to_string();
        let out = render_diff_payload(&payload).unwrap();
        assert!(out.contains("--- /f1"));
        assert!(out.contains("--- /f2"));
        assert!(out.contains("-a"));
        assert!(out.contains("+d"));
    }

    #[test]
    fn identical_sides_render_nothing() {
        let payload = serde_json::json!({
            "before": "same\n", "after": "same\n",
            "before_header": "/x", "after_header": "/x",
        })
        .to_string();
        assert!(render_diff_payload(&payload).is_none());
    }

    #[test]
    fn empty_or_garbage_payload_is_none() {
        assert!(render_diff_payload("").is_none());
        assert!(render_diff_payload("   ").is_none());
        assert!(render_diff_payload("not json").is_none());
    }
}
