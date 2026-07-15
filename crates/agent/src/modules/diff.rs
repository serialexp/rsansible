//! Shared `--diff` payload builder for file-writing modules (write_file,
//! copy_target).
//!
//! Produces the Ansible-shaped `{before, after, before_header, after_header}`
//! JSON that the agent ships back on `TaskDone.diff`. The controller stores it
//! verbatim on the task's structured report (gothab renders it) and renders a
//! human unified diff from it for `--diff` terminal output. Keeping the shape
//! semantically identical to Ansible's `diff` dict is a deliberate design
//! decision — no ARA/AWX wire-format interop, just the same field names so the
//! payload reads naturally to anyone who knows Ansible.
//!
//! Two content adjustments keep the payload bounded and the downstream
//! unified-diff renderer robust:
//! - **Binary content** (invalid UTF-8, or containing a NUL byte) is replaced
//!   with a one-line placeholder — a byte-level diff of binary blobs is noise,
//!   and Ansible omits it too.
//! - **Oversized content** is truncated at [`MAX_DIFF_BYTES`] per side with a
//!   marker line, so a multi-megabyte file can't blow up the report or the
//!   wire frame.

/// Per-side cap on the content carried in a diff payload. 256 KiB is generous
/// for config files (the overwhelming majority of what `write_file`/`copy`
/// touch) while bounding the wire frame and stored report.
const MAX_DIFF_BYTES: usize = 256 * 1024;

/// Build the diff JSON payload for a file that changed from `before`
/// (`None` = the file didn't previously exist) to `after`. Returns the
/// serialized JSON string ready to hand to `TaskDone.diff`.
///
/// Callers should only invoke this when a diff was requested (`--diff`) *and*
/// the task actually changed the file — an unchanged task ships an empty diff
/// string, which the controller treats as "no diff".
pub fn build_file_diff(path: &str, before: Option<&[u8]>, after: &[u8]) -> String {
    let payload = serde_json::json!({
        "before": render_side(before.unwrap_or(&[])),
        "after": render_side(after),
        "before_header": path,
        "after_header": path,
    });
    payload.to_string()
}

/// Render one side of the diff to a display string, applying the binary and
/// size guards described in the module docs.
fn render_side(bytes: &[u8]) -> String {
    // Binary guard: a NUL byte or invalid UTF-8 means a content diff would be
    // meaningless. Emit a placeholder instead so the unified-diff renderer has
    // clean text to work with.
    let text = match std::str::from_utf8(bytes) {
        Ok(s) if !s.as_bytes().contains(&0) => s,
        _ => return format!("<binary content, {} bytes; diff omitted>\n", bytes.len()),
    };

    if text.len() > MAX_DIFF_BYTES {
        // Truncate on a char boundary at or below the cap so the slice stays
        // valid UTF-8. `text` is already valid UTF-8, so a boundary exists.
        let mut end = MAX_DIFF_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        return format!(
            "{}\n<... truncated, {} of {} bytes shown>\n",
            &text[..end],
            end,
            text.len()
        );
    }

    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
        v.get(k).and_then(|x| x.as_str()).unwrap()
    }

    #[test]
    fn new_file_has_empty_before() {
        let raw = build_file_diff("/etc/foo", None, b"hello\n");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(field(&v, "before"), "");
        assert_eq!(field(&v, "after"), "hello\n");
        assert_eq!(field(&v, "before_header"), "/etc/foo");
        assert_eq!(field(&v, "after_header"), "/etc/foo");
    }

    #[test]
    fn changed_file_carries_both_sides() {
        let raw = build_file_diff("/etc/foo", Some(b"old\n"), b"new\n");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(field(&v, "before"), "old\n");
        assert_eq!(field(&v, "after"), "new\n");
    }

    #[test]
    fn binary_content_is_placeheld() {
        let raw = build_file_diff("/bin/blob", Some(b"\x00\x01\x02"), b"\x00\xff");
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(field(&v, "before").starts_with("<binary content, 3 bytes"));
        assert!(field(&v, "after").starts_with("<binary content, 2 bytes"));
    }

    #[test]
    fn invalid_utf8_is_treated_as_binary() {
        let raw = build_file_diff("/x", None, &[0xff, 0xfe, 0xfd]);
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(field(&v, "after").starts_with("<binary content, 3 bytes"));
    }

    #[test]
    fn oversized_content_is_truncated() {
        let big = "a".repeat(MAX_DIFF_BYTES + 100);
        let raw = build_file_diff("/x", None, big.as_bytes());
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let after = field(&v, "after");
        assert!(after.contains("truncated"));
        // The shown prefix is capped at MAX_DIFF_BYTES.
        assert!(after.len() < big.len());
    }
}
