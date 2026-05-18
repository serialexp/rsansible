//! `copy:` task body.

use super::template::default_template_mode;
use serde::Deserialize;

/// `copy: { src: foo.bin, dest: /etc/foo, mode: 0o644 }`
///
/// Two mutually-exclusive forms:
///
/// 1. **`src:` form** — file-on-disk lookup. Resolution mirrors
///    `template:` but looks in `files/` rather than `templates/`:
///
///    1. absolute path (used as-is)
///    2. `<role_dir>/files/<src>`
///    3. `<playbook_dir>/files/<src>`
///    4. `<playbook_dir>/<src>`
///
///    The resolved file is loaded as raw bytes into `body` during the
///    copy-resolution pass. Bytes are shipped verbatim — no Jinja
///    rendering, so `copy: src:` supports binary blobs.
///
/// 2. **`content:` form** — inline string content. The string is Jinja-
///    rendered against the per-host template context at dispatch time,
///    then shipped as UTF-8 bytes. Ansible-equivalent: `copy: content:`
///    is the inline-template form, semantically closer to `template:`
///    than to `copy: src:`. Binary content via `content:` is not
///    supported (YAML strings are UTF-8).
///
/// Exactly one of `src:` / `content:` must be set — enforced at parse
/// time via `TryFrom<RawCopyOp>`.
#[derive(Debug, Clone, PartialEq)]
pub struct CopyOp {
    /// Source file path (mutually exclusive with `content`).
    pub src: Option<String>,
    /// Inline content (mutually exclusive with `src`). Jinja-rendered
    /// at dispatch time.
    pub content: Option<String>,
    pub dest: String,
    pub mode: u32,
    /// File owner (POSIX user name). See `TemplateOp::owner` doc — same
    /// "parsed but not yet honored" caveat.
    pub owner: Option<String>,
    /// File group (POSIX group name). Same caveat as `owner:`.
    pub group: Option<String>,
    /// Populated by the load-time copy resolver (for `src:` form) or by
    /// the orchestrator's render pass (for `content:` form, after Jinja
    /// rendering). `None` between parse and dispatch.
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCopyOp {
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    content: Option<String>,
    dest: String,
    #[serde(
        default = "default_template_mode",
        deserialize_with = "super::shared::deserialize_file_mode_u32"
    )]
    mode: u32,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
}

impl<'de> Deserialize<'de> for CopyOp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawCopyOp::deserialize(d)?;
        match (&raw.src, &raw.content) {
            (Some(_), Some(_)) => Err(serde::de::Error::custom(
                "copy: `src:` and `content:` are mutually exclusive — set exactly one",
            )),
            (None, None) => Err(serde::de::Error::custom(
                "copy: exactly one of `src:` or `content:` is required",
            )),
            _ => Ok(CopyOp {
                src: raw.src,
                content: raw.content,
                dest: raw.dest,
                mode: raw.mode,
                owner: raw.owner,
                group: raw.group,
                body: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task, try_parse_task_for_test as try_parse_task};
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{TaskBody, TaskOp};

    #[test]
    fn parses_copy_body() {
        let t = parse_task(
            r#"
name: stage
copy:
  src: foo.bin
  dest: /etc/foo
  mode: 0o600
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Copy(c)) => {
                assert_eq!(c.src.as_deref(), Some("foo.bin"));
                assert!(c.content.is_none());
                assert_eq!(c.dest, "/etc/foo");
                assert_eq!(c.mode, 0o600);
                assert!(c.body.is_none(), "body is populated by the loader, not parse");
            }
            other => panic!("expected copy, got {other:?}"),
        }
    }

    #[test]
    fn copy_mode_defaults_to_0644() {
        let t = parse_task(
            r#"
name: stage
copy:
  src: foo.bin
  dest: /etc/foo
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Copy(c)) => assert_eq!(c.mode, 0o644),
            _ => panic!(),
        }
    }

    #[test]
    fn copy_rejects_missing_src_and_content() {
        let err = try_parse_task(
            r#"
name: stage
copy:
  dest: /etc/foo
"#,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exactly one of `src:` or `content:`"),
            "got: {msg}"
        );
    }

    #[test]
    fn copy_rejects_both_src_and_content() {
        let err = try_parse_task(
            r#"
name: stage
copy:
  src: a
  content: hi
  dest: /etc/foo
"#,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("mutually exclusive"), "got: {msg}");
    }

    #[test]
    fn parses_copy_content_form() {
        let t = parse_task(
            r#"
name: stage
copy:
  content: "hello {{ name }}\n"
  dest: /etc/greeting
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Copy(c)) => {
                assert!(c.src.is_none());
                assert_eq!(c.content.as_deref(), Some("hello {{ name }}\n"));
                assert_eq!(c.dest, "/etc/greeting");
                assert!(c.body.is_none(), "body is populated at dispatch, not parse");
            }
            other => panic!("expected copy, got {other:?}"),
        }
    }

    #[test]
    fn copy_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: stage
copy:
  src: a
  dest: /b
  rogue: 1
"#,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("rogue"), "got: {err}");
    }

    #[test]
    fn copy_to_wire_with_binary_body_ships_bytes_verbatim() {
        let t = TaskOp::Copy(CopyOp {
            src: Some("blob.bin".into()),
            content: None,
            dest: "/etc/blob".into(),
            mode: 0o600,
            owner: None,
            group: None,
            // Non-UTF-8 bytes — would corrupt through a String roundtrip.
            body: Some(vec![0xff, 0x00, 0xfe, 0xfd, 0x7f]),
        });
        let WireOp::OpWriteFile(w) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(w.path, "/etc/blob");
        assert_eq!(w.mode, 0o600);
        assert_eq!(w.content, vec![0xff, 0x00, 0xfe, 0xfd, 0x7f]);
    }

    #[test]
    fn copy_to_wire_errors_when_body_missing() {
        let t = TaskOp::Copy(CopyOp {
            src: Some("blob.bin".into()),
            content: None,
            dest: "/etc/blob".into(),
            mode: 0o644,
            owner: None,
            group: None,
            body: None,
        });
        let err = t.to_wire_op().unwrap_err();
        assert!(format!("{err}").contains("not resolved"), "got: {err}");
    }
}
