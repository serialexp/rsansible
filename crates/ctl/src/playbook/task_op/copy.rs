//! `copy:` task body.

use super::template::default_template_mode;
use serde::Deserialize;

/// `copy: { src: foo.bin, dest: /etc/foo, mode: 0o644 }`
///
/// Resolution mirrors `template:` but looks in `files/` rather than
/// `templates/`:
///
/// 1. absolute path (used as-is)
/// 2. `<role_dir>/files/<src>`
/// 3. `<playbook_dir>/files/<src>`
/// 4. `<playbook_dir>/<src>`
///
/// The resolved file is loaded as raw bytes into `body` during the
/// copy-resolution pass; `body` does not parse from YAML. Unlike
/// `template:`, the bytes are shipped verbatim — no Jinja rendering of
/// the content, so `copy:` supports binary blobs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CopyOp {
    pub src: String,
    pub dest: String,
    #[serde(default = "default_template_mode", deserialize_with = "super::shared::deserialize_file_mode_u32")]
    pub mode: u32,
    /// File owner (POSIX user name). See `TemplateOp::owner` doc — same
    /// "parsed but not yet honored" caveat.
    #[serde(default)]
    pub owner: Option<String>,
    /// File group (POSIX group name). Same caveat as `owner:`.
    #[serde(default)]
    pub group: Option<String>,
    /// Populated by the load-time copy resolver. `None` until then.
    #[serde(skip, default)]
    pub body: Option<Vec<u8>>,
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
                assert_eq!(c.src, "foo.bin");
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
    fn copy_rejects_missing_src() {
        let err = try_parse_task(
            r#"
name: stage
copy:
  dest: /etc/foo
"#,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("src"), "got: {err}");
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
            src: "blob.bin".into(),
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
            src: "blob.bin".into(),
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
