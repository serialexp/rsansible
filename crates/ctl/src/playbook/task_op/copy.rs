//! `copy:` task body.

use super::shared::{deserialize_mode_field, ModeField};
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
///
/// `remote_src: true` flips the meaning of `src:` from "look up a file
/// in the playbook tree on the controller" to "this path already
/// exists on the target host; have the agent read it." In that case
/// the controller's copy-resolver no longer loads `body`; instead
/// `to_wire_op` emits an `OpCopyTarget` so the agent performs a
/// target-local atomic copy. `remote_src: true` requires `src:` —
/// `content:` is inherently controller-side content, so the
/// combination is rejected at parse time.
#[derive(Debug, Clone, PartialEq)]
pub struct CopyOp {
    /// Source file path (mutually exclusive with `content`).
    pub src: Option<String>,
    /// Inline content (mutually exclusive with `src`). Jinja-rendered
    /// at dispatch time.
    pub content: Option<String>,
    pub dest: String,
    pub mode: ModeField,
    /// File owner (POSIX user name). See `TemplateOp::owner` doc — same
    /// "parsed but not yet honored" caveat.
    pub owner: Option<String>,
    /// File group (POSIX group name). Same caveat as `owner:`.
    pub group: Option<String>,
    /// Populated by the load-time copy resolver (for controller-side
    /// `src:` form) or by the orchestrator's render pass (for
    /// `content:` form, after Jinja rendering). `None` between parse
    /// and dispatch, and `None` permanently when `remote_src=true`
    /// since the bytes never traverse the wire — the agent reads
    /// `src` directly.
    pub body: Option<Vec<u8>>,
    /// Optional validator command (Ansible `validate:`). When set, the
    /// agent runs the command against the staged tmp file before the
    /// rename; non-zero exit aborts the write. `%s` is substituted by
    /// the tmp path. Empty / `None` = no validation. Classic use case:
    /// `validate: /usr/sbin/visudo -cf %s` on a sudoers drop-in.
    pub validate: Option<String>,
    /// `remote_src: true` — `src:` is a path on the target host, not
    /// in the playbook tree. Routes to `OpCopyTarget` at wire time.
    pub remote_src: bool,
    /// Search base directories captured at load time. Used by the
    /// orchestrator's Copy dispatch arm to locate the file when
    /// `src:` is Jinja-templated (and therefore wasn't pre-loaded into
    /// `body`). Empty when `body` is populated, when `content:` is the
    /// form, or when `remote_src` is true.
    pub search_dirs: Vec<std::path::PathBuf>,
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
        deserialize_with = "deserialize_mode_field"
    )]
    mode: ModeField,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    validate: Option<String>,
    #[serde(default, deserialize_with = "super::shared::deserialize_ansible_bool")]
    remote_src: bool,
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
            (None, Some(_)) if raw.remote_src => Err(serde::de::Error::custom(
                "copy: `remote_src: true` requires `src:` (a path on the target host) — \
                 `content:` is inherently controller-side and cannot be remote",
            )),
            _ => Ok(CopyOp {
                src: raw.src,
                content: raw.content,
                dest: raw.dest,
                mode: raw.mode,
                owner: raw.owner,
                group: raw.group,
                body: None,
                validate: raw.validate,
                remote_src: raw.remote_src,
                search_dirs: Vec::new(),
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
                assert_eq!(c.mode, crate::playbook::ModeField::Literal(0o600));
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
            TaskBody::Op(TaskOp::Copy(c)) => assert_eq!(c.mode, crate::playbook::ModeField::Literal(0o644)),
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
    fn copy_parses_validate_through_to_op() {
        // Regression: `validate:` (a.k.a. "check the tmp file before
        // rename") must be accepted on `copy:` and threaded onto the
        // resulting CopyOp. Classic use: visudo on sudoers drop-ins.
        let t = parse_task(
            r#"
name: stage sudoers
copy:
  content: "operator ALL=(ALL) NOPASSWD:ALL\n"
  dest: /etc/sudoers.d/operator
  mode: "0440"
  validate: /usr/sbin/visudo -cf %s
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Copy(c)) => {
                assert_eq!(c.validate.as_deref(), Some("/usr/sbin/visudo -cf %s"));
            }
            other => panic!("expected copy, got {other:?}"),
        }
    }

    #[test]
    fn copy_to_wire_carries_validate() {
        // Regression: the validate field must survive to_wire_op — if
        // it's dropped here the agent never sees it and the safety
        // guarantee evaporates silently.
        let t = TaskOp::Copy(CopyOp {
            src: None,
            content: Some("body".into()),
            dest: "/etc/sudoers.d/x".into(),
            mode: crate::playbook::ModeField::Literal(0o440),
            owner: None,
            group: None,
            body: Some(b"body".to_vec()),
            validate: Some("/usr/sbin/visudo -cf %s".into()),
            remote_src: false,
            search_dirs: Vec::new(),
        });
        let WireOp::OpWriteFile(w) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(w.validate, "/usr/sbin/visudo -cf %s");
    }

    #[test]
    fn copy_to_wire_with_binary_body_ships_bytes_verbatim() {
        let t = TaskOp::Copy(CopyOp {
            src: Some("blob.bin".into()),
            content: None,
            dest: "/etc/blob".into(),
            mode: crate::playbook::ModeField::Literal(0o600),
            owner: None,
            group: None,
            // Non-UTF-8 bytes — would corrupt through a String roundtrip.
            body: Some(vec![0xff, 0x00, 0xfe, 0xfd, 0x7f]),
            validate: None,
            remote_src: false,
            search_dirs: Vec::new(),
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
            mode: crate::playbook::ModeField::Literal(0o644),
            owner: None,
            group: None,
            body: None,
            validate: None,
            remote_src: false,
            search_dirs: Vec::new(),
        });
        let err = t.to_wire_op().unwrap_err();
        assert!(format!("{err}").contains("not resolved"), "got: {err}");
    }

    /// Regression: gothab uses `copy: remote_src: true` extensively
    /// to install upstream binaries (extract tarball → copy into
    /// /usr/local/bin). The parser must accept `remote_src: true`
    /// without trying to resolve `src:` against the controller's
    /// playbook tree.
    #[test]
    fn copy_parses_remote_src_true() {
        let t = parse_task(
            r#"
name: install
copy:
  src: /tmp/node_exporter/node_exporter
  dest: /usr/local/bin/node_exporter
  mode: "0755"
  remote_src: true
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Copy(c)) => {
                assert!(c.remote_src);
                assert_eq!(c.src.as_deref(), Some("/tmp/node_exporter/node_exporter"));
            }
            other => panic!("expected copy, got {other:?}"),
        }
    }

    /// `remote_src: true` is meaningless with `content:` — content is
    /// inherently controller-side. Reject at parse time so the
    /// playbook author gets a clear error instead of a silently-
    /// dropped flag.
    #[test]
    fn copy_rejects_remote_src_with_content() {
        let err = try_parse_task(
            r#"
name: stage
copy:
  content: "hi"
  dest: /etc/greeting
  remote_src: true
"#,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("remote_src") && msg.contains("content"),
            "got: {msg}"
        );
    }

    /// `remote_src: true` routes to `OpCopyTarget` on the wire — the
    /// agent reads `src` on the target host and writes to `dest`. The
    /// controller never loads bytes, so `body: None` is fine.
    #[test]
    fn copy_remote_src_emits_op_copy_target() {
        let t = TaskOp::Copy(CopyOp {
            src: Some("/tmp/node_exporter/node_exporter".into()),
            content: None,
            dest: "/usr/local/bin/node_exporter".into(),
            mode: crate::playbook::ModeField::Literal(0o755),
            owner: Some("root".into()),
            group: Some("root".into()),
            body: None, // remote_src: bytes never traverse the wire
            validate: None,
            remote_src: true,
            search_dirs: Vec::new(),
        });
        let WireOp::OpCopyTarget(o) = t.to_wire_op().unwrap() else {
            panic!("expected OpCopyTarget for remote_src=true")
        };
        assert_eq!(o.src, "/tmp/node_exporter/node_exporter");
        assert_eq!(o.dest, "/usr/local/bin/node_exporter");
        assert_eq!(o.has_mode, 1);
        assert_eq!(o.mode, 0o755);
        assert_eq!(o.owner, "root");
        assert_eq!(o.group, "root");
        assert_eq!(o.validate, "");
    }
}
