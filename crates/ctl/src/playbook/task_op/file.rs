//! `file:` task body.

use super::shared::{deserialize_ansible_bool, deserialize_mode_field_opt, ModeField};
use serde::Deserialize;

/// `file: { path: …, state: directory, mode: "0755", owner: root,
/// group: root, recurse: yes }`
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileOp {
    pub path: String,
    pub state: FileState,
    /// `mode: "0755"` (string), `mode: 0o755` (int), or a Jinja
    /// expression like `"{{ item.mode }}"`. Templates are resolved by
    /// the orchestrator at dispatch (see `ModeField`). Absent →
    /// don't chmod.
    #[serde(default, deserialize_with = "deserialize_mode_field_opt")]
    pub mode: Option<ModeField>,
    /// Owner / group as user-resolvable names. Empty → don't chown.
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    /// Only meaningful for `state: directory`. When true, recursively
    /// apply mode/owner/group to all descendants (Ansible behavior).
    #[serde(default, deserialize_with = "deserialize_ansible_bool")]
    pub recurse: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    Directory,
    Absent,
    Touch,
    /// Regular file — ensure it exists; doesn't create. Used to chmod /
    /// chown an existing file.
    File,
}

impl FileState {
    /// Wire byte matching `schema/wire.schema.json5` OpFile.state.
    pub fn wire_byte(self) -> u8 {
        match self {
            FileState::Directory => 0,
            FileState::Absent => 1,
            FileState::Touch => 2,
            FileState::File => 3,
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
    fn parses_file_directory_with_mode_string() {
        let t = parse_task(
            r#"
name: mkdir
file:
  path: /opt/foo
  state: directory
  owner: root
  group: root
  mode: "0755"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => {
                assert_eq!(f.path, "/opt/foo");
                assert_eq!(f.state, FileState::Directory);
                assert_eq!(f.owner.as_deref(), Some("root"));
                assert_eq!(f.group.as_deref(), Some("root"));
                assert_eq!(f.mode, Some(ModeField::Literal(0o755)));
                assert!(!f.recurse);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_file_absent_minimal() {
        let t = parse_task(
            r#"
name: rm
file:
  path: /tmp/junk
  state: absent
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => {
                assert_eq!(f.state, FileState::Absent);
                assert!(f.mode.is_none());
                assert!(f.owner.is_none());
                assert!(f.group.is_none());
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_file_touch_and_recurse() {
        let t = parse_task(
            r#"
name: t
file:
  path: /tmp/marker
  state: touch
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => assert_eq!(f.state, FileState::Touch),
            other => panic!("got {other:?}"),
        }

        let t = parse_task(
            r#"
name: r
file:
  path: /var/lib/x
  state: directory
  mode: "0700"
  recurse: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => {
                assert!(f.recurse);
                assert_eq!(f.state, FileState::Directory);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn file_mode_accepts_int_and_octal_string() {
        // Plain int (e.g. YAML `0o644` → 420; serde_yaml parses 0o…
        // octal literals).
        let t = parse_task(
            r#"
name: m
file:
  path: /tmp/x
  state: file
  mode: 0o644
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => assert_eq!(f.mode, Some(ModeField::Literal(0o644))),
            other => panic!("got {other:?}"),
        }
        // String form with leading 0.
        let t = parse_task(
            r#"
name: m
file:
  path: /tmp/x
  state: file
  mode: "0644"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::File(f)) => assert_eq!(f.mode, Some(ModeField::Literal(0o644))),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn file_rejects_unknown_state() {
        let err = try_parse_task(
            r#"
name: x
file:
  path: /tmp/x
  state: bogus
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("bogus") || err.contains("unknown variant"), "got: {err}");
    }

    #[test]
    fn file_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: x
file:
  path: /tmp/x
  state: file
  force: yes
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("force") || err.contains("unknown"), "got: {err}");
    }

    #[test]
    fn file_to_wire_carries_state_byte() {
        let t = TaskOp::File(FileOp {
            path: "/tmp/x".into(),
            state: FileState::Directory,
            mode: Some(ModeField::Literal(0o755)),
            owner: Some("root".into()),
            group: Some("root".into()),
            recurse: true,
        });
        let WireOp::OpFile(o) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(o.kind, 5);
        assert_eq!(o.path, "/tmp/x");
        assert_eq!(o.state, 0);
        assert_eq!(o.has_mode, 1);
        assert_eq!(o.mode, 0o755);
        assert_eq!(o.owner, "root");
        assert_eq!(o.group, "root");
        assert_eq!(o.recurse, 1);

        let t = TaskOp::File(FileOp {
            path: "/x".into(),
            state: FileState::Absent,
            mode: None,
            owner: None,
            group: None,
            recurse: false,
        });
        let WireOp::OpFile(o) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(o.state, 1);
        assert_eq!(o.has_mode, 0);
        assert_eq!(o.owner, "");
    }
}
