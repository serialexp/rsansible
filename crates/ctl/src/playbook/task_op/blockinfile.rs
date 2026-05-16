//! `blockinfile:` task body.

use super::shared::{
    take_optional_ansible_bool, take_optional_field_string, take_optional_mode,
};
use serde::{de::Error as _, Deserialize, Deserializer};

/// `blockinfile:` parsed form. `block` is the body (typically multi-line)
/// to ensure or remove; the `marker` template builds the BEGIN/END
/// marker lines via literal-token `{mark}` substitution. `insertbefore`
/// / `insertafter` are mutually exclusive; `EOF` for `insertafter`
/// means "append" (Ansible's default).
#[derive(Debug, Clone, PartialEq)]
pub struct BlockInFileOp {
    pub path: String,
    pub block: String,
    pub marker: String,
    pub marker_begin: String,
    pub marker_end: String,
    pub state: BlockInFileState,
    pub mode: Option<u32>,
    pub create: bool,
    pub insertbefore: String,
    pub insertafter: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockInFileState {
    Present,
    Absent,
}

impl BlockInFileState {
    pub fn wire_byte(self) -> u8 {
        match self {
            BlockInFileState::Present => 0,
            BlockInFileState::Absent => 1,
        }
    }
}

/// Hand-written so we can apply Ansible-flavored defaults (marker
/// template, marker_begin/end, append-default insertion) and enforce
/// cross-field constraints (insertbefore/insertafter mutual exclusion).
impl<'de> Deserialize<'de> for BlockInFileOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let path = match map.remove("path") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "blockinfile.path must be a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::custom("blockinfile: missing required field `path`")),
        };

        let block = match map.remove("block") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "blockinfile.block must be a string, got: {other:?}"
                )))
            }
        };

        let marker = take_optional_field_string(&mut map, "marker")?
            .unwrap_or_else(|| "# {mark} ANSIBLE MANAGED BLOCK".to_string());
        let marker_begin = take_optional_field_string(&mut map, "marker_begin")?
            .unwrap_or_else(|| "BEGIN".to_string());
        let marker_end = take_optional_field_string(&mut map, "marker_end")?
            .unwrap_or_else(|| "END".to_string());
        let insertbefore = take_optional_field_string(&mut map, "insertbefore")?.unwrap_or_default();
        let insertafter = take_optional_field_string(&mut map, "insertafter")?.unwrap_or_default();

        let state = match map.remove("state") {
            None => BlockInFileState::Present,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => BlockInFileState::Present,
                "absent" => BlockInFileState::Absent,
                other => {
                    return Err(D::Error::custom(format!(
                        "blockinfile.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "blockinfile.state must be a string, got: {other:?}"
                )))
            }
        };

        let mode = take_optional_mode(&mut map, "mode")?;
        let create = take_optional_ansible_bool(&mut map, "create")?.unwrap_or(false);

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "blockinfile: unknown field(s): {unknown:?}; expected one of \
                 [path, block, marker, marker_begin, marker_end, state, mode, create, insertbefore, insertafter]"
            )));
        }

        if !insertbefore.is_empty() && !insertafter.is_empty() {
            return Err(D::Error::custom(
                "blockinfile: insertbefore and insertafter are mutually exclusive",
            ));
        }
        if !marker.contains("{mark}") {
            return Err(D::Error::custom(
                "blockinfile.marker must contain the literal token `{mark}`",
            ));
        }

        Ok(BlockInFileOp {
            path,
            block,
            marker,
            marker_begin,
            marker_end,
            state,
            mode,
            create,
            insertbefore,
            insertafter,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_blockinfile_minimal() {
        let t = parse_task(
            r#"
name: t
blockinfile:
  path: /etc/foo
  block: |
    alpha
    beta
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::BlockInFile(b)) => {
                assert_eq!(b.path, "/etc/foo");
                assert_eq!(b.block, "alpha\nbeta\n");
                assert_eq!(b.marker, "# {mark} ANSIBLE MANAGED BLOCK");
                assert_eq!(b.marker_begin, "BEGIN");
                assert_eq!(b.marker_end, "END");
                assert_eq!(b.state, BlockInFileState::Present);
            }
            _ => panic!("expected BlockInFile body"),
        }
    }

    #[test]
    fn parses_blockinfile_with_custom_markers_and_create() {
        let t = parse_task(
            r#"
name: t
blockinfile:
  path: /etc/foo.conf
  block: "x"
  marker: "// ---- {mark} app ----"
  marker_begin: TOP
  marker_end: BOT
  create: yes
  mode: '0640'
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::BlockInFile(b)) => {
                assert_eq!(b.marker, "// ---- {mark} app ----");
                assert_eq!(b.marker_begin, "TOP");
                assert_eq!(b.marker_end, "BOT");
                assert!(b.create);
                assert_eq!(b.mode, Some(0o640));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn blockinfile_rejects_marker_without_mark_token() {
        let yaml = r#"
name: t
blockinfile:
  path: /etc/foo
  block: x
  marker: "no token here"
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("{mark}"),
            "got: {err}"
        );
    }

    #[test]
    fn blockinfile_rejects_both_insert_anchors() {
        let yaml = r#"
name: t
blockinfile:
  path: /etc/foo
  block: x
  insertbefore: '^A'
  insertafter: '^B'
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("mutually exclusive"),
            "got: {err}"
        );
    }

    #[test]
    fn blockinfile_to_wire_carries_fields() {
        let t = TaskOp::BlockInFile(BlockInFileOp {
            path: "/etc/foo".into(),
            block: "a\nb\n".into(),
            marker: "# {mark} M".into(),
            marker_begin: "BEGIN".into(),
            marker_end: "END".into(),
            state: BlockInFileState::Present,
            mode: Some(0o600),
            create: true,
            insertbefore: String::new(),
            insertafter: "EOF".into(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpBlockInFile(o) = wire else {
            panic!("expected OpBlockInFile")
        };
        assert_eq!(o.path, "/etc/foo");
        assert_eq!(o.block, "a\nb\n");
        assert_eq!(o.marker, "# {mark} M");
        assert_eq!(o.marker_begin, "BEGIN");
        assert_eq!(o.marker_end, "END");
        assert_eq!(o.state, 0);
        assert_eq!(o.has_mode, 1);
        assert_eq!(o.mode, 0o600);
        assert_eq!(o.create, 1);
        assert_eq!(o.insertafter, "EOF");
    }
}
