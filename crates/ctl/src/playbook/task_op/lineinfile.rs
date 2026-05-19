//! `lineinfile:` task body.

use super::shared::{
    take_optional_ansible_bool, take_optional_field_string, take_optional_mode, ModeField,
};
use serde::{de::Error as _, Deserialize, Deserializer};

/// `lineinfile:` parsed form. Mirrors Ansible's `ansible.builtin.lineinfile`
/// args (subset). `regexp` empty means match by literal equality with
/// `line`. `insertbefore` / `insertafter` are mutually exclusive; the
/// literal `EOF` for `insertafter` means "append".
#[derive(Debug, Clone, PartialEq)]
pub struct LineInFileOp {
    pub path: String,
    pub regexp: String,
    pub line: String,
    pub state: LineInFileState,
    pub mode: Option<ModeField>,
    pub create: bool,
    pub insertbefore: String,
    pub insertafter: String,
    pub backrefs: bool,
    /// Optional validator command (Ansible `validate:`). When set, the
    /// agent runs the command against the staged tmp file before the
    /// rename; non-zero exit aborts the write. `%s` is substituted by
    /// the tmp path. Empty / `None` = no validation. Classic use:
    /// `validate: /usr/sbin/sshd -t -f %s` on /etc/ssh/sshd_config.
    pub validate: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineInFileState {
    Present,
    Absent,
}

impl LineInFileState {
    pub fn wire_byte(self) -> u8 {
        match self {
            LineInFileState::Present => 0,
            LineInFileState::Absent => 1,
        }
    }
}

/// Hand-written so we can:
///   - default `state: present`
///   - default `regexp`/`insertbefore`/`insertafter`/`line` to empty
///   - accept Ansible-style `mode` (octal int or string)
///   - accept Ansible-style booleans for `create` / `backrefs`
///   - enforce insertbefore/insertafter mutual exclusion
///   - enforce backrefs requires regexp
impl<'de> Deserialize<'de> for LineInFileOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let path = match map.remove("path") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "lineinfile.path must be a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::custom("lineinfile: missing required field `path`")),
        };

        let line = match map.remove("line") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            // Accept numeric/bool lines by stringifying — Ansible allows
            // `line: 1234`.
            Some(serde_yaml::Value::Number(n)) => n.to_string(),
            Some(serde_yaml::Value::Bool(b)) => b.to_string(),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "lineinfile.line must be a scalar string, got: {other:?}"
                )))
            }
        };

        let regexp = take_optional_field_string(&mut map, "regexp")?;
        let regexp = regexp.unwrap_or_default();
        let insertbefore = take_optional_field_string(&mut map, "insertbefore")?.unwrap_or_default();
        let insertafter = take_optional_field_string(&mut map, "insertafter")?.unwrap_or_default();

        let state = match map.remove("state") {
            None => LineInFileState::Present,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" => LineInFileState::Present,
                "absent" => LineInFileState::Absent,
                other => {
                    return Err(D::Error::custom(format!(
                        "lineinfile.state: expected one of [present, absent], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "lineinfile.state must be a string, got: {other:?}"
                )))
            }
        };

        let mode = take_optional_mode(&mut map, "mode")?;
        let create = take_optional_ansible_bool(&mut map, "create")?.unwrap_or(false);
        let backrefs = take_optional_ansible_bool(&mut map, "backrefs")?.unwrap_or(false);
        let validate = take_optional_field_string(&mut map, "validate")?;

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "lineinfile: unknown field(s): {unknown:?}; expected one of \
                 [path, line, regexp, state, mode, create, insertbefore, insertafter, backrefs, validate]"
            )));
        }

        if !insertbefore.is_empty() && !insertafter.is_empty() {
            return Err(D::Error::custom(
                "lineinfile: insertbefore and insertafter are mutually exclusive",
            ));
        }
        if backrefs && regexp.is_empty() {
            return Err(D::Error::custom(
                "lineinfile: backrefs requires regexp to be set",
            ));
        }
        if matches!(state, LineInFileState::Present) && line.is_empty() && !backrefs {
            return Err(D::Error::custom(
                "lineinfile: state=present requires a non-empty `line` (unless using backrefs)",
            ));
        }

        Ok(LineInFileOp {
            path,
            regexp,
            line,
            state,
            mode,
            create,
            insertbefore,
            insertafter,
            backrefs,
            validate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_lineinfile_minimal() {
        let t = parse_task(
            r#"
name: t
lineinfile:
  path: /etc/foo
  line: bar=1
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::LineInFile(l)) => {
                assert_eq!(l.path, "/etc/foo");
                assert_eq!(l.line, "bar=1");
                assert_eq!(l.state, LineInFileState::Present);
                assert_eq!(l.regexp, "");
                assert!(!l.create);
                assert!(!l.backrefs);
            }
            _ => panic!("expected LineInFile body"),
        }
    }

    #[test]
    fn parses_lineinfile_with_regexp_and_create() {
        let t = parse_task(
            r#"
name: t
lineinfile:
  path: /etc/foo
  regexp: '^foo='
  line: foo=42
  state: present
  create: yes
  mode: '0644'
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::LineInFile(l)) => {
                assert_eq!(l.regexp, "^foo=");
                assert!(l.create);
                assert_eq!(l.mode, Some(crate::playbook::ModeField::Literal(0o644)));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_lineinfile_absent_state() {
        let t = parse_task(
            r#"
name: t
lineinfile:
  path: /etc/foo
  line: gone
  state: absent
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::LineInFile(l)) => {
                assert_eq!(l.state, LineInFileState::Absent);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn lineinfile_rejects_present_with_empty_line_no_backrefs() {
        let yaml = r#"
name: t
lineinfile:
  path: /etc/foo
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("non-empty `line`"),
            "got: {err}"
        );
    }

    #[test]
    fn lineinfile_rejects_both_insert_anchors() {
        let yaml = r#"
name: t
lineinfile:
  path: /etc/foo
  line: x
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
    fn lineinfile_backrefs_requires_regexp() {
        let yaml = r#"
name: t
lineinfile:
  path: /etc/foo
  line: $1=new
  backrefs: yes
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("backrefs requires"),
            "got: {err}"
        );
    }

    #[test]
    fn lineinfile_to_wire_carries_fields() {
        let t = TaskOp::LineInFile(LineInFileOp {
            path: "/etc/foo".into(),
            regexp: "^foo=".into(),
            line: "foo=42".into(),
            state: LineInFileState::Present,
            mode: Some(crate::playbook::ModeField::Literal(0o644)),
            create: true,
            insertbefore: String::new(),
            insertafter: "EOF".into(),
            backrefs: false,
            validate: None,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpLineInFile(o) = wire else {
            panic!("expected OpLineInFile")
        };
        assert_eq!(o.path, "/etc/foo");
        assert_eq!(o.regexp, "^foo=");
        assert_eq!(o.line, "foo=42");
        assert_eq!(o.state, 0);
        assert_eq!(o.has_mode, 1);
        assert_eq!(o.mode, 0o644);
        assert_eq!(o.create, 1);
        assert_eq!(o.insertafter, "EOF");
        assert_eq!(o.backrefs, 0);
        assert_eq!(o.validate, "");
    }

    /// Regression: validate: must be accepted and threaded through to
    /// the wire op. Classic use: `validate: sshd -t -f %s` on sshd_config.
    #[test]
    fn parses_lineinfile_with_validate() {
        let t = parse_task(
            r#"
name: t
lineinfile:
  path: /etc/ssh/sshd_config
  regexp: '^PasswordAuthentication '
  line: PasswordAuthentication no
  validate: /usr/sbin/sshd -t -f %s
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::LineInFile(l)) => {
                assert_eq!(l.validate.as_deref(), Some("/usr/sbin/sshd -t -f %s"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn lineinfile_to_wire_carries_validate() {
        let t = TaskOp::LineInFile(LineInFileOp {
            path: "/etc/ssh/sshd_config".into(),
            regexp: "^PasswordAuthentication ".into(),
            line: "PasswordAuthentication no".into(),
            state: LineInFileState::Present,
            mode: None,
            create: false,
            insertbefore: String::new(),
            insertafter: String::new(),
            backrefs: false,
            validate: Some("/usr/sbin/sshd -t -f %s".into()),
        });
        let rsansible_wire::generated::Op::OpLineInFile(o) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(o.validate, "/usr/sbin/sshd -t -f %s");
    }
}
