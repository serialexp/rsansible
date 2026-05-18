//! `group:` task body. Maps Ansible's `ansible.builtin.group` (subset).
//!
//! Supported fields: `name`, `state` (present/absent), `system`.
//!
//! NOT supported: explicit `gid`, `local`, `non_unique`. Refused at parse
//! time with a clear message so a fresh playbook fails loudly rather
//! than silently dropping fields.

use super::shared::{take_optional_ansible_bool, take_optional_field_string};

#[derive(Debug, Clone, PartialEq)]
pub struct GroupOp {
    pub name: String,
    pub state: GroupState,
    pub system: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    Present,
    Absent,
}

impl GroupState {
    pub fn wire_byte(self) -> u8 {
        match self {
            GroupState::Present => 0,
            GroupState::Absent => 1,
        }
    }
}

pub(super) fn parse_group_body<E: serde::de::Error>(
    mut map: serde_yaml::Mapping,
) -> Result<GroupOp, E> {
    let name = take_optional_field_string::<E>(&mut map, "name")?
        .ok_or_else(|| E::custom("group: missing required field `name`"))?;
    if name.trim().is_empty() {
        return Err(E::custom("group.name: empty"));
    }

    let state = match map.remove("state") {
        None => GroupState::Present,
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "present" => GroupState::Present,
            "absent" => GroupState::Absent,
            other => {
                return Err(E::custom(format!(
                    "group.state: expected one of [present, absent], got: {other:?}"
                )))
            }
        },
        Some(other) => {
            return Err(E::custom(format!(
                "group.state must be a string, got: {other:?}"
            )))
        }
    };

    let system = take_optional_ansible_bool::<E>(&mut map, "system")?.unwrap_or(false);

    // Refuse fields we don't yet implement so a playbook that depends on
    // them fails loudly instead of silently losing configuration.
    for k in ["gid", "local", "non_unique"] {
        if map.remove(k).is_some() {
            return Err(E::custom(format!(
                "group.{k}: not yet implemented (file an issue / PR if you need it)"
            )));
        }
    }

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        return Err(E::custom(format!(
            "group: unknown field(s): {unknown:?}; expected one of [name, state, system]"
        )));
    }

    Ok(GroupOp { name, state, system })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::parse_task_for_test as parse_task;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_minimal() {
        let t = parse_task(
            r#"
name: t
group:
  name: etcd
  system: true
  state: present
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Group(g)) => {
                assert_eq!(g.name, "etcd");
                assert!(g.system);
                assert_eq!(g.state, GroupState::Present);
            }
            _ => panic!("expected Group"),
        }
    }

    #[test]
    fn defaults() {
        let t = parse_task(
            r#"
name: t
group:
  name: docker
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Group(g)) => {
                assert_eq!(g.state, GroupState::Present);
                assert!(!g.system);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_missing_name() {
        let yaml = r#"
name: t
group:
  system: true
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field `name`"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_unimplemented_gid() {
        let yaml = r#"
name: t
group:
  name: app
  gid: 1234
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("not yet implemented"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field() {
        let yaml = r#"
name: t
group:
  name: app
  bogus: 1
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn to_wire() {
        let t = TaskOp::Group(GroupOp {
            name: "etcd".into(),
            state: GroupState::Present,
            system: true,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpGroup(o) = wire else {
            panic!("expected OpGroup")
        };
        assert_eq!(o.kind, 23);
        assert_eq!(o.name, "etcd");
        assert_eq!(o.state, 0);
        assert_eq!(o.system, 1);
    }
}
