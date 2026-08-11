//! `modprobe:` task body. Maps Ansible's `community.general.modprobe`
//! (subset).
//!
//! Supported fields: `name` (required, module name), `state`
//! (present/absent, default present), `params` (space-separated module
//! parameters applied at load time).
//!
//! NOT supported: `persistent:` — Ansible uses it to write a
//! `/etc/modules-load.d` entry so the module survives a reboot. We
//! deliberately don't, because it silently owns a file outside the task's
//! stated subject and the two halves drift (the module is loaded now but
//! the persistence file says something else). Write the file explicitly
//! with `copy:`/`template:` instead, which is what the playbooks using
//! this module already do. Rejected at parse time so the omission fails
//! loudly rather than a reboot quietly losing the module.
//!
//! See ANSIBLE_COMPAT.md §13 for the full rationale.

use super::shared::take_optional_field_string;

#[derive(Debug, Clone, PartialEq)]
pub struct ModprobeOp {
    pub name: String,
    pub state: ModprobeState,
    /// Space-separated `key=value` module parameters. Empty means none.
    /// Only meaningful for `state: present`.
    pub params: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModprobeState {
    Present,
    Absent,
}

impl ModprobeState {
    pub fn wire_byte(self) -> u8 {
        match self {
            ModprobeState::Present => 0,
            ModprobeState::Absent => 1,
        }
    }
}

pub(super) fn parse_modprobe_body<E: serde::de::Error>(
    mut map: serde_yaml::Mapping,
) -> Result<ModprobeOp, E> {
    let name = take_optional_field_string::<E>(&mut map, "name")?
        .ok_or_else(|| E::custom("modprobe: missing required field `name`"))?;
    if name.trim().is_empty() {
        return Err(E::custom("modprobe.name: empty"));
    }

    let state = match map.remove("state") {
        None => ModprobeState::Present,
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "present" => ModprobeState::Present,
            "absent" => ModprobeState::Absent,
            other => {
                return Err(E::custom(format!(
                    "modprobe.state: expected one of [present, absent], got: {other:?}"
                )))
            }
        },
        Some(other) => {
            return Err(E::custom(format!(
                "modprobe.state must be a string, got: {other:?}"
            )))
        }
    };

    let params = take_optional_field_string::<E>(&mut map, "params")?.unwrap_or_default();
    if state == ModprobeState::Absent && !params.trim().is_empty() {
        return Err(E::custom(
            "modprobe.params: meaningless with `state: absent` (parameters apply at load time)",
        ));
    }

    if map.remove("persistent").is_some() {
        return Err(E::custom(
            "modprobe.persistent: not supported — write /etc/modules-load.d/<name>.conf \
             with `copy:` or `template:` instead so the persisted set is explicit",
        ));
    }

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| {
                k.as_str()
                    .map(String::from)
                    .unwrap_or_else(|| format!("{k:?}"))
            })
            .collect();
        return Err(E::custom(format!(
            "modprobe: unknown field(s): {unknown:?}; expected one of [name, state, params]"
        )));
    }

    Ok(ModprobeOp {
        name,
        state,
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::parse_task_for_test as parse_task;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_minimal_defaulting_to_present() {
        let t = parse_task(
            r#"
name: t
modprobe:
  name: kvm_amd
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Modprobe(m)) => {
                assert_eq!(m.name, "kvm_amd");
                assert_eq!(m.state, ModprobeState::Present);
                assert_eq!(m.params, "");
            }
            _ => panic!("expected Modprobe"),
        }
    }

    /// The spelling the gothab playbooks actually use.
    #[test]
    fn parses_community_general_fqcn() {
        let t = parse_task(
            r#"
name: t
community.general.modprobe:
  name: loop
  state: present
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Modprobe(m)) => {
                assert_eq!(m.name, "loop");
                assert_eq!(m.state, ModprobeState::Present);
            }
            _ => panic!("expected Modprobe"),
        }
    }

    #[test]
    fn parses_absent_and_params() {
        let t = parse_task("name: t\nmodprobe:\n  name: loop\n  state: absent\n");
        match t.body {
            TaskBody::Op(TaskOp::Modprobe(m)) => assert_eq!(m.state, ModprobeState::Absent),
            _ => panic!("expected Modprobe"),
        }
        let t = parse_task(
            "name: t\nmodprobe:\n  name: nf_conntrack\n  params: nf_conntrack_max=65536\n",
        );
        match t.body {
            TaskBody::Op(TaskOp::Modprobe(m)) => {
                assert_eq!(m.params, "nf_conntrack_max=65536")
            }
            _ => panic!("expected Modprobe"),
        }
    }

    #[test]
    fn rejects_missing_name() {
        let err = serde_yaml::from_str::<Task>("name: t\nmodprobe: {}\n").unwrap_err();
        assert!(
            format!("{err}").contains("missing required field `name`"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_bad_state() {
        let err =
            serde_yaml::from_str::<Task>("name: t\nmodprobe:\n  name: loop\n  state: loaded\n")
                .unwrap_err();
        assert!(
            format!("{err}").contains("expected one of [present, absent]"),
            "got: {err}"
        );
    }

    /// Params on an unload is a silent no-op in Ansible; we'd rather say so.
    #[test]
    fn rejects_params_with_absent() {
        let err = serde_yaml::from_str::<Task>(
            "name: t\nmodprobe:\n  name: loop\n  state: absent\n  params: foo=1\n",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("meaningless with"), "got: {err}");
    }

    /// We don't write modules-load.d — say so instead of dropping it.
    #[test]
    fn rejects_persistent_field() {
        let err = serde_yaml::from_str::<Task>(
            "name: t\nmodprobe:\n  name: loop\n  persistent: present\n",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("not supported"), "got: {err}");
        assert!(format!("{err}").contains("modules-load.d"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let err = serde_yaml::from_str::<Task>("name: t\nmodprobe:\n  name: loop\n  bogus: 1\n")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn to_wire() {
        let t = TaskOp::Modprobe(ModprobeOp {
            name: "kvm_amd".into(),
            state: ModprobeState::Absent,
            params: String::new(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpModprobe(o) = wire else {
            panic!("expected OpModprobe")
        };
        assert_eq!(o.kind, 29);
        assert_eq!(o.name, "kvm_amd");
        assert_eq!(o.state, 1);
        assert_eq!(o.params, "");
    }
}
