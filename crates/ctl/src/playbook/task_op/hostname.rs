//! `hostname:` task body. Maps Ansible's `ansible.builtin.hostname` (subset).
//!
//! Supported fields: `name` (required).
//!
//! NOT supported: `use:` (we always auto-detect hostnamectl vs file). Refused
//! at parse time so a fresh playbook fails loudly rather than silently
//! dropping the strategy hint.

use super::shared::take_optional_field_string;

#[derive(Debug, Clone, PartialEq)]
pub struct HostnameOp {
    pub name: String,
}

pub(super) fn parse_hostname_body<E: serde::de::Error>(
    mut map: serde_yaml::Mapping,
) -> Result<HostnameOp, E> {
    let name = take_optional_field_string::<E>(&mut map, "name")?
        .ok_or_else(|| E::custom("hostname: missing required field `name`"))?;
    if name.trim().is_empty() {
        return Err(E::custom("hostname.name: empty"));
    }

    for k in ["use"] {
        if map.remove(k).is_some() {
            return Err(E::custom(format!(
                "hostname.{k}: not yet implemented (we always auto-detect hostnamectl vs /etc/hostname)"
            )));
        }
    }

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        return Err(E::custom(format!(
            "hostname: unknown field(s): {unknown:?}; expected one of [name]"
        )));
    }

    Ok(HostnameOp { name })
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
hostname:
  name: pg1
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Hostname(h)) => assert_eq!(h.name, "pg1"),
            _ => panic!("expected Hostname"),
        }
    }

    #[test]
    fn rejects_missing_name() {
        let yaml = "name: t\nhostname: {}\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("missing required field `name`"), "got: {err}");
    }

    #[test]
    fn rejects_use_field() {
        let yaml = "name: t\nhostname:\n  name: pg1\n  use: systemd\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("not yet implemented"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let yaml = "name: t\nhostname:\n  name: pg1\n  bogus: 1\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn to_wire() {
        let t = TaskOp::Hostname(HostnameOp { name: "pg1".into() });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpHostname(o) = wire else {
            panic!("expected OpHostname")
        };
        assert_eq!(o.kind, 26);
        assert_eq!(o.name, "pg1");
    }
}
