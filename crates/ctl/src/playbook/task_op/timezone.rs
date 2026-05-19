//! `timezone:` task body. Maps Ansible's `community.general.timezone`
//! (subset).
//!
//! Supported fields: `name` (required, zoneinfo identifier such as
//! `Europe/Amsterdam` or `UTC`).
//!
//! NOT supported: `hwclock:` — we don't touch the RTC. Reject at parse
//! time so a fresh playbook fails loudly rather than silently dropping
//! the hint.

use super::shared::take_optional_field_string;

#[derive(Debug, Clone, PartialEq)]
pub struct TimezoneOp {
    pub name: String,
}

pub(super) fn parse_timezone_body<E: serde::de::Error>(
    mut map: serde_yaml::Mapping,
) -> Result<TimezoneOp, E> {
    let name = take_optional_field_string::<E>(&mut map, "name")?
        .ok_or_else(|| E::custom("timezone: missing required field `name`"))?;
    if name.trim().is_empty() {
        return Err(E::custom("timezone.name: empty"));
    }

    for k in ["hwclock"] {
        if map.remove(k).is_some() {
            return Err(E::custom(format!(
                "timezone.{k}: not yet implemented (rsansible does not touch the RTC)"
            )));
        }
    }

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        return Err(E::custom(format!(
            "timezone: unknown field(s): {unknown:?}; expected one of [name]"
        )));
    }

    Ok(TimezoneOp { name })
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
timezone:
  name: Europe/Amsterdam
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Timezone(z)) => assert_eq!(z.name, "Europe/Amsterdam"),
            _ => panic!("expected Timezone"),
        }
    }

    #[test]
    fn parses_community_general_fqcn() {
        let t = parse_task(
            r#"
name: t
community.general.timezone:
  name: UTC
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Timezone(z)) => assert_eq!(z.name, "UTC"),
            _ => panic!("expected Timezone"),
        }
    }

    #[test]
    fn rejects_missing_name() {
        let yaml = "name: t\ntimezone: {}\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field `name`"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_hwclock_field() {
        let yaml = "name: t\ntimezone:\n  name: UTC\n  hwclock: local\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("not yet implemented"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field() {
        let yaml = "name: t\ntimezone:\n  name: UTC\n  bogus: 1\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn to_wire() {
        let t = TaskOp::Timezone(TimezoneOp {
            name: "Europe/Amsterdam".into(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpTimezone(o) = wire else {
            panic!("expected OpTimezone")
        };
        assert_eq!(o.kind, 27);
        assert_eq!(o.name, "Europe/Amsterdam");
    }
}
