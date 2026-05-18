//! `getent:` task body. Maps Ansible's `ansible.builtin.getent` (subset).
//!
//! Supported fields: `database` (required), `key` (required for v1), `fail_key`
//! (default true), `split` (default empty → database-derived).
//!
//! NOT supported: omitted `key` (Ansible permits "fetch the whole database"
//! but our scope hasn't needed it); `service:` (alternate NSS service name).
//! Both refused at parse time.

use super::shared::{take_optional_ansible_bool, take_optional_field_string};

#[derive(Debug, Clone, PartialEq)]
pub struct GetentOp {
    pub database: String,
    pub key: String,
    pub fail_key: bool,
    pub split: String,
}

pub(super) fn parse_getent_body<E: serde::de::Error>(
    mut map: serde_yaml::Mapping,
) -> Result<GetentOp, E> {
    let database = take_optional_field_string::<E>(&mut map, "database")?
        .ok_or_else(|| E::custom("getent: missing required field `database`"))?;
    if database.trim().is_empty() {
        return Err(E::custom("getent.database: empty"));
    }

    let key = take_optional_field_string::<E>(&mut map, "key")?
        .ok_or_else(|| E::custom("getent: missing required field `key` (omitted-key form not supported)"))?;
    if key.trim().is_empty() {
        return Err(E::custom("getent.key: empty"));
    }

    let fail_key = take_optional_ansible_bool::<E>(&mut map, "fail_key")?.unwrap_or(true);
    let split = take_optional_field_string::<E>(&mut map, "split")?.unwrap_or_default();

    for k in ["service"] {
        if map.remove(k).is_some() {
            return Err(E::custom(format!(
                "getent.{k}: not yet implemented (file an issue / PR if you need it)"
            )));
        }
    }

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        return Err(E::custom(format!(
            "getent: unknown field(s): {unknown:?}; expected one of [database, key, fail_key, split]"
        )));
    }

    Ok(GetentOp { database, key, fail_key, split })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::parse_task_for_test as parse_task;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_minimal_gothab_shape() {
        // From gothab postgres-node/user.yml.
        let t = parse_task(
            r#"
name: t
getent:
  database: passwd
  key: postgres
  fail_key: true
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Getent(g)) => {
                assert_eq!(g.database, "passwd");
                assert_eq!(g.key, "postgres");
                assert!(g.fail_key);
                assert_eq!(g.split, "");
            }
            _ => panic!("expected Getent"),
        }
    }

    #[test]
    fn fail_key_defaults_true() {
        let t = parse_task(
            r#"
name: t
getent:
  database: group
  key: docker
"#,
        );
        let TaskBody::Op(TaskOp::Getent(g)) = t.body else { panic!() };
        assert!(g.fail_key);
    }

    #[test]
    fn rejects_missing_database() {
        let yaml = "name: t\ngetent:\n  key: postgres\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("missing required field `database`"), "got: {err}");
    }

    #[test]
    fn rejects_missing_key() {
        let yaml = "name: t\ngetent:\n  database: passwd\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("missing required field `key`"), "got: {err}");
    }

    #[test]
    fn rejects_unimplemented_service() {
        let yaml = "name: t\ngetent:\n  database: passwd\n  key: bob\n  service: foo\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("not yet implemented"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let yaml = "name: t\ngetent:\n  database: passwd\n  key: bob\n  bogus: 1\n";
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn to_wire() {
        let t = TaskOp::Getent(GetentOp {
            database: "passwd".into(),
            key: "postgres".into(),
            fail_key: true,
            split: String::new(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpGetent(o) = wire else {
            panic!("expected OpGetent")
        };
        assert_eq!(o.kind, 25);
        assert_eq!(o.database, "passwd");
        assert_eq!(o.key, "postgres");
        assert_eq!(o.fail_key, 1);
    }
}
