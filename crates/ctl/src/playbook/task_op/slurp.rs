//! `slurp:` task body.

use serde::{de::Error as _, Deserialize, Deserializer};

/// `slurp:` parsed form. The YAML accepts `src:` (the file path on the
/// remote host) and an optional `max_bytes:` safety cap (extension; the
/// vanilla Ansible slurp has no cap and will happily read multi-GB
/// files). Zero means no cap.
#[derive(Debug, Clone, PartialEq)]
pub struct SlurpOp {
    pub src: String,
    pub max_bytes: u32,
}

impl<'de> Deserialize<'de> for SlurpOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let src = match map.remove("src") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "slurp.src: expected a non-empty string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("src")),
        };

        // Optional rsansible extension: `max_bytes:` safety cap. Zero is
        // the sentinel for "no cap" (matches the wire op). Vanilla
        // Ansible slurp has no cap.
        let max_bytes = match map.remove("max_bytes") {
            None | Some(serde_yaml::Value::Null) => 0u32,
            Some(serde_yaml::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| {
                    D::Error::custom(format!(
                        "slurp.max_bytes: expected non-negative integer ≤ u32::MAX, got: {n}"
                    ))
                })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "slurp.max_bytes: expected integer, got: {other:?}"
                )))
            }
        };

        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "slurp: unknown field {k:?}; only src/max_bytes accepted"
            )));
        }

        Ok(SlurpOp { src, max_bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parse_slurp_minimal() {
        let t = parse_task(
            r#"
name: t
slurp:
  src: /etc/ssh/ssh_host_ed25519_key.pub
"#,
        );
        let TaskBody::Op(TaskOp::Slurp(s)) = t.body else { panic!() };
        assert_eq!(s.src, "/etc/ssh/ssh_host_ed25519_key.pub");
        assert_eq!(s.max_bytes, 0);
    }

    #[test]
    fn parse_slurp_with_max_bytes() {
        let t = parse_task(
            r#"
name: t
slurp:
  src: /var/lib/pki/ca.pem
  max_bytes: 65536
"#,
        );
        let TaskBody::Op(TaskOp::Slurp(s)) = t.body else { panic!() };
        assert_eq!(s.max_bytes, 65_536);
    }

    #[test]
    fn parse_slurp_rejects_unknown_field() {
        let yaml = r#"
name: t
slurp:
  src: /etc/x
  bogus: yes
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("bogus"));
    }

    #[test]
    fn parse_slurp_rejects_missing_src() {
        let yaml = r#"
name: t
slurp: {}
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("src"));
    }

    #[test]
    fn slurp_to_wire_op_uses_read_file() {
        let op = TaskOp::Slurp(SlurpOp {
            src: "/etc/etcd/server.key".into(),
            max_bytes: 0,
        });
        let wire = op.to_wire_op().unwrap();
        match wire {
            WireOp::OpReadFile(o) => {
                assert_eq!(o.path, "/etc/etcd/server.key");
                assert_eq!(o.max_bytes, 0);
                assert_eq!(o.kind, 18);
            }
            other => panic!("expected OpReadFile, got {other:?}"),
        }
    }
}
