//! `ufw:` task body.

use super::shared::{
    take_optional_ansible_bool, take_optional_field_string, take_optional_port,
};
use serde::{de::Error as _, Deserialize, Deserializer};

/// `ufw:` parsed form. Mirrors `community.general.ufw` (subset). The
/// YAML surface accepts one set of fields per op kind; everything not
/// applicable to a given kind must be unset (validated at parse).
#[derive(Debug, Clone, PartialEq)]
pub struct UfwOp {
    pub op: UfwOpKind,
    /// rule body (allow/deny/limit/reject for op=rule; allow/deny/reject
    /// for op=default; on/off/low/medium/high/full for op=logging).
    pub rule: String,
    pub direction: String,
    pub proto: String,
    pub from_ip: String,
    pub from_port: String,
    pub to_ip: String,
    pub to_port: String,
    pub interface: String,
    pub comment: String,
    pub delete: bool,
    pub insert: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfwOpKind {
    Rule,
    Enable,
    Disable,
    Reset,
    Default,
    Reload,
    Logging,
}

impl UfwOpKind {
    pub fn wire_byte(self) -> u8 {
        match self {
            UfwOpKind::Rule => 0,
            UfwOpKind::Enable => 1,
            UfwOpKind::Disable => 2,
            UfwOpKind::Reset => 3,
            UfwOpKind::Default => 4,
            UfwOpKind::Reload => 5,
            UfwOpKind::Logging => 6,
        }
    }
}

/// Hand-written so we can:
///   - dispatch on `state:` (Ansible's surface) to pick an op kind,
///     since Ansible folds rule/enable/disable/reset/etc. under one
///     module argument set
///   - flatten port/proto/from/to/iface/comment into a single record
///   - default direction to empty (the agent expands defaults)
impl<'de> Deserialize<'de> for UfwOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let state = take_optional_field_string(&mut map, "state")?;
        let rule_field = take_optional_field_string(&mut map, "rule")?;
        let default_field = take_optional_field_string(&mut map, "default")?;
        let logging_field = take_optional_field_string(&mut map, "logging")?;
        let direction = take_optional_field_string(&mut map, "direction")?.unwrap_or_default();
        let proto = take_optional_field_string(&mut map, "proto")?.unwrap_or_default();
        let comment = take_optional_field_string(&mut map, "comment")?.unwrap_or_default();
        let interface = take_optional_field_string(&mut map, "interface")?
            .or(take_optional_field_string(&mut map, "if")?)
            .unwrap_or_default();
        let from_ip = take_optional_field_string(&mut map, "from_ip")?
            .or(take_optional_field_string(&mut map, "src")?)
            .or(take_optional_field_string(&mut map, "from")?)
            .unwrap_or_default();
        let to_ip = take_optional_field_string(&mut map, "to_ip")?
            .or(take_optional_field_string(&mut map, "dest")?)
            .or(take_optional_field_string(&mut map, "to")?)
            .unwrap_or_default();
        // Port fields accept either int (`port: 22`) or string (`port:
        // "22:25"` for ranges). Coerce int → string.
        let from_port = take_optional_port(&mut map, "from_port")?.unwrap_or_default();
        // `port:` is the common Ansible spelling for "destination port".
        let to_port = take_optional_port(&mut map, "to_port")?
            .or(take_optional_port(&mut map, "port")?)
            .unwrap_or_default();
        let delete = take_optional_ansible_bool(&mut map, "delete")?.unwrap_or(false);
        let insert = match map.remove("insert") {
            None | Some(serde_yaml::Value::Null) => 0u32,
            Some(serde_yaml::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                D::Error::custom(format!(
                    "ufw.insert must be a non-negative integer, got: {n}"
                ))
            })? as u32,
            Some(serde_yaml::Value::String(s)) => s.parse::<u32>().map_err(|e| {
                D::Error::custom(format!("ufw.insert: invalid int {s:?}: {e}"))
            })?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "ufw.insert must be a number, got: {other:?}"
                )))
            }
        };

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "ufw: unknown field(s): {unknown:?}; expected one of \
                 [state, rule, default, logging, direction, proto, from, from_ip, src, from_port, to, to_ip, dest, to_port, port, interface, if, comment, delete, insert]"
            )));
        }

        // Determine the op kind. Priority:
        //   * state: enabled/disabled/reloaded/reset → those ops
        //   * default: → default-policy op
        //   * logging: → logging op
        //   * rule + state default → rule op (default state)
        let state_lc = state.as_deref().map(|s| s.to_ascii_lowercase());
        let (op_kind, rule) = match state_lc.as_deref() {
            Some("enabled") => (UfwOpKind::Enable, String::new()),
            Some("disabled") => (UfwOpKind::Disable, String::new()),
            Some("reloaded") => (UfwOpKind::Reload, String::new()),
            Some("reset") => (UfwOpKind::Reset, String::new()),
            _ => {
                if let Some(d) = default_field {
                    (UfwOpKind::Default, d)
                } else if let Some(l) = logging_field {
                    (UfwOpKind::Logging, l)
                } else if let Some(r) = rule_field {
                    (UfwOpKind::Rule, r)
                } else {
                    return Err(D::Error::custom(
                        "ufw: must specify one of [rule, default, logging] or state=enabled/disabled/reloaded/reset",
                    ));
                }
            }
        };

        // Validation per kind.
        match op_kind {
            UfwOpKind::Rule => {
                let r = rule.to_ascii_lowercase();
                if !matches!(r.as_str(), "allow" | "deny" | "limit" | "reject") {
                    return Err(D::Error::custom(format!(
                        "ufw.rule: expected one of [allow, deny, limit, reject], got: {rule:?}"
                    )));
                }
            }
            UfwOpKind::Default => {
                let r = rule.to_ascii_lowercase();
                if !matches!(r.as_str(), "allow" | "deny" | "reject") {
                    return Err(D::Error::custom(format!(
                        "ufw.default: expected one of [allow, deny, reject], got: {rule:?}"
                    )));
                }
            }
            UfwOpKind::Logging => {
                let r = rule.to_ascii_lowercase();
                if !matches!(
                    r.as_str(),
                    "on" | "off" | "low" | "medium" | "high" | "full"
                ) {
                    return Err(D::Error::custom(format!(
                        "ufw.logging: expected one of [on, off, low, medium, high, full], got: {rule:?}"
                    )));
                }
            }
            _ => {}
        }

        if !direction.is_empty() {
            let d = direction.to_ascii_lowercase();
            if !matches!(
                d.as_str(),
                "in" | "out" | "routed" | "incoming" | "outgoing"
            ) {
                return Err(D::Error::custom(format!(
                    "ufw.direction: expected one of [in, out, routed, incoming, outgoing], got: {direction:?}"
                )));
            }
        }
        if !proto.is_empty() {
            let p = proto.to_ascii_lowercase();
            if !matches!(p.as_str(), "any" | "tcp" | "udp" | "esp" | "ah" | "ipv6" | "igmp") {
                return Err(D::Error::custom(format!(
                    "ufw.proto: expected one of [any, tcp, udp, esp, ah, ipv6, igmp], got: {proto:?}"
                )));
            }
        }

        Ok(UfwOp {
            op: op_kind,
            rule,
            direction,
            proto,
            from_ip,
            from_port,
            to_ip,
            to_port,
            interface,
            comment,
            delete,
            insert,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_ufw_allow_port() {
        let t = parse_task(
            r#"
name: t
ufw:
  rule: allow
  port: 22
  proto: tcp
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Rule);
                assert_eq!(u.rule, "allow");
                assert_eq!(u.to_port, "22");
                assert_eq!(u.proto, "tcp");
            }
            _ => panic!("expected Ufw"),
        }
    }

    #[test]
    fn parses_ufw_enable_via_state() {
        let t = parse_task(
            r#"
name: t
ufw:
  state: enabled
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Enable);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_ufw_default_policy() {
        let t = parse_task(
            r#"
name: t
ufw:
  default: deny
  direction: in
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Default);
                assert_eq!(u.rule, "deny");
                assert_eq!(u.direction, "in");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_ufw_logging() {
        let t = parse_task(
            r#"
name: t
ufw:
  logging: full
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Ufw(u)) => {
                assert_eq!(u.op, UfwOpKind::Logging);
                assert_eq!(u.rule, "full");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ufw_rejects_bad_proto() {
        let yaml = r#"
name: t
ufw:
  rule: allow
  port: 22
  proto: sctp
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("ufw.proto"), "got: {err}");
    }

    #[test]
    fn ufw_rejects_bad_rule() {
        let yaml = r#"
name: t
ufw:
  rule: bogus
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("ufw.rule"), "got: {err}");
    }

    #[test]
    fn ufw_requires_some_op_selector() {
        let yaml = r#"
name: t
ufw:
  proto: tcp
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("must specify"),
            "got: {err}"
        );
    }

    #[test]
    fn ufw_to_wire_carries_fields() {
        let t = TaskOp::Ufw(UfwOp {
            op: UfwOpKind::Rule,
            rule: "allow".into(),
            direction: "in".into(),
            proto: "tcp".into(),
            from_ip: String::new(),
            from_port: String::new(),
            to_ip: String::new(),
            to_port: "22".into(),
            interface: String::new(),
            comment: "ssh".into(),
            delete: false,
            insert: 0,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpUfw(o) = wire else {
            panic!("expected OpUfw")
        };
        assert_eq!(o.op, 0);
        assert_eq!(o.rule, "allow");
        assert_eq!(o.direction, "in");
        assert_eq!(o.proto, "tcp");
        assert_eq!(o.to_port, "22");
        assert_eq!(o.comment, "ssh");
    }
}
