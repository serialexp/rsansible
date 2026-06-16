//! `systemd:` / `service:` task body.

use super::shared::take_optional_ansible_bool;
use serde::{de::Error as _, Deserialize, Deserializer};

/// `systemd:` parsed form. Mirrors Ansible's `ansible.builtin.systemd_service`
/// (subset). Either `state` or `enabled` or `masked` (or `daemon_reload`)
/// must be specified — a task with none of those is a no-op and rejected
/// at validate.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemdOp {
    pub name: String,
    pub state: SystemdState,
    pub enabled: Option<bool>,
    pub masked: Option<bool>,
    pub daemon_reload: bool,
    pub no_block: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdState {
    /// No run-state change — `enabled`/`masked` only.
    None,
    Started,
    Stopped,
    Restarted,
    Reloaded,
}

impl SystemdState {
    pub fn wire_byte(self) -> u8 {
        match self {
            SystemdState::None => 0,
            SystemdState::Started => 1,
            SystemdState::Stopped => 2,
            SystemdState::Restarted => 3,
            SystemdState::Reloaded => 4,
        }
    }
}

/// Hand-written so we can accept Ansible-flavored booleans (yes/no) for
/// enabled/masked/daemon_reload/no_block, map Ansible state strings
/// (started/stopped/restarted/reloaded) to the byte enum, default
/// state to `None`, and validate that at least one knob is being
/// asked for.
impl<'de> Deserialize<'de> for SystemdOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        // `name` is required for state/enabled/masked operations, but
        // optional for a `daemon_reload`-only task (Ansible accepts it
        // without a unit). We defer the required-when check until
        // after we've parsed `daemon_reload` and friends below.
        let name = match map.remove("name") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "systemd.name must be a string, got: {other:?}"
                )))
            }
            None => String::new(),
        };

        let state = match map.remove("state") {
            None => SystemdState::None,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "started" => SystemdState::Started,
                "stopped" => SystemdState::Stopped,
                "restarted" => SystemdState::Restarted,
                "reloaded" => SystemdState::Reloaded,
                other => {
                    return Err(D::Error::custom(format!(
                        "systemd.state: expected one of [started, stopped, restarted, reloaded], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "systemd.state must be a string, got: {other:?}"
                )))
            }
        };

        let enabled = take_optional_ansible_bool(&mut map, "enabled")?;
        let masked = take_optional_ansible_bool(&mut map, "masked")?;
        let daemon_reload = take_optional_ansible_bool(&mut map, "daemon_reload")?.unwrap_or(false);
        let no_block = take_optional_ansible_bool(&mut map, "no_block")?.unwrap_or(false);
        // Ansible's `scope:` accepts user/system; we silently drop
        // user-scope as out of charter for now (acme doesn't use it).
        // Reject explicitly so the user knows.
        if let Some(scope) = map.remove("scope") {
            if let serde_yaml::Value::String(s) = &scope {
                if s != "system" {
                    return Err(D::Error::custom(format!(
                        "systemd.scope: only `system` is supported, got: {s:?}"
                    )));
                }
            }
        }

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "systemd: unknown field(s): {unknown:?}; expected one of \
                 [name, state, enabled, masked, daemon_reload, no_block, scope]"
            )));
        }

        if matches!(state, SystemdState::None)
            && enabled.is_none()
            && masked.is_none()
            && !daemon_reload
        {
            return Err(D::Error::custom(
                "systemd: must specify at least one of [state, enabled, masked, daemon_reload]",
            ));
        }

        // `name:` is required for anything that operates on a unit.
        // `daemon_reload: true` alone (with no state/enabled/masked) is
        // unit-agnostic, so we let that case through with an empty name
        // — the agent's apply() will skip unit-targeted blocks
        // automatically.
        let needs_unit = !matches!(state, SystemdState::None)
            || enabled.is_some()
            || masked.is_some();
        if needs_unit && name.is_empty() {
            return Err(D::Error::custom(
                "systemd: `name` is required when state/enabled/masked is set",
            ));
        }

        Ok(SystemdOp {
            name,
            state,
            enabled,
            masked,
            daemon_reload,
            no_block,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_systemd_started_with_enabled() {
        let t = parse_task(
            r#"
name: t
systemd:
  name: nginx
  state: started
  enabled: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Systemd(s)) => {
                assert_eq!(s.name, "nginx");
                assert_eq!(s.state, SystemdState::Started);
                assert_eq!(s.enabled, Some(true));
                assert!(s.masked.is_none());
                assert!(!s.daemon_reload);
            }
            _ => panic!("expected Systemd"),
        }
    }

    #[test]
    fn parses_systemd_via_service_alias() {
        let t = parse_task(
            r#"
name: t
service:
  name: sshd
  state: reloaded
"#,
        );
        assert!(matches!(t.body, TaskBody::Op(TaskOp::Systemd(_))));
    }

    #[test]
    fn parses_systemd_daemon_reload_only() {
        let t = parse_task(
            r#"
name: t
systemd:
  name: ignored
  daemon_reload: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Systemd(s)) => {
                assert_eq!(s.state, SystemdState::None);
                assert!(s.daemon_reload);
            }
            _ => panic!(),
        }
    }

    /// `daemon_reload: true` alone (no unit) is Ansible-idiomatic for
    /// "reload after a unit-file change in a handler." We accept it
    /// with an empty `name:` — the agent treats name as optional in
    /// the daemon-reload-only path.
    #[test]
    fn parses_systemd_daemon_reload_only_without_name() {
        let t = parse_task(
            r#"
name: t
systemd:
  daemon_reload: true
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Systemd(s)) => {
                assert_eq!(s.name, "");
                assert!(s.daemon_reload);
                assert_eq!(s.state, SystemdState::None);
            }
            _ => panic!(),
        }
    }

    /// State/enabled/masked still requires `name:`.
    #[test]
    fn systemd_rejects_state_without_name() {
        let yaml = r#"
name: t
systemd:
  state: restarted
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("`name` is required"),
            "got: {msg}"
        );
    }

    #[test]
    fn systemd_rejects_nothing_to_do() {
        let yaml = r#"
name: t
systemd:
  name: x
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("must specify"),
            "got: {err}"
        );
    }

    #[test]
    fn systemd_rejects_user_scope() {
        let yaml = r#"
name: t
systemd:
  name: x
  state: started
  scope: user
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("only `system`"),
            "got: {err}"
        );
    }

    #[test]
    fn systemd_to_wire_carries_state_and_flags() {
        let t = TaskOp::Systemd(SystemdOp {
            name: "nginx.service".into(),
            state: SystemdState::Started,
            enabled: Some(true),
            masked: None,
            daemon_reload: true,
            no_block: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpSystemd(o) = wire else {
            panic!("expected OpSystemd")
        };
        assert_eq!(o.name, "nginx.service");
        assert_eq!(o.state, 1);
        assert_eq!(o.has_enabled, 1);
        assert_eq!(o.enabled, 1);
        assert_eq!(o.has_masked, 0);
        assert_eq!(o.daemon_reload, 1);
        assert_eq!(o.no_block, 0);
    }
}
