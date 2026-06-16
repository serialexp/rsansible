//! `user:` task body. Maps Ansible's `ansible.builtin.user` (subset).
//!
//! Supported fields: `name`, `state` (present/absent), `system`, `shell`,
//! `home`, `create_home`, `group` (primary), `groups` (supplementary),
//! `append`.
//!
//! NOT supported (refused at parse time): `uid`, `comment`, `password`,
//! `password_hash`, `expires`, `move_home`, `ssh_key_*`, `update_password`,
//! `force`, `remove`, `skeleton`, `local`, `non_unique`. These are
//! either security-sensitive (password) or pull in significant
//! complexity for surface no playbook in our world uses yet. Refusing
//! up-front means a fresh playbook fails loudly rather than silently
//! dropping fields.

use super::shared::{take_optional_ansible_bool, take_optional_field_string};

#[derive(Debug, Clone, PartialEq)]
pub struct UserOp {
    pub name: String,
    pub state: UserState,
    pub system: bool,
    /// `None` = use OS default (don't touch). `Some("")` = empty string,
    /// meaningful for "no login shell" use cases via `/usr/sbin/nologin`.
    pub shell: Option<String>,
    pub home: Option<String>,
    /// Ansible defaults this to `true` when state=present. For
    /// state=absent it's ignored by the agent.
    pub create_home: bool,
    /// Primary group name. Empty = OS default (typically a same-name
    /// group, depending on /etc/login.defs).
    pub primary_group: String,
    /// Supplementary groups. Empty list = don't touch group membership.
    pub groups: Vec<String>,
    /// When `groups` is non-empty: `true` adds to existing membership
    /// (usermod -a -G), `false` replaces. Ignored when `groups` is empty.
    pub append: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserState {
    Present,
    Absent,
}

impl UserState {
    pub fn wire_byte(self) -> u8 {
        match self {
            UserState::Present => 0,
            UserState::Absent => 1,
        }
    }
}

pub(super) fn parse_user_body<E: serde::de::Error>(
    mut map: serde_yaml::Mapping,
) -> Result<UserOp, E> {
    let name = take_optional_field_string::<E>(&mut map, "name")?
        .ok_or_else(|| E::custom("user: missing required field `name`"))?;
    if name.trim().is_empty() {
        return Err(E::custom("user.name: empty"));
    }

    let state = match map.remove("state") {
        None => UserState::Present,
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "present" => UserState::Present,
            "absent" => UserState::Absent,
            other => {
                return Err(E::custom(format!(
                    "user.state: expected one of [present, absent], got: {other:?}"
                )))
            }
        },
        Some(other) => {
            return Err(E::custom(format!(
                "user.state must be a string, got: {other:?}"
            )))
        }
    };

    let system = take_optional_ansible_bool::<E>(&mut map, "system")?.unwrap_or(false);
    let shell = take_optional_field_string::<E>(&mut map, "shell")?;
    let home = take_optional_field_string::<E>(&mut map, "home")?;

    // create_home defaults to true for present (Ansible default), ignored
    // for absent. We bake the default in here so the wire byte is
    // unambiguous.
    let create_home =
        take_optional_ansible_bool::<E>(&mut map, "create_home")?.unwrap_or(true);

    let primary_group =
        take_optional_field_string::<E>(&mut map, "group")?.unwrap_or_default();

    let groups = match map.remove("groups") {
        None | Some(serde_yaml::Value::Null) => Vec::new(),
        Some(serde_yaml::Value::String(s)) => {
            // Ansible accepts a comma-separated string.
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
        Some(serde_yaml::Value::Sequence(seq)) => {
            let mut out = Vec::with_capacity(seq.len());
            for v in seq {
                match v {
                    serde_yaml::Value::String(s) => out.push(s),
                    other => {
                        return Err(E::custom(format!(
                            "user.groups: list items must be strings, got: {other:?}"
                        )))
                    }
                }
            }
            out
        }
        Some(other) => {
            return Err(E::custom(format!(
                "user.groups: must be a string or list of strings, got: {other:?}"
            )))
        }
    };

    let append = take_optional_ansible_bool::<E>(&mut map, "append")?.unwrap_or(false);

    for k in [
        "uid",
        "comment",
        "password",
        "password_hash",
        "password_lock",
        "expires",
        "move_home",
        "ssh_key_bits",
        "ssh_key_comment",
        "ssh_key_file",
        "ssh_key_passphrase",
        "ssh_key_type",
        "generate_ssh_key",
        "update_password",
        "force",
        "remove",
        "skeleton",
        "local",
        "non_unique",
    ] {
        if map.remove(k).is_some() {
            return Err(E::custom(format!(
                "user.{k}: not yet implemented (file an issue / PR if you need it)"
            )));
        }
    }

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        return Err(E::custom(format!(
            "user: unknown field(s): {unknown:?}; expected one of \
             [name, state, system, shell, home, create_home, group, groups, append]"
        )));
    }

    Ok(UserOp {
        name,
        state,
        system,
        shell,
        home,
        create_home,
        primary_group,
        groups,
        append,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::parse_task_for_test as parse_task;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_node_exporter_style_system_user() {
        // Pattern lifted from acme roles/node-exporter/tasks/main.yml.
        let t = parse_task(
            r#"
name: t
user:
  name: node_exporter
  system: true
  shell: /usr/sbin/nologin
  create_home: false
  home: /nonexistent
  state: present
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::User(u)) => {
                assert_eq!(u.name, "node_exporter");
                assert!(u.system);
                assert_eq!(u.shell.as_deref(), Some("/usr/sbin/nologin"));
                assert!(!u.create_home);
                assert_eq!(u.home.as_deref(), Some("/nonexistent"));
                assert_eq!(u.state, UserState::Present);
                assert!(u.groups.is_empty());
                assert_eq!(u.primary_group, "");
            }
            _ => panic!("expected User"),
        }
    }

    #[test]
    fn parses_operator_user_with_supplementary_groups() {
        // Pattern lifted from acme roles/common/tasks/users.yml.
        let t = parse_task(
            r#"
name: t
user:
  name: alice
  shell: /bin/bash
  groups: sudo
  append: true
  create_home: true
  state: present
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::User(u)) => {
                assert_eq!(u.groups, vec!["sudo".to_string()]);
                assert!(u.append);
                assert!(u.create_home);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_etcd_style_with_primary_group() {
        // Pattern lifted from acme roles/etcd/tasks/user.yml.
        let t = parse_task(
            r#"
name: t
user:
  name: etcd
  group: etcd
  system: true
  shell: /usr/sbin/nologin
  home: /var/lib/etcd
  create_home: false
  state: present
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::User(u)) => {
                assert_eq!(u.primary_group, "etcd");
                assert!(!u.create_home);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn defaults_create_home_true_for_present() {
        let t = parse_task(
            r#"
name: t
user:
  name: bob
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::User(u)) => {
                assert!(u.create_home, "default create_home=true for present");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn groups_as_csv_string() {
        let t = parse_task(
            r#"
name: t
user:
  name: alice
  groups: "sudo, docker"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::User(u)) => {
                assert_eq!(u.groups, vec!["sudo".to_string(), "docker".to_string()]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_password() {
        let yaml = r#"
name: t
user:
  name: bob
  password: "$6$rounds..."
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("not yet implemented"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_uid() {
        let yaml = r#"
name: t
user:
  name: bob
  uid: 1500
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
user:
  name: bob
  bogus: true
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn to_wire() {
        let t = TaskOp::User(UserOp {
            name: "etcd".into(),
            state: UserState::Present,
            system: true,
            shell: Some("/usr/sbin/nologin".into()),
            home: Some("/var/lib/etcd".into()),
            create_home: false,
            primary_group: "etcd".into(),
            groups: vec!["docker".into()],
            append: true,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpUser(o) = wire else {
            panic!("expected OpUser")
        };
        assert_eq!(o.kind, 22);
        assert_eq!(o.name, "etcd");
        assert_eq!(o.state, 0);
        assert_eq!(o.system, 1);
        assert_eq!(o.has_shell, 1);
        assert_eq!(o.shell, "/usr/sbin/nologin");
        assert_eq!(o.has_home, 1);
        assert_eq!(o.home, "/var/lib/etcd");
        assert_eq!(o.create_home, 0);
        assert_eq!(o.primary_group, "etcd");
        assert_eq!(o.groups, vec!["docker".to_string()]);
        assert_eq!(o.append, 1);
    }

    #[test]
    fn to_wire_unset_shell_and_home() {
        let t = TaskOp::User(UserOp {
            name: "alice".into(),
            state: UserState::Present,
            system: false,
            shell: None,
            home: None,
            create_home: true,
            primary_group: String::new(),
            groups: vec![],
            append: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpUser(o) = wire else {
            panic!()
        };
        assert_eq!(o.has_shell, 0);
        assert_eq!(o.has_home, 0);
        assert_eq!(o.create_home, 1);
    }
}
