//! `authorized_key:` task body. Maps Ansible's `ansible.posix.authorized_key`
//! (subset).
//!
//! Supported fields: `user`, `key`, `state` (present/absent), `exclusive`.
//!
//! NOT supported (refused at parse time): `path`, `manage_dir`,
//! `key_options`, `comment`, `validate_certs`, `follow`. The default
//! path (`~user/.ssh/authorized_keys`) covers every gothab use case,
//! and the rest are rarely needed. Adding `key_options` if a real
//! playbook wants it is straightforward — the wire format already
//! preserves the full key line, so it's a parse-side change.

use super::shared::{take_optional_ansible_bool, take_optional_field_string};

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedKeyOp {
    pub user: String,
    /// Full SSH pubkey line, e.g. "ssh-ed25519 AAAA... comment".
    pub key: String,
    pub state: AuthorizedKeyState,
    /// `true` → rotate the file so it contains exactly `{key}` for this
    /// user. `false` → add or remove only this one entry, leaving others
    /// intact. Ansible's default is `false`.
    pub exclusive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedKeyState {
    Present,
    Absent,
}

impl AuthorizedKeyState {
    pub fn wire_byte(self) -> u8 {
        match self {
            AuthorizedKeyState::Present => 0,
            AuthorizedKeyState::Absent => 1,
        }
    }
}

pub(super) fn parse_authorized_key_body<E: serde::de::Error>(
    mut map: serde_yaml::Mapping,
) -> Result<AuthorizedKeyOp, E> {
    let user = take_optional_field_string::<E>(&mut map, "user")?
        .ok_or_else(|| E::custom("authorized_key: missing required field `user`"))?;
    if user.trim().is_empty() {
        return Err(E::custom("authorized_key.user: empty"));
    }

    let key = take_optional_field_string::<E>(&mut map, "key")?
        .ok_or_else(|| E::custom("authorized_key: missing required field `key`"))?;
    if key.trim().is_empty() {
        return Err(E::custom("authorized_key.key: empty"));
    }

    let state = match map.remove("state") {
        None => AuthorizedKeyState::Present,
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "present" => AuthorizedKeyState::Present,
            "absent" => AuthorizedKeyState::Absent,
            other => {
                return Err(E::custom(format!(
                    "authorized_key.state: expected one of [present, absent], got: {other:?}"
                )))
            }
        },
        Some(other) => {
            return Err(E::custom(format!(
                "authorized_key.state must be a string, got: {other:?}"
            )))
        }
    };

    let exclusive =
        take_optional_ansible_bool::<E>(&mut map, "exclusive")?.unwrap_or(false);

    for k in [
        "path",
        "manage_dir",
        "key_options",
        "comment",
        "validate_certs",
        "follow",
    ] {
        if map.remove(k).is_some() {
            return Err(E::custom(format!(
                "authorized_key.{k}: not yet implemented (file an issue / PR if you need it)"
            )));
        }
    }

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        return Err(E::custom(format!(
            "authorized_key: unknown field(s): {unknown:?}; expected one of \
             [user, key, state, exclusive]"
        )));
    }

    Ok(AuthorizedKeyOp {
        user,
        key,
        state,
        exclusive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::parse_task_for_test as parse_task;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_operator_key_present() {
        // Pattern from gothab roles/common/tasks/users.yml.
        let t = parse_task(
            r#"
name: t
authorized_key:
  user: alice
  key: "ssh-ed25519 AAAAC3... alice@laptop"
  state: present
  exclusive: false
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::AuthorizedKey(a)) => {
                assert_eq!(a.user, "alice");
                assert_eq!(a.key, "ssh-ed25519 AAAAC3... alice@laptop");
                assert_eq!(a.state, AuthorizedKeyState::Present);
                assert!(!a.exclusive);
            }
            _ => panic!("expected AuthorizedKey"),
        }
    }

    #[test]
    fn defaults() {
        let t = parse_task(
            r#"
name: t
authorized_key:
  user: postgres
  key: "ssh-rsa AAAA... postgres@peer"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::AuthorizedKey(a)) => {
                assert_eq!(a.state, AuthorizedKeyState::Present);
                assert!(!a.exclusive, "default exclusive=false matches Ansible");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_missing_user() {
        let yaml = r#"
name: t
authorized_key:
  key: "ssh-ed25519 AAAA..."
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field `user`"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_missing_key() {
        let yaml = r#"
name: t
authorized_key:
  user: alice
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field `key`"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_path_field() {
        let yaml = r#"
name: t
authorized_key:
  user: alice
  key: "ssh-ed25519 AAAA..."
  path: /custom/keys
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("not yet implemented"),
            "got: {err}"
        );
    }

    #[test]
    fn to_wire() {
        let t = TaskOp::AuthorizedKey(AuthorizedKeyOp {
            user: "postgres".into(),
            key: "ssh-rsa AAAA... postgres@peer".into(),
            state: AuthorizedKeyState::Present,
            exclusive: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpAuthorizedKey(o) = wire else {
            panic!("expected OpAuthorizedKey")
        };
        assert_eq!(o.kind, 24);
        assert_eq!(o.user, "postgres");
        assert_eq!(o.key, "ssh-rsa AAAA... postgres@peer");
        assert_eq!(o.state, 0);
        assert_eq!(o.exclusive, 0);
    }
}
