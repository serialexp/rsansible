//! `stat:` task body.

use super::shared::deserialize_ansible_bool;
use serde::Deserialize;

/// `stat: { path: /etc/foo, follow: yes }`. `follow` selects stat() vs
/// lstat() — defaults to true (Ansible's default). Currently always
/// computes a sha256 for regular files (agent-side); a `get_checksum:
/// no` knob can be added if the size becomes a problem.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StatOp {
    pub path: String,
    /// Defaults to true (Ansible's default). Accepts `yes`/`no`/`true`/
    /// `false` in YAML — Ansible playbooks commonly spell booleans as
    /// `yes`/`no`, which serde_yaml otherwise refuses.
    #[serde(default = "default_stat_follow", deserialize_with = "deserialize_ansible_bool")]
    pub follow: bool,
}

fn default_stat_follow() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task, try_parse_task_for_test as try_parse_task};
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{TaskBody, TaskOp};

    #[test]
    fn stat_to_wire_carries_path_and_follow() {
        let t = TaskOp::Stat(StatOp {
            path: "/etc/foo".into(),
            follow: true,
        });
        let WireOp::OpStat(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.kind, 4);
        assert_eq!(s.path, "/etc/foo");
        assert_eq!(s.follow, 1);

        let t = TaskOp::Stat(StatOp {
            path: "/etc/foo".into(),
            follow: false,
        });
        let WireOp::OpStat(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.follow, 0);
    }

    #[test]
    fn parses_stat_minimal() {
        let t = parse_task(
            r#"
name: probe
stat:
  path: /etc/hostname
register: probe_stat
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Stat(s)) => {
                assert_eq!(s.path, "/etc/hostname");
                assert!(s.follow, "follow defaults to true (Ansible default)");
            }
            other => panic!("got {other:?}"),
        }
        assert_eq!(t.register.as_deref(), Some("probe_stat"));
    }

    #[test]
    fn parses_stat_with_follow_false() {
        let t = parse_task(
            r#"
name: probe
stat:
  path: /var/log/foo.log
  follow: no
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Stat(s)) => {
                assert_eq!(s.path, "/var/log/foo.log");
                assert!(!s.follow);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn stat_rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
stat:
  path: /x
  bogus: 1
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unknown") || err.contains("bogus"),
            "got: {err}"
        );
    }

    #[test]
    fn stat_rejects_missing_path() {
        let err = try_parse_task(
            r#"
name: t
stat:
  follow: yes
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("path"), "got: {err}");
    }
}
