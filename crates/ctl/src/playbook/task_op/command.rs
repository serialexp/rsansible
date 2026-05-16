//! `command:` task body.

use serde::{de::Error as _, Deserialize, Deserializer};

/// `command:` parsed form. Maps Ansible's `ansible.builtin.command`.
/// Accepts the string-shorthand (`command: foo --bar`), the dictionary
/// form with `cmd:` (`command: { cmd: "foo --bar" }`), and the
/// argv-list form (`command: { argv: [foo, "--bar"] }`).
///
/// Wire-side this is the same wire op as `exec:` (OpExec); the
/// orchestrator handles `creates:` / `removes:` idempotency via an
/// OpStat probe before dispatch.
///
/// `executable:` is parsed and rejected at parse time — Ansible's
/// `command` module ignores it (it doesn't go through a shell). Use
/// `shell:` if you need to choose the interpreter.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandOp {
    /// Argv after shlex-splitting (when the string form is used) or
    /// taken verbatim from the YAML list form. Always non-empty after
    /// successful parse.
    pub argv: Vec<String>,
    /// Working directory on the agent. Empty = "use the agent's cwd".
    pub chdir: String,
    /// Idempotency: if this path exists on the agent at task time,
    /// the command is not run and the task reports `changed=false`.
    /// Empty = no check.
    pub creates: String,
    /// Idempotency: if this path does NOT exist on the agent at task
    /// time, the command is not run and the task reports
    /// `changed=false`. Empty = no check.
    pub removes: String,
    /// stdin payload (UTF-8 only at this layer; binary stdin would
    /// land alongside the same gap on ExecOp).
    pub stdin: String,
    pub timeout_ms: u32,
}

impl<'de> Deserialize<'de> for CommandOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_yaml::Value::deserialize(d)?;
        // String shorthand: `command: ssh-keygen -t ed25519 -f ...`
        if let serde_yaml::Value::String(s) = &v {
            let argv = shlex_split_or_err::<D::Error>(s)?;
            if argv.is_empty() {
                return Err(D::Error::custom(
                    "command: empty command string after shlex-split",
                ));
            }
            return Ok(CommandOp {
                argv,
                chdir: String::new(),
                creates: String::new(),
                removes: String::new(),
                stdin: String::new(),
                timeout_ms: 0,
            });
        }
        let mut map = match v {
            serde_yaml::Value::Mapping(m) => m,
            other => {
                return Err(D::Error::custom(format!(
                    "command: expected a mapping (or string shorthand), got: {other:?}"
                )))
            }
        };

        let cmd = match map.remove("cmd") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "command.cmd: expected a non-empty string, got: {other:?}"
                )))
            }
        };
        let argv_list = match map.remove("argv") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::Sequence(seq)) => Some(
                seq.into_iter()
                    .map(|v| match v {
                        serde_yaml::Value::String(s) => Ok(s),
                        other => Err(D::Error::custom(format!(
                            "command.argv: each item must be a string, got: {other:?}"
                        ))),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "command.argv: expected list of strings, got: {other:?}"
                )))
            }
        };
        let argv = match (cmd, argv_list) {
            (Some(_), Some(_)) => {
                return Err(D::Error::custom(
                    "command: cmd and argv are mutually exclusive",
                ))
            }
            (Some(s), None) => {
                let v = shlex_split_or_err::<D::Error>(&s)?;
                if v.is_empty() {
                    return Err(D::Error::custom(
                        "command.cmd: empty after shlex-split",
                    ));
                }
                v
            }
            (None, Some(v)) => {
                if v.is_empty() {
                    return Err(D::Error::custom("command.argv: must be non-empty"));
                }
                v
            }
            (None, None) => {
                return Err(D::Error::custom(
                    "command: missing both cmd and argv — at least one is required",
                ))
            }
        };

        let chdir = match map.remove("chdir") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "command.chdir: expected a string, got: {other:?}"
                )))
            }
        };
        let creates = match map.remove("creates") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "command.creates: expected a string, got: {other:?}"
                )))
            }
        };
        let removes = match map.remove("removes") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "command.removes: expected a string, got: {other:?}"
                )))
            }
        };
        let stdin = match map.remove("stdin") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "command.stdin: expected a string, got: {other:?}"
                )))
            }
        };
        let timeout_ms = match map.remove("timeout") {
            None | Some(serde_yaml::Value::Null) => 0u32,
            Some(serde_yaml::Value::Number(n)) => {
                // Ansible accepts an integer number of seconds; convert.
                let secs = n.as_u64().ok_or_else(|| {
                    D::Error::custom(format!("command.timeout: must be a non-negative integer, got: {n}"))
                })?;
                u32::try_from(secs.saturating_mul(1_000)).map_err(|_| {
                    D::Error::custom("command.timeout: value too large (overflowed u32 ms)")
                })?
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "command.timeout: expected a number of seconds, got: {other:?}"
                )))
            }
        };
        // Reject `executable:` explicitly — Ansible silently ignores it
        // for `command:`; we'd rather be loud so users get pointed at
        // `shell:` if they actually need a different interpreter.
        // See `ANSIBLE_COMPAT.md` §2.
        if map.contains_key("executable") {
            return Err(D::Error::custom(
                "command.executable: not supported — use `shell:` to pick a different interpreter",
            ));
        }
        // `warn:`, `strip_empty_ends:` — Ansible flags we don't honor.
        // Accept and discard so vendored playbooks parse cleanly.
        let _ = map.remove("warn");
        let _ = map.remove("strip_empty_ends");
        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "command: unknown field {k:?}"
            )));
        }

        Ok(CommandOp {
            argv,
            chdir,
            creates,
            removes,
            stdin,
            timeout_ms,
        })
    }
}

/// shlex-split a string and surface parse errors as the deserializer
/// error type.
fn shlex_split_or_err<E: serde::de::Error>(s: &str) -> Result<Vec<String>, E> {
    shlex::split(s).ok_or_else(|| {
        E::custom(format!("command: shlex parse failed on {s:?} (unterminated quote?)"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn command_string_shorthand_parses_via_task() {
        let yaml = r#"
- name: t
  command: /usr/bin/echo hello "quoted arg"
"#;
        let tasks: Vec<Task> = serde_yaml::from_str(yaml).unwrap();
        let body = &tasks[0].body;
        let TaskBody::Op(TaskOp::Command(c)) = body else {
            panic!("expected Command, got {body:?}");
        };
        assert_eq!(
            c.argv,
            vec!["/usr/bin/echo", "hello", "quoted arg"]
        );
    }

    #[test]
    fn command_dict_cmd_parses() {
        let yaml = r#"
- name: t
  command:
    cmd: "/usr/bin/echo hi"
    chdir: /tmp
    timeout: 5
"#;
        let tasks: Vec<Task> = serde_yaml::from_str(yaml).unwrap();
        let TaskBody::Op(TaskOp::Command(c)) = &tasks[0].body else {
            panic!()
        };
        assert_eq!(c.argv, vec!["/usr/bin/echo", "hi"]);
        assert_eq!(c.chdir, "/tmp");
        assert_eq!(c.timeout_ms, 5_000);
    }

    #[test]
    fn command_argv_list_parses_verbatim() {
        let yaml = r#"
- name: t
  command:
    argv: ["/bin/sh", "-c", "echo 'spaces stay'"]
"#;
        let tasks: Vec<Task> = serde_yaml::from_str(yaml).unwrap();
        let TaskBody::Op(TaskOp::Command(c)) = &tasks[0].body else {
            panic!()
        };
        assert_eq!(c.argv, vec!["/bin/sh", "-c", "echo 'spaces stay'"]);
    }

    #[test]
    fn command_cmd_and_argv_mutually_exclusive() {
        let yaml = r#"
- name: t
  command:
    cmd: "/usr/bin/echo"
    argv: ["/bin/echo"]
"#;
        let err = serde_yaml::from_str::<Vec<Task>>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn command_executable_rejected() {
        let yaml = r#"
- name: t
  command:
    cmd: "/usr/bin/echo hi"
    executable: /bin/sh
"#;
        let err = serde_yaml::from_str::<Vec<Task>>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("executable"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn command_accepts_warn_and_strip_empty_ends() {
        // Both fields are silently discarded — vendored playbooks parse cleanly.
        let yaml = r#"
- name: t
  command:
    cmd: "/usr/bin/echo hi"
    warn: false
    strip_empty_ends: true
"#;
        let tasks: Vec<Task> = serde_yaml::from_str(yaml).unwrap();
        let TaskBody::Op(TaskOp::Command(c)) = &tasks[0].body else {
            panic!()
        };
        assert_eq!(c.argv, vec!["/usr/bin/echo", "hi"]);
    }

    #[test]
    fn command_unterminated_quote_errors() {
        let yaml = r#"
- name: t
  command: /usr/bin/echo "oops
"#;
        let err = serde_yaml::from_str::<Vec<Task>>(yaml).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("shlex"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn command_to_wire_maps_to_op_exec() {
        let t = TaskOp::Command(CommandOp {
            argv: vec!["/bin/echo".into(), "hi".into()],
            chdir: "/tmp".into(),
            creates: String::new(),
            removes: String::new(),
            stdin: String::new(),
            timeout_ms: 1234,
        });
        let WireOp::OpExec(e) = t.to_wire_op().unwrap() else {
            panic!("expected OpExec")
        };
        assert_eq!(e.argv, vec!["/bin/echo", "hi"]);
        assert_eq!(e.cwd, "/tmp");
        assert_eq!(e.timeout_ms, 1234);
        assert!(e.env_keys.is_empty());
        assert!(e.env_values.is_empty());
    }

    #[test]
    fn command_with_creates_rejected_at_to_wire() {
        let t = TaskOp::Command(CommandOp {
            argv: vec!["/bin/echo".into()],
            chdir: String::new(),
            creates: "/tmp/marker".into(),
            removes: String::new(),
            stdin: String::new(),
            timeout_ms: 0,
        });
        let err = t.to_wire_op().unwrap_err().to_string();
        assert!(err.contains("composite probe"), "got: {err}");
    }
}
