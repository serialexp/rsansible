//! `wait_for:` task body.

use super::shared::take_seconds_ms;
use serde::{de::Error as _, Deserialize, Deserializer};

/// `wait_for:` parsed form. Either (host + port) OR path must be set;
/// validated at parse + validate time. Timing fields are in
/// **seconds** in YAML (Ansible's spec) but stored as millis here.
#[derive(Debug, Clone, PartialEq)]
pub struct WaitForOp {
    pub host: Option<String>,
    pub port: Option<u32>,
    pub path: Option<String>,
    pub state: WaitForState,
    pub timeout_ms: u32,
    pub delay_ms: u32,
    pub sleep_ms: u32,
    /// (deferred) The original `port:` string when it contained Jinja
    /// and couldn't be parsed at load time. Empty otherwise. Rendered
    /// at dispatch and parsed into a fresh u32 that overrides `port`.
    pub port_template: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitForState {
    Present,
    Absent,
}

impl WaitForState {
    pub fn wire_byte(self) -> u8 {
        match self {
            WaitForState::Present => 0,
            WaitForState::Absent => 1,
        }
    }
}

/// Hand-written deserializer so we can:
///   - reject host+port mixed with path
///   - accept Ansible's aliases for `state` (`started`/`present` →
///     Present; `stopped`/`absent` → Absent)
///   - parse seconds (int or string) → millis for the wire
///   - default timeout=300s, sleep=1s, delay=0s
impl<'de> Deserialize<'de> for WaitForOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let host = match map.remove("host") {
            None => None,
            Some(serde_yaml::Value::String(s)) => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.host must be a string, got: {other:?}"
                )))
            }
        };
        let (port, port_template) = match map.remove("port") {
            None => (None, String::new()),
            Some(serde_yaml::Value::Number(n)) => (
                Some(n.as_u64().ok_or_else(|| {
                    D::Error::custom(format!("wait_for.port must be a non-negative int, got: {n}"))
                })? as u32),
                String::new(),
            ),
            Some(serde_yaml::Value::String(s)) => {
                if super::shared::string_is_jinja(&s) {
                    // Defer parsing — render arm validates at dispatch.
                    (None, s)
                } else {
                    (
                        Some(s.parse::<u32>().map_err(|e| {
                            D::Error::custom(format!("wait_for.port: invalid int {s:?}: {e}"))
                        })?),
                        String::new(),
                    )
                }
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.port must be an int or numeric string, got: {other:?}"
                )))
            }
        };
        let path = match map.remove("path") {
            None => None,
            Some(serde_yaml::Value::String(s)) => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.path must be a string, got: {other:?}"
                )))
            }
        };

        let state = match map.remove("state") {
            None => WaitForState::Present,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "present" | "started" => WaitForState::Present,
                "absent" | "stopped" => WaitForState::Absent,
                other => {
                    return Err(D::Error::custom(format!(
                        "wait_for.state: expected one of [present, started, absent, stopped], got: {other:?}"
                    )))
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "wait_for.state must be a string, got: {other:?}"
                )))
            }
        };

        let timeout_ms = take_seconds_ms(&mut map, "timeout", 300_000)?;
        let delay_ms = take_seconds_ms(&mut map, "delay", 0)?;
        let sleep_ms = take_seconds_ms(&mut map, "sleep", 1_000)?;
        // `msg:` is the Ansible-style custom message on timeout. We
        // accept and discard it for now — gothab sets it but the
        // agent-side error already names the resource. Drop it from
        // the map so the unknown-field check doesn't trip.
        let _ = map.remove("msg");

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "wait_for: unknown field(s): {unknown:?}; \
                 expected one of [host, port, path, state, timeout, delay, sleep, msg]"
            )));
        }

        // Mode mutual exclusion (defensive; agent re-checks).
        let has_tcp = port.is_some() || !port_template.is_empty();
        let has_path = path.is_some();
        if has_tcp && has_path {
            return Err(D::Error::custom(
                "wait_for: host+port and path are mutually exclusive",
            ));
        }
        // Bare wait_for (no host/port/path) is Ansible's "just sleep
        // for delay seconds" form — useful as a controlled pause and
        // as a TODO placeholder. We accept it; the agent executes a
        // pure sleep of `delay_ms`. `timeout`/`sleep` are ignored in
        // this mode (there's nothing to probe).
        if has_tcp && port == Some(0) {
            return Err(D::Error::custom("wait_for: port must be non-zero"));
        }

        Ok(WaitForOp {
            host,
            port,
            path,
            state,
            timeout_ms,
            delay_ms,
            sleep_ms,
            port_template,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_wait_for_tcp_basic() {
        let t = parse_task(
            r#"
name: wait
wait_for:
  host: 127.0.0.1
  port: 5432
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert_eq!(w.host.as_deref(), Some("127.0.0.1"));
                assert_eq!(w.port, Some(5432));
                assert!(w.path.is_none());
                assert_eq!(w.state, WaitForState::Present);
            }
            _ => panic!("expected WaitFor body"),
        }
    }

    #[test]
    fn parses_wait_for_path_with_absent() {
        let t = parse_task(
            r#"
name: wait
wait_for:
  path: /var/run/foo.pid
  state: absent
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert_eq!(w.path.as_deref(), Some("/var/run/foo.pid"));
                assert_eq!(w.state, WaitForState::Absent);
            }
            _ => panic!("expected WaitFor body"),
        }
    }

    #[test]
    fn parses_wait_for_state_aliases() {
        for s in ["started", "stopped", "present", "absent"] {
            let yaml = format!(
                "name: t\nwait_for:\n  path: /x\n  state: {s}\n",
            );
            let _ = parse_task(&yaml);
        }
    }

    #[test]
    fn wait_for_rejects_both_modes() {
        let yaml = r#"
name: t
wait_for:
  host: localhost
  port: 22
  path: /x
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("mutually exclusive"),
            "got: {err}"
        );
    }

    /// Regression: gothab spells the etcd verify port as
    /// `port: "{{ etcd_client_port }}"`. The literal string isn't a
    /// valid u32 — parse-time validation must store the template and
    /// defer parsing to the render arm.
    #[test]
    fn wait_for_port_accepts_jinja_template() {
        let t = parse_task(
            r#"
name: t
wait_for:
  host: 127.0.0.1
  port: "{{ etcd_client_port }}"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert!(w.port.is_none());
                assert_eq!(w.port_template, "{{ etcd_client_port }}");
                assert_eq!(w.host.as_deref(), Some("127.0.0.1"));
            }
            _ => panic!("expected wait_for"),
        }
    }

    /// Regression: bare wait_for (no host/port/path) is Ansible's
    /// "just sleep for delay seconds" form. Used as a controlled pause
    /// and as a TODO placeholder in playbooks that ship with `when:
    /// false`. Used to be rejected at parse time — that broke any
    /// playbook with `wait_for: timeout: 30` as a placeholder.
    #[test]
    fn wait_for_accepts_bare_form_as_sleep() {
        let t = parse_task(
            r#"
name: t
wait_for:
  timeout: 10
  delay: 2
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert!(w.host.is_none());
                assert!(w.port.is_none());
                assert!(w.path.is_none());
                assert_eq!(w.delay_ms, 2_000);
                assert_eq!(w.timeout_ms, 10_000);
            }
            _ => panic!("expected wait_for"),
        }
    }

    #[test]
    fn wait_for_seconds_convert_to_ms() {
        let t = parse_task(
            r#"
name: t
wait_for:
  host: 127.0.0.1
  port: 1
  timeout: 3
  delay: 1
  sleep: 2
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::WaitFor(w)) => {
                assert_eq!(w.timeout_ms, 3_000);
                assert_eq!(w.delay_ms, 1_000);
                assert_eq!(w.sleep_ms, 2_000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn wait_for_to_wire_carries_fields() {
        let t = TaskOp::WaitFor(WaitForOp {
                host: Some("h".into()),
                port: Some(80),
                path: None,
                state: WaitForState::Present,
                timeout_ms: 5000,
                delay_ms: 100,
                sleep_ms: 250,
                port_template: String::new(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpWaitFor(w) = wire else {
            panic!("expected OpWaitFor")
        };
        assert_eq!(w.host, "h");
        assert_eq!(w.port, 80);
        assert_eq!(w.path, "");
        assert_eq!(w.state, 0);
        assert_eq!(w.timeout_ms, 5000);
        assert_eq!(w.delay_ms, 100);
        assert_eq!(w.sleep_ms, 250);
    }
}
