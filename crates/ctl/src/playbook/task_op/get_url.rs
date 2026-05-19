//! `get_url:` task body.

use super::shared::{parse_ansible_bool, take_optional_mode, take_optional_string, ModeField};
#[allow(unused_imports)]
use super::shared::parse_octal_mode;
use rsansible_wire::msg::uri_follow;
use serde::{de::Error as _, Deserialize, Deserializer};
use std::collections::BTreeMap;

/// `get_url:` parsed form. Mirrors `ansible.builtin.get_url` (subset).
/// All string fields are Jinja-templated at run time by the
/// orchestrator before `to_wire_op`.
#[derive(Debug, Clone, PartialEq)]
pub struct GetUrlOp {
    pub url: String,
    pub dest: String,
    /// `<algo>:<hex>` (sha256/sha1/md5). Empty = no verification.
    pub checksum: String,
    /// Octal file mode applied to dest after rename. `None` = leave
    /// alone. Accepts a Jinja template; resolved at dispatch.
    pub mode: Option<ModeField>,
    /// Owner name (resolved to uid agent-side). Empty = leave alone.
    pub owner: String,
    /// Group name (resolved to gid agent-side). Empty = leave alone.
    pub group: String,
    /// Request headers. BTreeMap = deterministic on the wire.
    pub headers: BTreeMap<String, String>,
    /// Total request timeout in milliseconds. Default 30_000.
    pub timeout_ms: u32,
    /// Force re-download even when dest is already present.
    pub force: bool,
    /// TLS cert/hostname verification. Default true.
    pub validate_certs: bool,
    /// `uri_follow::*` byte: NONE/SAFE/ALL. Default ALL (matches
    /// Ansible's `get_url` default — `safe` would refuse most CDN
    /// redirect chains).
    pub follow_redirects: u8,
    /// Optional mTLS material — paths on the controller, read at
    /// to_wire_op time. Empty = absent.
    pub client_cert: String,
    pub client_key: String,
    pub ca_path: String,
}

impl<'de> Deserialize<'de> for GetUrlOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let url = match map.remove("url") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.url: expected a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("url")),
        };

        let dest = match map.remove("dest") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.dest: expected a string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("dest")),
        };

        let checksum = match map.remove("checksum") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.checksum: expected a string like sha256:<hex>, got: {other:?}"
                )))
            }
        };

        // mode — Ansible accepts octal strings ("0644"), raw ints, and
        // Jinja templates. Shared helper handles all three.
        let mode = take_optional_mode::<D::Error>(&mut map, "mode")?;

        let owner = match map.remove("owner") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.owner: expected a string, got: {other:?}"
                )))
            }
        };
        let group = match map.remove("group") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.group: expected a string, got: {other:?}"
                )))
            }
        };

        let headers: BTreeMap<String, String> = match map.remove("headers") {
            None | Some(serde_yaml::Value::Null) => BTreeMap::new(),
            Some(serde_yaml::Value::Mapping(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    let key = match k {
                        serde_yaml::Value::String(s) => s,
                        other => {
                            return Err(D::Error::custom(format!(
                                "get_url.headers: keys must be strings, got: {other:?}"
                            )))
                        }
                    };
                    let val = match v {
                        serde_yaml::Value::String(s) => s,
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "get_url.headers[{key}]: expected scalar, got: {other:?}"
                            )))
                        }
                    };
                    out.insert(key, val);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.headers: expected a mapping, got: {other:?}"
                )))
            }
        };

        // `timeout:` is in seconds (matching Ansible). Accept int or float.
        let timeout_ms = match map.remove("timeout") {
            None | Some(serde_yaml::Value::Null) => 30_000u32,
            Some(serde_yaml::Value::Number(n)) => {
                if let Some(i) = n.as_u64() {
                    (i * 1000) as u32
                } else if let Some(f) = n.as_f64() {
                    (f * 1000.0) as u32
                } else {
                    return Err(D::Error::custom(format!(
                        "get_url.timeout: bad number {n:?}"
                    )));
                }
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.timeout: expected a number of seconds, got: {other:?}"
                )))
            }
        };

        let force = parse_ansible_bool::<D::Error>(map.remove("force"), "get_url.force", false)?;
        let validate_certs = parse_ansible_bool::<D::Error>(
            map.remove("validate_certs"),
            "get_url.validate_certs",
            true,
        )?;

        let follow_redirects = match map.remove("follow_redirects") {
            None | Some(serde_yaml::Value::Null) => uri_follow::ALL,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "none" => uri_follow::NONE,
                "safe" => uri_follow::SAFE,
                "all" | "yes" | "true" => uri_follow::ALL,
                other => {
                    return Err(D::Error::custom(format!(
                        "get_url.follow_redirects: expected one of [none, safe, all], got: {other:?}"
                    )))
                }
            },
            Some(serde_yaml::Value::Bool(true)) => uri_follow::ALL,
            Some(serde_yaml::Value::Bool(false)) => uri_follow::NONE,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "get_url.follow_redirects: expected string or bool, got: {other:?}"
                )))
            }
        };

        let client_cert = take_optional_string(&mut map, "client_cert", "get_url")?
            .unwrap_or_default();
        let client_key = take_optional_string(&mut map, "client_key", "get_url")?
            .unwrap_or_default();
        let ca_path = take_optional_string(&mut map, "ca_path", "get_url")?
            .unwrap_or_default();

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_str().map(String::from))
                .collect();
            return Err(D::Error::custom(format!(
                "get_url: unknown field(s): {unknown:?}; expected one of \
                 [url, dest, checksum, mode, owner, group, headers, timeout, \
                 force, validate_certs, follow_redirects, client_cert, \
                 client_key, ca_path]"
            )));
        }

        Ok(GetUrlOp {
            url,
            dest,
            checksum,
            mode,
            owner,
            group,
            headers,
            timeout_ms,
            force,
            validate_certs,
            follow_redirects,
            client_cert,
            client_key,
            ca_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::playbook::task_op::{parse_task_for_test as parse_task, Task, TaskBody, TaskOp};
    use rsansible_wire::generated::Op as WireOp;
    use rsansible_wire::msg::uri_follow;

    #[test]
    fn parse_get_url_minimal() {
        let t = parse_task(
            r#"
name: t
get_url:
  url: https://example.com/x.tar.gz
  dest: /tmp/x.tar.gz
"#,
        );
        let TaskBody::Op(TaskOp::GetUrl(g)) = t.body else { panic!() };
        assert_eq!(g.url, "https://example.com/x.tar.gz");
        assert_eq!(g.dest, "/tmp/x.tar.gz");
        assert_eq!(g.checksum, "");
        assert_eq!(g.mode, None);
        assert!(!g.force);
        assert!(g.validate_certs);
        assert_eq!(g.follow_redirects, uri_follow::ALL);
        assert_eq!(g.timeout_ms, 30_000);
    }

    #[test]
    fn parse_get_url_full() {
        let t = parse_task(
            r#"
name: t
get_url:
  url: https://example.com/payload
  dest: /opt/payload
  checksum: sha256:abc123
  mode: "0644"
  owner: root
  group: wheel
  headers:
    Authorization: Bearer xyz
    X-Trace: "42"
  timeout: 60
  force: yes
  validate_certs: no
  follow_redirects: safe
"#,
        );
        let TaskBody::Op(TaskOp::GetUrl(g)) = t.body else { panic!() };
        assert_eq!(g.checksum, "sha256:abc123");
        assert_eq!(g.mode, Some(super::super::ModeField::Literal(0o644)));
        assert_eq!(g.owner, "root");
        assert_eq!(g.group, "wheel");
        assert_eq!(g.headers.get("Authorization").unwrap(), "Bearer xyz");
        assert_eq!(g.headers.get("X-Trace").unwrap(), "42");
        assert_eq!(g.timeout_ms, 60_000);
        assert!(g.force);
        assert!(!g.validate_certs);
        assert_eq!(g.follow_redirects, uri_follow::SAFE);
    }

    #[test]
    fn parse_get_url_rejects_unknown_field() {
        let yaml = r#"
name: t
get_url:
  url: https://example.com/x
  dest: /tmp/x
  bogus: yes
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "unknown field should be rejected");
        let err = format!("{:?}", result.err());
        assert!(err.contains("bogus"), "error should mention the unknown field: {err}");
    }

    #[test]
    fn parse_get_url_to_wire_op_round_trip() {
        let t = parse_task(
            r#"
name: t
get_url:
  url: https://example.com/p
  dest: /tmp/p
  checksum: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  mode: "0640"
  force: yes
"#,
        );
        let TaskBody::Op(op) = t.body else { panic!() };
        let wire = op.to_wire_op().unwrap();
        let WireOp::OpGetUrl(g) = wire else { panic!("got {wire:?}") };
        assert_eq!(g.kind, 15);
        assert_eq!(g.url, "https://example.com/p");
        assert_eq!(g.dest, "/tmp/p");
        assert!(g.checksum.starts_with("sha256:"));
        assert_eq!(g.mode, 0o640);
        assert_eq!(g.force, 1);
        assert_eq!(g.validate_certs, 1);
        assert_eq!(g.follow_redirects, uri_follow::ALL);
    }
}
