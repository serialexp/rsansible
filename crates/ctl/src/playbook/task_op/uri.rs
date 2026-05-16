//! `uri:` task body.

use super::shared::{take_optional_ansible_bool, take_optional_string};
use rsansible_wire::msg::{uri_body_format, uri_follow, uri_method};
use serde::{de::Error as _, Deserialize, Deserializer};
use std::collections::BTreeMap;

/// `uri:` parsed form. Mirrors Ansible's `ansible.builtin.uri` (subset).
/// Fields documented at the module-level for `OpUri` in `wire.schema.json5`.
///
/// `body` here is always a string at this layer — for `body_format: json`
/// with a YAML mapping/list source, the deserializer serializes to JSON
/// at parse time so the wire transport stays a single bytes field.
#[derive(Debug, Clone, PartialEq)]
pub struct UriOp {
    /// Jinja-templated URL. Required.
    pub url: String,
    /// `uri_method::*` byte: GET/POST/PUT/PATCH/DELETE/HEAD.
    pub method: u8,
    /// Request headers. Values are Jinja-templated at run time.
    /// BTreeMap so iteration order is deterministic on the wire.
    pub headers: BTreeMap<String, String>,
    /// Possibly Jinja-templated. For `body_format: json` with a YAML
    /// map/list source, this is the pre-serialized JSON string.
    pub body: String,
    /// `uri_body_format::*` byte: RAW/JSON/FORM.
    pub body_format: u8,
    /// Accepted HTTP statuses. Non-empty; default `[200]`.
    pub status_codes: Vec<u16>,
    /// Total request timeout in milliseconds. Default 30_000.
    pub timeout_ms: u32,
    /// If true, include the response body (UTF-8) in the envelope.
    pub return_content: bool,
    /// If false, disable TLS cert / hostname verification. Default true.
    pub validate_certs: bool,
    /// `uri_follow::*` byte: NONE/SAFE/ALL. Default SAFE.
    pub follow_redirects: u8,
    /// Path on the controller to a PEM-encoded client certificate.
    /// Empty = absent. Jinja-templatable. Read into bytes at render
    /// time (so a per-host path templated from `inventory_hostname`
    /// works). Matches Ansible's `uri.client_cert`.
    pub client_cert: String,
    /// Path on the controller to the PEM-encoded private key paired
    /// with `client_cert`. Required if `client_cert` is set. Empty =
    /// absent. Jinja-templatable. Matches Ansible's `uri.client_key`.
    pub client_key: String,
    /// Path on the controller to a PEM-encoded CA bundle used to
    /// verify the server certificate (added on top of the system
    /// roots, not replacing them). Empty = absent. Jinja-templatable.
    /// Matches Ansible's `uri.ca_path`.
    pub ca_path: String,
}

/// Hand-written so we can:
///   - accept method case-insensitively (`get`/`Get`/`GET`)
///   - accept `status_code` as a single int OR a list of ints
///   - accept `body` as string OR mapping/list (with `body_format: json`
///     a non-string body is serialized to JSON at parse time)
///   - accept `headers` as a mapping of string→string
///   - accept `timeout` as seconds (int or float) and convert to ms
///   - accept `follow_redirects` as `none`/`safe`/`all` (case-insensitive)
impl<'de> Deserialize<'de> for UriOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        // url — required, must be a non-empty string here (Jinja can
        // render to empty at runtime; that's validate-time's job).
        let url = match map.remove("url") {
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.url: expected a string, got: {other:?}"
                )));
            }
            None => return Err(D::Error::missing_field("url")),
        };

        // method — case-insensitive verb, default GET.
        let method = match map.remove("method") {
            None | Some(serde_yaml::Value::Null) => uri_method::GET,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_uppercase().as_str() {
                "GET" => uri_method::GET,
                "POST" => uri_method::POST,
                "PUT" => uri_method::PUT,
                "PATCH" => uri_method::PATCH,
                "DELETE" => uri_method::DELETE,
                "HEAD" => uri_method::HEAD,
                other => {
                    return Err(D::Error::custom(format!(
                        "uri.method: expected one of [GET, POST, PUT, PATCH, DELETE, HEAD], got: {other:?}"
                    )));
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.method: expected a string, got: {other:?}"
                )));
            }
        };

        // headers — a YAML mapping with string keys + string values.
        let headers: BTreeMap<String, String> = match map.remove("headers") {
            None | Some(serde_yaml::Value::Null) => BTreeMap::new(),
            Some(serde_yaml::Value::Mapping(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    let key = match k {
                        serde_yaml::Value::String(s) => s,
                        other => {
                            return Err(D::Error::custom(format!(
                                "uri.headers: keys must be strings, got: {other:?}"
                            )));
                        }
                    };
                    let val = match v {
                        serde_yaml::Value::String(s) => s,
                        // Ansible accepts numeric header values; coerce.
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => {
                            return Err(D::Error::custom(format!(
                                "uri.headers[{key:?}]: expected a string or scalar, got: {other:?}"
                            )));
                        }
                    };
                    out.insert(key, val);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.headers: expected a mapping, got: {other:?}"
                )));
            }
        };

        // body_format — default raw.
        let body_format = match map.remove("body_format") {
            None | Some(serde_yaml::Value::Null) => uri_body_format::RAW,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "raw" => uri_body_format::RAW,
                "json" => uri_body_format::JSON,
                "form" | "form-urlencoded" => uri_body_format::FORM,
                other => {
                    return Err(D::Error::custom(format!(
                        "uri.body_format: expected one of [raw, json, form], got: {other:?}"
                    )));
                }
            },
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.body_format: expected a string, got: {other:?}"
                )));
            }
        };

        // body — accept string verbatim; or, for body_format=json, accept
        // YAML mapping/list and serialize to JSON at parse time.
        let body = match map.remove("body") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(v @ serde_yaml::Value::Mapping(_)) | Some(v @ serde_yaml::Value::Sequence(_)) => {
                if body_format != uri_body_format::JSON {
                    return Err(D::Error::custom(
                        "uri.body: non-string body requires `body_format: json` \
                         (a YAML mapping/list is only auto-serialized as JSON)",
                    ));
                }
                serde_json::to_string(&v).map_err(|e| {
                    D::Error::custom(format!("uri.body: failed to JSON-encode: {e}"))
                })?
            }
            Some(serde_yaml::Value::Number(n)) => n.to_string(),
            Some(serde_yaml::Value::Bool(b)) => b.to_string(),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.body: expected a string or (with body_format=json) a mapping/list, got: {other:?}"
                )));
            }
        };

        // status_code — single int or list of ints; default [200].
        let status_codes = match map.remove("status_code") {
            None | Some(serde_yaml::Value::Null) => vec![200u16],
            Some(serde_yaml::Value::Number(n)) => {
                let v = n.as_u64().ok_or_else(|| {
                    D::Error::custom(format!("uri.status_code: expected a non-negative int, got: {n}"))
                })?;
                if !(100..=599).contains(&v) {
                    return Err(D::Error::custom(format!(
                        "uri.status_code: {v} out of range [100, 599]"
                    )));
                }
                vec![v as u16]
            }
            Some(serde_yaml::Value::Sequence(seq)) => {
                if seq.is_empty() {
                    return Err(D::Error::custom("uri.status_code: list must be non-empty"));
                }
                let mut out = Vec::with_capacity(seq.len());
                for item in seq {
                    let n = match item {
                        serde_yaml::Value::Number(n) => n,
                        other => {
                            return Err(D::Error::custom(format!(
                                "uri.status_code: list entries must be ints, got: {other:?}"
                            )));
                        }
                    };
                    let v = n.as_u64().ok_or_else(|| {
                        D::Error::custom(format!("uri.status_code: expected a non-negative int, got: {n}"))
                    })?;
                    if !(100..=599).contains(&v) {
                        return Err(D::Error::custom(format!(
                            "uri.status_code: {v} out of range [100, 599]"
                        )));
                    }
                    out.push(v as u16);
                }
                out
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.status_code: expected an int or list of ints, got: {other:?}"
                )));
            }
        };

        // timeout — seconds (int or float) → ms. Default 30s.
        let timeout_ms = match map.remove("timeout") {
            None | Some(serde_yaml::Value::Null) => 30_000u32,
            Some(serde_yaml::Value::Number(n)) => {
                let s = n.as_f64().ok_or_else(|| {
                    D::Error::custom(format!("uri.timeout: invalid number {n}"))
                })?;
                if !s.is_finite() || s < 0.0 {
                    return Err(D::Error::custom(format!(
                        "uri.timeout: expected non-negative seconds, got {s}"
                    )));
                }
                (s * 1000.0) as u32
            }
            Some(serde_yaml::Value::String(s)) => {
                let f = s.parse::<f64>().map_err(|e| {
                    D::Error::custom(format!("uri.timeout: invalid number {s:?}: {e}"))
                })?;
                if !f.is_finite() || f < 0.0 {
                    return Err(D::Error::custom(format!(
                        "uri.timeout: expected non-negative seconds, got {f}"
                    )));
                }
                (f * 1000.0) as u32
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.timeout: expected a number or numeric string, got: {other:?}"
                )));
            }
        };

        // return_content / validate_certs — Ansible-flavored bools.
        let return_content = take_optional_ansible_bool::<D::Error>(&mut map, "return_content")?
            .unwrap_or(false);
        let validate_certs = take_optional_ansible_bool::<D::Error>(&mut map, "validate_certs")?
            .unwrap_or(true);

        // follow_redirects — none/safe/all. Default safe.
        let follow_redirects = match map.remove("follow_redirects") {
            None | Some(serde_yaml::Value::Null) => uri_follow::SAFE,
            Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
                "none" | "no" | "false" => uri_follow::NONE,
                "safe" => uri_follow::SAFE,
                "all" | "yes" | "true" => uri_follow::ALL,
                other => {
                    return Err(D::Error::custom(format!(
                        "uri.follow_redirects: expected one of [none, safe, all], got: {other:?}"
                    )));
                }
            },
            // Ansible historically accepts a bool here too (no/yes).
            Some(serde_yaml::Value::Bool(b)) => {
                if b {
                    uri_follow::ALL
                } else {
                    uri_follow::NONE
                }
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "uri.follow_redirects: expected a string, got: {other:?}"
                )));
            }
        };

        // mTLS / custom-CA paths. Strings (paths on the controller),
        // Jinja-templatable, optional. Empty string = absent. Bytes are
        // read at render time so per-host paths work.
        let client_cert = take_optional_string::<D::Error>(&mut map, "client_cert", "uri")?
            .unwrap_or_default();
        let client_key = take_optional_string::<D::Error>(&mut map, "client_key", "uri")?
            .unwrap_or_default();
        let ca_path = take_optional_string::<D::Error>(&mut map, "ca_path", "uri")?
            .unwrap_or_default();
        if !client_cert.is_empty() && client_key.is_empty() {
            return Err(D::Error::custom(
                "uri.client_cert is set but uri.client_key is missing — \
                 a client cert without its key cannot complete the mTLS handshake",
            ));
        }
        if client_cert.is_empty() && !client_key.is_empty() {
            return Err(D::Error::custom(
                "uri.client_key is set but uri.client_cert is missing — \
                 a client key on its own is useless",
            ));
        }

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "uri: unknown field(s): {unknown:?}; expected one of \
                 [url, method, headers, body, body_format, status_code, \
                 timeout, return_content, validate_certs, follow_redirects, \
                 client_cert, client_key, ca_path]"
            )));
        }

        Ok(UriOp {
            url,
            method,
            headers,
            body,
            body_format,
            status_codes,
            timeout_ms,
            return_content,
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
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use rsansible_wire::msg::{uri_body_format, uri_follow, uri_method};
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};
    use std::collections::BTreeMap;

    fn parse_uri(yaml: &str) -> UriOp {
        let t = parse_task(yaml);
        match t.body {
            TaskBody::Op(TaskOp::Uri(u)) => u,
            other => panic!("expected TaskOp::Uri, got {other:?}"),
        }
    }

    #[test]
    fn uri_minimal_url_defaults() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://example.com/x
"#,
        );
        assert_eq!(u.url, "https://example.com/x");
        assert_eq!(u.method, uri_method::GET);
        assert!(u.headers.is_empty());
        assert_eq!(u.body, "");
        assert_eq!(u.body_format, uri_body_format::RAW);
        assert_eq!(u.status_codes, vec![200]);
        assert_eq!(u.timeout_ms, 30_000);
        assert!(!u.return_content);
        assert!(u.validate_certs);
        assert_eq!(u.follow_redirects, uri_follow::SAFE);
    }

    #[test]
    fn uri_method_case_insensitive() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  method: post
"#,
        );
        assert_eq!(u.method, uri_method::POST);
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  method: PaTcH
"#,
        );
        assert_eq!(u.method, uri_method::PATCH);
    }

    #[test]
    fn uri_status_code_accepts_int_and_list() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  status_code: 201
"#,
        );
        assert_eq!(u.status_codes, vec![201]);
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  status_code: [200, 201, 204]
"#,
        );
        assert_eq!(u.status_codes, vec![200, 201, 204]);
    }

    #[test]
    fn uri_status_code_out_of_range_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  status_code: 99
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("status_code"), "got: {err}");
    }

    #[test]
    fn uri_body_format_json_serializes_map() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  method: post
  body_format: json
  body:
    foo: bar
    n: 42
"#,
        );
        assert_eq!(u.body_format, uri_body_format::JSON);
        // BTreeMap ordering in serde_json::Value::Object → "foo" before "n".
        let parsed: serde_json::Value = serde_json::from_str(&u.body).unwrap();
        assert_eq!(parsed["foo"], serde_json::json!("bar"));
        assert_eq!(parsed["n"], serde_json::json!(42));
    }

    #[test]
    fn uri_body_map_with_raw_body_format_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  body:
    foo: bar
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("body_format: json"),
            "got: {err}"
        );
    }

    #[test]
    fn uri_headers_non_map_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  headers: "Authorization: Bearer xxx"
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("headers"), "got: {err}");
    }

    #[test]
    fn uri_follow_redirects_bogus_rejected() {
        let yaml = r#"
name: t
uri:
  url: https://x/
  follow_redirects: maybe
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("follow_redirects"),
            "got: {err}"
        );
    }

    #[test]
    fn uri_timeout_float_seconds_to_ms() {
        let u = parse_uri(
            r#"
name: t
uri:
  url: https://x/
  timeout: 1.5
"#,
        );
        assert_eq!(u.timeout_ms, 1500);
    }

    #[test]
    fn uri_missing_url_rejected() {
        let yaml = r#"
name: t
uri:
  method: get
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("url"), "got: {err}");
    }

    #[test]
    fn uri_to_wire_carries_fields() {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".into(), "Bearer xyz".into());
        headers.insert("Accept".into(), "application/json".into());
        let t = TaskOp::Uri(UriOp {
            url: "https://api/x".into(),
            method: uri_method::POST,
            headers,
            body: r#"{"a":1}"#.into(),
            body_format: uri_body_format::JSON,
            status_codes: vec![200, 201],
            timeout_ms: 5_000,
            return_content: true,
            validate_certs: false,
            follow_redirects: uri_follow::ALL,
            client_cert: String::new(),
            client_key: String::new(),
            ca_path: String::new(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpUri(o) = wire else {
            panic!("expected OpUri")
        };
        assert_eq!(o.kind, 12);
        assert_eq!(o.method, uri_method::POST);
        assert_eq!(o.url, "https://api/x");
        // BTreeMap sorted: Accept before Authorization.
        assert_eq!(o.header_keys, vec!["Accept", "Authorization"]);
        assert_eq!(
            o.header_values,
            vec!["application/json", "Bearer xyz"]
        );
        assert_eq!(o.body, br#"{"a":1}"#.to_vec());
        assert_eq!(o.body_format, uri_body_format::JSON);
        assert_eq!(o.status_codes, vec![200u16, 201u16]);
        assert_eq!(o.timeout_ms, 5_000);
        assert_eq!(o.return_content, 1);
        assert_eq!(o.validate_certs, 0);
        assert_eq!(o.follow_redirects, uri_follow::ALL);
        // No mTLS bytes when paths are empty.
        assert!(o.client_cert_pem.is_empty());
        assert!(o.client_key_pem.is_empty());
        assert!(o.ca_bundle_pem.is_empty());
    }

    #[test]
    fn uri_mtls_paths_are_read_into_wire_bytes() {
        // Write three PEM-ish files to a tempdir; verify to_wire_op
        // slurps them into the wire bytes fields. We don't need real
        // PEM here — agent-side parsing isn't exercised; only the
        // controller's read-file-and-embed pass is.
        let dir = std::env::temp_dir().join(format!(
            "rsansible-mtls-paths-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("client.crt");
        let key_path = dir.join("client.key");
        let ca_path = dir.join("ca.crt");
        std::fs::write(&cert_path, b"CERT-CONTENT").unwrap();
        std::fs::write(&key_path, b"KEY-CONTENT").unwrap();
        std::fs::write(&ca_path, b"CA-CONTENT").unwrap();

        let t = TaskOp::Uri(UriOp {
            url: "https://etcd/v2".into(),
            method: uri_method::GET,
            headers: BTreeMap::new(),
            body: String::new(),
            body_format: uri_body_format::RAW,
            status_codes: vec![200],
            timeout_ms: 30_000,
            return_content: false,
            validate_certs: true,
            follow_redirects: uri_follow::SAFE,
            client_cert: cert_path.to_string_lossy().into_owned(),
            client_key: key_path.to_string_lossy().into_owned(),
            ca_path: ca_path.to_string_lossy().into_owned(),
        });
        let wire = t.to_wire_op().expect("to_wire_op");
        let rsansible_wire::generated::Op::OpUri(o) = wire else {
            panic!("expected OpUri");
        };
        assert_eq!(o.client_cert_pem, b"CERT-CONTENT".to_vec());
        assert_eq!(o.client_key_pem, b"KEY-CONTENT".to_vec());
        assert_eq!(o.ca_bundle_pem, b"CA-CONTENT".to_vec());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uri_mtls_missing_file_surfaces_as_clear_error() {
        let t = TaskOp::Uri(UriOp {
            url: "https://x/".into(),
            method: uri_method::GET,
            headers: BTreeMap::new(),
            body: String::new(),
            body_format: uri_body_format::RAW,
            status_codes: vec![200],
            timeout_ms: 30_000,
            return_content: false,
            validate_certs: true,
            follow_redirects: uri_follow::SAFE,
            client_cert: "/definitely/not/here.crt".into(),
            client_key: "/definitely/not/here.key".into(),
            ca_path: String::new(),
        });
        let err = t.to_wire_op().expect_err("missing file should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("client_cert") && msg.contains("here.crt"),
            "error should mention field+path: {msg}"
        );
    }

    #[test]
    fn uri_rejects_client_cert_without_key() {
        // YAML-level validation: cert without key fails at parse, not
        // wire-emit, so a malformed playbook surfaces during `validate`.
        let yaml = r#"
name: t
uri:
  url: https://x/
  client_cert: /etc/pki/client.crt
"#;
        let err = serde_yaml::from_str::<Task>(yaml).expect_err("should reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("client_key"),
            "expected client_key complaint: {msg}"
        );
    }
}
