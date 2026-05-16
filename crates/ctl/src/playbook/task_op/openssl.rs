//! `openssl_privatekey:` / `openssl_csr_pipe:` / `x509_certificate_pipe:`
//!
//! Grouped together because they form a single PKI pipeline: privkey
//! generation feeds CSR generation feeds self-signed cert generation.
//! The CSR and x509 ops are pure controller-side (`_pipe` suffix in
//! Ansible's nomenclature) — they synthesize a register entry without
//! any wire dispatch.

use super::shared::{take_optional_ansible_bool, take_optional_string_list};
use serde::{de::Error as _, Deserialize, Deserializer};

/// `openssl_privatekey:` parsed form. Maps
/// `community.crypto.openssl_privatekey`. v1 supports `RSA` and
/// `Ed25519` key types. Generation happens controller-side at dispatch
/// time (not load time) — the orchestrator only mints a PEM after it
/// has decided ship-blind vs probe-first, and on the probe branch
/// skips generation entirely when the file already exists. So `body`
/// stays None at parse / validate / template-precompile time.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenSslPrivkeyOp {
    /// Destination path on the remote. Jinja-templatable.
    pub path: String,
    /// `RSA` or `Ed25519`. Default RSA (matches Ansible).
    pub kind: crate::x509::PrivkeyType,
    /// RSA modulus bits. Default 4096. Ignored for Ed25519.
    pub size: u32,
    /// Unix permission bits for the key file. Default 0o600.
    pub mode: u32,
    /// Force the probe-first branch (OpStat → maybe OpWriteFile) even
    /// when the wire-cost heuristic says ship-blind would be cheaper.
    /// Useful when an operator wants exact Ansible-flavored
    /// idempotency reporting (changed=false on the no-op case is then
    /// guaranteed at the cost of one round trip per task).
    pub force_probe: bool,
}

fn default_privkey_size() -> u32 { 4096 }
fn default_privkey_mode() -> u32 { 0o600 }

impl<'de> Deserialize<'de> for OpenSslPrivkeyOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        let path = match map.remove("path") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(serde_yaml::Value::String(_)) => {
                return Err(D::Error::custom("openssl_privatekey.path: must be non-empty"));
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.path: expected a string, got: {other:?}"
                )));
            }
            None => return Err(D::Error::custom("openssl_privatekey: `path` is required")),
        };
        let kind = match map.remove("type") {
            None | Some(serde_yaml::Value::Null) => crate::x509::PrivkeyType::Rsa,
            Some(serde_yaml::Value::String(s)) => crate::x509::PrivkeyType::from_yaml(&s)
                .map_err(|e| D::Error::custom(format!("openssl_privatekey.type: {e}")))?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.type: expected a string, got: {other:?}"
                )));
            }
        };
        let size = match map.remove("size") {
            None | Some(serde_yaml::Value::Null) => default_privkey_size(),
            Some(serde_yaml::Value::Number(n)) => n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| D::Error::custom(format!(
                    "openssl_privatekey.size: expected a positive integer, got: {n}"
                )))?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.size: expected an integer, got: {other:?}"
                )));
            }
        };
        let mode = match map.remove("mode") {
            None | Some(serde_yaml::Value::Null) => default_privkey_mode(),
            Some(serde_yaml::Value::Number(n)) => n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| D::Error::custom(format!(
                    "openssl_privatekey.mode: expected a non-negative integer, got: {n}"
                )))?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.mode: expected an integer (octal in YAML), got: {other:?}"
                )));
            }
        };
        let force_probe = take_optional_ansible_bool::<D::Error>(&mut map, "force_probe")?
            .unwrap_or(false);
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "openssl_privatekey: unknown field(s): {unknown:?}; expected one of \
                 [path, type, size, mode, force_probe]"
            )));
        }
        Ok(OpenSslPrivkeyOp { path, kind, size, mode, force_probe })
    }
}

/// `openssl_csr_pipe:` parsed form. The `_pipe` suffix in Ansible
/// means the CSR PEM is returned via the registered result
/// (`register.content`) rather than written to disk. Controller-side
/// only — no wire dispatch. The private key bytes come from
/// `HostCtx.privkey_pem_cache` keyed by `privatekey_path`.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenSslCsrPipeOp {
    /// Path on the remote that the private key lives at — used purely
    /// as the cache lookup key on the controller's privkey cache.
    /// Jinja-templatable so a per-host path works.
    pub privatekey_path: String,
    /// Subject CN. Jinja-templatable.
    pub common_name: String,
    /// Subject Alt Names, Ansible syntax: `DNS:foo`, `IP:1.2.3.4`,
    /// `email:ops@x`, `URI:https://x/`. Each entry is Jinja-templatable.
    pub subject_alt_name: Vec<String>,
    /// Optional KeyUsage flags (digitalSignature, keyEncipherment, …).
    pub key_usage: Vec<String>,
    /// Optional Extended KeyUsage names or dotted OIDs.
    pub extended_key_usage: Vec<String>,
}

impl<'de> Deserialize<'de> for OpenSslCsrPipeOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        let privatekey_path = match map.remove("privatekey_path") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "openssl_csr_pipe: `privatekey_path` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "openssl_csr_pipe.privatekey_path: expected non-empty string, got: {other:?}"
            ))),
        };
        let common_name = match map.remove("common_name") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "openssl_csr_pipe: `common_name` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "openssl_csr_pipe.common_name: expected non-empty string, got: {other:?}"
            ))),
        };
        let subject_alt_name = take_optional_string_list::<D::Error>(&mut map, "subject_alt_name")?
            .unwrap_or_default();
        let key_usage = take_optional_string_list::<D::Error>(&mut map, "key_usage")?
            .unwrap_or_default();
        let extended_key_usage = take_optional_string_list::<D::Error>(&mut map, "extended_key_usage")?
            .unwrap_or_default();
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "openssl_csr_pipe: unknown field(s): {unknown:?}; expected one of \
                 [privatekey_path, common_name, subject_alt_name, key_usage, extended_key_usage]"
            )));
        }
        Ok(OpenSslCsrPipeOp {
            privatekey_path, common_name, subject_alt_name, key_usage, extended_key_usage,
        })
    }
}

/// `x509_certificate_pipe:` parsed form. v1: self-signed only. The
/// CSR and private key both flow in as PEM strings (typically from
/// `{{ csr_result.content }}` / `{{ privkey_var }}` Jinja
/// expressions), so this op is decoupled from the controller-side
/// privkey cache.
#[derive(Debug, Clone, PartialEq)]
pub struct X509CertificatePipeOp {
    /// CSR PEM string. Jinja-templatable.
    pub csr_content: String,
    /// Private key PEM string used to self-sign. Jinja-templatable.
    pub privatekey_content: String,
    /// Provider name. v1 accepts only "selfsigned".
    pub provider: String,
    /// Validity window in days from controller-now. Default 365.
    pub valid_for_days: u32,
}

fn default_cert_provider() -> String { "selfsigned".to_string() }
fn default_cert_valid_days() -> u32 { 365 }

impl<'de> Deserialize<'de> for X509CertificatePipeOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        let csr_content = match map.remove("csr_content") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "x509_certificate_pipe: `csr_content` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.csr_content: expected non-empty string, got: {other:?}"
            ))),
        };
        let privatekey_content = match map.remove("privatekey_content") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            None => return Err(D::Error::custom(
                "x509_certificate_pipe: `privatekey_content` is required",
            )),
            other => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.privatekey_content: expected non-empty string, got: {other:?}"
            ))),
        };
        let provider = match map.remove("provider") {
            None | Some(serde_yaml::Value::Null) => default_cert_provider(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.provider: expected a string, got: {other:?}"
            ))),
        };
        // Fail loudly for the unimplemented providers so users don't
        // get a silently-wrong cert (e.g. a self-signed cert when they
        // asked for a CA-signed one).
        if provider != "selfsigned" {
            return Err(D::Error::custom(format!(
                "x509_certificate_pipe.provider {provider:?} not supported in v1; \
                 expected \"selfsigned\""
            )));
        }
        let valid_for_days = match map.remove("valid_for_days") {
            None | Some(serde_yaml::Value::Null) => default_cert_valid_days(),
            Some(serde_yaml::Value::Number(n)) => n.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| D::Error::custom(format!(
                    "x509_certificate_pipe.valid_for_days: expected a positive integer, got: {n}"
                )))?,
            Some(other) => return Err(D::Error::custom(format!(
                "x509_certificate_pipe.valid_for_days: expected an integer, got: {other:?}"
            ))),
        };
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "x509_certificate_pipe: unknown field(s): {unknown:?}; expected one of \
                 [csr_content, privatekey_content, provider, valid_for_days]"
            )));
        }
        Ok(X509CertificatePipeOp { csr_content, privatekey_content, provider, valid_for_days })
    }
}

#[cfg(test)]
mod tests {
    use crate::playbook::task_op::{parse_task_for_test as parse_task, try_parse_task_for_test as try_parse_task};
    use crate::playbook::task_op::{TaskBody, TaskOp};

    #[test]
    fn parses_openssl_privatekey_minimal() {
        let t = parse_task(
            r#"
name: privkey
openssl_privatekey:
  path: /etc/etcd/server.key
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslPrivkey(p)) => {
                assert_eq!(p.path, "/etc/etcd/server.key");
                assert_eq!(p.kind, crate::x509::PrivkeyType::Rsa);
                assert_eq!(p.size, 4096);
                assert_eq!(p.mode, 0o600);
                assert!(!p.force_probe);
            }
            other => panic!("expected OpenSslPrivkey, got {other:?}"),
        }
    }

    #[test]
    fn parses_openssl_privatekey_full() {
        let t = parse_task(
            r#"
name: ed
openssl_privatekey:
  path: /etc/etcd/peer.key
  type: Ed25519
  size: 2048
  mode: 0o400
  force_probe: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslPrivkey(p)) => {
                assert_eq!(p.kind, crate::x509::PrivkeyType::Ed25519);
                assert_eq!(p.size, 2048);
                assert_eq!(p.mode, 0o400);
                assert!(p.force_probe);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_openssl_csr_pipe() {
        let t = parse_task(
            r#"
name: csr
openssl_csr_pipe:
  privatekey_path: /etc/etcd/server.key
  common_name: etcd-server
  subject_alt_name:
    - "DNS:etcd.example.com"
    - "IP:10.0.0.10"
  key_usage: [digitalSignature, keyEncipherment]
  extended_key_usage: [serverAuth, clientAuth]
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslCsrPipe(c)) => {
                assert_eq!(c.privatekey_path, "/etc/etcd/server.key");
                assert_eq!(c.common_name, "etcd-server");
                assert_eq!(c.subject_alt_name.len(), 2);
                assert!(c.subject_alt_name[0].starts_with("DNS:"));
                assert_eq!(c.key_usage, vec!["digitalSignature", "keyEncipherment"]);
                assert_eq!(c.extended_key_usage, vec!["serverAuth", "clientAuth"]);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_x509_certificate_pipe() {
        let t = parse_task(
            r#"
name: cert
x509_certificate_pipe:
  csr_content: "{{ csr.content }}"
  privatekey_content: "{{ key.content }}"
  provider: selfsigned
  valid_for_days: 30
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::X509CertificatePipe(c)) => {
                assert_eq!(c.csr_content, "{{ csr.content }}");
                assert_eq!(c.privatekey_content, "{{ key.content }}");
                assert_eq!(c.provider, "selfsigned");
                assert_eq!(c.valid_for_days, 30);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn rejects_openssl_privatekey_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
openssl_privatekey:
  path: /etc/k
  curve: P-256
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("curve") || msg.contains("unknown"), "got: {msg}");
    }
}
