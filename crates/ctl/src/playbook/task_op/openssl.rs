//! `openssl_privatekey:` / `openssl_csr_pipe:` / `x509_certificate_pipe:`
//!
//! Grouped together because they form a single PKI pipeline: privkey
//! generation feeds CSR generation feeds self-signed cert generation.
//! The CSR and x509 ops are pure controller-side (`_pipe` suffix in
//! Ansible's nomenclature) — they synthesize a register entry without
//! any wire dispatch.

use super::shared::{
    take_optional_ansible_bool, take_optional_field_string, take_optional_mode,
    take_optional_string_list, ModeField,
};
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
    /// Unix permission bits for the key file. Default 0o600. Accepts a
    /// Jinja template too; resolved at dispatch.
    pub mode: ModeField,
    /// File owner (POSIX user name). Parsed but not yet applied — the
    /// underlying `OpWriteFile` wire op doesn't carry owner/group yet.
    /// See TODO.md.
    pub owner: Option<String>,
    /// File group (POSIX group name). Same caveat as `owner:`.
    pub group: Option<String>,
    /// Force the probe-first branch (OpStat → maybe OpWriteFile) even
    /// when the wire-cost heuristic says ship-blind would be cheaper.
    /// Useful when an operator wants exact Ansible-flavored
    /// idempotency reporting (changed=false on the no-op case is then
    /// guaranteed at the cost of one round trip per task).
    pub force_probe: bool,
}

fn default_privkey_size() -> u32 { 4096 }
fn default_privkey_mode() -> ModeField { ModeField::Literal(0o600) }

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
        // Ansible writes mode as either an int (`0o600`) or a string
        // (`"0600"`); accept both via the shared helper so we don't
        // diverge from per-key Bucket-A behavior.
        let mode = take_optional_mode::<D::Error>(&mut map, "mode")?
            .unwrap_or_else(default_privkey_mode);
        // Ansible's openssl_privatekey accepts `owner` and `group` (it
        // chowns the generated key). We accept them at parse time so
        // playbooks that set them don't trip on unknown-field rejection;
        // they're not yet applied at dispatch — see TODO.md.
        let owner = match map.remove("owner") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => Some(s),
            Some(serde_yaml::Value::String(_)) => None,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.owner: expected a string, got: {other:?}"
                )));
            }
        };
        let group = match map.remove("group") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => Some(s),
            Some(serde_yaml::Value::String(_)) => None,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "openssl_privatekey.group: expected a string, got: {other:?}"
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
                 [path, type, size, mode, owner, group, force_probe]"
            )));
        }
        Ok(OpenSslPrivkeyOp { path, kind, size, mode, owner, group, force_probe })
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
    /// Subject Country (C). Optional. Jinja-templatable.
    pub country_name: String,
    /// Subject Organization (O). Optional. Jinja-templatable.
    pub organization_name: String,
    /// Subject Organizational Unit (OU). Optional. Jinja-templatable.
    pub organizational_unit_name: String,
    /// Subject Alt Names, Ansible syntax: `DNS:foo`, `IP:1.2.3.4`,
    /// `email:ops@x`, `URI:https://x/`. Each entry is Jinja-templatable.
    pub subject_alt_name: Vec<String>,
    /// Optional KeyUsage flags (digitalSignature, keyEncipherment, …).
    pub key_usage: Vec<String>,
    /// Optional Extended KeyUsage names or dotted OIDs.
    pub extended_key_usage: Vec<String>,
    /// `basic_constraints:` — list of strings in Ansible's syntax:
    /// `CA:TRUE` / `CA:FALSE`, optional `pathlen:N`. Empty list means
    /// "omit the basic-constraints extension" (matches Ansible's
    /// default when the field is absent).
    pub basic_constraints: Vec<String>,
    /// `digest:` — Ansible's signature digest selection
    /// (sha256/sha384/sha512). **Parsed but honored indirectly:**
    /// rcgen picks the digest based on the signing key (RSA →
    /// SHA-256, Ed25519 → its built-in PureEd25519). We store the
    /// field so playbooks parse cleanly; mismatching the key's
    /// natural digest would require rcgen plumbing we don't yet
    /// have. See ANSIBLE_COMPAT.md §6.
    pub digest: String,
    /// `basic_constraints_critical:` — mark the BC extension critical.
    /// Default false. **rsansible always emits BC as critical when
    /// it's present** because rcgen doesn't expose the criticality bit
    /// at this layer; setting `false` while `basic_constraints` is
    /// non-empty is rejected. See ANSIBLE_COMPAT.md §6.
    pub basic_constraints_critical: bool,
    /// `key_usage_critical:` — mark the KeyUsage extension critical.
    /// Default false. Same rcgen limitation as `basic_constraints_critical`:
    /// when `key_usage` is non-empty rcgen always emits the extension
    /// critical, so `false` here is rejected.
    pub key_usage_critical: bool,
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
        let country_name = take_optional_field_string::<D::Error>(&mut map, "country_name")?
            .unwrap_or_default();
        let organization_name = take_optional_field_string::<D::Error>(&mut map, "organization_name")?
            .unwrap_or_default();
        let organizational_unit_name =
            take_optional_field_string::<D::Error>(&mut map, "organizational_unit_name")?
                .unwrap_or_default();
        let subject_alt_name = take_optional_string_list::<D::Error>(&mut map, "subject_alt_name")?
            .unwrap_or_default();
        let key_usage = take_optional_string_list::<D::Error>(&mut map, "key_usage")?
            .unwrap_or_default();
        let extended_key_usage = take_optional_string_list::<D::Error>(&mut map, "extended_key_usage")?
            .unwrap_or_default();
        let basic_constraints = take_optional_string_list::<D::Error>(&mut map, "basic_constraints")?
            .unwrap_or_default();
        // `digest:` is the signing hash algorithm. rcgen picks one
        // implicitly from the key type, so we just store the requested
        // value and let the renderer trust rcgen's choice. See
        // ANSIBLE_COMPAT.md §6 — same divergence as
        // `selfsigned_digest:` on x509_certificate_pipe.
        let digest =
            take_optional_field_string::<D::Error>(&mut map, "digest")?.unwrap_or_default();
        // rcgen 0.13 always emits BC/KU as critical when present.
        // Accept `*_critical: true` (matches behavior); reject
        // `*_critical: false` paired with a non-empty extension list
        // to avoid silently lying about criticality. Absent → default
        // false (matches Ansible). The error here is at parse time so
        // a playbook author hits it on the first validate.
        let basic_constraints_critical =
            take_optional_ansible_bool::<D::Error>(&mut map, "basic_constraints_critical")?
                .unwrap_or(false);
        if !basic_constraints.is_empty() && !basic_constraints_critical {
            return Err(D::Error::custom(
                "openssl_csr_pipe.basic_constraints_critical: rsansible always \
                 emits the BasicConstraints extension as critical (rcgen \
                 limitation); set `basic_constraints_critical: true` when \
                 supplying `basic_constraints:`. See ANSIBLE_COMPAT.md §6.",
            ));
        }
        let key_usage_critical =
            take_optional_ansible_bool::<D::Error>(&mut map, "key_usage_critical")?
                .unwrap_or(false);
        if !key_usage.is_empty() && !key_usage_critical {
            return Err(D::Error::custom(
                "openssl_csr_pipe.key_usage_critical: rsansible always emits \
                 the KeyUsage extension as critical (rcgen limitation); set \
                 `key_usage_critical: true` when supplying `key_usage:`. See \
                 ANSIBLE_COMPAT.md §6.",
            ));
        }
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "openssl_csr_pipe: unknown field(s): {unknown:?}; expected one of \
                 [privatekey_path, common_name, country_name, organization_name, \
                 organizational_unit_name, subject_alt_name, key_usage, \
                 extended_key_usage, basic_constraints, basic_constraints_critical, \
                 key_usage_critical, digest]"
            )));
        }
        Ok(OpenSslCsrPipeOp {
            privatekey_path,
            common_name,
            country_name,
            organization_name,
            organizational_unit_name,
            subject_alt_name,
            key_usage,
            extended_key_usage,
            basic_constraints,
            basic_constraints_critical,
            key_usage_critical,
            digest,
        })
    }
}

/// `x509_certificate_pipe:` parsed form. Two providers supported:
///
/// - **`selfsigned`** — the CSR is signed by the same private key that
///   produced it. The key may flow in as a PEM string
///   (`privatekey_content:`) OR as a controller-side path
///   (`privatekey_path:`) — exactly one is required.
///
/// - **`ownca`** — the CSR is signed by a separate CA cert + CA private
///   key. `ownca_content:` (CA cert PEM) and either
///   `ownca_privatekey_content:` (CA key PEM) or
///   `ownca_privatekey_path:` (controller-side path to the CA key) are
///   required. The CSR's own private key is not needed on the
///   controller — the public key embedded in the CSR is what ends up
///   in the issued cert.
///
/// The CSR PEM always flows in via `csr_content:` (typically a
/// previous `openssl_csr_pipe` register).
#[derive(Debug, Clone, PartialEq)]
pub struct X509CertificatePipeOp {
    /// CSR PEM string. Jinja-templatable.
    pub csr_content: String,
    /// (selfsigned only) Private key PEM string used to self-sign.
    /// Empty when `privatekey_path` is set instead. Jinja-templatable.
    pub privatekey_content: String,
    /// (selfsigned only) Controller-side path to read the private key
    /// from. Empty when `privatekey_content` is set instead.
    /// Jinja-templatable. The PEM is read at dispatch time.
    pub privatekey_path: String,
    /// Provider name: `selfsigned` (default) or `ownca`.
    pub provider: String,
    /// Validity window in days from controller-now. Default 365.
    /// Populated either from `valid_for_days:` directly or by parsing
    /// the provider-specific duration spelling
    /// (`selfsigned_not_after:` / `ownca_not_after:`).
    pub valid_for_days: u32,
    /// `selfsigned_digest:` — Ansible's signature digest selection
    /// (sha256/sha384/sha512). **Parsed but currently honored only
    /// indirectly:** rcgen picks the digest based on the signing key
    /// (`RSA → SHA256`, `Ed25519 → Ed25519's built-in`, `ECDSA P-256
    /// → SHA256`), which matches Ansible's default behavior. We store
    /// the field so playbooks parse cleanly; mismatching the key's
    /// natural digest would require rcgen plumbing we don't yet have.
    /// See ANSIBLE_COMPAT.md §6.
    pub selfsigned_digest: String,
    /// (ownca only) CA certificate PEM string. Jinja-templatable.
    pub ownca_content: String,
    /// (ownca only) CA private key PEM string. Empty when
    /// `ownca_privatekey_path` is set instead. Jinja-templatable.
    pub ownca_privatekey_content: String,
    /// (ownca only) Controller-side path to the CA private key.
    /// Empty when `ownca_privatekey_content` is set instead.
    /// Jinja-templatable. The PEM is read at dispatch time.
    pub ownca_privatekey_path: String,
    /// (ownca only) `ownca_digest:` — same parse-but-honor-indirectly
    /// caveat as `selfsigned_digest:`. See ANSIBLE_COMPAT.md §6.
    pub ownca_digest: String,
    /// (deferred) The original `selfsigned_not_after:` / `ownca_not_after:`
    /// string when it contained Jinja and couldn't be parsed at load
    /// time. Empty otherwise. Rendered at dispatch and parsed into a
    /// fresh day count that overrides `valid_for_days`. Same dance as
    /// other "Jinja-renderable enum-validated field" cases (ufw rule
    /// kinds, etc.).
    pub not_after_template: String,
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
        let privatekey_content =
            take_optional_field_string::<D::Error>(&mut map, "privatekey_content")?
                .unwrap_or_default();
        let privatekey_path =
            take_optional_field_string::<D::Error>(&mut map, "privatekey_path")?
                .unwrap_or_default();
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
        if provider != "selfsigned" && provider != "ownca" {
            return Err(D::Error::custom(format!(
                "x509_certificate_pipe.provider {provider:?} not supported; \
                 expected \"selfsigned\" or \"ownca\""
            )));
        }

        // ownca-specific inputs. Only validated when provider is ownca.
        let ownca_content =
            take_optional_field_string::<D::Error>(&mut map, "ownca_content")?
                .unwrap_or_default();
        let ownca_privatekey_content =
            take_optional_field_string::<D::Error>(&mut map, "ownca_privatekey_content")?
                .unwrap_or_default();
        let ownca_privatekey_path =
            take_optional_field_string::<D::Error>(&mut map, "ownca_privatekey_path")?
                .unwrap_or_default();
        let ownca_not_after =
            take_optional_field_string::<D::Error>(&mut map, "ownca_not_after")?;
        let ownca_digest =
            take_optional_field_string::<D::Error>(&mut map, "ownca_digest")?
                .unwrap_or_default();

        // Provider-specific required-field validation.
        match provider.as_str() {
            "selfsigned" => {
                if privatekey_content.is_empty() && privatekey_path.is_empty() {
                    return Err(D::Error::custom(
                        "x509_certificate_pipe: one of `privatekey_content` or \
                         `privatekey_path` is required for provider=selfsigned",
                    ));
                }
                if !privatekey_content.is_empty() && !privatekey_path.is_empty() {
                    return Err(D::Error::custom(
                        "x509_certificate_pipe: set exactly one of \
                         `privatekey_content` or `privatekey_path`, not both",
                    ));
                }
                if !ownca_content.is_empty()
                    || !ownca_privatekey_content.is_empty()
                    || !ownca_privatekey_path.is_empty()
                    || ownca_not_after.is_some()
                    || !ownca_digest.is_empty()
                {
                    return Err(D::Error::custom(
                        "x509_certificate_pipe: `ownca_*` fields are only valid \
                         with provider=ownca",
                    ));
                }
            }
            "ownca" => {
                if ownca_content.is_empty() {
                    return Err(D::Error::custom(
                        "x509_certificate_pipe: `ownca_content` (CA cert PEM) is \
                         required for provider=ownca",
                    ));
                }
                if ownca_privatekey_content.is_empty() && ownca_privatekey_path.is_empty() {
                    return Err(D::Error::custom(
                        "x509_certificate_pipe: one of `ownca_privatekey_content` \
                         or `ownca_privatekey_path` is required for provider=ownca",
                    ));
                }
                if !ownca_privatekey_content.is_empty() && !ownca_privatekey_path.is_empty() {
                    return Err(D::Error::custom(
                        "x509_certificate_pipe: set exactly one of \
                         `ownca_privatekey_content` or `ownca_privatekey_path`, \
                         not both",
                    ));
                }
                if !privatekey_content.is_empty() || !privatekey_path.is_empty() {
                    return Err(D::Error::custom(
                        "x509_certificate_pipe: `privatekey_content` / \
                         `privatekey_path` are only valid with \
                         provider=selfsigned (provider=ownca signs with the CA's \
                         key, not the CSR's)",
                    ));
                }
            }
            _ => unreachable!("provider validity already checked above"),
        }
        let valid_for_days_explicit = match map.remove("valid_for_days") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::Number(n)) => Some(
                n.as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| {
                        D::Error::custom(format!(
                            "x509_certificate_pipe.valid_for_days: expected a positive integer, got: {n}"
                        ))
                    })?,
            ),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "x509_certificate_pipe.valid_for_days: expected an integer, got: {other:?}"
                )))
            }
        };
        // {selfsigned,ownca}_not_after: Ansible's "+3650d" / "+1y" /
        // etc. duration syntax. Both spell the same window — pick the
        // one matching the active provider. Mutually exclusive with
        // valid_for_days and with each other.
        let selfsigned_not_after =
            take_optional_field_string::<D::Error>(&mut map, "selfsigned_not_after")?;
        if let (Some(_), Some(_)) = (selfsigned_not_after.as_ref(), ownca_not_after.as_ref()) {
            return Err(D::Error::custom(
                "x509_certificate_pipe: set either `selfsigned_not_after` or \
                 `ownca_not_after`, not both",
            ));
        }
        let provider_not_after = match provider.as_str() {
            "selfsigned" => selfsigned_not_after,
            "ownca" => ownca_not_after,
            _ => unreachable!(),
        };
        // If the `*_not_after:` value contains Jinja we can't validate
        // the duration spelling at parse time — defer to dispatch.
        // Stash the template in `not_after_template`; valid_for_days
        // gets a placeholder that's overwritten at render time.
        let (valid_for_days, not_after_template) = match (valid_for_days_explicit, &provider_not_after) {
            (Some(_), Some(_)) => {
                return Err(D::Error::custom(
                    "x509_certificate_pipe: set either `valid_for_days` or the \
                     provider-specific `*_not_after`, not both",
                ));
            }
            (Some(d), None) => (d, String::new()),
            (None, Some(s)) => {
                if super::shared::string_is_jinja(s) {
                    (default_cert_valid_days(), s.clone())
                } else {
                    (parse_relative_duration_days(s).map_err(D::Error::custom)?, String::new())
                }
            }
            (None, None) => (default_cert_valid_days(), String::new()),
        };
        let selfsigned_digest =
            take_optional_field_string::<D::Error>(&mut map, "selfsigned_digest")?
                .unwrap_or_default();
        if !map.is_empty() {
            let unknown: Vec<String> = map.keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "x509_certificate_pipe: unknown field(s): {unknown:?}; expected one of \
                 [csr_content, privatekey_content, privatekey_path, provider, \
                 valid_for_days, selfsigned_not_after, selfsigned_digest, \
                 ownca_content, ownca_privatekey_content, ownca_privatekey_path, \
                 ownca_not_after, ownca_digest]"
            )));
        }
        Ok(X509CertificatePipeOp {
            csr_content,
            privatekey_content,
            privatekey_path,
            provider,
            valid_for_days,
            selfsigned_digest,
            ownca_content,
            ownca_privatekey_content,
            ownca_privatekey_path,
            ownca_digest,
            not_after_template,
        })
    }
}

/// Parse Ansible's `selfsigned_not_after: "+3650d"` / `"+1y"` style
/// relative duration and return the resulting day count. Bare integers
/// are interpreted as days (matching Ansible's loose handling). Years
/// expand to 365 days each (no leap-day accounting — Ansible does the
/// same).
///
/// Accepted suffixes: `s`, `m`, `h`, `d`, `w`, `y`. The leading `+`
/// is required by Ansible for relative-from-now (the only mode v1
/// supports); we accept it bare too because the YAML is unambiguous.
pub(crate) fn parse_relative_duration_days(s: &str) -> Result<u32, String> {
    let t = s.trim().strip_prefix('+').unwrap_or(s.trim());
    if t.is_empty() {
        return Err("selfsigned_not_after: empty string".to_string());
    }
    let (num_part, unit) = t
        .find(|c: char| !c.is_ascii_digit())
        .map(|i| (&t[..i], &t[i..]))
        .unwrap_or((t, "d"));
    if num_part.is_empty() {
        return Err(format!(
            "selfsigned_not_after {s:?}: expected a number followed by an optional \
             unit (s/m/h/d/w/y)"
        ));
    }
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("selfsigned_not_after {s:?}: invalid number {num_part:?}: {e}"))?;
    let days = match unit {
        "" | "d" => n,
        "w" => n.saturating_mul(7),
        "y" => n.saturating_mul(365),
        "s" => n / 86400,
        "m" => n / 1440,
        "h" => n / 24,
        other => {
            return Err(format!(
                "selfsigned_not_after {s:?}: unknown unit {other:?}; \
                 expected one of s/m/h/d/w/y"
            ))
        }
    };
    if days == 0 {
        return Err(format!(
            "selfsigned_not_after {s:?}: rounds down to 0 days; rsansible's \
             cert validity is day-granular"
        ));
    }
    u32::try_from(days).map_err(|_| {
        format!("selfsigned_not_after {s:?}: {days} days exceeds u32 — pick a saner window")
    })
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
                assert_eq!(p.mode, crate::playbook::ModeField::Literal(0o600));
                assert!(!p.force_probe);
            }
            other => panic!("expected OpenSslPrivkey, got {other:?}"),
        }
    }

    /// Regression: Ansible's `openssl_privatekey` accepts `owner:`
    /// and `group:`. gothab uses both on its CA/server key tasks.
    /// We parse them (so playbooks don't trip on unknown-field
    /// rejection); they're not yet applied at dispatch — see
    /// TODO.md.
    #[test]
    fn parses_openssl_privatekey_owner_and_group() {
        let t = parse_task(
            r#"
name: privkey
openssl_privatekey:
  path: /etc/etcd/server.key
  owner: etcd
  group: etcd
  mode: "0600"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslPrivkey(p)) => {
                assert_eq!(p.owner.as_deref(), Some("etcd"));
                assert_eq!(p.group.as_deref(), Some("etcd"));
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
                assert_eq!(p.mode, crate::playbook::ModeField::Literal(0o400));
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
  key_usage_critical: true
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
                assert!(c.key_usage_critical);
                assert_eq!(c.extended_key_usage, vec!["serverAuth", "clientAuth"]);
            }
            other => panic!("got {other:?}"),
        }
    }

    /// Regression: Ansible's `openssl_csr_pipe` accepts `digest:`.
    /// gothab uses `digest: sha256` on every CSR task. We parse it
    /// for compat; rcgen picks the hash from the key type
    /// implicitly. See ANSIBLE_COMPAT.md §6.
    #[test]
    fn parses_openssl_csr_pipe_digest_field() {
        let t = parse_task(
            r#"
name: csr
openssl_csr_pipe:
  privatekey_path: /etc/etcd/server.key
  common_name: etcd-server
  digest: sha256
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslCsrPipe(c)) => {
                assert_eq!(c.digest, "sha256");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_openssl_csr_pipe_with_dn_and_basic_constraints() {
        let t = parse_task(
            r#"
name: ca-csr
openssl_csr_pipe:
  privatekey_path: /tmp/ca.key
  common_name: "rsansible test CA"
  country_name: FI
  organization_name: Gothab
  organizational_unit_name: etcd-ca
  basic_constraints: ["CA:TRUE"]
  basic_constraints_critical: true
  key_usage: ["keyCertSign", "cRLSign"]
  key_usage_critical: true
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::OpenSslCsrPipe(c)) => {
                assert_eq!(c.country_name, "FI");
                assert_eq!(c.organization_name, "Gothab");
                assert_eq!(c.organizational_unit_name, "etcd-ca");
                assert_eq!(c.basic_constraints, vec!["CA:TRUE"]);
                assert!(c.basic_constraints_critical);
                assert!(c.key_usage_critical);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn rejects_key_usage_without_critical_true() {
        let err = try_parse_task(
            r#"
name: csr
openssl_csr_pipe:
  privatekey_path: /tmp/k
  common_name: x
  key_usage: ["digitalSignature"]
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("key_usage_critical"), "got: {msg}");
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
    fn parses_x509_certificate_pipe_with_path_and_relative_duration() {
        let t = parse_task(
            r#"
name: ca
x509_certificate_pipe:
  csr_content: "{{ ca_csr.csr }}"
  privatekey_path: "/tmp/ca.key"
  provider: selfsigned
  selfsigned_not_after: "+3650d"
  selfsigned_digest: sha256
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::X509CertificatePipe(c)) => {
                assert_eq!(c.privatekey_path, "/tmp/ca.key");
                assert!(c.privatekey_content.is_empty());
                assert_eq!(c.valid_for_days, 3650);
                assert_eq!(c.selfsigned_digest, "sha256");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn x509_pipe_relative_duration_year_unit() {
        let t = parse_task(
            r#"
name: c
x509_certificate_pipe:
  csr_content: x
  privatekey_content: y
  selfsigned_not_after: "+1y"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::X509CertificatePipe(c)) => {
                assert_eq!(c.valid_for_days, 365);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn x509_pipe_jinja_not_after_is_deferred() {
        // gothab's etcd role spells the cert validity as a Jinja
        // template against a role var:
        //   selfsigned_not_after: "+{{ etcd_cert_validity_days }}d"
        // Parse-time validation must not reject the template — it
        // must store it as `not_after_template` and leave parsing to
        // the dispatch-time render pass.
        let t = parse_task(
            r#"
name: c
x509_certificate_pipe:
  csr_content: x
  privatekey_content: y
  selfsigned_not_after: "+{{ etcd_cert_validity_days }}d"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::X509CertificatePipe(c)) => {
                assert_eq!(c.not_after_template, "+{{ etcd_cert_validity_days }}d");
                // valid_for_days falls back to the default placeholder
                // — render arm overwrites at dispatch.
                assert_eq!(c.valid_for_days, 365);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn x509_pipe_rejects_both_privkey_sources() {
        let err = try_parse_task(
            r#"
name: c
x509_certificate_pipe:
  csr_content: x
  privatekey_content: y
  privatekey_path: /tmp/k
"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("exactly one"));
    }

    #[test]
    fn x509_pipe_rejects_neither_privkey_source() {
        let err = try_parse_task(
            r#"
name: c
x509_certificate_pipe:
  csr_content: x
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("privatekey_content") || msg.contains("required"), "got: {msg}");
    }

    #[test]
    fn x509_pipe_rejects_valid_for_days_and_not_after_together() {
        let err = try_parse_task(
            r#"
name: c
x509_certificate_pipe:
  csr_content: x
  privatekey_content: y
  valid_for_days: 30
  selfsigned_not_after: "+30d"
"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not both"));
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
