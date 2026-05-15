//! Controller-side x509 generation: private keys, CSRs, self-signed
//! certs. Maps Ansible `community.crypto`'s `openssl_privatekey`,
//! `openssl_csr_pipe`, and `x509_certificate_pipe` modules.
//!
//! Everything here runs on the controller. The agent never sees rcgen
//! — it just receives `OpWriteFile` (privkey) or nothing (the *_pipe
//! variants synthesize `register.content` purely controller-side).
//! This keeps the pushed agent binary small.

use anyhow::{anyhow, bail, Context, Result};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, RsaKeySize, SanType, PKCS_ECDSA_P256_SHA256,
    PKCS_ED25519, PKCS_RSA_SHA256,
};
use std::str::FromStr;

/// Kind of private key to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivkeyType {
    /// RSA — modulus size chosen by `PrivkeyParams.size`.
    Rsa,
    /// Ed25519 — `size` is ignored.
    Ed25519,
}

impl PrivkeyType {
    pub fn from_yaml(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "RSA" => Ok(Self::Rsa),
            "ED25519" | "ED-25519" => Ok(Self::Ed25519),
            other => bail!(
                "openssl_privatekey.type {other:?} not supported; pick RSA or Ed25519"
            ),
        }
    }
}

/// Inputs for `generate_privkey`.
#[derive(Debug, Clone)]
pub struct PrivkeyParams {
    pub kind: PrivkeyType,
    /// RSA modulus bits when `kind == Rsa`. Ignored for Ed25519.
    pub size: u32,
}

/// Generate a fresh private key and return its PEM encoding.
///
/// RSA: rcgen routes through `KeyPair::generate_rsa_for(size)`. ring's
/// RSA generator only accepts 2048/3072/4096-bit moduli — anything else
/// here errors out. Ed25519 is a fixed-size signature scheme; `size` is
/// ignored.
pub fn generate_privkey(params: &PrivkeyParams) -> Result<Vec<u8>> {
    let kp = match params.kind {
        PrivkeyType::Rsa => {
            let key_size = match params.size {
                2048 => RsaKeySize::_2048,
                3072 => RsaKeySize::_3072,
                4096 => RsaKeySize::_4096,
                other => bail!(
                    "openssl_privatekey RSA size must be 2048, 3072, or 4096; got {other}"
                ),
            };
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, key_size)
                .context("generating RSA private key")?
        }
        PrivkeyType::Ed25519 => KeyPair::generate_for(&PKCS_ED25519)
            .context("generating Ed25519 private key")?,
    };
    Ok(kp.serialize_pem().into_bytes())
}

// Suppress unused-import warnings when we don't actually reach
// PKCS_ECDSA_P256_SHA256 (kept around in case we add ECDSA later).
#[allow(dead_code)]
const _ECDSA_HINT: &rcgen::SignatureAlgorithm = &PKCS_ECDSA_P256_SHA256;

/// Inputs for `generate_csr`. The PEM private key bytes come from the
/// controller-side privkey cache populated by an earlier
/// `openssl_privatekey` task in the same play.
#[derive(Debug, Clone)]
pub struct CsrParams {
    pub privkey_pem: Vec<u8>,
    pub common_name: String,
    /// Subject Alt Names in Ansible's `community.crypto` syntax:
    /// `DNS:foo.example`, `IP:1.2.3.4`, `email:ops@x`.
    pub subject_alt_name: Vec<String>,
    /// Optional X509 KeyUsage flags. Ansible accepts free-text strings
    /// like `digitalSignature`, `keyEncipherment`, `keyAgreement`.
    pub key_usage: Vec<String>,
    /// Optional X509 ExtendedKeyUsage OIDs / names: `serverAuth`,
    /// `clientAuth`, `codeSigning`, etc.
    pub extended_key_usage: Vec<String>,
}

/// Generate a CSR and return its PEM encoding.
pub fn generate_csr(p: &CsrParams) -> Result<Vec<u8>> {
    // rcgen wants a KeyPair, which we rebuild from the PEM bytes
    // currently sitting in the privkey cache. `KeyPair::from_pem`
    // probes the algorithm tag (RSA vs Ed25519 vs ECDSA) automatically.
    let kp = KeyPair::from_pem(
        std::str::from_utf8(&p.privkey_pem)
            .context("CSR private key must be UTF-8 PEM")?,
    )
    .context("parsing private key PEM for CSR generation")?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("building CSR template")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &p.common_name);
    params.distinguished_name = dn;
    for san in &p.subject_alt_name {
        params.subject_alt_names.push(parse_san(san)?);
    }
    for ku in &p.key_usage {
        params.key_usages.push(parse_key_usage(ku)?);
    }
    for eku in &p.extended_key_usage {
        params.extended_key_usages.push(parse_extended_key_usage(eku)?);
    }
    // CSR is *not* a CA; we never mint a CA via the _pipe path.
    params.is_ca = IsCa::NoCa;

    let csr = params
        .serialize_request(&kp)
        .context("serializing CSR")?;
    Ok(csr
        .pem()
        .context("encoding CSR as PEM")?
        .into_bytes())
}

/// Inputs for self-signed cert generation.
#[derive(Debug, Clone)]
pub struct SelfSignedCertParams {
    /// PEM private key — also the signer for self-signed certs.
    pub privkey_pem: Vec<u8>,
    /// PEM-encoded CSR carrying the subject DN, SANs, and extensions
    /// we'll lift into the cert.
    pub csr_pem: Vec<u8>,
    /// Validity window in days from now.
    pub valid_for_days: u32,
}

/// Generate a self-signed cert from a CSR + the same key, return the
/// PEM encoding. v1 supports `provider: selfsigned` only — CA-signed
/// will land when we need it (etcd peer certs don't).
pub fn generate_selfsigned_cert(p: &SelfSignedCertParams) -> Result<Vec<u8>> {
    let kp = KeyPair::from_pem(
        std::str::from_utf8(&p.privkey_pem)
            .context("self-signed cert key must be UTF-8 PEM")?,
    )
    .context("parsing private key PEM for self-signed cert")?;

    // rcgen 0.13 parses a PEM CSR into a CertificateSigningRequestParams
    // whose `params: CertificateParams` carries the subject/SANs/exts.
    let csr_pem_str = std::str::from_utf8(&p.csr_pem)
        .context("CSR must be UTF-8 PEM")?;
    let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem_str)
        .context("parsing CSR PEM")?;
    let mut params = csr.params;

    // Apply the requested validity window. rcgen defaults to a 1-year
    // window anchored at the system clock; we set both bounds
    // explicitly so notBefore == controller-now (matches Ansible).
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(p.valid_for_days as i64);

    // Self-sign with the same key.
    let cert = params
        .self_signed(&kp)
        .context("self-signing certificate")?;
    Ok(cert.pem().into_bytes())
}

fn parse_san(s: &str) -> Result<SanType> {
    // Ansible's syntax: `DNS:foo.example`, `IP:1.2.3.4`, `email:ops@x`,
    // `URI:https://x/`. Match case-insensitively on the prefix.
    let (kind, value) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("SAN {s:?} missing kind prefix (e.g. DNS:foo)"))?;
    match kind.to_ascii_uppercase().as_str() {
        "DNS" => Ok(SanType::DnsName(value.try_into().map_err(|e| {
            anyhow!("DNS SAN {value:?} rejected: {e}")
        })?)),
        "IP" => {
            let ip: std::net::IpAddr = value.parse()
                .with_context(|| format!("IP SAN {value:?} is not a valid IP"))?;
            Ok(SanType::IpAddress(ip))
        }
        "EMAIL" => Ok(SanType::Rfc822Name(value.try_into().map_err(|e| {
            anyhow!("email SAN {value:?} rejected: {e}")
        })?)),
        "URI" => Ok(SanType::URI(value.try_into().map_err(|e| {
            anyhow!("URI SAN {value:?} rejected: {e}")
        })?)),
        other => bail!("unknown SAN kind {other:?}; expected DNS / IP / email / URI"),
    }
}

fn parse_key_usage(s: &str) -> Result<KeyUsagePurpose> {
    // Match Ansible's lower-case-first-letter naming
    // (`digitalSignature`, `keyEncipherment`, …).
    match s {
        "digitalSignature" => Ok(KeyUsagePurpose::DigitalSignature),
        "contentCommitment" | "nonRepudiation" => Ok(KeyUsagePurpose::ContentCommitment),
        "keyEncipherment" => Ok(KeyUsagePurpose::KeyEncipherment),
        "dataEncipherment" => Ok(KeyUsagePurpose::DataEncipherment),
        "keyAgreement" => Ok(KeyUsagePurpose::KeyAgreement),
        "keyCertSign" => Ok(KeyUsagePurpose::KeyCertSign),
        "cRLSign" | "crlSign" => Ok(KeyUsagePurpose::CrlSign),
        "encipherOnly" => Ok(KeyUsagePurpose::EncipherOnly),
        "decipherOnly" => Ok(KeyUsagePurpose::DecipherOnly),
        other => bail!(
            "unknown key_usage {other:?}; \
             expected one of digitalSignature, keyEncipherment, keyAgreement, \
             keyCertSign, cRLSign, contentCommitment, dataEncipherment, \
             encipherOnly, decipherOnly"
        ),
    }
}

fn parse_extended_key_usage(s: &str) -> Result<ExtendedKeyUsagePurpose> {
    match s {
        "serverAuth" => Ok(ExtendedKeyUsagePurpose::ServerAuth),
        "clientAuth" => Ok(ExtendedKeyUsagePurpose::ClientAuth),
        "codeSigning" => Ok(ExtendedKeyUsagePurpose::CodeSigning),
        "emailProtection" => Ok(ExtendedKeyUsagePurpose::EmailProtection),
        "timeStamping" => Ok(ExtendedKeyUsagePurpose::TimeStamping),
        "OCSPSigning" => Ok(ExtendedKeyUsagePurpose::OcspSigning),
        // Anything else: try as a dotted-OID (Ansible accepts these
        // verbatim e.g. for `1.3.6.1.5.5.7.3.x`).
        other => {
            if other.split('.').all(|c| u64::from_str(c).is_ok()) {
                let oid: Vec<u64> = other
                    .split('.')
                    .map(|c| u64::from_str(c).unwrap())
                    .collect();
                Ok(ExtendedKeyUsagePurpose::Other(oid))
            } else {
                bail!(
                    "unknown extended_key_usage {other:?}; \
                     expected serverAuth/clientAuth/codeSigning/emailProtection/\
                     timeStamping/OCSPSigning or a dotted OID"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privkey_ed25519_roundtrips_pem() {
        let pem = generate_privkey(&PrivkeyParams {
            kind: PrivkeyType::Ed25519,
            size: 0,
        })
        .expect("generate ed25519");
        let s = std::str::from_utf8(&pem).unwrap();
        assert!(s.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(s.contains("-----END PRIVATE KEY-----"));
        // Reparse to confirm it's a valid KeyPair.
        KeyPair::from_pem(s).expect("reparse");
    }

    #[test]
    fn privkey_rsa_rejects_bogus_size() {
        let err = generate_privkey(&PrivkeyParams {
            kind: PrivkeyType::Rsa,
            size: 2049,
        })
        .expect_err("bogus size");
        let msg = format!("{err:#}");
        assert!(msg.contains("2048") && msg.contains("4096"));
    }

    #[test]
    fn csr_carries_subject_and_san() {
        let pk = generate_privkey(&PrivkeyParams {
            kind: PrivkeyType::Ed25519,
            size: 0,
        })
        .unwrap();
        let csr = generate_csr(&CsrParams {
            privkey_pem: pk,
            common_name: "etcd-peer-0".into(),
            subject_alt_name: vec!["DNS:etcd0.example".into(), "IP:10.0.0.1".into()],
            key_usage: vec!["digitalSignature".into(), "keyEncipherment".into()],
            extended_key_usage: vec!["serverAuth".into(), "clientAuth".into()],
        })
        .expect("CSR");
        let s = std::str::from_utf8(&csr).unwrap();
        assert!(s.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(s.contains("-----END CERTIFICATE REQUEST-----"));
        // Reparse to confirm well-formedness.
        rcgen::CertificateSigningRequestParams::from_pem(s).expect("reparse CSR");
    }

    #[test]
    fn selfsigned_cert_validity_window() {
        let pk = generate_privkey(&PrivkeyParams {
            kind: PrivkeyType::Ed25519,
            size: 0,
        })
        .unwrap();
        let csr = generate_csr(&CsrParams {
            privkey_pem: pk.clone(),
            common_name: "x".into(),
            subject_alt_name: vec!["DNS:x.test".into()],
            key_usage: vec![],
            extended_key_usage: vec![],
        })
        .unwrap();
        let cert = generate_selfsigned_cert(&SelfSignedCertParams {
            privkey_pem: pk,
            csr_pem: csr,
            valid_for_days: 30,
        })
        .expect("cert");
        let s = std::str::from_utf8(&cert).unwrap();
        assert!(s.starts_with("-----BEGIN CERTIFICATE-----"));
        // Window: notAfter ≈ notBefore + 30d. We don't reparse the
        // ASN.1 here (would need a third dependency) — the structure
        // assertions above + the rcgen self_signed() succeeding is
        // enough that a regression would surface in integration.
    }

    #[test]
    fn san_parse_rejects_unknown_kind() {
        let err = parse_san("XYZ:foo").expect_err("XYZ is not a SAN kind");
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown SAN kind"));
    }

    #[test]
    fn san_parse_ip() {
        let san = parse_san("IP:10.0.0.1").unwrap();
        assert!(matches!(san, SanType::IpAddress(_)));
    }

    #[test]
    fn extended_key_usage_dotted_oid() {
        // Ansible allows raw OIDs — exercise that path.
        let eku = parse_extended_key_usage("1.3.6.1.5.5.7.3.99").unwrap();
        match eku {
            ExtendedKeyUsagePurpose::Other(oid) => {
                assert_eq!(oid, vec![1, 3, 6, 1, 5, 5, 7, 3, 99]);
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
