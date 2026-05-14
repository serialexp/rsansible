//! Ansible Vault file decryption.
//!
//! Format:
//!
//! ```text
//! $ANSIBLE_VAULT;1.1;AES256
//! 64616666...      (hex-encoded body, wrapped at 80 cols)
//! ```
//!
//! The body, once de-hexed, is itself a `\n`-separated sequence of three
//! hex strings: `salt`, `hmac`, `ciphertext`. Key material comes from
//! PBKDF2-HMAC-SHA256(password, salt, 10000, 80 bytes), split into
//! AES-256 key (32) / HMAC-SHA256 key (32) / AES-CTR counter (16). HMAC
//! is verified constant-time over the ciphertext before AES-CTR decrypts.
//! PKCS#7 padding stripped at the end.
//!
//! Format `1.2` is identical except the header has a fourth segment with
//! a "vault label". We accept (and ignore) the label — we don't do
//! multi-vault routing.
//!
//! `1.0` (pre-AES256) is rejected; nobody using rsansible has a 1.0 file.

use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const PBKDF2_ROUNDS: u32 = 10_000;
const KEY_LEN: usize = 32;
const HMAC_KEY_LEN: usize = 32;
const COUNTER_LEN: usize = 16;
const DERIVED_LEN: usize = KEY_LEN + HMAC_KEY_LEN + COUNTER_LEN;

/// Return true if `bytes` begin with an `$ANSIBLE_VAULT;` header. Cheap
/// enough that file loaders can check every YAML before trying to parse.
pub fn is_vault(bytes: &[u8]) -> bool {
    bytes.starts_with(b"$ANSIBLE_VAULT;")
}

/// Decrypt a vault file (raw bytes off disk) using `password`. Returns the
/// plaintext bytes; the caller can hand them to `serde_yaml::from_slice`.
pub fn decrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).context("vault file is not UTF-8")?;
    let mut lines = text.lines();
    let header = lines.next().ok_or_else(|| anyhow!("vault file is empty"))?;
    parse_header(header)?;

    // Body: every remaining line concatenated, whitespace stripped, then
    // hex-decoded. The de-hexed bytes are a `\n`-separated triple of more
    // hex strings.
    let mut hex_body = String::new();
    for line in lines {
        for c in line.chars() {
            if !c.is_whitespace() {
                hex_body.push(c);
            }
        }
    }
    let outer = hex::decode(&hex_body).context("vault body: outer hex decode failed")?;
    let outer_text =
        std::str::from_utf8(&outer).context("vault body: inner blob is not UTF-8")?;
    let parts: Vec<&str> = outer_text.split('\n').collect();
    if parts.len() != 3 {
        bail!(
            "vault body: expected 3 newline-separated hex parts (salt, hmac, ciphertext), got {}",
            parts.len()
        );
    }
    let salt = hex::decode(parts[0]).context("vault: salt hex decode failed")?;
    let stored_hmac = hex::decode(parts[1]).context("vault: hmac hex decode failed")?;
    let ciphertext = hex::decode(parts[2]).context("vault: ciphertext hex decode failed")?;

    let mut derived = [0u8; DERIVED_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ROUNDS, &mut derived);
    let aes_key = &derived[..KEY_LEN];
    let hmac_key = &derived[KEY_LEN..KEY_LEN + HMAC_KEY_LEN];
    let counter = &derived[KEY_LEN + HMAC_KEY_LEN..];

    // Verify HMAC first (constant-time) — fail fast on wrong password.
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .map_err(|e| anyhow!("vault: bad hmac key length: {e}"))?;
    mac.update(&ciphertext);
    let computed = mac.finalize().into_bytes();
    if computed.as_slice().ct_eq(&stored_hmac).unwrap_u8() != 1 {
        bail!("vault: HMAC mismatch — wrong password or corrupted file");
    }

    // AES-256-CTR decrypt in place.
    let mut buf = ciphertext;
    let mut cipher = Aes256Ctr::new_from_slices(aes_key, counter)
        .map_err(|e| anyhow!("vault: AES key/counter setup failed: {e}"))?;
    cipher.apply_keystream(&mut buf);

    // Strip PKCS#7 padding.
    let pad = *buf.last().ok_or_else(|| anyhow!("vault: empty plaintext"))?;
    if pad == 0 || pad as usize > buf.len() {
        bail!("vault: invalid PKCS#7 padding byte {pad}");
    }
    let cut = buf.len() - pad as usize;
    if !buf[cut..].iter().all(|&b| b == pad) {
        bail!("vault: PKCS#7 padding bytes inconsistent");
    }
    buf.truncate(cut);
    Ok(buf)
}

/// Parse and accept an `$ANSIBLE_VAULT;<ver>;<cipher>[;<label>]` header.
fn parse_header(header: &str) -> Result<()> {
    let header = header.trim();
    let rest = header
        .strip_prefix("$ANSIBLE_VAULT;")
        .ok_or_else(|| anyhow!("vault: missing $ANSIBLE_VAULT; prefix"))?;
    let mut parts = rest.split(';');
    let version = parts.next().ok_or_else(|| anyhow!("vault: missing version"))?;
    let cipher = parts.next().ok_or_else(|| anyhow!("vault: missing cipher"))?;
    let _label = parts.next(); // 1.2 attaches a label; ignored
    match version {
        "1.1" | "1.2" => {}
        "1.0" => bail!(
            "vault: format 1.0 is not supported — re-encrypt with `ansible-vault rekey` to 1.1+"
        ),
        other => bail!("vault: unsupported format version {other:?}"),
    }
    if cipher != "AES256" {
        bail!("vault: unsupported cipher {cipher:?} (only AES256 is supported)");
    }
    Ok(())
}

/// Resolve a vault password from CLI flag, env var, or `None`.
///
/// 1. If `cli_path` is `Some`, read the file at that path.
/// 2. Else if `ANSIBLE_VAULT_PASSWORD_FILE` env var is set, read that.
/// 3. Else return `None`.
///
/// The password file's trailing newline (if any) is stripped — `echo
/// foo > pw` and `printf foo > pw` should produce the same password.
pub fn resolve_password_from(cli_path: Option<&std::path::Path>) -> Result<Option<String>> {
    let path = match cli_path {
        Some(p) => Some(p.to_path_buf()),
        None => std::env::var_os("ANSIBLE_VAULT_PASSWORD_FILE").map(std::path::PathBuf::from),
    };
    let Some(path) = path else { return Ok(None) };
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading vault password file {}", path.display()))?;
    let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
    Ok(Some(trimmed))
}

/// Encrypt `plaintext` under `password` with a fixed `salt`. Public so
/// integration tests in `tests/` can produce vault fixtures; the
/// production code path is decrypt-only.
pub fn encrypt_for_test(plaintext: &[u8], password: &str, salt: &[u8; 32]) -> Vec<u8> {
    let mut derived = [0u8; DERIVED_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut derived);
    let aes_key = &derived[..KEY_LEN];
    let hmac_key = &derived[KEY_LEN..KEY_LEN + HMAC_KEY_LEN];
    let counter = &derived[KEY_LEN + HMAC_KEY_LEN..];

    // PKCS#7 pad to 16-byte boundary.
    let block = 16usize;
    let pad = block - (plaintext.len() % block);
    let mut buf = Vec::with_capacity(plaintext.len() + pad);
    buf.extend_from_slice(plaintext);
    buf.extend(std::iter::repeat(pad as u8).take(pad));

    let mut cipher = Aes256Ctr::new_from_slices(aes_key, counter).unwrap();
    cipher.apply_keystream(&mut buf);

    let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
    mac.update(&buf);
    let tag = mac.finalize().into_bytes();

    let inner = format!("{}\n{}\n{}", hex::encode(salt), hex::encode(tag), hex::encode(&buf));
    let outer = hex::encode(inner.as_bytes());

    let mut out = String::from("$ANSIBLE_VAULT;1.1;AES256\n");
    // Wrap at 80 chars for readability — not required by parser but
    // mirrors what `ansible-vault` writes.
    for chunk in outer.as_bytes().chunks(80) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_vault_header() {
        assert!(is_vault(b"$ANSIBLE_VAULT;1.1;AES256\nabc\n"));
        assert!(!is_vault(b"key: value\n"));
    }

    #[test]
    fn rejects_1_0_header() {
        let err = decrypt(b"$ANSIBLE_VAULT;1.0;AES\nabc\n", "x").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("1.0"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_cipher() {
        let err = decrypt(b"$ANSIBLE_VAULT;1.1;CHACHA20\nabc\n", "x").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("AES256"), "got: {msg}");
    }

    #[test]
    fn accepts_1_2_header_with_label() {
        // `1.2` adds a vault label that we accept and ignore. The body is
        // invalid hex, so decryption still bails — but only after the
        // header was parsed successfully.
        let err = decrypt(b"$ANSIBLE_VAULT;1.2;AES256;production\nzz\n", "x").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("hex"), "expected hex-decode error after header accept; got: {msg}");
    }

    #[test]
    fn roundtrip_known_plaintext() {
        let plaintext = b"secret_value: hunter2\n";
        let salt = [0x11u8; 32];
        let ct = encrypt_for_test(plaintext, "testpass", &salt);
        let pt = decrypt(&ct, "testpass").expect("decrypt ok");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn roundtrip_block_aligned_plaintext() {
        // Block-aligned (16 byte) plaintext exercises the "full pad block"
        // PKCS#7 case where the last block is all `0x10`.
        let plaintext = b"sixteen-bytes!!\n";
        assert_eq!(plaintext.len() % 16, 0);
        let salt = [0x22u8; 32];
        let ct = encrypt_for_test(plaintext, "pw", &salt);
        let pt = decrypt(&ct, "pw").expect("decrypt ok");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_password_fails_with_hmac_mismatch() {
        let plaintext = b"x\n";
        let salt = [0x33u8; 32];
        let ct = encrypt_for_test(plaintext, "right", &salt);
        let err = decrypt(&ct, "WRONG").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("HMAC"), "got: {msg}");
    }

    #[test]
    fn truncated_body_rejected() {
        let bad = "$ANSIBLE_VAULT;1.1;AES256\n3561\n";
        let err = decrypt(bad.as_bytes(), "x").unwrap_err();
        let msg = format!("{err:#}");
        // Either inner-text-not-utf8 OR not-3-parts — both are valid rejections.
        assert!(
            msg.contains("3") || msg.contains("UTF-8") || msg.contains("hex"),
            "got: {msg}"
        );
    }

    #[test]
    fn resolve_password_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pw");
        std::fs::write(&p, "secret\n").unwrap();
        let got = resolve_password_from(Some(&p)).unwrap();
        assert_eq!(got.as_deref(), Some("secret"));
    }

    #[test]
    fn resolve_password_returns_none_when_unset() {
        // Clear env var if set so this is deterministic.
        let prev = std::env::var_os("ANSIBLE_VAULT_PASSWORD_FILE");
        std::env::remove_var("ANSIBLE_VAULT_PASSWORD_FILE");
        let got = resolve_password_from(None).unwrap();
        assert!(got.is_none());
        if let Some(p) = prev {
            std::env::set_var("ANSIBLE_VAULT_PASSWORD_FILE", p);
        }
    }
}
