//! Deciding whether a Postgres role's password actually needs changing.
//!
//! `postgresql_user:` is handed a plaintext password and has to answer a
//! question the server will not answer for it: *is this already the
//! password?* Postgres stores a verifier, never the password, and the
//! verifier for the same plaintext differs every time it is computed
//! (the salt is random). So a naive implementation re-issues
//! `ALTER ROLE ... PASSWORD` on every run and reports `changed` forever
//! — which is what this module exists to stop.
//!
//! The verifier is reproducible if you keep the salt, and Postgres
//! stores the salt inside it. Both formats are self-describing:
//!
//! ```text
//! SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>   (PG10+, default since PG14)
//! md5<md5-hex of password ++ username>                        (legacy)
//! ```
//!
//! So we can recompute and compare, which is exactly what Ansible's
//! `community.postgresql` does. (It compares the ServerKey only; we
//! compare both keys, which costs nothing extra — the expensive part is
//! the PBKDF2 that produces them.)
//!
//! **Every uncertainty resolves to "change it".** An unparseable
//! verifier, a hash type we don't recognise, an absurd iteration count,
//! a password we cannot normalise the way the server would — all return
//! `true`. Being wrong in that direction costs a redundant `ALTER ROLE`
//! and a spurious `changed`, i.e. exactly the old behaviour. Being wrong
//! in the other direction would silently leave the role on a stale
//! password, and the operator would have no way to tell from the run
//! output that their change had not been applied.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Postgres' own default is 4096. A hostile or corrupt verifier could
/// claim millions and turn an idempotency check into a CPU burn, so cap
/// it well above any plausible real value and treat anything past that
/// as "cannot verify".
const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;

/// Does this role need `ALTER ROLE ... PASSWORD`?
///
/// `current` is the role's `rolpassword` from `pg_authid` (`None` when
/// the role has no password set).
pub(crate) fn needs_password_change(password: &str, username: &str, current: Option<&str>) -> bool {
    if password.is_empty() {
        // The caller treats "no password requested" as "don't touch the
        // password", not as "remove it".
        return false;
    }
    let Some(current) = current else {
        // Role exists with no password at all. Definitely set one.
        return true;
    };

    // The operator may pass an already-hashed verifier instead of a
    // plaintext password, in which case it is compared literally — there
    // is nothing to derive. Postgres accepts this form in
    // `ALTER ROLE ... PASSWORD` and stores it verbatim.
    if looks_like_verifier(password) {
        return password != current;
    }

    if let Some(rest) = current.strip_prefix("SCRAM-SHA-256$") {
        return scram_differs(password, rest);
    }
    if let Some(hex) = current.strip_prefix("md5") {
        // Legacy md5 verifier: md5(password ++ username), hex.
        if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true;
        }
        let mut h = Md5::new();
        h.update(password.as_bytes());
        h.update(username.as_bytes());
        let want = hex::encode(h.finalize());
        return !bool::from(want.as_bytes().ct_eq(hex.to_ascii_lowercase().as_bytes()));
    }

    // Some other hash type, or a plaintext password stored by a very old
    // server. Not something we can verify.
    true
}

/// Is this string already a Postgres password verifier rather than a
/// plaintext password?
fn looks_like_verifier(s: &str) -> bool {
    s.starts_with("SCRAM-SHA-256$")
        || (s.len() == 35 && s.starts_with("md5") && s[3..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `rest` is everything after the `SCRAM-SHA-256$` prefix:
/// `<iterations>:<salt>$<StoredKey>:<ServerKey>`, all three keys base64.
///
/// Returns true (change the password) whenever the envelope cannot be
/// parsed or the plaintext cannot be normalised the way the server
/// would have normalised it.
fn scram_differs(password: &str, rest: &str) -> bool {
    let Some((params, keys)) = rest.split_once('$') else {
        return true;
    };
    let Some((iterations, salt_b64)) = params.split_once(':') else {
        return true;
    };
    let Some((stored_b64, server_b64)) = keys.split_once(':') else {
        return true;
    };
    let Ok(iterations) = iterations.parse::<u32>() else {
        return true;
    };
    if iterations == 0 || iterations > MAX_SCRAM_ITERATIONS {
        return true;
    }
    let (Ok(salt), Ok(stored), Ok(server)) = (
        B64.decode(salt_b64),
        B64.decode(stored_b64),
        B64.decode(server_b64),
    ) else {
        return true;
    };

    // RFC 5802: SaltedPassword := Hi(Normalize(password), salt, i).
    // `Normalize` is SASLprep, which we do not implement — for anything
    // outside printable ASCII it can reorder, fold, or reject characters,
    // and guessing wrong would mean reporting "unchanged" for a password
    // that is actually different. Printable ASCII — space included, which
    // SASLprep maps to itself — passes through untouched, so that is the
    // case we verify and the rest we defer on.
    if !password.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return true;
    }

    let mut salted = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut salted);

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    // StoredKey := H(ClientKey)
    // ServerKey := HMAC(SaltedPassword, "Server Key")
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = Sha256::digest(client_key);
    let server_key = hmac_sha256(&salted, b"Server Key");

    let same = stored_key.as_slice().ct_eq(&stored) & server_key.as_slice().ct_eq(&server);
    !bool::from(same)
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Verifier construction, for tests elsewhere in the crate that need a
/// realistic `rolpassword` value. Builds it the way Postgres would, so
/// the tests exercise the real derivation rather than a pasted fixture
/// that could drift away from the code that has to match it.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn scram_verifier(password: &str, salt: &[u8], iterations: u32) -> String {
        let mut salted = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = Sha256::digest(client_key);
        let server_key = hmac_sha256(&salted, b"Server Key");
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            iterations,
            B64.encode(salt),
            B64.encode(stored_key),
            B64.encode(server_key),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::scram_verifier;
    use super::*;

    fn md5_verifier(password: &str, username: &str) -> String {
        let mut h = Md5::new();
        h.update(password.as_bytes());
        h.update(username.as_bytes());
        format!("md5{}", hex::encode(h.finalize()))
    }

    #[test]
    fn matching_scram_password_needs_no_change() {
        let v = scram_verifier("hunter2", b"sixteenbytesalt!", 4096);
        assert!(!needs_password_change("hunter2", "app", Some(&v)));
    }

    #[test]
    fn different_scram_password_needs_a_change() {
        let v = scram_verifier("hunter2", b"sixteenbytesalt!", 4096);
        assert!(needs_password_change("hunter3", "app", Some(&v)));
    }

    /// The salt is what makes two verifiers for the same password
    /// differ; recomputing with the *stored* salt is the whole trick.
    #[test]
    fn the_same_password_under_a_different_salt_still_matches() {
        let a = scram_verifier("hunter2", b"first-salt-here!", 4096);
        let b = scram_verifier("hunter2", b"second-salt-here", 4096);
        assert_ne!(a, b, "fixture is pointless if the verifiers are equal");
        assert!(!needs_password_change("hunter2", "app", Some(&a)));
        assert!(!needs_password_change("hunter2", "app", Some(&b)));
    }

    #[test]
    fn a_non_default_iteration_count_is_honoured() {
        let v = scram_verifier("hunter2", b"sixteenbytesalt!", 8192);
        assert!(!needs_password_change("hunter2", "app", Some(&v)));
    }

    #[test]
    fn matching_md5_password_needs_no_change() {
        let v = md5_verifier("hunter2", "app");
        assert!(!needs_password_change("hunter2", "app", Some(&v)));
    }

    /// The md5 verifier hashes password ++ *username*, so the same
    /// password on a different role is a different verifier.
    #[test]
    fn md5_is_bound_to_the_username() {
        let v = md5_verifier("hunter2", "app");
        assert!(needs_password_change("hunter2", "other", Some(&v)));
    }

    #[test]
    fn a_role_with_no_password_gets_one() {
        assert!(needs_password_change("hunter2", "app", None));
    }

    #[test]
    fn no_requested_password_means_leave_it_alone() {
        let v = scram_verifier("hunter2", b"sixteenbytesalt!", 4096);
        assert!(!needs_password_change("", "app", Some(&v)));
        assert!(!needs_password_change("", "app", None));
    }

    /// An operator may supply the verifier itself instead of a
    /// plaintext; then there is nothing to derive and it compares
    /// literally.
    #[test]
    fn a_prehashed_password_is_compared_verbatim() {
        let v = scram_verifier("hunter2", b"sixteenbytesalt!", 4096);
        assert!(!needs_password_change(&v, "app", Some(&v)));
        let other = scram_verifier("hunter3", b"sixteenbytesalt!", 4096);
        assert!(needs_password_change(&other, "app", Some(&v)));

        let m = md5_verifier("hunter2", "app");
        assert!(!needs_password_change(&m, "app", Some(&m)));
    }

    /// Every unparseable shape must fail toward "change it" — a wrong
    /// "no change here" would leave the role on a stale password with
    /// nothing in the run output to say so.
    #[test]
    fn unverifiable_verifiers_all_fail_toward_changing() {
        for current in [
            "SCRAM-SHA-256$4096",                      // no key section
            "SCRAM-SHA-256$4096:c2FsdA==",             // no key section
            "SCRAM-SHA-256$4096c2FsdA==$aaa:bbb",      // no iterations separator
            "SCRAM-SHA-256$notanumber:c2FsdA==$aa:bb", // iterations not a number
            "SCRAM-SHA-256$0:c2FsdA==$aa:bb",          // zero iterations
            "SCRAM-SHA-256$99999999:c2FsdA==$aa:bb",   // absurd iterations
            "SCRAM-SHA-256$4096:!!notbase64!!$aa:bb",  // undecodable salt
            "SCRAM-SHA-256$4096:c2FsdA==$aaa",         // no key separator
            "md5",                                     // truncated
            "md5nothexatall",                          // not hex
            "md5deadbeef",                             // wrong length
            "SHA-512$whatever",                        // unknown scheme
            "",                                        // empty
        ] {
            assert!(
                needs_password_change("hunter2", "app", Some(current)),
                "should have failed toward changing: {current:?}"
            );
        }
    }

    /// SASLprep is not implemented, so a password containing anything
    /// outside printable ASCII cannot be checked and defers to a change
    /// — including when it is in fact the current password.
    #[test]
    fn a_non_ascii_password_defers_to_changing() {
        let v = scram_verifier("pässwörd", b"sixteenbytesalt!", 4096);
        assert!(needs_password_change("pässwörd", "app", Some(&v)));
    }

    /// A space is ordinary printable ASCII and SASLprep maps it to
    /// itself, so a passphrase with spaces is verified like any other
    /// rather than being pushed onto the conservative path.
    #[test]
    fn a_password_with_a_space_is_still_verified() {
        let v = scram_verifier("correct horse battery staple", b"sixteenbytesalt!", 4096);
        assert!(!needs_password_change(
            "correct horse battery staple",
            "app",
            Some(&v)
        ));
        assert!(needs_password_change(
            "correct horse battery stapler",
            "app",
            Some(&v)
        ));
    }
}
