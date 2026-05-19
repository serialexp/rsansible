//! Shared `validate:` helper.
//!
//! Mirrors Ansible's `validate:` semantics on `copy` / `template` /
//! `lineinfile` / `blockinfile`: the staged tmp file is fed to a
//! user-supplied command before the rename. The command is tokenized
//! on whitespace and the literal token `%s` is replaced by the tmp
//! path. Non-zero exit => abort the rename, leave dest untouched, and
//! surface the validator's stderr in the agent's TaskError.
//!
//! We deliberately spawn `program args ...` rather than `sh -c
//! <command>` — this matches Ansible's behavior and avoids
//! shell-injection surface from playbook strings (`%s` substitution
//! happens after tokenization, so a tmp path containing whitespace
//! still lands as a single argv slot).
//!
//! The helper is **synchronous** (uses `std::process::Command`) so
//! the lineinfile / blockinfile modules — which do their own atomic
//! write with `std::fs` — can call it without async plumbing.
//! `write_file.rs` is on the tokio runtime; it wraps this call in
//! `tokio::task::spawn_blocking`, which is appropriate for a brief
//! validator that's usually <100ms (visudo, nginx -t, sshd -t).

use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug)]
pub enum ValidateError {
    /// The validate string is malformed (empty after tokenization,
    /// missing `%s` placeholder). Doesn't reach a process spawn.
    BadRequest(String),
    /// Validator ran but exited non-zero.
    Failed { code: i32, stderr: String },
    /// Validator couldn't be spawned (binary missing, EACCES, ...).
    Spawn(std::io::Error),
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidateError::BadRequest(msg) => write!(f, "{msg}"),
            ValidateError::Failed { code, stderr } => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    write!(f, "validate command exited {code}")
                } else {
                    write!(f, "validate command exited {code}: {trimmed}")
                }
            }
            ValidateError::Spawn(e) => write!(f, "validate spawn failed: {e}"),
        }
    }
}

/// Tokenize on whitespace, substitute `%s` with `tmp_path`, spawn the
/// result. Returns `Ok(())` on exit 0; everything else maps to a
/// `ValidateError` variant.
pub fn validate_tmp(validate: &str, tmp_path: &Path) -> Result<(), ValidateError> {
    let mut tokens = validate.split_whitespace();
    let prog = match tokens.next() {
        Some(p) => p.to_string(),
        None => {
            return Err(ValidateError::BadRequest(
                "validate: empty command after tokenization".into(),
            ))
        }
    };
    let mut args: Vec<String> = Vec::new();
    let mut substituted = false;
    let tmp_str = tmp_path.to_string_lossy();
    for tok in tokens {
        if tok.contains("%s") {
            // Replace `%s` anywhere inside the token. Matches
            // Ansible: `validate: 'vmagent -config=%s -dryRun'`
            // (gothab's vmagent task) and `validate: 'visudo -cf
            // %s'` (the canonical example with a standalone token)
            // are both valid forms. The previous "must equal `%s`
            // as a whole token" check rejected the embedded-arg
            // form, breaking real playbooks at module-validate
            // time. Caught in the gothab drill.
            args.push(tok.replace("%s", &tmp_str));
            substituted = true;
        } else {
            args.push(tok.to_string());
        }
    }
    if !substituted {
        return Err(ValidateError::BadRequest(format!(
            "validate: command must contain `%s` placeholder for the tmp path; got {validate:?}"
        )));
    }
    let out = Command::new(&prog)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(ValidateError::Spawn)?;
    if out.status.success() {
        Ok(())
    } else {
        // Prefer stderr; visudo / nginx -t / sshd -t write the
        // diagnostic to stderr. Fall back to stdout for tools that
        // misbehave.
        let stderr = if out.stderr.is_empty() {
            String::from_utf8_lossy(&out.stdout).into_owned()
        } else {
            String::from_utf8_lossy(&out.stderr).into_owned()
        };
        Err(ValidateError::Failed {
            code: out.status.code().unwrap_or(-1),
            stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_with_contents(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rsansible-validate-{name}-{}",
            std::process::id()
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn success_exits_zero() {
        let p = tmp_with_contents("ok", b"hello\n");
        validate_tmp("/bin/true %s", &p).expect("validator should pass");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn failure_returns_failed_with_code() {
        let p = tmp_with_contents("fail", b"bad\n");
        let err = validate_tmp("/bin/false %s", &p).expect_err("validator must fail");
        match err {
            ValidateError::Failed { code, .. } => assert_eq!(code, 1),
            other => panic!("expected Failed, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_command_without_percent_s() {
        let p = tmp_with_contents("no_s", b"x");
        let err = validate_tmp("/bin/true", &p).expect_err("must reject");
        match err {
            ValidateError::BadRequest(msg) => assert!(msg.contains("%s"), "msg: {msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_empty_command() {
        let p = tmp_with_contents("empty", b"x");
        let err = validate_tmp("   ", &p).expect_err("must reject");
        match err {
            ValidateError::BadRequest(_) => {}
            other => panic!("expected BadRequest, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn substitutes_percent_s_with_tmp_path() {
        // `test -f %s` succeeds only if the substituted path actually
        // exists — exercises both substitution and the success path.
        let p = tmp_with_contents("subst", b"x");
        validate_tmp("/usr/bin/test -f %s", &p).expect("file must exist after substitution");
        let _ = std::fs::remove_file(&p);
    }

    /// Regression: `%s` must be substituted whether it stands alone
    /// (`visudo -cf %s`) OR is embedded in an argument
    /// (`vmagent -promscrape.config=%s -dryRun`). The latter is how
    /// gothab's vmagent and many real-world validators are spelled,
    /// and rsansible used to reject those at module-validate time
    /// with "validate: command must contain `%s` placeholder"
    /// because we only matched the standalone-token form. Caught
    /// in the gothab live drill.
    #[test]
    fn substitutes_percent_s_embedded_in_argument() {
        let p = tmp_with_contents("embedded", b"x");
        // Before the fix, this returned BadRequest("must contain
        // `%s` placeholder") because `--file=%s` wasn't a whole-
        // token match. After the fix it should proceed to spawn —
        // and either succeed or fail-on-exit, but NOT BadRequest.
        let res = validate_tmp("/bin/cat --not-a-flag=%s", &p);
        match res {
            Err(ValidateError::BadRequest(msg)) => panic!(
                "embedded %s must be substituted, not rejected as BadRequest: {msg}"
            ),
            _ => {}
        }
        let _ = std::fs::remove_file(&p);
    }
}
