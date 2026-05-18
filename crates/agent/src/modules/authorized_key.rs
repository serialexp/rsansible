//! `OpAuthorizedKey` — idempotent line management for
//! `~<user>/.ssh/authorized_keys`.
//!
//! Idempotency identity: two key lines are "the same key" if their
//! `(type, key-body)` pair matches. Comment trailing the key body is
//! ignored for matching but preserved verbatim on insertion. This
//! mirrors Ansible's `authorized_key` — re-running with a tweaked
//! comment doesn't add a duplicate.
//!
//! Layout it manages:
//!   ~user/.ssh/                mode 0700, owned by user:user
//!   ~user/.ssh/authorized_keys mode 0600, owned by user:user
//!
//! Atomic update: write tmp file in the same directory, chmod 0600,
//! chown to user, rename over the target. If the .ssh dir doesn't
//! exist, create it owned by the user with 0700 first.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use rsansible_wire::generated::OpAuthorizedKeyOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpAuthorizedKeyOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    if op.user.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "authorized_key: empty `user`").await;
        return Ok(());
    }
    if op.key.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "authorized_key: empty `key`").await;
        return Ok(());
    }
    let result = tokio::task::spawn_blocking(move || apply(&op, check_mode))
        .await
        .map_err(|e| anyhow::anyhow!("authorized_key join: {e}"))?;
    match result {
        Ok(changed) => {
            ctx.emit(msg::task_done(
                seq,
                0,
                changed,
                false,
                started_unix_ns,
                now_unix_ns(),
            ))
            .await;
        }
        Err(AuthorizedKeyError::Io(m)) => emit_error(ctx, seq, err::IO, m).await,
        Err(AuthorizedKeyError::Spawn(m)) => emit_error(ctx, seq, err::SPAWN_FAILED, m).await,
        Err(AuthorizedKeyError::BadRequest(m)) => {
            emit_error(ctx, seq, err::BAD_REQUEST, m).await
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum AuthorizedKeyError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

pub(crate) struct Bins {
    pub getent: String,
    pub chown: String,
}
impl Bins {
    pub fn from_env() -> Self {
        Self {
            getent: std::env::var("RSANSIBLE_GETENT").unwrap_or_else(|_| "getent".into()),
            chown: std::env::var("RSANSIBLE_CHOWN").unwrap_or_else(|_| "chown".into()),
        }
    }
}

pub(crate) fn apply(
    op: &OpAuthorizedKeyOutput,
    check_mode: bool,
) -> Result<bool, AuthorizedKeyError> {
    apply_with_paths(&Bins::from_env(), op, check_mode)
}

pub(crate) fn apply_with_paths(
    bins: &Bins,
    op: &OpAuthorizedKeyOutput,
    check_mode: bool,
) -> Result<bool, AuthorizedKeyError> {
    let home = resolve_home(&bins.getent, &op.user)?;
    let ssh_dir = home.join(".ssh");
    let keys_path = ssh_dir.join("authorized_keys");

    let new_key = parse_key(&op.key)
        .ok_or_else(|| AuthorizedKeyError::BadRequest(format!("authorized_key: malformed key {:?}", op.key)))?;

    let existing_text = match fs::read_to_string(&keys_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(AuthorizedKeyError::Io(format!(
                "read {}: {e}",
                keys_path.display()
            )))
        }
    };

    let desired_text = compute_desired(&existing_text, &new_key, op.state, op.exclusive != 0)?;
    if desired_text == existing_text {
        return Ok(false);
    }
    if check_mode {
        return Ok(true);
    }

    // Ensure .ssh dir exists, 0700, owned by user.
    if !ssh_dir.exists() {
        fs::create_dir_all(&ssh_dir).map_err(|e| {
            AuthorizedKeyError::Io(format!("mkdir {}: {e}", ssh_dir.display()))
        })?;
    }
    fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
        AuthorizedKeyError::Io(format!("chmod {}: {e}", ssh_dir.display()))
    })?;
    chown(&bins.chown, &ssh_dir, &op.user)?;

    // Atomic write of authorized_keys.
    let tmp = ssh_dir.join(".authorized_keys.rsansible-tmp");
    let _ = fs::remove_file(&tmp);
    fs::write(&tmp, &desired_text)
        .map_err(|e| AuthorizedKeyError::Io(format!("write {}: {e}", tmp.display())))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| AuthorizedKeyError::Io(format!("chmod {}: {e}", tmp.display())))?;
    chown(&bins.chown, &tmp, &op.user)?;
    fs::rename(&tmp, &keys_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        AuthorizedKeyError::Io(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            keys_path.display()
        ))
    })?;
    Ok(true)
}

/// `(type, key-body, full-line-with-comment)`. Comment is preserved but
/// not part of identity.
#[derive(Debug, Clone)]
struct Key {
    kind: String,
    body: String,
    full: String,
}

fn parse_key(line: &str) -> Option<Key> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let kind = parts.next()?.to_string();
    let body = parts.next()?.to_string();
    if !kind.starts_with("ssh-") && !kind.starts_with("ecdsa-") && !kind.starts_with("sk-") {
        return None;
    }
    if body.is_empty() {
        return None;
    }
    Some(Key {
        kind,
        body,
        full: trimmed.to_string(),
    })
}

fn key_matches(existing: &str, candidate: &Key) -> bool {
    match parse_key(existing) {
        Some(k) => k.kind == candidate.kind && k.body == candidate.body,
        None => false,
    }
}

/// Compute the desired file contents. Trailing newline if non-empty.
fn compute_desired(
    existing: &str,
    new_key: &Key,
    state: u8,
    exclusive: bool,
) -> Result<String, AuthorizedKeyError> {
    if exclusive {
        // The file should contain exactly this key (when present) or be
        // empty (when absent).
        return Ok(match state {
            STATE_PRESENT => format!("{}\n", new_key.full),
            STATE_ABSENT => String::new(),
            other => {
                return Err(AuthorizedKeyError::BadRequest(format!(
                    "authorized_key: unknown state byte {other}"
                )))
            }
        });
    }
    // Non-exclusive: keep all unrelated lines, add or remove the one we
    // were asked about.
    let mut kept: Vec<String> = Vec::new();
    let mut found = false;
    for line in existing.lines() {
        if key_matches(line, new_key) {
            found = true;
            // Drop matching line for now; we'll re-add canonicalised one
            // below if state=present.
            continue;
        }
        kept.push(line.to_string());
    }
    match state {
        STATE_PRESENT => {
            // Add canonicalised line. If it was already present, we
            // re-insert the line verbatim from the op (so a comment
            // tweak DOES rewrite the line — Ansible behaves the same).
            kept.push(new_key.full.clone());
            if !found {
                // No-op signal: matches `changed=true`. Caller computes
                // via text equality.
            }
        }
        STATE_ABSENT => {
            // `kept` already excludes the matching line; if it wasn't
            // found, kept == existing.lines(), text equality → no-op.
        }
        other => {
            return Err(AuthorizedKeyError::BadRequest(format!(
                "authorized_key: unknown state byte {other}"
            )))
        }
    }
    if kept.is_empty() {
        return Ok(String::new());
    }
    let mut out = kept.join("\n");
    out.push('\n');
    Ok(out)
}

fn resolve_home(getent: &str, user: &str) -> Result<std::path::PathBuf, AuthorizedKeyError> {
    let out = Command::new(getent)
        .args(["passwd", user])
        .output()
        .map_err(|e| AuthorizedKeyError::Spawn(format!("spawn {getent}: {e}")))?;
    match out.status.code() {
        Some(0) => {}
        Some(2) => {
            return Err(AuthorizedKeyError::BadRequest(format!(
                "authorized_key: user {user:?} does not exist"
            )))
        }
        Some(code) => {
            return Err(AuthorizedKeyError::Io(format!(
                "{getent} passwd {user}: exit {code} stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            )))
        }
        None => {
            return Err(AuthorizedKeyError::Io(format!(
                "{getent} passwd {user}: killed by signal"
            )))
        }
    }
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return Err(AuthorizedKeyError::Io(format!(
            "{getent} passwd {user}: malformed line {line:?}"
        )));
    }
    Ok(std::path::PathBuf::from(parts[5].to_string()))
}

fn chown(chown_bin: &str, path: &Path, user: &str) -> Result<(), AuthorizedKeyError> {
    // `chown user: <path>` sets owner=user and group=user's primary.
    let arg = format!("{user}:");
    let out = Command::new(chown_bin)
        .arg(&arg)
        .arg(path)
        .output()
        .map_err(|e| AuthorizedKeyError::Spawn(format!("spawn {chown_bin}: {e}")))?;
    if !out.status.success() {
        return Err(AuthorizedKeyError::Io(format!(
            "{chown_bin} {arg} {}: failed ({:?}): stderr={:?}",
            path.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::msg::now_unix_ns;
    use std::io::Write as _;
    use std::path::PathBuf;

    fn op(user: &str, key: &str, state: u8, exclusive: bool) -> OpAuthorizedKeyOutput {
        OpAuthorizedKeyOutput {
            kind: 24,
            user: user.into(),
            key: key.into(),
            state,
            exclusive: if exclusive { 1 } else { 0 },
        }
    }

    /// Build a sandboxed user "home" directory layout and a stub getent
    /// that points the user at that home. Chown is also stubbed to a
    /// no-op (tests can't chown to other users without root).
    struct Stub {
        dir: PathBuf,
        bins: Bins,
        home: PathBuf,
    }
    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    fn build_stub(label: &str, user: &str) -> Stub {
        let dir = std::env::temp_dir().join(format!(
            "rsansible-akey-{label}-{}-{}",
            std::process::id(),
            now_unix_ns()
        ));
        let home = dir.join(user);
        std::fs::create_dir_all(&home).unwrap();
        let getent = dir.join("getent");
        let getent_script = format!(
            r#"#!/bin/sh
[ "$1" = "passwd" ] || exit 2
[ "$2" = "{user}" ] || exit 2
echo "{user}:x:1000:1000::{home}:/bin/bash"
"#,
            user = user,
            home = home.display(),
        );
        let chown_bin = dir.join("chown");
        // chown stub: no-op. Tests don't need real ownership changes.
        let chown_script = "#!/bin/sh\nexit 0\n".to_string();
        for (p, body) in [(&getent, getent_script), (&chown_bin, chown_script)] {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(p)
                .unwrap();
            f.write_all(body.as_bytes()).unwrap();
            f.sync_all().unwrap();
            let mut perms = std::fs::metadata(p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(p, perms).unwrap();
        }
        let bins = Bins {
            getent: getent.to_string_lossy().into_owned(),
            chown: chown_bin.to_string_lossy().into_owned(),
        };
        Stub { dir, bins, home }
    }
    fn read_keys(stub: &Stub) -> String {
        std::fs::read_to_string(stub.home.join(".ssh").join("authorized_keys"))
            .unwrap_or_default()
    }

    const K1: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAA alice@laptop";
    const K1_NEW_COMMENT: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAA alice@desktop";
    const K2: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAA bob@server";

    #[test]
    fn adds_first_key_into_empty_file() {
        let stub = build_stub("first", "alice");
        let changed = apply_with_paths(&stub.bins, &op("alice", K1, STATE_PRESENT, false), false)
            .unwrap();
        assert!(changed);
        assert_eq!(read_keys(&stub), format!("{K1}\n"));
        let md = std::fs::metadata(stub.home.join(".ssh")).unwrap();
        assert_eq!(md.permissions().mode() & 0o7777, 0o700);
        let md2 = std::fs::metadata(stub.home.join(".ssh").join("authorized_keys")).unwrap();
        assert_eq!(md2.permissions().mode() & 0o7777, 0o600);
    }

    #[test]
    fn idempotent_when_key_already_present() {
        let stub = build_stub("idem", "alice");
        std::fs::create_dir_all(stub.home.join(".ssh")).unwrap();
        std::fs::write(stub.home.join(".ssh").join("authorized_keys"), format!("{K1}\n")).unwrap();
        let changed = apply_with_paths(&stub.bins, &op("alice", K1, STATE_PRESENT, false), false)
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn matches_key_ignoring_comment() {
        // Adding K1_NEW_COMMENT when K1 (same kind+body, different comment)
        // is already present rewrites the comment but doesn't duplicate.
        let stub = build_stub("comment", "alice");
        std::fs::create_dir_all(stub.home.join(".ssh")).unwrap();
        std::fs::write(stub.home.join(".ssh").join("authorized_keys"), format!("{K1}\n")).unwrap();
        let changed = apply_with_paths(
            &stub.bins,
            &op("alice", K1_NEW_COMMENT, STATE_PRESENT, false),
            false,
        )
        .unwrap();
        assert!(changed);
        let after = read_keys(&stub);
        assert_eq!(after, format!("{K1_NEW_COMMENT}\n"));
        assert_eq!(after.lines().count(), 1);
    }

    #[test]
    fn preserves_other_keys_when_adding() {
        let stub = build_stub("multi", "alice");
        std::fs::create_dir_all(stub.home.join(".ssh")).unwrap();
        std::fs::write(stub.home.join(".ssh").join("authorized_keys"), format!("{K2}\n")).unwrap();
        let changed = apply_with_paths(&stub.bins, &op("alice", K1, STATE_PRESENT, false), false)
            .unwrap();
        assert!(changed);
        let after = read_keys(&stub);
        assert!(after.contains(K1));
        assert!(after.contains(K2));
        assert_eq!(after.lines().count(), 2);
    }

    #[test]
    fn removes_only_specified_key() {
        let stub = build_stub("remove-one", "alice");
        std::fs::create_dir_all(stub.home.join(".ssh")).unwrap();
        std::fs::write(
            stub.home.join(".ssh").join("authorized_keys"),
            format!("{K1}\n{K2}\n"),
        )
        .unwrap();
        let changed = apply_with_paths(&stub.bins, &op("alice", K1, STATE_ABSENT, false), false)
            .unwrap();
        assert!(changed);
        let after = read_keys(&stub);
        assert!(!after.contains(K1));
        assert!(after.contains(K2));
    }

    #[test]
    fn absent_when_already_absent_is_noop() {
        let stub = build_stub("absent-noop", "alice");
        std::fs::create_dir_all(stub.home.join(".ssh")).unwrap();
        std::fs::write(stub.home.join(".ssh").join("authorized_keys"), format!("{K2}\n")).unwrap();
        let changed = apply_with_paths(&stub.bins, &op("alice", K1, STATE_ABSENT, false), false)
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn exclusive_present_replaces_file_contents() {
        let stub = build_stub("excl", "alice");
        std::fs::create_dir_all(stub.home.join(".ssh")).unwrap();
        std::fs::write(
            stub.home.join(".ssh").join("authorized_keys"),
            format!("{K1}\n{K2}\n"),
        )
        .unwrap();
        let changed = apply_with_paths(&stub.bins, &op("alice", K1, STATE_PRESENT, true), false)
            .unwrap();
        assert!(changed);
        assert_eq!(read_keys(&stub), format!("{K1}\n"));
    }

    #[test]
    fn user_not_found_errors() {
        let stub = build_stub("nouser", "alice");
        let err = apply_with_paths(&stub.bins, &op("bob", K1, STATE_PRESENT, false), false)
            .unwrap_err();
        match err {
            AuthorizedKeyError::BadRequest(m) => assert!(m.contains("does not exist")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn check_mode_reports_change_without_writing() {
        let stub = build_stub("check", "alice");
        let changed = apply_with_paths(&stub.bins, &op("alice", K1, STATE_PRESENT, false), true)
            .unwrap();
        assert!(changed);
        assert!(!stub.home.join(".ssh").join("authorized_keys").exists());
    }
}
