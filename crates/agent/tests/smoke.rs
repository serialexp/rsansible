//! End-to-end smoke tests for the agent binary.
//!
//! Each test launches the compiled agent, pipes a sequence of framed messages
//! into its stdin, reads frames from its stdout, and asserts the protocol
//! contract. Run with `cargo test -p rsansible-agent`.

use std::process::Stdio;

use rsansible_wire::{msg, read_frame, write_frame, Message};
use tokio::io::BufReader;
use tokio::process::Command;

/// Path to the built agent binary. Cargo sets `CARGO_BIN_EXE_<name>` for
/// integration tests, which builds the agent on demand for this test.
fn agent_path() -> &'static str {
    env!("CARGO_BIN_EXE_rsansible-agent")
}

async fn read_until_done(reader: &mut BufReader<tokio::process::ChildStdout>, seq: u32) -> (Vec<Message>, Message) {
    let mut progress = Vec::new();
    loop {
        let frame = read_frame(reader)
            .await
            .expect("read_frame io")
            .expect("agent closed stdin before TaskDone");
        match &frame {
            Message::TaskDone(td) if td.seq == seq => return (progress, frame),
            Message::TaskError(te) if te.seq == seq => return (progress, frame),
            Message::TaskProgress(_) => progress.push(frame),
            other => panic!("unexpected frame while awaiting TaskDone: {other:?}"),
        }
    }
}

#[tokio::test]
async fn hello_then_shell_then_bye() {
    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let hello = read_frame(&mut stdout).await.unwrap().expect("hello");
    assert!(matches!(hello, Message::Hello(_)), "expected Hello, got {hello:?}");

    // Run `echo hello`.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(1, false, msg::op_shell("echo hello".into(), vec![], vec![], 0)),
    )
    .await
    .unwrap();
    let (progress, done) = read_until_done(&mut stdout, 1).await;
    let stdout_bytes: Vec<u8> = progress
        .iter()
        .filter_map(|m| match m {
            Message::TaskProgress(tp) if tp.stream == msg::stream::STDOUT => Some(tp.chunk.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(stdout_bytes, b"hello\n");
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 0);
    assert_eq!(td.changed, 1);

    // Non-zero exit propagates cleanly.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(2, false, msg::op_shell("exit 7".into(), vec![], vec![], 0)),
    )
    .await
    .unwrap();
    let (_progress, done) = read_until_done(&mut stdout, 2).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 7);
    assert_eq!(td.changed, 0);

    // Bye → agent exits.
    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success(), "agent exited with {status:?}");
}

#[tokio::test]
async fn op_exec_with_env_and_cwd() {
    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_exec(
                vec!["/bin/sh".into(), "-c".into(), "printf '%s:%s' \"$FOO\" \"$PWD\"".into()],
                vec!["FOO".into()],
                vec!["bar".into()],
                "/tmp".into(),
                vec![],
                0,
            ),
        ),
    )
    .await
    .unwrap();

    let (progress, done) = read_until_done(&mut stdout, 1).await;
    let out: Vec<u8> = progress
        .iter()
        .filter_map(|m| match m {
            Message::TaskProgress(tp) if tp.stream == msg::stream::STDOUT => Some(tp.chunk.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(out, b"bar:/tmp");
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 0);

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
}

/// Regression: `OpExec` previously called `cmd.env_clear()` before
/// adding the controller-supplied env vars, which empties the
/// child's environment. That broke `command: netplan apply` (and
/// any other binary in /usr/sbin) because `execvp(argv[0], ...)`
/// uses the child's PATH for resolution — with an empty PATH, the
/// kernel returns ENOENT and the agent reports "spawn failed: No
/// such file or directory". Caught in the gothab drill on
/// monitor-1. The fix: drop `env_clear()` and overlay
/// controller-supplied vars on top of the inherited env, matching
/// the symmetric `run_shell` path and Ansible's `environment:`
/// keyword semantics.
///
/// This test runs a real exec with an unqualified binary name and
/// asserts the inherited PATH is enough to resolve it. If
/// env_clear came back, this test fails with ENOENT.
#[tokio::test]
async fn op_exec_inherits_path_for_bare_argv0() {
    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    // `true` is in PATH on every POSIX system. With env_clear()
    // active and no PATH passed by the controller, this spawn
    // would fail with ENOENT.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_exec(
                vec!["true".into()],
                vec![],
                vec![],
                String::new(),
                vec![],
                0,
            ),
        ),
    )
    .await
    .unwrap();

    let (_progress, done) = read_until_done(&mut stdout, 1).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(
        td.exit_code, 0,
        "bare argv[0] must resolve via inherited PATH; \
         a non-zero exit (esp. ENOENT) means env_clear regressed",
    );

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
}

#[tokio::test]
async fn op_write_file_atomic() {
    let dir = tempdir_path("rsansible-write-test");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("greeting.txt");

    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    // First write: should be `changed = true`.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o644,
                false,
                b"hello\n".to_vec(),
                String::new(),
            
                String::new(),
                String::new(),),
        ),
    )
    .await
    .unwrap();
    let (_p, done) = read_until_done(&mut stdout, 1).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 0);
    assert_eq!(td.changed, 1, "first write should report changed");
    assert_eq!(std::fs::read(&target).unwrap(), b"hello\n");

    // Identical write: `changed = false`.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            2,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o644,
                false,
                b"hello\n".to_vec(),
                String::new(),
            
                String::new(),
                String::new(),),
        ),
    )
    .await
    .unwrap();
    let (_p, done) = read_until_done(&mut stdout, 2).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.changed, 0, "rewriting same content should report unchanged");

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn op_write_file_only_if_missing() {
    // `only_if_missing=1` must be a no-op (changed=0) when the dest
    // already exists, and a normal write (changed=1) when it doesn't.
    // This is the ship-blind idempotency contract the controller's
    // privkey path depends on.
    let dir = tempdir_path("rsansible-only-if-missing");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("key.pem");

    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    // Target does not exist → only_if_missing should still write.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o600,
                true,
                b"first-content\n".to_vec(),
                String::new(),
            
                String::new(),
                String::new(),),
        ),
    )
    .await
    .unwrap();
    let (_p, done) = read_until_done(&mut stdout, 1).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 0);
    assert_eq!(td.changed, 1, "missing → should write and report changed");
    assert_eq!(std::fs::read(&target).unwrap(), b"first-content\n");

    // Now the file exists. only_if_missing must skip — even if the
    // would-be content is different, the agent must NOT overwrite.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            2,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o600,
                true,
                b"DIFFERENT-content\n".to_vec(),
                String::new(),
            
                String::new(),
                String::new(),),
        ),
    )
    .await
    .unwrap();
    let (_p, done) = read_until_done(&mut stdout, 2).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 0);
    assert_eq!(td.changed, 0, "existing dest → only_if_missing must skip");
    // Crucially, the original bytes must still be on disk — the differ
    // payload above must not have clobbered them.
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"first-content\n",
        "only_if_missing must not overwrite existing content"
    );

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression for the whole reason `validate:` exists: a copy that
/// fails validation must leave the dest untouched. The smoke test
/// covers the wire path end-to-end (controller→agent→fs), which is
/// the only level where the "dest never gets the bad bytes" property
/// is actually testable as a property and not a precondition.
#[tokio::test]
async fn op_write_file_validate_failure_leaves_dest_untouched() {
    let dir = tempdir_path("rsansible-validate-fail");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("sudoers.d-operator");
    std::fs::write(&target, b"original-known-good\n").unwrap();

    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    // `/bin/false` always exits 1 — simulates a syntax error from a
    // real validator like `visudo -cf` against a broken sudoers.
    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o440,
                false,
                b"BROKEN-would-lock-out-root\n".to_vec(),
                "/bin/false %s".into(),
            
                String::new(),
                String::new(),),
        ),
    )
    .await
    .unwrap();
    let (_p, terminal) = read_until_done(&mut stdout, 1).await;
    let Message::TaskError(te) = terminal else {
        panic!("expected TaskError on validate failure, got {terminal:?}")
    };
    assert_eq!(te.code, msg::err::BAD_REQUEST);
    // The dest must STILL be the original content. This is the safety
    // contract — if this assert ever fails, broken sudoers got
    // installed and someone got locked out of a host.
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"original-known-good\n",
        "validate failed → dest must be untouched"
    );

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression for the Caddyfile-deployed-as-root bug (Bug 11). The
/// template module passes `owner:`/`group:` through to OpWriteFile;
/// before the fix, those fields were parsed but never applied, so a
/// playbook saying `group: caddy` still produced a root:root file
/// and `systemctl reload caddy` would fail because caddy couldn't
/// read its own config.
///
/// We can't easily test "chown to a different user" without root, but
/// we can verify the wire path honors the field at all:
///   - unknown owner name → BAD_REQUEST (resolve_user path)
///   - empty owner/group → no-op (the historical default behavior)
/// The chown call itself is exercised by virtue of resolve_user
/// returning Ok for valid names; if the plumbing regresses to ignore
/// the field, the BAD_REQUEST case would silently pass instead.
#[tokio::test]
async fn op_write_file_unknown_owner_yields_bad_request() {
    let dir = tempdir_path("rsansible-owner-bad");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("config");

    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o644,
                false,
                b"hi\n".to_vec(),
                String::new(),
                "this-user-does-not-exist-xyzzy".into(),
                String::new(),
            ),
        ),
    )
    .await
    .unwrap();
    let (_p, terminal) = read_until_done(&mut stdout, 1).await;
    let Message::TaskError(te) = terminal else {
        panic!("expected TaskError for unknown owner, got {terminal:?} \
                — regression: owner field is being ignored")
    };
    assert_eq!(te.code, msg::err::BAD_REQUEST);
    // Dest must not have been created.
    assert!(!target.exists(), "dest must not be created on owner resolve failure");

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Companion to the unknown-owner test: unknown group also yields
/// BAD_REQUEST. Catches the case where owner was wired through but
/// group wasn't.
#[tokio::test]
async fn op_write_file_unknown_group_yields_bad_request() {
    let dir = tempdir_path("rsansible-group-bad");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("config");

    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o644,
                false,
                b"hi\n".to_vec(),
                String::new(),
                String::new(),
                "this-group-does-not-exist-xyzzy".into(),
            ),
        ),
    )
    .await
    .unwrap();
    let (_p, terminal) = read_until_done(&mut stdout, 1).await;
    let Message::TaskError(te) = terminal else {
        panic!("expected TaskError for unknown group, got {terminal:?} \
                — regression: group field is being ignored")
    };
    assert_eq!(te.code, msg::err::BAD_REQUEST);
    assert!(!target.exists(), "dest must not be created on group resolve failure");

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Direct positive: chown to the current user (the test process's
/// own uid, looked up by name) — no privilege needed, but we DO get
/// to exercise resolve_user → lchown_path → metadata round-trip. If
/// the agent regresses to ignoring `owner:`, the file's uid would
/// still match (since we're chowning to ourselves), but the
/// `would_change` accounting and the wire-side resolve_user call
/// remain exercised. Pair this with the unknown-owner test above
/// for the no-silent-ignore property.
#[tokio::test]
async fn op_write_file_applies_owner_to_self() {
    // Resolve current user's name. `whoami` is in every container
    // image we test against; falling back to `id -un` if not.
    let me = std::process::Command::new("id")
        .arg("-un")
        .output()
        .expect("run id -un");
    let username = String::from_utf8(me.stdout).unwrap().trim().to_string();
    assert!(!username.is_empty(), "could not determine current user");

    let dir = tempdir_path("rsansible-owner-self");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("config");

    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o644,
                false,
                b"hi\n".to_vec(),
                String::new(),
                username.clone(),
                String::new(),
            ),
        ),
    )
    .await
    .unwrap();
    let (_p, done) = read_until_done(&mut stdout, 1).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 0);
    assert!(target.exists(), "dest must exist after successful write");

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Symmetric to the failure case: validator that exits 0 must let the
/// write through. Guards against accidentally short-circuiting all
/// writes when `validate:` is set.
#[tokio::test]
async fn op_write_file_validate_success_writes_dest() {
    let dir = tempdir_path("rsansible-validate-ok");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("config");

    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_write_file(
                target.to_string_lossy().into_owned(),
                0o644,
                false,
                b"valid-content\n".to_vec(),
                // `test -f %s` succeeds only if the tmp file actually
                // exists at the substituted path — exercises both the
                // %s substitution and the success path.
                "/usr/bin/test -f %s".into(),
            
                String::new(),
                String::new(),),
        ),
    )
    .await
    .unwrap();
    let (_p, done) = read_until_done(&mut stdout, 1).await;
    let Message::TaskDone(td) = done else { panic!("expected TaskDone, got {done:?}") };
    assert_eq!(td.exit_code, 0);
    assert_eq!(td.changed, 1);
    assert_eq!(std::fs::read(&target).unwrap(), b"valid-content\n");

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn missing_binary_is_not_found() {
    let mut child = Command::new(agent_path())
        .env("RSANSIBLE_AGENT_LOG", "warn")
        .env("RSANSIBLE_AGENT_KEEP_BINARY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn agent");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let _ = read_frame(&mut stdout).await.unwrap();

    write_frame(
        &mut stdin,
        &msg::task_dispatch(
            1,
            false,
            msg::op_exec(
                vec!["/no/such/binary".into()],
                vec![],
                vec![],
                "".into(),
                vec![],
                0,
            ),
        ),
    )
    .await
    .unwrap();
    let (_p, terminal) = read_until_done(&mut stdout, 1).await;
    let Message::TaskError(te) = terminal else { panic!("expected TaskError, got {terminal:?}") };
    assert_eq!(te.code, msg::err::NOT_FOUND);

    write_frame(&mut stdin, &msg::bye()).await.unwrap();
    drop(stdin);
    child.wait().await.ok();
}

fn tempdir_path(prefix: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{ts}", std::process::id()))
}
