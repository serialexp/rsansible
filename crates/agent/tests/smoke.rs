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
        &msg::task_dispatch(1, false, msg::op_shell("echo hello".into(), 0)),
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
        &msg::task_dispatch(2, false, msg::op_shell("exit 7".into(), 0)),
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
            ),
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
            ),
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
            ),
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
            ),
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
