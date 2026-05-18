//! `OpGroup` — unix group management via `groupadd` / `groupdel`,
//! idempotent via a `getent group <name>` probe.

use std::process::Command;

use rsansible_wire::generated::OpGroupOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpGroupOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    if op.name.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "group: empty `name`").await;
        return Ok(());
    }
    let result = tokio::task::spawn_blocking(move || apply(&op, check_mode))
        .await
        .map_err(|e| anyhow::anyhow!("group join: {e}"))?;
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
        Err(GroupError::Io(m)) => emit_error(ctx, seq, err::IO, m).await,
        Err(GroupError::Spawn(m)) => emit_error(ctx, seq, err::SPAWN_FAILED, m).await,
        Err(GroupError::BadRequest(m)) => emit_error(ctx, seq, err::BAD_REQUEST, m).await,
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum GroupError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

pub(crate) fn apply(op: &OpGroupOutput, check_mode: bool) -> Result<bool, GroupError> {
    let getent = std::env::var("RSANSIBLE_GETENT").unwrap_or_else(|_| "getent".into());
    let groupadd = std::env::var("RSANSIBLE_GROUPADD").unwrap_or_else(|_| "groupadd".into());
    let groupdel = std::env::var("RSANSIBLE_GROUPDEL").unwrap_or_else(|_| "groupdel".into());
    apply_with_bins(&getent, &groupadd, &groupdel, op, check_mode)
}

pub(crate) fn apply_with_bins(
    getent: &str,
    groupadd: &str,
    groupdel: &str,
    op: &OpGroupOutput,
    check_mode: bool,
) -> Result<bool, GroupError> {
    let exists = probe_exists(getent, &op.name)?;
    match op.state {
        STATE_PRESENT => {
            if exists {
                Ok(false)
            } else {
                if check_mode {
                    return Ok(true);
                }
                let mut args: Vec<&str> = Vec::new();
                if op.system != 0 {
                    args.push("--system");
                }
                args.push(&op.name);
                run_cmd(groupadd, &args)?;
                Ok(true)
            }
        }
        STATE_ABSENT => {
            if !exists {
                Ok(false)
            } else {
                if check_mode {
                    return Ok(true);
                }
                run_cmd(groupdel, &[&op.name])?;
                Ok(true)
            }
        }
        other => Err(GroupError::BadRequest(format!(
            "group: unknown state byte {other}"
        ))),
    }
}

fn probe_exists(getent: &str, name: &str) -> Result<bool, GroupError> {
    // `getent group <name>` exits 0 if found, 2 if not found, other on error.
    let out = Command::new(getent)
        .args(["group", name])
        .output()
        .map_err(|e| GroupError::Spawn(format!("spawn {getent}: {e}")))?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(2) => Ok(false),
        Some(code) => Err(GroupError::Io(format!(
            "{getent} group {name}: exit {code} stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        ))),
        None => Err(GroupError::Io(format!(
            "{getent} group {name}: killed by signal"
        ))),
    }
}

fn run_cmd(bin: &str, args: &[&str]) -> Result<(), GroupError> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| GroupError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(GroupError::Io(format!(
            "{bin} {args:?} failed ({:?}): stderr={:?}",
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
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Build a sandbox with stub getent/groupadd/groupdel that read/write
    /// a tiny in-dir "groups" file as the source of truth.
    struct Stub {
        dir: PathBuf,
        getent: PathBuf,
        groupadd: PathBuf,
        groupdel: PathBuf,
    }
    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    impl Stub {
        fn new(label: &str, existing: &[&str]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rsansible-group-{label}-{}-{}",
                std::process::id(),
                now_unix_ns()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let db = dir.join("groups");
            std::fs::write(&db, existing.join("\n") + "\n").unwrap();

            let getent = dir.join("getent");
            let getent_script = format!(
                r#"#!/bin/sh
DB="{db}"
[ "$1" = "group" ] || exit 2
shift
grep -q "^$1$" "$DB" && exit 0
exit 2
"#,
                db = db.display()
            );

            let groupadd = dir.join("groupadd");
            let groupadd_script = format!(
                r#"#!/bin/sh
DB="{db}"
# skip flags
while [ "${{1#-}}" != "$1" ]; do shift; done
echo "$1" >> "$DB"
"#,
                db = db.display()
            );

            let groupdel = dir.join("groupdel");
            let groupdel_script = format!(
                r#"#!/bin/sh
DB="{db}"
grep -v "^$1$" "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
"#,
                db = db.display()
            );

            for (p, body) in [
                (&getent, getent_script),
                (&groupadd, groupadd_script),
                (&groupdel, groupdel_script),
            ] {
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
            Stub { dir, getent, groupadd, groupdel }
        }
        fn db(&self) -> String {
            std::fs::read_to_string(self.dir.join("groups")).unwrap_or_default()
        }
    }

    fn op(name: &str, state: u8, system: bool) -> OpGroupOutput {
        OpGroupOutput {
            kind: 23,
            name: name.into(),
            state,
            system: if system { 1 } else { 0 },
        }
    }

    fn run_stub(stub: &Stub, op: &OpGroupOutput) -> Result<bool, GroupError> {
        apply_with_bins(
            stub.getent.to_str().unwrap(),
            stub.groupadd.to_str().unwrap(),
            stub.groupdel.to_str().unwrap(),
            op,
            false,
        )
    }

    #[test]
    fn creates_missing_group() {
        let stub = Stub::new("create", &[]);
        let changed = run_stub(&stub, &op("etcd", STATE_PRESENT, true)).unwrap();
        assert!(changed);
        assert!(stub.db().contains("etcd"));
    }

    #[test]
    fn noop_when_present() {
        let stub = Stub::new("noop", &["etcd"]);
        let changed = run_stub(&stub, &op("etcd", STATE_PRESENT, true)).unwrap();
        assert!(!changed);
    }

    #[test]
    fn removes_present() {
        let stub = Stub::new("remove", &["etcd", "docker"]);
        let changed = run_stub(&stub, &op("etcd", STATE_ABSENT, false)).unwrap();
        assert!(changed);
        assert!(!stub.db().contains("etcd"));
        assert!(stub.db().contains("docker"));
    }

    #[test]
    fn noop_remove_when_absent() {
        let stub = Stub::new("rm-noop", &["docker"]);
        let changed = run_stub(&stub, &op("etcd", STATE_ABSENT, false)).unwrap();
        assert!(!changed);
    }
}
