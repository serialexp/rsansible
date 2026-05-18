//! `OpUser` — unix user management via `useradd` / `usermod` / `userdel`,
//! idempotent via `getent passwd` (existence + current shell/home/gid)
//! and `id -nG` (current supplementary groups).
//!
//! For an existing user under state=present, we compute deltas against
//! the live record and call `usermod` with ONLY the flags that need to
//! change. If nothing needs to change, `changed=0` and `usermod` isn't
//! run at all. Matches Ansible's contract: re-runs of an unchanged
//! playbook report no change.

use std::process::Command;

use rsansible_wire::generated::OpUserOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

pub async fn run(
    ctx: &Context,
    seq: u32,
    op: OpUserOutput,
    check_mode: bool,
) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();
    if op.name.trim().is_empty() {
        emit_error(ctx, seq, err::BAD_REQUEST, "user: empty `name`").await;
        return Ok(());
    }
    let result = tokio::task::spawn_blocking(move || apply(&op, check_mode))
        .await
        .map_err(|e| anyhow::anyhow!("user join: {e}"))?;
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
        Err(UserError::Io(m)) => emit_error(ctx, seq, err::IO, m).await,
        Err(UserError::Spawn(m)) => emit_error(ctx, seq, err::SPAWN_FAILED, m).await,
        Err(UserError::BadRequest(m)) => emit_error(ctx, seq, err::BAD_REQUEST, m).await,
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum UserError {
    Io(String),
    Spawn(String),
    BadRequest(String),
}

/// Tooling paths, overridable via env vars for tests.
pub(crate) struct Bins {
    pub getent: String,
    pub id: String,
    pub useradd: String,
    pub usermod: String,
    pub userdel: String,
}

impl Bins {
    pub fn from_env() -> Self {
        Self {
            getent: std::env::var("RSANSIBLE_GETENT").unwrap_or_else(|_| "getent".into()),
            id: std::env::var("RSANSIBLE_ID").unwrap_or_else(|_| "id".into()),
            useradd: std::env::var("RSANSIBLE_USERADD").unwrap_or_else(|_| "useradd".into()),
            usermod: std::env::var("RSANSIBLE_USERMOD").unwrap_or_else(|_| "usermod".into()),
            userdel: std::env::var("RSANSIBLE_USERDEL").unwrap_or_else(|_| "userdel".into()),
        }
    }
}

pub(crate) fn apply(op: &OpUserOutput, check_mode: bool) -> Result<bool, UserError> {
    apply_with_bins(&Bins::from_env(), op, check_mode)
}

/// What `getent passwd <name>` told us about the user. Only the fields we
/// need for delta computation are extracted.
#[derive(Debug, Clone)]
struct Existing {
    /// Primary group name (resolved via the gid field of the passwd line +
    /// `getent group <gid>`).
    primary_group: String,
    home: String,
    shell: String,
    /// Supplementary groups via `id -nG <name>`, with the primary group
    /// filtered out (Ansible's contract: `groups:` is the supplementary
    /// set, not the union with primary).
    supplementary: Vec<String>,
}

pub(crate) fn apply_with_bins(
    bins: &Bins,
    op: &OpUserOutput,
    check_mode: bool,
) -> Result<bool, UserError> {
    let existing = probe(bins, &op.name)?;
    match op.state {
        STATE_PRESENT => match existing {
            None => {
                if check_mode {
                    return Ok(true);
                }
                useradd(bins, op)?;
                Ok(true)
            }
            Some(e) => {
                let mut args = compute_usermod_args(op, &e);
                if args.is_empty() {
                    Ok(false)
                } else {
                    if check_mode {
                        return Ok(true);
                    }
                    args.push(op.name.clone());
                    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                    run_cmd(&bins.usermod, &argv)?;
                    Ok(true)
                }
            }
        },
        STATE_ABSENT => {
            if existing.is_none() {
                Ok(false)
            } else {
                if check_mode {
                    return Ok(true);
                }
                run_cmd(&bins.userdel, &[&op.name])?;
                Ok(true)
            }
        }
        other => Err(UserError::BadRequest(format!(
            "user: unknown state byte {other}"
        ))),
    }
}

fn probe(bins: &Bins, name: &str) -> Result<Option<Existing>, UserError> {
    // `getent passwd <name>` → name:x:uid:gid:gecos:home:shell
    let out = Command::new(&bins.getent)
        .args(["passwd", name])
        .output()
        .map_err(|e| UserError::Spawn(format!("spawn {}: {e}", bins.getent)))?;
    match out.status.code() {
        Some(0) => {}
        Some(2) => return Ok(None),
        Some(code) => {
            return Err(UserError::Io(format!(
                "{} passwd {name}: exit {code} stderr={:?}",
                bins.getent,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        None => {
            return Err(UserError::Io(format!(
                "{} passwd {name}: killed by signal",
                bins.getent
            )));
        }
    };
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return Err(UserError::Io(format!(
            "{} passwd {name}: malformed line {line:?}",
            bins.getent
        )));
    }
    let gid = parts[3].to_string();
    let home = parts[5].to_string();
    let shell = parts[6].to_string();

    // Resolve gid → primary group name.
    let primary_group = match Command::new(&bins.getent)
        .args(["group", &gid])
        .output()
        .map_err(|e| UserError::Spawn(format!("spawn {}: {e}", bins.getent)))?
    {
        out if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    };

    // `id -nG <user>` → space-separated group names (primary first).
    let id_out = Command::new(&bins.id)
        .args(["-nG", name])
        .output()
        .map_err(|e| UserError::Spawn(format!("spawn {}: {e}", bins.id)))?;
    if !id_out.status.success() {
        return Err(UserError::Io(format!(
            "{} -nG {name}: failed stderr={:?}",
            bins.id,
            String::from_utf8_lossy(&id_out.stderr)
        )));
    }
    let id_text = String::from_utf8_lossy(&id_out.stdout);
    let supplementary: Vec<String> = id_text
        .split_ascii_whitespace()
        .filter(|g| !g.is_empty() && *g != primary_group)
        .map(|g| g.to_string())
        .collect();

    Ok(Some(Existing {
        primary_group,
        home,
        shell,
        supplementary,
    }))
}

fn useradd(bins: &Bins, op: &OpUserOutput) -> Result<(), UserError> {
    let mut args: Vec<String> = Vec::new();
    if op.system != 0 {
        args.push("--system".into());
    }
    if op.create_home != 0 {
        args.push("-m".into());
    } else {
        args.push("-M".into());
    }
    if op.has_shell != 0 {
        args.push("-s".into());
        args.push(op.shell.clone());
    }
    if op.has_home != 0 {
        args.push("-d".into());
        args.push(op.home.clone());
    }
    if !op.primary_group.is_empty() {
        args.push("-g".into());
        args.push(op.primary_group.clone());
    }
    if !op.groups.is_empty() {
        args.push("-G".into());
        args.push(op.groups.join(","));
    }
    args.push(op.name.clone());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cmd(&bins.useradd, &argv)
}

fn compute_usermod_args(op: &OpUserOutput, existing: &Existing) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    if op.has_shell != 0 && op.shell != existing.shell {
        args.push("-s".into());
        args.push(op.shell.clone());
    }
    if op.has_home != 0 && op.home != existing.home {
        args.push("-d".into());
        args.push(op.home.clone());
    }
    if !op.primary_group.is_empty() && op.primary_group != existing.primary_group {
        args.push("-g".into());
        args.push(op.primary_group.clone());
    }
    if !op.groups.is_empty() {
        // For append=true: only push -aG if any requested group is missing
        // from the existing supplementary list. For append=false: push -G
        // with the full requested list if it differs from the existing set
        // (as a set comparison — order doesn't matter).
        if op.append != 0 {
            let missing: Vec<&String> = op
                .groups
                .iter()
                .filter(|g| !existing.supplementary.iter().any(|e| e == *g))
                .collect();
            if !missing.is_empty() {
                let combined: Vec<String> = missing.iter().map(|s| (*s).clone()).collect();
                args.push("-a".into());
                args.push("-G".into());
                args.push(combined.join(","));
            }
        } else {
            let mut requested = op.groups.clone();
            requested.sort();
            let mut current = existing.supplementary.clone();
            current.sort();
            if requested != current {
                args.push("-G".into());
                args.push(op.groups.join(","));
            }
        }
    }
    // `system` and `create_home` are creation-time flags only; usermod
    // can't change either. Ignore.
    args
}

fn run_cmd(bin: &str, args: &[&str]) -> Result<(), UserError> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| UserError::Spawn(format!("spawn {bin} {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(UserError::Io(format!(
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

    struct Stub {
        dir: PathBuf,
        bins: Bins,
    }
    impl Drop for Stub {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// `passwd` lines look like `name:x:uid:gid:gecos:home:shell`.
    /// `group_db` lines look like `groupname:x:gid:` (members are tracked
    /// separately in `groups_db` as `user gname1,gname2`).
    fn build_stub(label: &str, passwd: &[&str], group_db: &[&str], groups_db: &[&str]) -> Stub {
        let dir = std::env::temp_dir().join(format!(
            "rsansible-user-{label}-{}-{}",
            std::process::id(),
            now_unix_ns()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let passwd_path = dir.join("passwd");
        std::fs::write(&passwd_path, passwd.join("\n") + "\n").unwrap();
        let group_path = dir.join("group");
        std::fs::write(&group_path, group_db.join("\n") + "\n").unwrap();
        let groups_path = dir.join("usergroups");
        std::fs::write(&groups_path, groups_db.join("\n") + "\n").unwrap();
        let log_path = dir.join("log");
        std::fs::write(&log_path, "").unwrap();

        // getent: handles `getent passwd <name>` and `getent group <name|gid>`.
        let getent = dir.join("getent");
        let getent_script = format!(
            r#"#!/bin/sh
case "$1" in
  passwd)
    line=$(grep "^$2:" "{passwd}" | head -n1)
    if [ -z "$line" ]; then exit 2; fi
    echo "$line"
    ;;
  group)
    # accept lookup by name or by gid
    line=$(grep -E "^$2:|:$2:" "{group}" | head -n1)
    if [ -z "$line" ]; then exit 2; fi
    echo "$line"
    ;;
  *) exit 2 ;;
esac
"#,
            passwd = passwd_path.display(),
            group = group_path.display(),
        );

        // id -nG <user>: emit space-separated group list. Primary group
        // first (resolved from passwd → group), then supplementaries from
        // usergroups db. If user not found, exit 1.
        let id = dir.join("id");
        let id_script = format!(
            r#"#!/bin/sh
[ "$1" = "-nG" ] || exit 1
user="$2"
pwline=$(grep "^$user:" "{passwd}" | head -n1)
[ -z "$pwline" ] && exit 1
pgid=$(echo "$pwline" | cut -d: -f4)
pname=$(grep -E ":$pgid:" "{group}" | head -n1 | cut -d: -f1)
sups=$(grep "^$user " "{groups}" | head -n1 | cut -d' ' -f2-)
echo "$pname $sups" | xargs
"#,
            passwd = passwd_path.display(),
            group = group_path.display(),
            groups = groups_path.display(),
        );

        // useradd <flags> <name>: append a record to passwd. Records
        // observed flags. Defaults shell=/bin/sh, home=/home/<name>, gid=100.
        let useradd = dir.join("useradd");
        let useradd_script = format!(
            r#"#!/bin/sh
PASSWD="{passwd}"
LOG="{log}"
echo "useradd $@" >> "$LOG"
shell="/bin/sh"
home=""
sys=0
gid="100"
sups=""
while [ $# -gt 1 ]; do
  case "$1" in
    --system) sys=1; shift;;
    -m|-M) shift;;
    -s) shell="$2"; shift 2;;
    -d) home="$2"; shift 2;;
    -g)
      # primary group → resolve name → gid
      gid_line=$(grep "^$2:" "{group}" | head -n1)
      if [ -n "$gid_line" ]; then gid=$(echo "$gid_line" | cut -d: -f3); fi
      shift 2;;
    -G) sups="$2"; shift 2;;
    *) shift;;
  esac
done
name="$1"
if [ -z "$home" ]; then home="/home/$name"; fi
echo "$name:x:9999:$gid::$home:$shell" >> "$PASSWD"
if [ -n "$sups" ]; then echo "$name $(echo $sups | tr ',' ' ')" >> "{groups}"; fi
"#,
            passwd = passwd_path.display(),
            log = log_path.display(),
            group = group_path.display(),
            groups = groups_path.display(),
        );

        // usermod <flags> <name>: apply changes in passwd / usergroups.
        let usermod = dir.join("usermod");
        let usermod_script = format!(
            r#"#!/bin/sh
PASSWD="{passwd}"
GROUPS="{groups}"
LOG="{log}"
echo "usermod $@" >> "$LOG"
shell=""
home=""
new_gid=""
sups=""
append=0
while [ $# -gt 1 ]; do
  case "$1" in
    -s) shell="$2"; shift 2;;
    -d) home="$2"; shift 2;;
    -g)
      gid_line=$(grep "^$2:" "{group}" | head -n1)
      if [ -n "$gid_line" ]; then new_gid=$(echo "$gid_line" | cut -d: -f3); fi
      shift 2;;
    -G) sups="$2"; shift 2;;
    -a) append=1; shift;;
    *) shift;;
  esac
done
name="$1"
# Rewrite passwd line with changes.
line=$(grep "^$name:" "$PASSWD" | head -n1)
if [ -n "$line" ]; then
  old_shell=$(echo "$line" | cut -d: -f7)
  old_home=$(echo "$line" | cut -d: -f6)
  old_gid=$(echo "$line" | cut -d: -f4)
  uid=$(echo "$line" | cut -d: -f3)
  gecos=$(echo "$line" | cut -d: -f5)
  [ -n "$shell" ] || shell="$old_shell"
  [ -n "$home" ] || home="$old_home"
  [ -n "$new_gid" ] || new_gid="$old_gid"
  grep -v "^$name:" "$PASSWD" > "$PASSWD.tmp"
  echo "$name:x:$uid:$new_gid:$gecos:$home:$shell" >> "$PASSWD.tmp"
  mv "$PASSWD.tmp" "$PASSWD"
fi
if [ -n "$sups" ]; then
  if [ "$append" = 1 ]; then
    old=$(grep "^$name " "$GROUPS" | head -n1 | cut -d' ' -f2-)
    new="$old $(echo $sups | tr ',' ' ')"
  else
    new="$(echo $sups | tr ',' ' ')"
  fi
  grep -v "^$name " "$GROUPS" > "$GROUPS.tmp" || true
  echo "$name $new" >> "$GROUPS.tmp"
  mv "$GROUPS.tmp" "$GROUPS"
fi
"#,
            passwd = passwd_path.display(),
            groups = groups_path.display(),
            log = log_path.display(),
            group = group_path.display(),
        );

        let userdel = dir.join("userdel");
        let userdel_script = format!(
            r#"#!/bin/sh
PASSWD="{passwd}"
GROUPS="{groups}"
LOG="{log}"
echo "userdel $@" >> "$LOG"
name="$1"
grep -v "^$name:" "$PASSWD" > "$PASSWD.tmp" || true
mv "$PASSWD.tmp" "$PASSWD"
grep -v "^$name " "$GROUPS" > "$GROUPS.tmp" || true
mv "$GROUPS.tmp" "$GROUPS" 2>/dev/null || true
"#,
            passwd = passwd_path.display(),
            groups = groups_path.display(),
            log = log_path.display(),
        );

        for (p, body) in [
            (&getent, getent_script),
            (&id, id_script),
            (&useradd, useradd_script),
            (&usermod, usermod_script),
            (&userdel, userdel_script),
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

        let bins = Bins {
            getent: getent.to_string_lossy().into_owned(),
            id: id.to_string_lossy().into_owned(),
            useradd: useradd.to_string_lossy().into_owned(),
            usermod: usermod.to_string_lossy().into_owned(),
            userdel: userdel.to_string_lossy().into_owned(),
        };
        Stub { dir, bins }
    }

    fn passwd(stub: &Stub) -> String {
        std::fs::read_to_string(stub.dir.join("passwd")).unwrap_or_default()
    }
    fn log(stub: &Stub) -> String {
        std::fs::read_to_string(stub.dir.join("log")).unwrap_or_default()
    }
    fn user_groups(stub: &Stub) -> String {
        std::fs::read_to_string(stub.dir.join("usergroups")).unwrap_or_default()
    }

    fn op(name: &str, state: u8) -> OpUserOutput {
        OpUserOutput {
            kind: 22,
            name: name.into(),
            state,
            system: 0,
            has_shell: 0,
            shell: String::new(),
            has_home: 0,
            home: String::new(),
            create_home: 1,
            primary_group: String::new(),
            groups: vec![],
            append: 0,
        }
    }

    #[test]
    fn creates_new_user_with_shell_and_home() {
        let stub = build_stub("create", &["root:x:0:0::/root:/bin/bash"], &["root:x:0:"], &[]);
        let mut o = op("alice", STATE_PRESENT);
        o.has_shell = 1;
        o.shell = "/bin/bash".into();
        o.create_home = 1;
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(changed);
        assert!(passwd(&stub).contains("alice:"));
        let lg = log(&stub);
        assert!(lg.contains("useradd"));
        assert!(lg.contains("-s /bin/bash"));
        assert!(lg.contains("-m"));
    }

    #[test]
    fn idempotent_when_existing_matches() {
        let stub = build_stub(
            "noop",
            &["alice:x:1000:1000::/home/alice:/bin/bash"],
            &["alice:x:1000:"],
            &[],
        );
        let mut o = op("alice", STATE_PRESENT);
        o.has_shell = 1;
        o.shell = "/bin/bash".into();
        o.has_home = 1;
        o.home = "/home/alice".into();
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(!changed);
        assert!(!log(&stub).contains("usermod"));
    }

    #[test]
    fn usermod_only_when_shell_differs() {
        let stub = build_stub(
            "shell-change",
            &["alice:x:1000:1000::/home/alice:/bin/sh"],
            &["alice:x:1000:"],
            &[],
        );
        let mut o = op("alice", STATE_PRESENT);
        o.has_shell = 1;
        o.shell = "/bin/bash".into();
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(changed);
        assert!(passwd(&stub).contains(":/bin/bash"));
        assert!(log(&stub).contains("-s /bin/bash"));
    }

    #[test]
    fn deletes_existing_user() {
        let stub = build_stub(
            "del",
            &["alice:x:1000:1000::/home/alice:/bin/bash"],
            &["alice:x:1000:"],
            &[],
        );
        let o = op("alice", STATE_ABSENT);
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(changed);
        assert!(!passwd(&stub).contains("alice:"));
    }

    #[test]
    fn noop_delete_when_absent() {
        let stub = build_stub("del-noop", &["root:x:0:0::/root:/bin/bash"], &["root:x:0:"], &[]);
        let o = op("alice", STATE_ABSENT);
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(!changed);
    }

    #[test]
    fn append_only_adds_missing_groups() {
        let stub = build_stub(
            "append",
            &["alice:x:1000:1000::/home/alice:/bin/bash"],
            &["alice:x:1000:", "sudo:x:27:", "docker:x:998:"],
            &["alice sudo"],
        );
        let mut o = op("alice", STATE_PRESENT);
        o.groups = vec!["sudo".into(), "docker".into()];
        o.append = 1;
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(changed);
        let lg = log(&stub);
        assert!(lg.contains("-a"));
        // Only docker should be in the -G argument (sudo already present).
        assert!(lg.contains("-G docker"), "log={lg}");
        assert!(user_groups(&stub).contains("docker"));
    }

    #[test]
    fn append_noop_when_already_member() {
        let stub = build_stub(
            "append-noop",
            &["alice:x:1000:1000::/home/alice:/bin/bash"],
            &["alice:x:1000:", "sudo:x:27:"],
            &["alice sudo"],
        );
        let mut o = op("alice", STATE_PRESENT);
        o.groups = vec!["sudo".into()];
        o.append = 1;
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(!changed);
    }

    #[test]
    fn non_append_replaces_when_set_differs() {
        let stub = build_stub(
            "replace",
            &["alice:x:1000:1000::/home/alice:/bin/bash"],
            &["alice:x:1000:", "sudo:x:27:", "docker:x:998:"],
            &["alice sudo docker"],
        );
        let mut o = op("alice", STATE_PRESENT);
        o.groups = vec!["sudo".into()];
        // append=false: replace
        let changed = apply_with_bins(&stub.bins, &o, false).unwrap();
        assert!(changed);
        let lg = log(&stub);
        // No -a flag.
        assert!(!lg.contains("usermod -a"));
        assert!(lg.contains("-G sudo"));
    }
}
