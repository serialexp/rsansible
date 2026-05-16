//! `unarchive:` task body.

use super::shared::{parse_ansible_bool, parse_mode_str};
use serde::{de::Error as _, Deserialize, Deserializer};

/// `unarchive:` parsed form. v1 requires `remote_src: yes` (the
/// archive lives on the agent — controller-pushed archives must come
/// via a prior `copy:` or `get_url:` task). YAML surface:
///
/// ```yaml
/// - unarchive:
///     src: /srv/cache/etcd.tar.gz
///     dest: /usr/local/bin
///     remote_src: yes              # required for v1
///     creates: /usr/local/bin/etcd
///     keep_newer: yes
///     list_files: yes
///     include: [etcd, etcdctl]
///     exclude: [README.md]
///     owner: root
///     group: root
///     mode: "0755"
/// ```
///
/// `format` accepts `auto` (default) or one of `tar.gz`/`tgz`,
/// `tar.bz2`/`tbz2`, `tar.xz`/`txz`, `tar`, `zip`. When omitted, the
/// agent infers from `src`'s extension.
#[derive(Debug, Clone, PartialEq)]
pub struct UnarchiveOp {
    pub src: String,
    pub dest: String,
    pub format: u8,
    pub creates: String,
    pub mode: Option<u32>,
    pub owner: String,
    pub group: String,
    pub keep_newer: bool,
    pub list_files: bool,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl<'de> Deserialize<'de> for UnarchiveOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let src = match map.remove("src") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.src: expected a non-empty string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("src")),
        };

        let dest = match map.remove("dest") {
            Some(serde_yaml::Value::String(s)) if !s.is_empty() => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.dest: expected a non-empty string, got: {other:?}"
                )))
            }
            None => return Err(D::Error::missing_field("dest")),
        };

        // v1 requires `remote_src: yes`. The controller-pushed-archive
        // path (`copy:` ... + extract) isn't wired yet; surface a clear
        // error instead of silently uploading nothing.
        let remote_src =
            parse_ansible_bool::<D::Error>(map.remove("remote_src"), "unarchive.remote_src", false)?;
        if !remote_src {
            return Err(D::Error::custom(
                "unarchive: only `remote_src: yes` is supported in v1; \
                 push the archive in a prior copy/get_url task",
            ));
        }
        // `copy` is the deprecated inverse alias. Accept it for
        // compatibility but require it not to contradict remote_src.
        if let Some(v) = map.remove("copy") {
            let copy_val = parse_ansible_bool::<D::Error>(Some(v), "unarchive.copy", false)?;
            // `copy: no` means remote_src: yes (matches). `copy: yes` means push from controller — unsupported.
            if copy_val {
                return Err(D::Error::custom(
                    "unarchive: `copy: yes` (controller→agent push) not supported in v1",
                ));
            }
        }

        let format_str = match map.remove("format") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) => Some(s),
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.format: expected a string, got: {other:?}"
                )))
            }
        };
        let format = match format_str.as_deref() {
            None | Some("") | Some("auto") => rsansible_wire::msg::unarchive_format::AUTO,
            Some("tar.gz") | Some("tgz") | Some("gz") | Some("gzip") => {
                rsansible_wire::msg::unarchive_format::TAR_GZ
            }
            Some("tar.bz2") | Some("tbz2") | Some("tbz") | Some("bz2") | Some("bzip2") => {
                rsansible_wire::msg::unarchive_format::TAR_BZ2
            }
            Some("tar.xz") | Some("txz") | Some("xz") => rsansible_wire::msg::unarchive_format::TAR_XZ,
            Some("tar") => rsansible_wire::msg::unarchive_format::TAR,
            Some("zip") => rsansible_wire::msg::unarchive_format::ZIP,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.format: unknown format {other:?}; \
                     accepted: auto/tar.gz/tgz/tar.bz2/tbz2/tar.xz/txz/tar/zip"
                )))
            }
        };

        let creates = match map.remove("creates") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.creates: expected a string, got: {other:?}"
                )))
            }
        };

        let owner = match map.remove("owner") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.owner: expected a string, got: {other:?}"
                )))
            }
        };
        let group = match map.remove("group") {
            None | Some(serde_yaml::Value::Null) => String::new(),
            Some(serde_yaml::Value::String(s)) => s,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.group: expected a string, got: {other:?}"
                )))
            }
        };

        let mode = match map.remove("mode") {
            None | Some(serde_yaml::Value::Null) => None,
            Some(serde_yaml::Value::String(s)) => Some(
                parse_mode_str(&s)
                    .map_err(|e| D::Error::custom(format!("unarchive.mode: {e}")))?,
            ),
            Some(serde_yaml::Value::Number(n)) => {
                // Numeric mode in YAML is treated as octal-looking
                // decimal (matches Ansible behaviour: `mode: 0755`).
                let s = n.to_string();
                Some(
                    parse_mode_str(&s)
                        .map_err(|e| D::Error::custom(format!("unarchive.mode: {e}")))?,
                )
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.mode: expected string or number, got: {other:?}"
                )))
            }
        };

        let keep_newer = parse_ansible_bool::<D::Error>(
            map.remove("keep_newer"),
            "unarchive.keep_newer",
            false,
        )?;
        let list_files = parse_ansible_bool::<D::Error>(
            map.remove("list_files"),
            "unarchive.list_files",
            false,
        )?;

        let include = match map.remove("include") {
            None | Some(serde_yaml::Value::Null) => Vec::new(),
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .into_iter()
                .map(|v| match v {
                    serde_yaml::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!(
                        "unarchive.include: each item must be a string, got: {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.include: expected list of strings, got: {other:?}"
                )))
            }
        };
        let exclude = match map.remove("exclude") {
            None | Some(serde_yaml::Value::Null) => Vec::new(),
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .into_iter()
                .map(|v| match v {
                    serde_yaml::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!(
                        "unarchive.exclude: each item must be a string, got: {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "unarchive.exclude: expected list of strings, got: {other:?}"
                )))
            }
        };

        if let Some((k, _)) = map.into_iter().next() {
            return Err(D::Error::custom(format!(
                "unarchive: unknown field {k:?}"
            )));
        }

        Ok(UnarchiveOp {
            src,
            dest,
            format,
            creates,
            mode,
            owner,
            group,
            keep_newer,
            list_files,
            include,
            exclude,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parse_unarchive_minimal() {
        let t = parse_task(
            r#"
name: t
unarchive:
  src: /srv/cache/etcd.tar.gz
  dest: /usr/local/bin
  remote_src: yes
"#,
        );
        let TaskBody::Op(TaskOp::Unarchive(u)) = t.body else { panic!() };
        assert_eq!(u.src, "/srv/cache/etcd.tar.gz");
        assert_eq!(u.dest, "/usr/local/bin");
        assert_eq!(u.format, rsansible_wire::msg::unarchive_format::AUTO);
        assert_eq!(u.creates, "");
        assert_eq!(u.mode, None);
        assert!(!u.keep_newer);
        assert!(!u.list_files);
        assert!(u.include.is_empty());
        assert!(u.exclude.is_empty());
    }

    #[test]
    fn parse_unarchive_full_surface() {
        let t = parse_task(
            r#"
name: t
unarchive:
  src: /srv/cache/etcd.zip
  dest: /opt/etcd
  remote_src: yes
  format: zip
  creates: /opt/etcd/etcd
  keep_newer: yes
  list_files: yes
  owner: root
  group: root
  mode: "0755"
  include:
    - etcd
    - etcdctl
  exclude:
    - README.md
"#,
        );
        let TaskBody::Op(TaskOp::Unarchive(u)) = t.body else { panic!() };
        assert_eq!(u.format, rsansible_wire::msg::unarchive_format::ZIP);
        assert_eq!(u.creates, "/opt/etcd/etcd");
        assert!(u.keep_newer);
        assert!(u.list_files);
        assert_eq!(u.owner, "root");
        assert_eq!(u.group, "root");
        assert_eq!(u.mode, Some(0o755));
        assert_eq!(u.include, vec!["etcd".to_string(), "etcdctl".to_string()]);
        assert_eq!(u.exclude, vec!["README.md".to_string()]);
    }

    #[test]
    fn parse_unarchive_format_aliases() {
        for (label, byte) in [
            ("tgz", rsansible_wire::msg::unarchive_format::TAR_GZ),
            ("tar.bz2", rsansible_wire::msg::unarchive_format::TAR_BZ2),
            ("txz", rsansible_wire::msg::unarchive_format::TAR_XZ),
            ("tar", rsansible_wire::msg::unarchive_format::TAR),
        ] {
            let yaml = format!(
                "name: t\nunarchive:\n  src: /a/b\n  dest: /c\n  remote_src: yes\n  format: {label}\n"
            );
            let t: Task = serde_yaml::from_str(&yaml).unwrap();
            let TaskBody::Op(TaskOp::Unarchive(u)) = t.body else { panic!() };
            assert_eq!(u.format, byte, "format alias {label}");
        }
    }

    #[test]
    fn parse_unarchive_rejects_remote_src_false() {
        let yaml = r#"
name: t
unarchive:
  src: /tmp/a.tar
  dest: /opt
  remote_src: no
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("remote_src"));
    }

    #[test]
    fn parse_unarchive_missing_remote_src_is_default_no_and_rejected() {
        let yaml = r#"
name: t
unarchive:
  src: /tmp/a.tar
  dest: /opt
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unarchive_unknown_field_rejected() {
        let yaml = r#"
name: t
unarchive:
  src: /a
  dest: /b
  remote_src: yes
  bogus: 1
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = format!("{:?}", result.err());
        assert!(err.contains("bogus"));
    }

    #[test]
    fn parse_unarchive_unknown_format_rejected() {
        let yaml = r#"
name: t
unarchive:
  src: /a
  dest: /b
  remote_src: yes
  format: 7z
"#;
        let result: Result<Task, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn unarchive_to_wire_op_shape() {
        let op = TaskOp::Unarchive(UnarchiveOp {
            src: "/srv/cache/etcd.tar.gz".into(),
            dest: "/usr/local/bin".into(),
            format: rsansible_wire::msg::unarchive_format::TAR_GZ,
            creates: "/usr/local/bin/etcd".into(),
            mode: Some(0o755),
            owner: "root".into(),
            group: "root".into(),
            keep_newer: true,
            list_files: true,
            include: vec!["etcd".into()],
            exclude: vec!["README.md".into()],
        });
        let wire = op.to_wire_op().unwrap();
        match wire {
            WireOp::OpUnarchive(o) => {
                assert_eq!(o.kind, 19);
                assert_eq!(o.src, "/srv/cache/etcd.tar.gz");
                assert_eq!(o.dest, "/usr/local/bin");
                assert_eq!(o.format, rsansible_wire::msg::unarchive_format::TAR_GZ);
                assert_eq!(o.creates, "/usr/local/bin/etcd");
                assert_eq!(o.has_mode, 1);
                assert_eq!(o.mode, 0o755);
                assert_eq!(o.keep_newer, 1);
                assert_eq!(o.list_files, 1);
                assert_eq!(o.include, vec!["etcd".to_string()]);
                assert_eq!(o.exclude, vec!["README.md".to_string()]);
            }
            other => panic!("expected OpUnarchive, got {other:?}"),
        }
    }

    #[test]
    fn unarchive_to_wire_op_omits_mode_when_unset() {
        let op = TaskOp::Unarchive(UnarchiveOp {
            src: "/a".into(),
            dest: "/b".into(),
            format: rsansible_wire::msg::unarchive_format::AUTO,
            creates: String::new(),
            mode: None,
            owner: String::new(),
            group: String::new(),
            keep_newer: false,
            list_files: false,
            include: Vec::new(),
            exclude: Vec::new(),
        });
        let wire = op.to_wire_op().unwrap();
        let WireOp::OpUnarchive(o) = wire else { panic!() };
        assert_eq!(o.has_mode, 0);
        assert_eq!(o.mode, 0);
    }
}
