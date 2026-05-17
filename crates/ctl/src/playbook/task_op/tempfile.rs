//! `tempfile:` — create a temporary file or directory.
//!
//! Maps Ansible's `ansible.builtin.tempfile`. **Controller-side only**
//! in v1: the temp object is created on the controller filesystem
//! using Rust's `std::env::temp_dir()` semantics (honors `TMPDIR`). The
//! register reports `.path` as the absolute path to the created object,
//! matching Ansible's contract. See `ANSIBLE_COMPAT.md` §5 for the
//! controller-vs-target divergence rationale.
//!
//! The op is intentionally "synthetic" (no wire dispatch) the same way
//! `openssl_csr_pipe:` and `x509_certificate_pipe:` are. For Phase 1
//! the only consumer is the bootstrap-etcd-ca playbook, which runs
//! `connection: local` on `localhost` and needs a working directory for
//! CA material — controller-side is exactly what that needs.
//!
//! When a future playbook needs a temp file on a remote target we will
//! grow a wire op (`OpTempfile`) and the controller-side branch becomes
//! the "execute when connection: local OR delegate_to: localhost" arm.
//! Until then, using `tempfile:` against a remote target is a documented
//! divergence — see `ANSIBLE_COMPAT.md`.

use super::shared::take_optional_field_string;
use serde::{de::Error as _, Deserialize, Deserializer};

/// Whether to create a temporary file (the default) or a temporary
/// directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempfileKind {
    File,
    Directory,
}

impl TempfileKind {
    fn from_yaml_str(s: &str) -> Result<Self, String> {
        match s {
            "file" => Ok(TempfileKind::File),
            "directory" => Ok(TempfileKind::Directory),
            other => Err(format!(
                "tempfile.state: expected \"file\" or \"directory\", got: {other:?}"
            )),
        }
    }
}

/// `tempfile:` parsed form.
#[derive(Debug, Clone, PartialEq)]
pub struct TempfileOp {
    /// `state: file | directory`. Default `file`.
    pub state: TempfileKind,
    /// `suffix:` — appended to the random part. Default empty.
    /// Jinja-templatable.
    pub suffix: String,
    /// `prefix:` — prepended to the random part. Default `"ansible."`
    /// (matches Ansible). Jinja-templatable.
    pub prefix: String,
    /// `path:` — parent directory. None means "system tmp dir"
    /// (`$TMPDIR` → `/tmp`). Jinja-templatable.
    pub path: Option<String>,
}

fn default_prefix() -> String {
    "ansible.".to_string()
}

impl<'de> Deserialize<'de> for TempfileOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;
        let state = match map.remove("state") {
            None | Some(serde_yaml::Value::Null) => TempfileKind::File,
            Some(serde_yaml::Value::String(s)) => {
                TempfileKind::from_yaml_str(&s).map_err(D::Error::custom)?
            }
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "tempfile.state: expected a string, got: {other:?}"
                )));
            }
        };
        let suffix = take_optional_field_string::<D::Error>(&mut map, "suffix")?
            .unwrap_or_default();
        let prefix = take_optional_field_string::<D::Error>(&mut map, "prefix")?
            .unwrap_or_else(default_prefix);
        let path = take_optional_field_string::<D::Error>(&mut map, "path")?;
        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "tempfile: unknown field(s): {unknown:?}; expected one of \
                 [state, suffix, prefix, path]"
            )));
        }
        Ok(TempfileOp { state, suffix, prefix, path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{
        parse_task_for_test as parse_task, try_parse_task_for_test as try_parse_task, TaskBody,
        TaskOp,
    };

    #[test]
    fn parses_minimal_tempfile() {
        let t = parse_task(
            r#"
name: tmp
tempfile: {}
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Tempfile(p)) => {
                assert_eq!(p.state, TempfileKind::File);
                assert_eq!(p.prefix, "ansible.");
                assert_eq!(p.suffix, "");
                assert!(p.path.is_none());
            }
            other => panic!("expected Tempfile, got {other:?}"),
        }
    }

    #[test]
    fn parses_directory_with_suffix() {
        let t = parse_task(
            r#"
name: tmpdir
tempfile:
  state: directory
  suffix: "_etcd_ca"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Tempfile(p)) => {
                assert_eq!(p.state, TempfileKind::Directory);
                assert_eq!(p.suffix, "_etcd_ca");
                assert_eq!(p.prefix, "ansible.");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parses_full_tempfile() {
        let t = parse_task(
            r#"
name: tmp
tempfile:
  state: file
  prefix: "custom-"
  suffix: ".log"
  path: /var/tmp
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Tempfile(p)) => {
                assert_eq!(p.state, TempfileKind::File);
                assert_eq!(p.prefix, "custom-");
                assert_eq!(p.suffix, ".log");
                assert_eq!(p.path.as_deref(), Some("/var/tmp"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_state() {
        let err = try_parse_task(
            r#"
name: t
tempfile:
  state: socket
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("socket"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_field() {
        let err = try_parse_task(
            r#"
name: t
tempfile:
  template: blah
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("template") || msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn accepts_fqcn_spelling() {
        let t = parse_task(
            r#"
name: tmp
ansible.builtin.tempfile:
  state: directory
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Tempfile(p)) => {
                assert_eq!(p.state, TempfileKind::Directory);
            }
            other => panic!("got {other:?}"),
        }
    }
}
