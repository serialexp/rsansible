//! `write_file:` task body.

use super::shared::{deserialize_mode_field, ModeField};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WriteFileOp {
    pub path: String,
    /// Octal in YAML (e.g. `0o644` literal, `"0644"` string, or 420
    /// decimal). Also accepts a Jinja expression like
    /// `"{{ item.mode }}"`, resolved at dispatch.
    #[serde(deserialize_with = "deserialize_mode_field")]
    pub mode: ModeField,
    pub content: String,
    /// Optional validator command; same shape as Ansible's `validate:`
    /// on `copy`/`template`. Empty / `None` = no validation. When set,
    /// the agent runs the command against the staged tmp file before
    /// rename; non-zero exit aborts the write. `%s` is substituted by
    /// the tmp path.
    #[serde(default)]
    pub validate: Option<String>,
    /// File owner (POSIX user name). Empty / `None` = don't chown.
    /// Resolved on the agent host via /etc/passwd and applied to the
    /// staged tmp before rename.
    #[serde(default)]
    pub owner: Option<String>,
    /// File group (POSIX group name). Empty / `None` = don't chgrp.
    /// Resolved on the agent host via /etc/group and applied to the
    /// staged tmp before rename.
    #[serde(default)]
    pub group: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{TaskOp};

    #[test]
    fn write_file_to_wire() {
        let t = TaskOp::WriteFile(WriteFileOp {
            path: "/tmp/x".into(),
            mode: crate::playbook::ModeField::Literal(0o600),
            content: "hello".into(),
            validate: None,
            owner: None,
            group: None,
        });
        let WireOp::OpWriteFile(w) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(w.kind, 2);
        assert_eq!(w.path, "/tmp/x");
        assert_eq!(w.mode, 0o600);
        assert_eq!(w.content, b"hello");
    }
}
