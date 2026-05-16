//! `write_file:` task body.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WriteFileOp {
    pub path: String,
    /// Octal in YAML (e.g. `0o644`) — serde-yaml parses that natively.
    pub mode: u32,
    pub content: String,
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
            mode: 0o600,
            content: "hello".into(),
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
