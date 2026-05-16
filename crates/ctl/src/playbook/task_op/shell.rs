//! `shell:` task body.

use serde::Deserialize;

/// `shell: "..."` (most common) or `shell: { command: "...", timeout_ms: N }`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ShellOp {
    Simple(String),
    Detailed {
        command: String,
        #[serde(default)]
        timeout_ms: u32,
    },
}

impl ShellOp {
    pub fn command(&self) -> &str {
        match self {
            ShellOp::Simple(s) => s,
            ShellOp::Detailed { command, .. } => command,
        }
    }
    pub fn timeout_ms(&self) -> u32 {
        match self {
            ShellOp::Simple(_) => 0,
            ShellOp::Detailed { timeout_ms, .. } => *timeout_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{TaskOp};

    #[test]
    fn shell_simple_to_wire() {
        let t = TaskOp::Shell(ShellOp::Simple("echo hi".into()));
        let WireOp::OpShell(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.kind, 1);
        assert_eq!(s.command, "echo hi");
        assert_eq!(s.timeout_ms, 0);
    }

    #[test]
    fn shell_detailed_to_wire() {
        let t = TaskOp::Shell(ShellOp::Detailed {
            command: "sleep 1".into(),
            timeout_ms: 500,
        });
        let WireOp::OpShell(s) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(s.timeout_ms, 500);
    }
}
