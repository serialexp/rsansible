//! `exec:` task body.

use super::shared::deserialize_scalar_string_map;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecOp {
    pub argv: Vec<String>,
    /// Env keys map to string values. YAML often spells these as bare
    /// scalars (`COUNT: 3`, `DEBUG: true`); coerce ints/bools to their
    /// string form to match Ansible's behavior.
    #[serde(default, deserialize_with = "deserialize_scalar_string_map")]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Optional stdin payload, base64-encoded in YAML so binary data survives.
    /// (Empty/absent → empty stdin.) v0 keeps this minimal; we only handle
    /// the UTF-8 string form here. Bytes form lands when we need it.
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub timeout_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsansible_wire::generated::Op as WireOp;
    use crate::playbook::task_op::{TaskOp};
    use std::collections::BTreeMap;

    #[test]
    fn exec_to_wire_preserves_env_order() {
        let mut env = BTreeMap::new();
        env.insert("B".into(), "2".into());
        env.insert("A".into(), "1".into());
        let t = TaskOp::Exec(ExecOp {
            argv: vec!["/bin/true".into()],
            env,
            cwd: Some("/tmp".into()),
            stdin: String::new(),
            timeout_ms: 1000,
        });
        let WireOp::OpExec(e) = t.to_wire_op().unwrap() else {
            panic!()
        };
        assert_eq!(e.kind, 0);
        assert_eq!(e.argv, vec!["/bin/true"]);
        // BTreeMap → sorted keys → CSR parallel arrays.
        assert_eq!(e.env_keys, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(e.env_values, vec!["1".to_string(), "2".to_string()]);
        assert_eq!(e.cwd, "/tmp");
        assert_eq!(e.timeout_ms, 1000);
    }

    #[test]
    fn exec_empty_argv_rejected() {
        let t = TaskOp::Exec(ExecOp {
            argv: vec![],
            env: BTreeMap::new(),
            cwd: None,
            stdin: String::new(),
            timeout_ms: 0,
        });
        assert!(t.to_wire_op().is_err());
    }
}
