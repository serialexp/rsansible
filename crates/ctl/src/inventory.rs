//! Inventory parsing.
//!
//! v0 is deliberately tiny: a flat map of host name → connection coordinates.
//! No groups, no host_vars, no SSH-config lookup — the plan calls that out
//! explicitly (see `~/.claude/plans/rustling-imagining-journal.md`).
//!
//! The shape:
//!
//! ```yaml
//! hosts:
//!   web1:
//!     host: 192.168.1.10
//!     user: deploy
//!     key_path: ~/.ssh/id_ed25519
//!   web2:
//!     host: 192.168.1.11
//!     port: 2222
//!     user: deploy
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub hosts: BTreeMap<String, Host>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

fn default_port() -> u16 {
    22
}

pub fn load(path: &Path) -> Result<Inventory> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading inventory {}", path.display()))?;
    parse(&text).with_context(|| format!("parsing inventory {}", path.display()))
}

pub fn parse(text: &str) -> Result<Inventory> {
    let inv: Inventory = serde_yaml::from_str(text)?;
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_inventory() {
        let inv = parse(
            r#"
hosts:
  web1:
    host: 10.0.0.1
    user: deploy
"#,
        )
        .unwrap();
        assert_eq!(inv.hosts.len(), 1);
        let h = &inv.hosts["web1"];
        assert_eq!(h.host, "10.0.0.1");
        assert_eq!(h.port, 22);
        assert_eq!(h.user, "deploy");
        assert!(h.key_path.is_none());
    }

    #[test]
    fn parses_full_host_entry() {
        let inv = parse(
            r#"
hosts:
  web2:
    host: 192.168.1.11
    port: 2222
    user: ops
    key_path: /home/me/.ssh/id_ed25519
"#,
        )
        .unwrap();
        let h = &inv.hosts["web2"];
        assert_eq!(h.port, 2222);
        assert_eq!(h.user, "ops");
        assert_eq!(
            h.key_path.as_deref().unwrap().to_string_lossy(),
            "/home/me/.ssh/id_ed25519"
        );
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let err = parse(
            r#"
hosts:
  web1:
    host: 10.0.0.1
    user: deploy
groups: {}
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("groups"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_host_key() {
        let err = parse(
            r#"
hosts:
  web1:
    host: 10.0.0.1
    user: deploy
    becomes: root
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("becomes"), "got: {msg}");
    }

    #[test]
    fn rejects_missing_required_fields() {
        let err = parse(
            r#"
hosts:
  web1:
    host: 10.0.0.1
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("user"), "got: {msg}");
    }
}
