//! `--limit` host-pattern filter.
//!
//! Thin wrapper around [`HostPattern`] that turns the controller's
//! repeated `--limit` CLI args into a single pattern and exposes the
//! two queries the orchestrator needs:
//!
//! - [`LimitFilter::preflight`]: resolve the pattern against the full
//!   inventory once at startup. Empty result → operator typo, the
//!   orchestrator bails before any SSH dial.
//! - [`LimitFilter::apply`]: per-play intersection of a play's resolved
//!   host list with the limit. Cheap no-op when the filter is inactive.
//!
//! The grammar is the same as the playbook `hosts:` field — see
//! [`crate::host_pattern`] for the full pattern reference.

use std::collections::BTreeSet;

use crate::host_pattern::{HostPattern, HostPatternError};
use crate::inventory::Inventory;

/// CLI-driven host-set filter.
#[derive(Debug, Clone, Default)]
pub struct LimitFilter {
    pattern: Option<HostPattern>,
}

impl LimitFilter {
    /// Build from the raw `--limit` arg vector. Repeated flags and
    /// comma-splits are joined with `,` (Ansible-equivalent: each
    /// repetition adds union terms). Whitespace-only entries are
    /// rejected so `--limit ""` and `--limit foo, ,bar` surface clearly.
    pub fn from_cli(parts: &[String]) -> Result<Self, HostPatternError> {
        if parts.is_empty() {
            return Ok(Self { pattern: None });
        }
        // Any whitespace-only entry is a typo (most likely `--limit ""`
        // or a stray comma in `--limit foo,,bar`). Surface explicitly
        // rather than silently dropping.
        for s in parts {
            if s.trim().is_empty() {
                return Err(HostPatternError::EmptyTerm(parts.join(",")));
            }
        }
        let joined = parts
            .iter()
            .map(|s| s.trim())
            .collect::<Vec<_>>()
            .join(",");
        let pattern = HostPattern::parse(&joined)?;
        Ok(Self { pattern: Some(pattern) })
    }

    /// Returns true iff the user supplied a `--limit` value.
    pub fn is_active(&self) -> bool {
        self.pattern.is_some()
    }

    /// Resolve the pattern against the full inventory. Used at run
    /// startup to detect the zero-match case before any SSH dial.
    pub fn preflight(&self, inv: &Inventory) -> Vec<String> {
        match &self.pattern {
            Some(p) => p.resolve(inv),
            None => inv.hosts.keys().cloned().collect(),
        }
    }

    /// Intersect a play's host list with the limit. Pass-through when
    /// the filter is inactive. Preserves the play's host order.
    pub fn apply(&self, inv: &Inventory, play_hosts: &[String]) -> Vec<String> {
        let Some(pattern) = &self.pattern else {
            return play_hosts.to_vec();
        };
        let allowed: BTreeSet<String> = pattern.resolve(inv).into_iter().collect();
        play_hosts
            .iter()
            .filter(|h| allowed.contains(h.as_str()))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Host;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn fixture() -> Inventory {
        let mut hosts = BTreeMap::new();
        for n in ["web1", "web2", "web3", "db1"] {
            hosts.insert(
                n.to_string(),
                Host {
                    host: format!("{n}.local"),
                    port: 22,
                    user: "u".into(),
                    key_path: None::<PathBuf>,
                    inline_vars: BTreeMap::new(),
                    member_of: vec!["all".into()],
                },
            );
        }
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        groups.insert(
            "all".into(),
            vec!["db1", "web1", "web2", "web3"]
                .into_iter()
                .map(String::from)
                .collect(),
        );
        groups.insert(
            "webservers".into(),
            vec!["web1", "web2", "web3"].into_iter().map(String::from).collect(),
        );
        Inventory {
            hosts,
            groups,
            all_vars: BTreeMap::new(),
            group_inline_vars: BTreeMap::new(),
        }
    }

    #[test]
    fn inactive_when_no_args() {
        let f = LimitFilter::from_cli(&[]).unwrap();
        assert!(!f.is_active());
    }

    #[test]
    fn inactive_when_only_whitespace_filtered_out_by_clap() {
        // Clap's value_delimiter would already split into one empty
        // string for `--limit ""`; we treat the resulting single
        // whitespace-only entry as an error (typo).
        let err = LimitFilter::from_cli(&[" ".to_string()]).unwrap_err();
        assert!(matches!(err, HostPatternError::EmptyTerm(_)));
    }

    #[test]
    fn comma_splitting() {
        let f = LimitFilter::from_cli(&["web*,!web2".to_string()]).unwrap();
        let inv = fixture();
        assert_eq!(f.preflight(&inv), vec!["web1", "web3"]);
    }

    #[test]
    fn repeated_flags_join_via_union() {
        let f =
            LimitFilter::from_cli(&["web1".to_string(), "db1".to_string()]).unwrap();
        let inv = fixture();
        assert_eq!(f.preflight(&inv), vec!["web1", "db1"]);
    }

    #[test]
    fn apply_intersects_play_hosts() {
        let f = LimitFilter::from_cli(&["web*".to_string()]).unwrap();
        let inv = fixture();
        let play = vec!["web1".to_string(), "db1".to_string(), "web3".to_string()];
        assert_eq!(f.apply(&inv, &play), vec!["web1", "web3"]);
    }

    #[test]
    fn apply_passthrough_when_inactive() {
        let f = LimitFilter::from_cli(&[]).unwrap();
        let inv = fixture();
        let play = vec!["web1".to_string(), "db1".to_string()];
        assert_eq!(f.apply(&inv, &play), play);
    }
}
