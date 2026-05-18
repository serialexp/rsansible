//! `iptables:` task body. Mirrors Ansible's `ansible.builtin.iptables`
//! (subset). The parsed surface goes straight onto the wire as
//! `OpIptables` — no controller-side branching, the agent does the
//! probe + apply.

use super::shared::{take_optional_field_string, take_optional_port};
use serde::{de::Error as _, Deserialize, Deserializer};

#[derive(Debug, Clone, PartialEq)]
pub struct IptablesOp {
    /// Defaults to `"filter"` at apply time when empty.
    pub table: String,
    /// Required. Typical values: INPUT/OUTPUT/FORWARD or any
    /// user-defined chain.
    pub chain: String,
    /// e.g. `tcp`, `udp`, `icmp`. Empty = any.
    pub protocol: String,
    /// `-s` argument; empty = any.
    pub source: String,
    /// `-d` argument; empty = any.
    pub destination: String,
    /// `--sport`; empty = any. Stringly-typed so range syntax works
    /// (`"1024:65535"`).
    pub source_port: String,
    /// `--dport`; empty = any.
    pub destination_port: String,
    /// `-i`; empty = any.
    pub in_interface: String,
    /// `-o`; empty = any.
    pub out_interface: String,
    /// `-j` target. ACCEPT / DROP / REJECT / RETURN / chain name / etc.
    pub jump: String,
    /// `-m conntrack --ctstate`; empty = none.
    pub ctstate: String,
    /// `-m comment --comment`; empty = none.
    pub comment: String,
    /// 4 (default) or 6. ip_version: ip6 → `ip6tables`.
    pub ip_version: IptablesIpVersion,
    /// `-A` (append, default) or `-I` (insert at position 1).
    pub action: IptablesAction,
    /// `present` (default) creates the rule; `absent` removes it.
    pub rule_state: IptablesRuleState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptablesIpVersion {
    V4,
    V6,
}

impl IptablesIpVersion {
    pub fn wire_byte(self) -> u8 {
        match self {
            IptablesIpVersion::V4 => 4,
            IptablesIpVersion::V6 => 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptablesAction {
    Append,
    Insert,
}

impl IptablesAction {
    pub fn wire_byte(self) -> u8 {
        match self {
            IptablesAction::Append => 0,
            IptablesAction::Insert => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptablesRuleState {
    Present,
    Absent,
}

impl IptablesRuleState {
    pub fn wire_byte(self) -> u8 {
        match self {
            IptablesRuleState::Absent => 0,
            IptablesRuleState::Present => 1,
        }
    }
}

/// Hand-written deserializer so we can:
///   - validate `chain` is set (no default — required field)
///   - reject knobs we know about but don't support yet (so a
///     playbook author sees a clear "not implemented" rather than
///     silent acceptance + wrong behavior)
///   - normalize `state` / `action` / `ip_version` strings to typed enums
impl<'de> Deserialize<'de> for IptablesOp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut map = serde_yaml::Mapping::deserialize(d)?;

        let table = take_optional_field_string(&mut map, "table")?.unwrap_or_default();
        let chain = take_optional_field_string(&mut map, "chain")?
            .ok_or_else(|| D::Error::custom("iptables.chain: required field"))?;
        let protocol = take_optional_field_string(&mut map, "protocol")?
            .or(take_optional_field_string(&mut map, "proto")?)
            .unwrap_or_default();
        let source = take_optional_field_string(&mut map, "source")?
            .or(take_optional_field_string(&mut map, "src")?)
            .unwrap_or_default();
        let destination = take_optional_field_string(&mut map, "destination")?
            .or(take_optional_field_string(&mut map, "dest")?)
            .unwrap_or_default();
        // Ports tolerate ints or strings (range / service-name forms).
        let source_port = take_optional_port(&mut map, "source_port")?.unwrap_or_default();
        let destination_port =
            take_optional_port(&mut map, "destination_port")?.unwrap_or_default();
        let in_interface =
            take_optional_field_string(&mut map, "in_interface")?.unwrap_or_default();
        let out_interface =
            take_optional_field_string(&mut map, "out_interface")?.unwrap_or_default();
        let jump = take_optional_field_string(&mut map, "jump")?.unwrap_or_default();
        let ctstate = take_optional_field_string(&mut map, "ctstate")?.unwrap_or_default();
        let comment = take_optional_field_string(&mut map, "comment")?.unwrap_or_default();

        let ip_version_str = take_optional_field_string(&mut map, "ip_version")?;
        let ip_version = match ip_version_str.as_deref().map(str::to_ascii_lowercase) {
            None => IptablesIpVersion::V4,
            Some(ref s) if s == "ipv4" || s == "4" => IptablesIpVersion::V4,
            Some(ref s) if s == "ipv6" || s == "6" => IptablesIpVersion::V6,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "iptables.ip_version: expected ipv4/4/ipv6/6, got {other:?}"
                )));
            }
        };

        let action_str = take_optional_field_string(&mut map, "action")?;
        let action = match action_str.as_deref().map(str::to_ascii_lowercase) {
            None => IptablesAction::Append,
            Some(s) if s == "append" => IptablesAction::Append,
            Some(s) if s == "insert" => IptablesAction::Insert,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "iptables.action: expected append/insert, got {other:?}"
                )));
            }
        };

        let state_str = take_optional_field_string(&mut map, "state")?;
        let rule_state = match state_str.as_deref().map(str::to_ascii_lowercase) {
            None => IptablesRuleState::Present,
            Some(s) if s == "present" => IptablesRuleState::Present,
            Some(s) if s == "absent" => IptablesRuleState::Absent,
            Some(other) => {
                return Err(D::Error::custom(format!(
                    "iptables.state: expected present/absent, got {other:?}"
                )));
            }
        };

        // Knobs we recognize but don't yet support — surface them
        // loudly so the playbook author sees the gap instead of running
        // and getting silently wrong behavior (e.g. NAT rules that
        // never fire because we ignored to_destination).
        for unsupported in [
            "match",          // generic -m extension we don't expose
            "tcp_flags",      // requires `-m tcp --tcp-flags`
            "syn",            // `--syn`
            "to_destination", // DNAT target arg
            "to_source",      // SNAT target arg
            "to_ports",       // REDIRECT / SNAT target arg
            "reject_with",    // REJECT target arg
            "icmp_type",      // ICMP filter
            "uid_owner",      // -m owner
            "gid_owner",      // -m owner
            "log_prefix",     // LOG target arg
            "log_level",      // LOG target arg
            "limit",          // -m limit
            "limit_burst",
            "flush",          // -F whole chain — different op shape
            "policy",         // chain policy — different op shape
            "rule_num",       // -I <chain> <num> — different positional insert
            "gateway",        // route target arg
            "numeric",        // -L formatting; we don't list rules
            "wait",           // xtables-lock wait time
        ] {
            if map.remove(unsupported).is_some() {
                return Err(D::Error::custom(format!(
                    "iptables.{unsupported}: not yet supported — \
                     please file an issue if you need this knob"
                )));
            }
        }

        if !map.is_empty() {
            let unknown: Vec<String> = map
                .keys()
                .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
                .collect();
            return Err(D::Error::custom(format!(
                "iptables: unknown field(s): {unknown:?}; expected one of \
                 [table, chain, protocol/proto, source/src, destination/dest, source_port, \
                 destination_port, in_interface, out_interface, jump, ctstate, comment, \
                 ip_version, action, state]"
            )));
        }

        Ok(IptablesOp {
            table,
            chain,
            protocol,
            source,
            destination,
            source_port,
            destination_port,
            in_interface,
            out_interface,
            jump,
            ctstate,
            comment,
            ip_version,
            action,
            rule_state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> IptablesOp {
        serde_yaml::from_str(yaml).unwrap_or_else(|e| panic!("parse failed: {e}\n---\n{yaml}"))
    }

    #[test]
    fn parses_minimal_present_rule() {
        let op = parse(
            r#"
chain: OUTPUT
protocol: tcp
destination: 10.0.0.1
destination_port: "2379"
jump: DROP
comment: "drill"
action: insert
state: present
"#,
        );
        assert_eq!(op.chain, "OUTPUT");
        assert_eq!(op.protocol, "tcp");
        assert_eq!(op.destination, "10.0.0.1");
        assert_eq!(op.destination_port, "2379");
        assert_eq!(op.jump, "DROP");
        assert_eq!(op.comment, "drill");
        assert_eq!(op.action, IptablesAction::Insert);
        assert_eq!(op.rule_state, IptablesRuleState::Present);
        assert_eq!(op.ip_version, IptablesIpVersion::V4);
    }

    #[test]
    fn parses_absent_default_action_append() {
        let op = parse(
            r#"
chain: OUTPUT
protocol: tcp
destination: 10.0.0.1
destination_port: "2379"
jump: DROP
state: absent
"#,
        );
        assert_eq!(op.rule_state, IptablesRuleState::Absent);
        assert_eq!(op.action, IptablesAction::Append);
    }

    #[test]
    fn destination_port_as_int_accepts() {
        let op = parse(
            r#"
chain: OUTPUT
protocol: tcp
destination_port: 2379
jump: DROP
"#,
        );
        assert_eq!(op.destination_port, "2379");
    }

    #[test]
    fn ipv6_alias() {
        let op = parse(
            r#"
chain: INPUT
protocol: tcp
destination_port: "22"
jump: ACCEPT
ip_version: ipv6
"#,
        );
        assert_eq!(op.ip_version, IptablesIpVersion::V6);
    }

    #[test]
    fn missing_chain_errors() {
        let r: Result<IptablesOp, _> = serde_yaml::from_str("jump: DROP\n");
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(err.contains("chain"), "msg: {err}");
    }

    #[test]
    fn unsupported_knob_rejected_loudly() {
        let r: Result<IptablesOp, _> = serde_yaml::from_str(
            r#"
chain: PREROUTING
table: nat
jump: DNAT
to_destination: 10.0.0.5:80
"#,
        );
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(
            err.contains("to_destination") && err.contains("not yet supported"),
            "msg: {err}"
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let r: Result<IptablesOp, _> = serde_yaml::from_str(
            r#"
chain: OUTPUT
jump: DROP
totally_made_up: yes
"#,
        );
        let err = format!("{:?}", r.err().expect("expected error"));
        assert!(err.contains("totally_made_up"), "msg: {err}");
    }

    #[test]
    fn proto_alias_accepts() {
        let op = parse(
            r#"
chain: OUTPUT
proto: udp
jump: DROP
"#,
        );
        assert_eq!(op.protocol, "udp");
    }

    #[test]
    fn src_dest_aliases() {
        let op = parse(
            r#"
chain: OUTPUT
src: 10.0.0.1
dest: 10.0.0.2
jump: DROP
"#,
        );
        assert_eq!(op.source, "10.0.0.1");
        assert_eq!(op.destination, "10.0.0.2");
    }
}
