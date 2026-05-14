//! Inventory parsing with Ansible-shaped schema.
//!
//! Wire shape:
//!
//! ```yaml
//! all:
//!   vars:
//!     ansible_user: deploy        # baseline vars applied to every host
//!   children:
//!     postgres:
//!       vars:                     # per-group inline vars (optional)
//!         pg_role: primary
//!       hosts:
//!         db-1:
//!           ansible_host: 10.0.0.5
//!           ansible_port: 22      # optional, default 22
//!           # any other key here is a per-host inventory var
//!     etcd_cluster:
//!       hosts:
//!         e-1: { ansible_host: 10.0.0.20 }
//! ```
//!
//! After loading we expose:
//!   * `Inventory.hosts[name]` — Host with connection coordinates +
//!     per-host inline vars + `member_of` (group memberships).
//!   * `Inventory.groups[name]` — group → host-name list. Always
//!     includes `"all"`.
//!   * `Inventory.all_vars` and `Inventory.group_inline_vars` — vars
//!     declared inline in the inventory YAML (not on disk).
//!
//! On-disk `group_vars/<g>/*.yml` and `host_vars/<h>/*.yml` (and their
//! flat-file variants) are loaded by [`load_with_vars`] alongside the
//! inventory; vault-encrypted files are decrypted using the supplied
//! password.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::exec_ctx::yaml_to_json;
use crate::vault;

/// Fully-parsed inventory.
#[derive(Debug, Clone, PartialEq)]
pub struct Inventory {
    /// Every host that appears anywhere in the tree, with its connection
    /// coordinates pre-resolved (host/port/user/key_path) plus the raw
    /// inline vars declared on the host's own mapping.
    pub hosts: BTreeMap<String, Host>,
    /// Group membership: group name → host names. Insertion order matches
    /// declaration order in the YAML (BTreeMap is sorted, but `all` is
    /// always included). For Ansible-faithful var layering we also keep
    /// the declaration-order list in [`Host::member_of`].
    pub groups: BTreeMap<String, Vec<String>>,
    /// Vars declared inline at `all.vars`. Lowest-precedence source.
    pub all_vars: BTreeMap<String, JsonValue>,
    /// Vars declared inline at `all.children.<g>.vars`. Keyed by group.
    pub group_inline_vars: BTreeMap<String, BTreeMap<String, JsonValue>>,
}

/// Per-host record. `host`/`port`/`user`/`key_path` are the four recognised
/// connection coordinates lifted out of the inline mapping; everything
/// else (other than `ansible_ssh_private_key_file` and the four above)
/// lands in `inline_vars` so it participates in the precedence chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_path: Option<PathBuf>,
    /// Per-host inline vars from the inventory YAML (the non-connection
    /// keys directly under `all.children.<g>.hosts.<h>`).
    pub inline_vars: BTreeMap<String, JsonValue>,
    /// Groups the host belongs to, in declaration order. Always starts
    /// with `"all"`.
    pub member_of: Vec<String>,
}

/// Companion to [`Inventory`] holding the on-disk var files. Indexed by
/// group/host name; absent groups/hosts simply don't have entries.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InventoryVars {
    pub group_vars: BTreeMap<String, BTreeMap<String, JsonValue>>,
    pub host_vars: BTreeMap<String, BTreeMap<String, JsonValue>>,
}

// ---------- raw YAML shape ----------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoot {
    all: RawAll,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAll {
    #[serde(default)]
    vars: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    hosts: BTreeMap<String, RawHostEntry>,
    #[serde(default)]
    children: BTreeMap<String, RawGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    #[serde(default)]
    vars: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    hosts: BTreeMap<String, RawHostEntry>,
}

/// `null` (`db-1:` with no value) is allowed and means "this host with no
/// inline vars". Otherwise: a mapping of `key: value` pairs.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawHostEntry {
    Null,
    Map(BTreeMap<String, serde_yaml::Value>),
}

impl Default for RawHostEntry {
    fn default() -> Self {
        RawHostEntry::Null
    }
}

// ---------- public entry points ----------

/// Parse + flatten an inventory file. `host_vars/` and `group_vars/` on
/// disk are NOT loaded by this entry point — use [`load_with_vars`] for
/// the full picture.
pub fn load(path: &Path) -> Result<Inventory> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading inventory {}", path.display()))?;
    parse(&text).with_context(|| format!("parsing inventory {}", path.display()))
}

/// Parse + flatten + discover adjacent `host_vars/` and `group_vars/`.
///
/// `vault_password` is used to decrypt any `$ANSIBLE_VAULT;…` files
/// encountered. If `None`, encrypted files are skipped with a warning.
pub fn load_with_vars(
    path: &Path,
    vault_password: Option<&str>,
) -> Result<(Inventory, InventoryVars)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading inventory {}", path.display()))?;
    let raw: RawRoot = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing inventory {}: schema", path.display()))?;
    let pre = flatten_pre_hosts(raw)
        .with_context(|| format!("parsing inventory {}", path.display()))?;
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let group_names: Vec<String> = pre.groups.keys().cloned().collect();
    let host_names: Vec<String> = pre.hosts_raw.keys().cloned().collect();
    let vars = discover_vars_named(&base, &group_names, &host_names, vault_password)
        .with_context(|| format!("discovering host_vars/group_vars next to {}", path.display()))?;
    let inv = assemble_inventory(pre, Some(&vars))
        .with_context(|| format!("assembling inventory {}", path.display()))?;
    Ok((inv, vars))
}

/// Parse a YAML string. Same shape as [`load`] but with no filesystem I/O.
pub fn parse(text: &str) -> Result<Inventory> {
    let raw: RawRoot = serde_yaml::from_str(text).context("inventory YAML schema")?;
    flatten(raw)
}

// ---------- raw → Inventory ----------

const CONNECTION_KEYS: &[&str] = &[
    "ansible_host",
    "ansible_port",
    "ansible_user",
    "ansible_ssh_private_key_file",
];

/// Intermediate state produced by the YAML-shape flatten pass. Hosts have
/// not yet been assembled — that's a second pass so we can layer on-disk
/// `group_vars/` and `host_vars/` into the connection-coord resolution.
struct PreHosts {
    all_vars: BTreeMap<String, JsonValue>,
    groups: BTreeMap<String, Vec<String>>,
    group_inline_vars: BTreeMap<String, BTreeMap<String, JsonValue>>,
    hosts_raw: BTreeMap<String, (Vec<String>, BTreeMap<String, JsonValue>)>,
}

fn flatten(raw: RawRoot) -> Result<Inventory> {
    let pre = flatten_pre_hosts(raw)?;
    assemble_inventory(pre, None)
}

fn flatten_pre_hosts(raw: RawRoot) -> Result<PreHosts> {
    let RawRoot { all } = raw;

    // all.vars
    let all_vars = yaml_map_to_json(all.vars).context("all.vars")?;

    // Reject hosts declared directly under `all.hosts` for the survey-driven
    // simplification — gothab puts everything under children groups. Once
    // we need to support ungrouped hosts we can flip this on, but unknown
    // shapes are better caught early.
    if !all.hosts.is_empty() {
        bail!(
            "all.hosts is not supported; declare hosts inside an `all.children.<group>.hosts` mapping (got {} ungrouped host(s))",
            all.hosts.len()
        );
    }

    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut group_inline_vars: BTreeMap<String, BTreeMap<String, JsonValue>> = BTreeMap::new();
    // host_name -> (Vec<group>, inline_vars from per-host mapping)
    let mut hosts_raw: BTreeMap<String, (Vec<String>, BTreeMap<String, JsonValue>)> = BTreeMap::new();

    for (group_name, group) in all.children {
        if group_name == "all" {
            bail!("inventory: cannot redeclare the implicit `all` group as a child");
        }
        let gv = yaml_map_to_json(group.vars)
            .with_context(|| format!("all.children.{group_name}.vars"))?;
        if !gv.is_empty() {
            group_inline_vars.insert(group_name.clone(), gv);
        }
        let mut members = Vec::new();
        for (host_name, entry) in group.hosts {
            members.push(host_name.clone());
            let inline = match entry {
                RawHostEntry::Null => BTreeMap::new(),
                RawHostEntry::Map(m) => yaml_map_to_json(m)
                    .with_context(|| format!("host {host_name} inline vars"))?,
            };
            let slot = hosts_raw
                .entry(host_name.clone())
                .or_insert_with(|| (Vec::new(), BTreeMap::new()));
            // Merge inline vars across multiple group appearances (last
            // write wins, matching Ansible's shallow merge).
            for (k, v) in inline {
                slot.1.insert(k, v);
            }
            slot.0.push(group_name.clone());
        }
        groups.insert(group_name, members);
    }

    // Build the `all` group as the union of every group's members, in
    // declaration order, deduped.
    let mut all_members: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (_, ms) in &groups {
        for h in ms {
            if seen.insert(h.clone()) {
                all_members.push(h.clone());
            }
        }
    }
    groups.insert("all".to_string(), all_members);

    Ok(PreHosts {
        all_vars,
        groups,
        group_inline_vars,
        hosts_raw,
    })
}

fn assemble_inventory(pre: PreHosts, disk: Option<&InventoryVars>) -> Result<Inventory> {
    let PreHosts {
        all_vars,
        groups,
        group_inline_vars,
        hosts_raw,
    } = pre;

    // Now assemble Hosts. Connection coords come from a precedence merge
    // of all_vars + on-disk group_vars/all + group_inline_vars +
    // on-disk group_vars/<group> (in member_of order) + on-disk host_vars
    // + host inline.
    let mut hosts: BTreeMap<String, Host> = BTreeMap::new();
    for (name, (member_groups, inline)) in hosts_raw {
        let mut member_of: Vec<String> = Vec::with_capacity(member_groups.len() + 1);
        member_of.push("all".to_string());
        for g in &member_groups {
            if !member_of.contains(g) {
                member_of.push(g.clone());
            }
        }

        // Build the effective view for connection-coord lookup. Precedence
        // (low → high): all.vars → on-disk group_vars/<group> in
        // member_of order → all.children.<group>.vars (inline) for each
        // group → on-disk host_vars/<host> → host's inline mapping.
        let mut view: BTreeMap<String, JsonValue> = BTreeMap::new();
        for (k, v) in &all_vars {
            view.insert(k.clone(), v.clone());
        }
        for g in &member_of {
            if let Some(d) = disk.and_then(|d| d.group_vars.get(g)) {
                for (k, v) in d {
                    view.insert(k.clone(), v.clone());
                }
            }
            if let Some(gv) = group_inline_vars.get(g) {
                for (k, v) in gv {
                    view.insert(k.clone(), v.clone());
                }
            }
        }
        if let Some(d) = disk.and_then(|d| d.host_vars.get(&name)) {
            for (k, v) in d {
                view.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &inline {
            view.insert(k.clone(), v.clone());
        }

        let host_addr = view
            .get("ansible_host")
            .and_then(JsonValue::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("host {name:?}: ansible_host is required"))?;
        let port = match view.get("ansible_port") {
            Some(JsonValue::Number(n)) => n
                .as_u64()
                .and_then(|u| u16::try_from(u).ok())
                .ok_or_else(|| anyhow!("host {name:?}: ansible_port out of range"))?,
            Some(JsonValue::String(s)) => s
                .parse::<u16>()
                .map_err(|e| anyhow!("host {name:?}: ansible_port {s:?} not a u16: {e}"))?,
            Some(other) => bail!("host {name:?}: ansible_port has wrong type: {other:?}"),
            None => 22,
        };
        let user = view
            .get("ansible_user")
            .and_then(JsonValue::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                anyhow!("host {name:?}: ansible_user is required (set it at host, group, or all.vars scope)")
            })?;
        let key_path = view
            .get("ansible_ssh_private_key_file")
            .and_then(JsonValue::as_str)
            .map(PathBuf::from);

        // Inline-only retained vars excluded from CONNECTION_KEYS — these
        // are what step 4 of the precedence chain layers on per host.
        let mut inline_vars = inline;
        for k in CONNECTION_KEYS {
            inline_vars.remove(*k);
        }

        hosts.insert(
            name,
            Host {
                host: host_addr,
                port,
                user,
                key_path,
                inline_vars,
                member_of,
            },
        );
    }

    Ok(Inventory {
        hosts,
        groups,
        all_vars,
        group_inline_vars,
    })
}

fn yaml_map_to_json(
    m: BTreeMap<String, serde_yaml::Value>,
) -> Result<BTreeMap<String, JsonValue>> {
    let mut out = BTreeMap::new();
    for (k, v) in m {
        out.insert(k, yaml_to_json(v)?);
    }
    Ok(out)
}

// ---------- group_vars / host_vars discovery ----------

fn discover_vars_named(
    base: &Path,
    group_names: &[String],
    host_names: &[String],
    vault_password: Option<&str>,
) -> Result<InventoryVars> {
    let mut out = InventoryVars::default();
    let gv_root = base.join("group_vars");
    // Always look for `all/` even if it's only the implicit group.
    let mut seen_all = false;
    for group in group_names {
        if group == "all" {
            seen_all = true;
        }
        if let Some(map) = load_var_target(&gv_root, group, vault_password)? {
            out.group_vars.insert(group.clone(), map);
        }
    }
    if !seen_all {
        if let Some(map) = load_var_target(&gv_root, "all", vault_password)? {
            out.group_vars.insert("all".to_string(), map);
        }
    }
    let hv_root = base.join("host_vars");
    for host in host_names {
        if let Some(map) = load_var_target(&hv_root, host, vault_password)? {
            out.host_vars.insert(host.clone(), map);
        }
    }
    Ok(out)
}

/// Look for `<root>/<name>/<any>.yml|yaml` (dir form) or `<root>/<name>.yml|yaml`
/// (file form). Returns `Ok(None)` when nothing was found.
fn load_var_target(
    root: &Path,
    name: &str,
    vault_password: Option<&str>,
) -> Result<Option<BTreeMap<String, JsonValue>>> {
    let dir = root.join(name);
    if dir.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .with_context(|| format!("listing {}", dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e == "yml" || e == "yaml")
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        let mut merged: BTreeMap<String, JsonValue> = BTreeMap::new();
        for f in files {
            let m = load_var_file(&f, vault_password)?;
            for (k, v) in m {
                merged.insert(k, v);
            }
        }
        return Ok(Some(merged));
    }
    for ext in ["yml", "yaml"] {
        let file = root.join(format!("{name}.{ext}"));
        if file.is_file() {
            return Ok(Some(load_var_file(&file, vault_password)?));
        }
    }
    Ok(None)
}

fn load_var_file(
    path: &Path,
    vault_password: Option<&str>,
) -> Result<BTreeMap<String, JsonValue>> {
    let raw = std::fs::read(path)
        .with_context(|| format!("reading var file {}", path.display()))?;
    let bytes: Vec<u8> = if vault::is_vault(&raw) {
        match vault_password {
            Some(pw) => vault::decrypt(&raw, pw)
                .with_context(|| format!("decrypting vault file {}", path.display()))?,
            None => {
                tracing::warn!(
                    file = %path.display(),
                    "vault-encrypted file skipped: no vault password supplied",
                );
                return Ok(BTreeMap::new());
            }
        }
    } else {
        raw
    };
    let yaml: serde_yaml::Value = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("parsing var file {}", path.display()))?;
    let map = match yaml {
        serde_yaml::Value::Null => return Ok(BTreeMap::new()),
        serde_yaml::Value::Mapping(m) => m,
        other => bail!(
            "var file {} must be a YAML mapping (got {other:?})",
            path.display()
        ),
    };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        let key = match k {
            serde_yaml::Value::String(s) => s,
            other => bail!(
                "var file {}: keys must be strings, got {other:?}",
                path.display()
            ),
        };
        out.insert(key, yaml_to_json(v)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn ok(inv: Result<Inventory>) -> Inventory {
        inv.unwrap()
    }

    #[test]
    fn parses_minimal_inventory() {
        let inv = ok(parse(
            r#"
all:
  vars:
    ansible_user: deploy
  children:
    web:
      hosts:
        web1:
          ansible_host: 10.0.0.1
"#,
        ));
        let h = &inv.hosts["web1"];
        assert_eq!(h.host, "10.0.0.1");
        assert_eq!(h.port, 22);
        assert_eq!(h.user, "deploy");
        assert!(h.key_path.is_none());
        assert_eq!(h.member_of, vec!["all".to_string(), "web".to_string()]);
        assert_eq!(inv.groups["all"], vec!["web1"]);
        assert_eq!(inv.groups["web"], vec!["web1"]);
        assert_eq!(inv.all_vars.get("ansible_user").map(|v| v.as_str().unwrap()), Some("deploy"));
    }

    #[test]
    fn lifts_connection_coords_and_keeps_other_inline_vars() {
        let inv = ok(parse(
            r#"
all:
  vars:
    ansible_user: deploy
  children:
    db:
      vars:
        pg_role: primary
      hosts:
        db1:
          ansible_host: 192.0.2.1
          ansible_port: 2222
          ansible_ssh_private_key_file: /home/me/.ssh/id_ed25519
          instance_marker: alpha
"#,
        ));
        let h = &inv.hosts["db1"];
        assert_eq!(h.port, 2222);
        assert_eq!(h.key_path.as_deref().unwrap().to_string_lossy(), "/home/me/.ssh/id_ed25519");
        assert!(!h.inline_vars.contains_key("ansible_host"));
        assert!(!h.inline_vars.contains_key("ansible_port"));
        assert!(!h.inline_vars.contains_key("ansible_ssh_private_key_file"));
        assert_eq!(
            h.inline_vars.get("instance_marker").and_then(|v| v.as_str()),
            Some("alpha")
        );
        assert_eq!(
            inv.group_inline_vars["db"].get("pg_role").and_then(|v| v.as_str()),
            Some("primary")
        );
    }

    #[test]
    fn host_in_two_groups_carries_both_in_member_of() {
        let inv = ok(parse(
            r#"
all:
  vars:
    ansible_user: deploy
  children:
    web:
      hosts:
        h1: { ansible_host: 1.1.1.1 }
    bastion:
      hosts:
        h1: { ansible_host: 1.1.1.1 }
"#,
        ));
        let h = &inv.hosts["h1"];
        assert!(h.member_of.contains(&"web".to_string()));
        assert!(h.member_of.contains(&"bastion".to_string()));
        assert_eq!(h.member_of[0], "all");
    }

    #[test]
    fn missing_ansible_host_errors() {
        let err = parse(
            r#"
all:
  vars:
    ansible_user: deploy
  children:
    web:
      hosts:
        broken: {}
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ansible_host"), "got: {msg}");
    }

    #[test]
    fn missing_ansible_user_errors() {
        let err = parse(
            r#"
all:
  children:
    web:
      hosts:
        h1: { ansible_host: 1.2.3.4 }
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ansible_user"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let err = parse(
            r#"
all:
  vars: {}
  children: {}
extra_root: nope
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("extra_root") || msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_group_key() {
        let err = parse(
            r#"
all:
  vars:
    ansible_user: deploy
  children:
    web:
      mistyped: {}
      hosts:
        h1: { ansible_host: 1.2.3.4 }
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("mistyped") || msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn discovers_group_and_host_vars_dir_form() {
        let dir = tempfile::tempdir().unwrap();
        let inv_path = dir.path().join("inv.yml");
        fs::write(
            &inv_path,
            r#"
all:
  vars:
    ansible_user: deploy
  children:
    web:
      hosts:
        h1: { ansible_host: 1.1.1.1 }
        h2: { ansible_host: 1.1.1.2 }
"#,
        )
        .unwrap();
        let gv = dir.path().join("group_vars").join("all");
        fs::create_dir_all(&gv).unwrap();
        fs::write(gv.join("main.yml"), "region: us-east-1\n").unwrap();
        let gv_web = dir.path().join("group_vars").join("web");
        fs::create_dir_all(&gv_web).unwrap();
        fs::write(gv_web.join("a.yml"), "tier: a\n").unwrap();
        fs::write(gv_web.join("b.yml"), "tier: b\n").unwrap(); // overrides
        let hv = dir.path().join("host_vars");
        fs::create_dir_all(&hv).unwrap();
        fs::write(hv.join("h1.yml"), "instance_marker: alpha\n").unwrap();

        let (_inv, vars) = load_with_vars(&inv_path, None).unwrap();
        assert_eq!(
            vars.group_vars["all"].get("region").and_then(|v| v.as_str()),
            Some("us-east-1")
        );
        // alphabetical order → b.yml overrides a.yml
        assert_eq!(
            vars.group_vars["web"].get("tier").and_then(|v| v.as_str()),
            Some("b")
        );
        assert_eq!(
            vars.host_vars["h1"].get("instance_marker").and_then(|v| v.as_str()),
            Some("alpha")
        );
        assert!(!vars.host_vars.contains_key("h2"));
    }

    #[test]
    fn discovers_vault_when_password_supplied() {
        let dir = tempfile::tempdir().unwrap();
        let inv_path = dir.path().join("inv.yml");
        fs::write(
            &inv_path,
            r#"
all:
  vars:
    ansible_user: deploy
  children:
    web:
      hosts:
        h1: { ansible_host: 1.1.1.1 }
"#,
        )
        .unwrap();
        let gv = dir.path().join("group_vars").join("web");
        fs::create_dir_all(&gv).unwrap();
        let ct = crate::vault::encrypt_for_test(b"secret: hunter2\n", "pw", &[7u8; 32]);
        fs::write(gv.join("vault.yml"), &ct).unwrap();

        // Without password — skipped, no entry.
        let (_inv, vars_no) = load_with_vars(&inv_path, None).unwrap();
        assert!(vars_no.group_vars.get("web").map(|m| m.is_empty()).unwrap_or(true));

        // With password — decrypted.
        let (_inv, vars_yes) = load_with_vars(&inv_path, Some("pw")).unwrap();
        assert_eq!(
            vars_yes.group_vars["web"].get("secret").and_then(|v| v.as_str()),
            Some("hunter2")
        );
    }
}
