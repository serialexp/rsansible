//! `package:` / `apt:` / `dnf:` / `apk:` / ... task body.

use super::shared::{take_optional_ansible_bool, take_optional_field_string};

/// `package:` / `apt:` / `dnf:` / ... parsed form. The wire shape
/// carries the union of all backends' knobs (some are apt-only); the
/// agent ignores fields its backend doesn't consume. `names` is the
/// list of packages — Ansible's `name:` accepts either a single string
/// or a list; we normalize to a Vec at parse time.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageOp {
    /// Which backend to dispatch to. The YAML keys `apt:`, `dnf:`,
    /// `apk:`, etc. pin this at parse time. The generic `package:` key
    /// sets it to `Auto` and lets the agent choose at run time.
    pub manager: PackageManager,
    pub names: Vec<String>,
    pub state: PackageState,
    pub update_cache: bool,
    /// Seconds; only meaningful with `update_cache=true`. 0 = always
    /// update. Apt-only on the agent side (other backends ignore).
    pub cache_valid_time: u32,
    /// Apt-only: switches `remove` for `purge` on absent.
    pub purge: bool,
    /// Apt/dnf: run an autoremove pass after the main op.
    pub autoremove: bool,
    /// Apt-only: maps to `apt-get -t <release>`. Empty = unused.
    pub default_release: String,
    /// Apt-only: adds `--allow-unauthenticated`.
    pub allow_unauthenticated: bool,
    /// Pip-only: install target virtualenv directory. Empty = system pip
    /// (no venv). If the directory doesn't exist the agent creates it
    /// via `virtualenv_command`.
    pub virtualenv: String,
    /// Pip-only: command used to materialise a missing virtualenv.
    /// Empty = default `python3 -m venv`. Tokenised on whitespace at
    /// the agent (shell metacharacters NOT honored).
    pub virtualenv_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageState {
    Present,
    Absent,
    Latest,
}

impl PackageState {
    pub fn wire_byte(self) -> u8 {
        match self {
            PackageState::Present => 0,
            PackageState::Absent => 1,
            PackageState::Latest => 2,
        }
    }
}

/// Which package-manager backend to dispatch the wire op to. The YAML
/// per-manager keys (`apt:`, `dnf:`, ...) pin this to a specific value;
/// the generic `package:` key uses `Auto` so the agent detects what's
/// available on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Auto,
    Apt,
    Pip,
    // Reserved for future backends — wire bytes already allocated in
    // rsansible_wire::msg::package_manager. Uncomment + add to wire_byte
    // when the agent gains a backend for them.
    // Dnf,
    // Yum,
    // Apk,
    // Pacman,
    // Zypper,
}

impl PackageManager {
    pub fn wire_byte(self) -> u8 {
        match self {
            PackageManager::Auto => 0,
            PackageManager::Apt => 1,
            PackageManager::Pip => 7,
        }
    }

    /// Human-readable label for error messages. Used by the validator
    /// and the per-manager YAML parsers so a rejection message names
    /// the module surface (`apt`) rather than the wire byte.
    pub fn label(self) -> &'static str {
        match self {
            PackageManager::Auto => "package",
            PackageManager::Apt => "apt",
            PackageManager::Pip => "pip",
        }
    }

    /// Which apt-specific knobs the backend actually consumes. Used by
    /// the YAML parser to reject e.g. `default_release:` under
    /// `package:` (generic dispatch) since we can't promise the chosen
    /// backend will honor it.
    fn accepts_apt_knobs(self) -> bool {
        matches!(self, PackageManager::Apt)
    }

    /// Which pip-specific knobs (`virtualenv:`, `virtualenv_command:`)
    /// the backend honors. `package:` (Auto) refuses them — we can't
    /// promise the auto-detected backend is pip.
    fn accepts_pip_knobs(self) -> bool {
        matches!(self, PackageManager::Pip)
    }
}

/// Parse a `PackageOp` from a YAML body. `pinned_manager` is set by
/// the per-manager YAML shims (`apt:`, `pip:`, …) and is None under
/// the canonical `package:` key, in which case `manager:` is read
/// from the body (default `Auto`). When pinned, an explicit
/// `manager:` in the body must agree with the pin or parsing fails.
///
/// Per-manager surface differences:
///   * `apt:` accepts apt-specific knobs (`cache_valid_time`, `purge`,
///     `default_release`, `allow_unauthenticated`)
///   * `pip:` accepts pip-specific knobs (`virtualenv`,
///     `virtualenv_command`)
///   * `package:` with `manager:` left at `Auto` rejects both sets —
///     we can't promise the auto-detected backend honors them
///
/// `force_apt_get` and `install_recommends` are accepted-and-discarded
/// under apt for Ansible compatibility (we always use apt-get; we keep
/// recommends ON which matches Ansible's default).
pub(super) fn parse_package_body<E: serde::de::Error>(
    pinned_manager: Option<PackageManager>,
    mut map: serde_yaml::Mapping,
) -> Result<PackageOp, E> {
    // Resolve the manager: either pinned by the shim, or read from
    // the body (default Auto). Body must agree with the pin if both
    // are present — this lets a playbook keep an explicit `manager:`
    // line for self-documentation under `apt: { manager: apt, ... }`
    // without triggering a false conflict.
    let body_manager = match map.remove("manager") {
        None => None,
        Some(serde_yaml::Value::String(s)) => Some(match s.to_ascii_lowercase().as_str() {
            "auto" | "package" => PackageManager::Auto,
            "apt" => PackageManager::Apt,
            "pip" => PackageManager::Pip,
            other => {
                return Err(E::custom(format!(
                    "package.manager: unsupported value {other:?}; expected one of [auto, apt, pip]"
                )))
            }
        }),
        Some(other) => {
            return Err(E::custom(format!(
                "package.manager must be a string, got: {other:?}"
            )))
        }
    };
    let manager = match (pinned_manager, body_manager) {
        (None, None) => PackageManager::Auto,
        (None, Some(m)) => m,
        (Some(p), None) => p,
        (Some(p), Some(m)) if p == m => p,
        (Some(p), Some(m)) => {
            return Err(E::custom(format!(
                "{}: body sets `manager: {}` which conflicts with the pinned manager `{}`",
                p.label(),
                m.label(),
                p.label()
            )))
        }
    };
    let label = manager.label();

    // `name:` is required and may be a string or a list of strings.
    // Ansible also accepts `pkg:` as an alias under `apt:` / `package:`.
    let names = match map.remove("name").or_else(|| map.remove("pkg")) {
        None => {
            return Err(E::custom(format!(
                "{label}: missing required field `name`"
            )))
        }
        Some(serde_yaml::Value::String(s)) => vec![s],
        Some(serde_yaml::Value::Sequence(seq)) => {
            let mut out = Vec::with_capacity(seq.len());
            for v in seq {
                match v {
                    serde_yaml::Value::String(s) => out.push(s),
                    other => {
                        return Err(E::custom(format!(
                            "{label}.name list items must be strings, got: {other:?}"
                        )))
                    }
                }
            }
            out
        }
        Some(other) => {
            return Err(E::custom(format!(
                "{label}.name must be a string or list of strings, got: {other:?}"
            )))
        }
    };

    let state = match map.remove("state") {
        None => PackageState::Present,
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "present" | "installed" => PackageState::Present,
            "absent" | "removed" => PackageState::Absent,
            "latest" => PackageState::Latest,
            other => {
                return Err(E::custom(format!(
                    "{label}.state: expected one of [present, installed, absent, removed, latest], got: {other:?}"
                )))
            }
        },
        Some(other) => {
            return Err(E::custom(format!(
                "{label}.state must be a string, got: {other:?}"
            )))
        }
    };

    let update_cache =
        take_optional_ansible_bool::<E>(&mut map, "update_cache")?.unwrap_or(false);
    let autoremove =
        take_optional_ansible_bool::<E>(&mut map, "autoremove")?.unwrap_or(false);

    // Apt-specific knobs: only consumed when manager pins an apt-aware
    // backend. Under `package:` (auto), we refuse them at parse time so
    // users don't silently lose configuration when the auto-detected
    // backend ignores them.
    let (cache_valid_time, purge, default_release, allow_unauthenticated) =
        if manager.accepts_apt_knobs() {
            let cache_valid_time = match map.remove("cache_valid_time") {
                None | Some(serde_yaml::Value::Null) => 0u32,
                Some(serde_yaml::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    E::custom(format!(
                        "{label}.cache_valid_time must be a non-negative integer, got: {n}"
                    ))
                })? as u32,
                Some(serde_yaml::Value::String(s)) => s.parse::<u32>().map_err(|e| {
                    E::custom(format!(
                        "{label}.cache_valid_time: invalid int {s:?}: {e}"
                    ))
                })?,
                Some(other) => {
                    return Err(E::custom(format!(
                        "{label}.cache_valid_time must be a number, got: {other:?}"
                    )))
                }
            };
            let purge =
                take_optional_ansible_bool::<E>(&mut map, "purge")?.unwrap_or(false);
            let default_release =
                take_optional_field_string::<E>(&mut map, "default_release")?
                    .unwrap_or_default();
            let allow_unauthenticated =
                take_optional_ansible_bool::<E>(&mut map, "allow_unauthenticated")?
                    .unwrap_or(false);
            // Accept and discard `force_apt_get` — we always use apt-get.
            let _ = map.remove("force_apt_get");
            // Accept and discard `install_recommends` for now; gothab
            // doesn't set it. (Ansible's default ON matches apt-get's
            // default ON.)
            let _ = map.remove("install_recommends");
            (cache_valid_time, purge, default_release, allow_unauthenticated)
        } else {
            // `package:` (auto) / `pip:` etc. refuse apt-only knobs.
            for k in [
                "cache_valid_time",
                "purge",
                "default_release",
                "allow_unauthenticated",
                "force_apt_get",
                "install_recommends",
            ] {
                if map.contains_key(serde_yaml::Value::String(k.to_string())) {
                    return Err(E::custom(format!(
                        "{label}: field `{k}` is only valid under `apt:` (manager-specific). \
                         Use `apt:` instead to set it."
                    )));
                }
            }
            (0, false, String::new(), false)
        };

    // Pip-specific knobs: only consumed under `pip:` (manager=Pip) or
    // `package: manager: pip`. Refused under apt / auto.
    let (virtualenv, virtualenv_command) = if manager.accepts_pip_knobs() {
        let virtualenv =
            take_optional_field_string::<E>(&mut map, "virtualenv")?.unwrap_or_default();
        let virtualenv_command =
            take_optional_field_string::<E>(&mut map, "virtualenv_command")?.unwrap_or_default();
        if virtualenv.is_empty() && !virtualenv_command.is_empty() {
            return Err(E::custom(
                "pip.virtualenv_command requires pip.virtualenv to be set",
            ));
        }
        // Pip fields we don't honour yet — refuse rather than silently
        // drop them.
        for k in [
            "virtualenv_site_packages",
            "virtualenv_python",
            "executable",
            "chdir",
            "editable",
            "extra_args",
            "umask",
        ] {
            if map.contains_key(serde_yaml::Value::String(k.to_string())) {
                return Err(E::custom(format!(
                    "{label}.{k}: not yet implemented (file an issue / PR if you need it)"
                )));
            }
        }
        (virtualenv, virtualenv_command)
    } else {
        for k in ["virtualenv", "virtualenv_command"] {
            if map.contains_key(serde_yaml::Value::String(k.to_string())) {
                return Err(E::custom(format!(
                    "{label}: field `{k}` is only valid under `pip:` (or `package: manager: pip`)"
                )));
            }
        }
        (String::new(), String::new())
    };

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        let allowed = if manager.accepts_apt_knobs() {
            "[name, pkg, state, update_cache, cache_valid_time, purge, autoremove, default_release, allow_unauthenticated, install_recommends, force_apt_get]"
        } else if manager.accepts_pip_knobs() {
            "[name, pkg, state, update_cache, autoremove, virtualenv, virtualenv_command]"
        } else {
            "[name, pkg, state, update_cache, autoremove]"
        };
        return Err(E::custom(format!(
            "{label}: unknown field(s): {unknown:?}; expected one of {allowed}"
        )));
    }

    if names.is_empty() {
        return Err(E::custom(format!(
            "{label}.name: must specify at least one package"
        )));
    }
    for n in &names {
        if n.trim().is_empty() {
            return Err(E::custom(format!("{label}.name: empty package name")));
        }
    }
    if !update_cache && cache_valid_time != 0 {
        return Err(E::custom(format!(
            "{label}: `cache_valid_time` requires `update_cache: true`"
        )));
    }

    Ok(PackageOp {
        manager,
        names,
        state,
        update_cache,
        cache_valid_time,
        purge,
        autoremove,
        default_release,
        allow_unauthenticated,
        virtualenv,
        virtualenv_command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::{parse_task_for_test as parse_task};
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn parses_apt_single_name_default_state() {
        let t = parse_task(
            r#"
name: t
apt:
  name: nginx
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Apt);
                assert_eq!(p.names, vec!["nginx".to_string()]);
                assert_eq!(p.state, PackageState::Present);
                assert!(!p.update_cache);
                assert!(!p.purge);
            }
            _ => panic!("expected Package"),
        }
    }

    #[test]
    fn parses_apt_name_list_with_state_latest() {
        let t = parse_task(
            r#"
name: t
apt:
  name:
    - nginx
    - curl
  state: latest
  update_cache: yes
  cache_valid_time: 3600
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Apt);
                assert_eq!(p.names, vec!["nginx".to_string(), "curl".to_string()]);
                assert_eq!(p.state, PackageState::Latest);
                assert!(p.update_cache);
                assert_eq!(p.cache_valid_time, 3600);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn apt_rejects_cache_valid_time_without_update_cache() {
        let yaml = r#"
name: t
apt:
  name: nginx
  cache_valid_time: 3600
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("requires `update_cache: true`"),
            "got: {err}"
        );
    }

    #[test]
    fn apt_rejects_unknown_field() {
        let yaml = r#"
name: t
apt:
  name: nginx
  bogus: true
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn apt_accepts_installed_and_removed_aliases() {
        let t = parse_task(
            r#"
name: t
apt:
  name: nginx
  state: installed
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => assert_eq!(p.state, PackageState::Present),
            _ => panic!(),
        }
        let t = parse_task(
            r#"
name: t
apt:
  name: nginx
  state: removed
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => assert_eq!(p.state, PackageState::Absent),
            _ => panic!(),
        }
    }

    #[test]
    fn apt_to_wire_carries_fields() {
        let t = TaskOp::Package(PackageOp {
            manager: PackageManager::Apt,
            names: vec!["nginx".into(), "curl".into()],
            state: PackageState::Latest,
            update_cache: true,
            cache_valid_time: 3600,
            purge: false,
            autoremove: true,
            default_release: "bookworm-backports".into(),
            allow_unauthenticated: false,
            virtualenv: String::new(),
            virtualenv_command: String::new(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpPackage(o) = wire else {
            panic!("expected OpPackage")
        };
        assert_eq!(o.manager, 1);
        assert_eq!(o.names, vec!["nginx".to_string(), "curl".to_string()]);
        assert_eq!(o.state, 2);
        assert_eq!(o.update_cache, 1);
        assert_eq!(o.cache_valid_time, 3600);
        assert_eq!(o.purge, 0);
        assert_eq!(o.autoremove, 1);
        assert_eq!(o.default_release, "bookworm-backports");
        assert_eq!(o.allow_unauthenticated, 0);
    }

    #[test]
    fn parses_package_generic_sets_manager_auto() {
        // `package:` (no manager-pinning YAML key) → Auto.
        let t = parse_task(
            r#"
name: t
package:
  name: curl
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Auto);
                assert_eq!(p.names, vec!["curl".to_string()]);
                assert_eq!(p.state, PackageState::Present);
            }
            _ => panic!("expected Package"),
        }
    }

    #[test]
    fn parses_package_accepts_name_list_and_update_cache() {
        let t = parse_task(
            r#"
name: t
package:
  name: [nginx, curl]
  state: latest
  update_cache: yes
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Package(p)) => {
                assert_eq!(p.manager, PackageManager::Auto);
                assert_eq!(p.names, vec!["nginx".to_string(), "curl".to_string()]);
                assert_eq!(p.state, PackageState::Latest);
                assert!(p.update_cache);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn package_rejects_apt_only_knobs() {
        // `default_release` is apt-specific; it's an error under
        // `package:` because we can't promise the auto-detected backend
        // will honor it.
        let yaml = r#"
name: t
package:
  name: nginx
  default_release: bookworm-backports
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("only valid under `apt:`") && msg.contains("default_release"),
            "got: {msg}"
        );
    }

    #[test]
    fn package_rejects_purge_and_cache_valid_time() {
        for field in ["purge: yes", "cache_valid_time: 3600", "allow_unauthenticated: yes"] {
            let yaml = format!(
                r#"
name: t
package:
  name: nginx
  {field}
"#
            );
            let err = serde_yaml::from_str::<Task>(&yaml).unwrap_err();
            assert!(
                format!("{err}").contains("only valid under `apt:`"),
                "field={field} got: {err}"
            );
        }
    }

    #[test]
    fn package_to_wire_carries_manager_auto() {
        let t = TaskOp::Package(PackageOp {
            manager: PackageManager::Auto,
            names: vec!["curl".into()],
            state: PackageState::Present,
            update_cache: false,
            cache_valid_time: 0,
            purge: false,
            autoremove: false,
            default_release: String::new(),
            allow_unauthenticated: false,
            virtualenv: String::new(),
            virtualenv_command: String::new(),
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpPackage(o) = wire else {
            panic!("expected OpPackage")
        };
        assert_eq!(o.manager, 0); // AUTO
        assert_eq!(o.state, 0); // PRESENT
    }
}
