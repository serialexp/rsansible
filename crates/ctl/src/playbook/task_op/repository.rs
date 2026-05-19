//! `repository:` (canonical) / `apt_repository:` (compat shim) task body.
//!
//! Canonical rsansible spelling for "add or remove a third-party package
//! repository" — a manager-agnostic wrapper around what Ansible exposes as
//! one module per package manager (`apt_repository`, `yum_repository`,
//! `zypper_repository`, …). Mirrors the `package:` / `apt:` split.
//!
//! See `RSANSIBLE_IDIOMS.md §2` for the rationale on splitting canonical
//! `repository:` from the per-manager Ansible spellings.
//!
//! ```yaml
//! # Canonical (rsansible-preferred):
//! - repository:
//!     manager: apt        # optional; auto-detect if omitted
//!     repo: "deb [signed-by=/etc/apt/keyrings/pg.asc] https://apt.postgresql.org/pub/repos/apt {{ ansible_distribution_release }}-pgdg main"
//!     filename: pgdg      # optional; derived from `repo` if omitted
//!     state: present
//!     update_cache: true
//!
//! # Compat shim (existing Ansible playbooks port unchanged):
//! - apt_repository:
//!     repo: "deb ..."
//!     filename: pgdg
//! ```

use super::shared::{take_optional_ansible_bool, take_optional_field_string, take_optional_mode, ModeField};

/// `repository:` / `apt_repository:` parsed form.
///
/// Knobs that vary by manager (none yet, but reserved) live as `Option`s
/// so each backend can decide what to do with them. `mode == 0` means
/// "use the manager's default" (0o644 for apt).
#[derive(Debug, Clone, PartialEq)]
pub struct RepositoryOp {
    /// Which backend to dispatch to. The YAML key `apt_repository:` pins
    /// this to `Apt`. The canonical `repository:` key sets it to `Auto`
    /// unless the user passes an explicit `manager:` value.
    pub manager: RepositoryManager,
    /// The source-list line. For apt this is a literal `deb ...` line; for
    /// future managers it'll be whatever their grammar wants. Never
    /// templated here — the orchestrator renders Jinja before to_wire.
    pub repo: String,
    pub state: RepositoryState,
    /// On-disk basename (without extension) for the source file. Empty
    /// string means "derive from sanitised `repo` string" (Ansible-compat).
    pub filename: String,
    /// Unix file mode for the source file. `None` means "use default"
    /// (0o644 for apt). Accepts a Jinja template too; resolved at
    /// dispatch.
    pub mode: Option<ModeField>,
    /// Run the manager's index refresh after a successful change.
    /// Default `true` to match Ansible's `apt_repository`.
    pub update_cache: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryState {
    Present,
    Absent,
}

impl RepositoryState {
    pub fn wire_byte(self) -> u8 {
        match self {
            RepositoryState::Present => 0,
            RepositoryState::Absent => 1,
        }
    }
}

/// Mirrors `PackageManager` byte-for-byte so a single auto-detect step on
/// the agent can serve both ops. Adding a new manager here SHOULD be
/// accompanied by adding the same value to `PackageManager` (and vice
/// versa) — they share `repository_manager` / `package_manager` byte
/// allocations in `rsansible_wire::msg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryManager {
    Auto,
    Apt,
    // Reserved — wire bytes already allocated. Uncomment + extend
    // `wire_byte` when the agent grows a backend for them.
    // Dnf,
    // Yum,
    // Apk,
    // Pacman,
    // Zypper,
}

impl RepositoryManager {
    pub fn wire_byte(self) -> u8 {
        match self {
            RepositoryManager::Auto => 0,
            RepositoryManager::Apt => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            RepositoryManager::Auto => "repository",
            RepositoryManager::Apt => "apt_repository",
        }
    }

    fn from_yaml_str<E: serde::de::Error>(s: &str) -> Result<Self, E> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(RepositoryManager::Auto),
            "apt" => Ok(RepositoryManager::Apt),
            other => Err(E::custom(format!(
                "repository.manager: unsupported manager {other:?}; \
                 supported: [auto, apt]"
            ))),
        }
    }
}

/// Parse a `RepositoryOp` from a YAML body under either the canonical
/// `repository:` key (where `manager` is read from the body, defaulting
/// to `Auto`) or the compat-shim `apt_repository:` key (where the caller
/// pins `manager: Apt` and we forbid the body from contradicting it).
///
/// The `pinned_manager` parameter encodes the YAML-key choice:
///   * `None` — canonical `repository:` key; read `manager:` from body
///     (defaults to `Auto`).
///   * `Some(m)` — per-manager YAML key; reject `manager:` in the body if
///     it disagrees (silently overwriting it would be a footgun).
pub(super) fn parse_repository_body<E: serde::de::Error>(
    pinned_manager: Option<RepositoryManager>,
    mut map: serde_yaml::Mapping,
) -> Result<RepositoryOp, E> {
    let label = pinned_manager
        .map(|m| m.label())
        .unwrap_or("repository");

    // `manager:` — explicit field on canonical `repository:`. On the
    // `apt_repository:` shim we still tolerate an explicit `manager: apt`
    // (it's a no-op) but reject any other value.
    let body_manager: Option<RepositoryManager> = match map.remove("manager") {
        None | Some(serde_yaml::Value::Null) => None,
        Some(serde_yaml::Value::String(s)) => Some(RepositoryManager::from_yaml_str::<E>(&s)?),
        Some(other) => {
            return Err(E::custom(format!(
                "{label}.manager: must be a string, got: {other:?}"
            )))
        }
    };
    let manager = match (pinned_manager, body_manager) {
        (Some(pinned), Some(body)) if pinned != body => {
            return Err(E::custom(format!(
                "{label}: body field `manager: {}` disagrees with the \
                 YAML key (which implies `manager: {}`). \
                 Use the canonical `repository:` key if you want to set \
                 `manager:` explicitly.",
                body.label(),
                pinned.label()
            )));
        }
        (Some(pinned), _) => pinned,
        (None, Some(body)) => body,
        (None, None) => RepositoryManager::Auto,
    };

    // `repo:` — required, single string. Empty/whitespace rejected.
    let repo = match map.remove("repo") {
        None => {
            return Err(E::custom(format!(
                "{label}: missing required field `repo`"
            )))
        }
        Some(serde_yaml::Value::String(s)) => s,
        Some(other) => {
            return Err(E::custom(format!(
                "{label}.repo: must be a string, got: {other:?}"
            )))
        }
    };
    if repo.trim().is_empty() {
        return Err(E::custom(format!("{label}.repo: empty repo string")));
    }

    // `state:` — present (default) / absent. We don't accept the
    // `installed` / `removed` aliases here; Ansible's `apt_repository`
    // doesn't accept them either.
    let state = match map.remove("state") {
        None => RepositoryState::Present,
        Some(serde_yaml::Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "present" => RepositoryState::Present,
            "absent" => RepositoryState::Absent,
            other => {
                return Err(E::custom(format!(
                    "{label}.state: expected one of [present, absent], got: {other:?}"
                )))
            }
        },
        Some(other) => {
            return Err(E::custom(format!(
                "{label}.state must be a string, got: {other:?}"
            )))
        }
    };

    let filename = take_optional_field_string::<E>(&mut map, "filename")?.unwrap_or_default();
    let mode = take_optional_mode::<E>(&mut map, "mode")?;
    // Ansible's `apt_repository` defaults `update_cache: yes`. We match.
    let update_cache =
        take_optional_ansible_bool::<E>(&mut map, "update_cache")?.unwrap_or(true);

    // `codename:` and `validate_certs:` are accepted-and-discarded for
    // ansible compatibility. `codename` is rarely useful (most playbooks
    // use `{{ ansible_distribution_release }}` directly in the repo line)
    // and `validate_certs` only meaningfully applies to PPA fetches which
    // we don't support yet. If a real playbook needs them, we'll wire them
    // through.
    let _ = map.remove("codename");
    let _ = map.remove("validate_certs");
    // `install_python_apt` is an Ansible-side bootstrap knob ensuring
    // python-apt is on the box before apt_repository runs. We don't need
    // it — the agent talks to apt-get/dpkg directly, no python.
    let _ = map.remove("install_python_apt");

    if !map.is_empty() {
        let unknown: Vec<String> = map
            .keys()
            .map(|k| k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")))
            .collect();
        return Err(E::custom(format!(
            "{label}: unknown field(s): {unknown:?}; expected one of \
             [manager, repo, state, filename, mode, update_cache, \
              codename, validate_certs, install_python_apt]"
        )));
    }

    Ok(RepositoryOp {
        manager,
        repo,
        state,
        filename,
        mode,
        update_cache,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::task_op::parse_task_for_test as parse_task;
    use crate::playbook::task_op::{Task, TaskBody, TaskOp};

    #[test]
    fn apt_repository_pins_manager_apt() {
        let t = parse_task(
            r#"
name: t
apt_repository:
  repo: "deb https://example.com/repo focal main"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Repository(r)) => {
                assert_eq!(r.manager, RepositoryManager::Apt);
                assert_eq!(r.repo, "deb https://example.com/repo focal main");
                assert_eq!(r.state, RepositoryState::Present);
                // Default update_cache matches Ansible's apt_repository.
                assert!(r.update_cache);
                assert_eq!(r.filename, "");
                assert_eq!(r.mode, None);
            }
            _ => panic!("expected Repository"),
        }
    }

    #[test]
    fn canonical_repository_defaults_manager_auto() {
        let t = parse_task(
            r#"
name: t
repository:
  repo: "deb https://example.com/repo focal main"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Repository(r)) => {
                assert_eq!(r.manager, RepositoryManager::Auto);
                assert!(r.update_cache);
            }
            _ => panic!("expected Repository"),
        }
    }

    #[test]
    fn canonical_repository_with_explicit_manager_apt() {
        let t = parse_task(
            r#"
name: t
repository:
  manager: apt
  repo: "deb https://example.com/repo focal main"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Repository(r)) => {
                assert_eq!(r.manager, RepositoryManager::Apt);
            }
            _ => panic!("expected Repository"),
        }
    }

    #[test]
    fn apt_repository_accepts_redundant_manager_apt() {
        // `apt_repository: { manager: apt }` is redundant but not wrong.
        let t = parse_task(
            r#"
name: t
apt_repository:
  manager: apt
  repo: "deb https://example.com/repo focal main"
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Repository(r)) => {
                assert_eq!(r.manager, RepositoryManager::Apt);
            }
            _ => panic!("expected Repository"),
        }
    }

    #[test]
    fn apt_repository_rejects_contradictory_manager() {
        let yaml = r#"
name: t
apt_repository:
  manager: auto
  repo: "deb https://example.com/repo focal main"
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("disagrees with the YAML key"),
            "got: {err}"
        );
    }

    #[test]
    fn canonical_repository_unknown_manager_errors() {
        let yaml = r#"
name: t
repository:
  manager: dnf
  repo: "https://example.com/repo.repo"
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("unsupported manager"),
            "got: {err}"
        );
    }

    #[test]
    fn repository_full_fields() {
        let t = parse_task(
            r#"
name: t
apt_repository:
  repo: "deb https://example.com/repo focal main"
  filename: pgdg
  state: absent
  mode: "0640"
  update_cache: false
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Repository(r)) => {
                assert_eq!(r.filename, "pgdg");
                assert_eq!(r.state, RepositoryState::Absent);
                assert_eq!(r.mode, Some(crate::playbook::ModeField::Literal(0o640)));
                assert!(!r.update_cache);
            }
            _ => panic!("expected Repository"),
        }
    }

    #[test]
    fn repository_rejects_missing_repo() {
        let yaml = r#"
name: t
apt_repository:
  filename: pgdg
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("missing required field `repo`"),
            "got: {err}"
        );
    }

    #[test]
    fn repository_rejects_empty_repo() {
        let yaml = r#"
name: t
apt_repository:
  repo: "   "
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("empty repo string"), "got: {err}");
    }

    #[test]
    fn repository_rejects_bad_state() {
        let yaml = r#"
name: t
apt_repository:
  repo: "deb https://x/r f main"
  state: latest
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(
            format!("{err}").contains("[present, absent]"),
            "got: {err}"
        );
    }

    #[test]
    fn repository_rejects_unknown_field() {
        let yaml = r#"
name: t
apt_repository:
  repo: "deb https://x/r f main"
  bogus: true
"#;
        let err = serde_yaml::from_str::<Task>(yaml).unwrap_err();
        assert!(format!("{err}").contains("unknown field"), "got: {err}");
    }

    #[test]
    fn repository_accepts_and_discards_ansible_codename_validate_certs() {
        // Both fields are Ansible-only knobs we don't currently honor;
        // we accept them so existing playbooks port unchanged.
        let t = parse_task(
            r#"
name: t
apt_repository:
  repo: "deb https://x/r f main"
  codename: focal
  validate_certs: false
  install_python_apt: false
"#,
        );
        match t.body {
            TaskBody::Op(TaskOp::Repository(r)) => {
                assert_eq!(r.repo, "deb https://x/r f main");
            }
            _ => panic!("expected Repository"),
        }
    }

    #[test]
    fn repository_to_wire_carries_fields() {
        let t = TaskOp::Repository(RepositoryOp {
            manager: RepositoryManager::Apt,
            repo: "deb https://example.com/repo focal main".into(),
            state: RepositoryState::Present,
            filename: "pgdg".into(),
            mode: Some(crate::playbook::ModeField::Literal(0o644)),
            update_cache: true,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpRepository(o) = wire else {
            panic!("expected OpRepository")
        };
        assert_eq!(o.kind, 21);
        assert_eq!(o.manager, 1);
        assert_eq!(o.repo, "deb https://example.com/repo focal main");
        assert_eq!(o.state, 0);
        assert_eq!(o.filename, "pgdg");
        assert_eq!(o.mode, 0o644);
        assert_eq!(o.update_cache, 1);
    }

    #[test]
    fn repository_to_wire_auto_state_absent() {
        let t = TaskOp::Repository(RepositoryOp {
            manager: RepositoryManager::Auto,
            repo: "deb x".into(),
            state: RepositoryState::Absent,
            filename: "".into(),
            mode: None,
            update_cache: false,
        });
        let wire = t.to_wire_op().unwrap();
        let rsansible_wire::generated::Op::OpRepository(o) = wire else {
            panic!("expected OpRepository")
        };
        assert_eq!(o.manager, 0);
        assert_eq!(o.state, 1);
        assert_eq!(o.mode, 0);
        assert_eq!(o.update_cache, 0);
    }
}
