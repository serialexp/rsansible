//! `template:` task body.

use super::shared::{deserialize_mode_field, ModeField};
use serde::Deserialize;
use std::path::PathBuf;

/// `template: { src: foo.j2, dest: /etc/foo, mode: 0o644 }`
///
/// `src:` is resolved at playbook load time. When the task came from a
/// role (`task.role_dir.is_some()`), the lookup order is:
///
/// 1. absolute path (used as-is)
/// 2. `<role_dir>/templates/<src>`
/// 3. `<playbook_dir>/templates/<src>`
/// 4. `<playbook_dir>/<src>`
///
/// The resolved file's contents are loaded into `body` during the
/// template-resolution pass and rendered at task execution time. `src`
/// is retained for diagnostics. `body` does not parse from YAML — it's
/// populated by the loader, after which `body.is_some()` indicates the
/// template was found.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TemplateOp {
    pub src: String,
    pub dest: String,
    #[serde(default = "default_template_mode", deserialize_with = "deserialize_mode_field")]
    pub mode: ModeField,
    /// File owner (POSIX user name). `None` keeps whatever owner the
    /// agent's effective uid would assign on create — usually root when
    /// the task runs under `become:`. **Parsed but not yet honored** —
    /// the agent's `OpWriteFile` does not currently chown after writing.
    /// Storing the field so playbooks parse cleanly; the runtime hook
    /// lands when we extend `OpWriteFile` with owner/group bytes.
    #[serde(default)]
    pub owner: Option<String>,
    /// File group (POSIX group name). See `owner:` for the not-yet-
    /// honored caveat.
    #[serde(default)]
    pub group: Option<String>,
    /// Optional validator command (Ansible `validate:`). When set, the
    /// agent runs the command against the staged tmp file before the
    /// rename; non-zero exit aborts the write. `%s` is substituted by
    /// the tmp path. Empty / `None` = no validation.
    #[serde(default)]
    pub validate: Option<String>,
    /// Populated by the load-time template resolver. `None` until then.
    /// Stays `None` when `src:` contains Jinja — in that case the
    /// dispatch site renders `src:` against the per-host view and uses
    /// `search_dirs` to locate the actual file at task execution time.
    #[serde(skip, default)]
    pub body: Option<String>,
    /// Search base directories captured at load time. Used by the
    /// orchestrator's Template dispatch arm to locate the file when
    /// `src:` is Jinja-templated (and therefore wasn't pre-loaded into
    /// `body`). Empty when `body` is populated (the load-time resolver
    /// already found the file).
    #[serde(skip, default)]
    pub search_dirs: Vec<PathBuf>,
}

/// Ansible's `template:` default; matches the surveyed acme usage
/// where most templated files are non-executable config files.
///
/// Re-used by `copy:` because the two ops share the same default.
pub(super) fn default_template_mode() -> ModeField {
    ModeField::Literal(0o644)
}
