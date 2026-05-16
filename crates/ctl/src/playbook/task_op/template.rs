//! `template:` task body.

use serde::Deserialize;

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
    #[serde(default = "default_template_mode")]
    pub mode: u32,
    /// Populated by the load-time template resolver. `None` until then.
    #[serde(skip, default)]
    pub body: Option<String>,
}

/// Ansible's `template:` default; matches the surveyed gothab usage
/// where most templated files are non-executable config files.
///
/// Re-used by `copy:` because the two ops share the same default.
pub(super) fn default_template_mode() -> u32 {
    0o644
}
