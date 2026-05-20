//! Forward-mode workspace bundling.
//!
//! Builds the gzipped tarball that ships from the laptop to the
//! forwarder over SSH. The tar contains the playbook directory tree
//! and the inventory directory tree — everything the forwarder's
//! orchestrator may want at dispatch time: roles, group_vars, files,
//! templates, includes.
//!
//! ## What we deliberately EXCLUDE
//!
//! - Anything that smells like a secrets file. `vault.yml` /
//!   `vault.yaml` (with or without the conventional `group_vars/*/`
//!   parent), `secrets.yml` / `secrets.yaml`, and anything ending in
//!   `.vault`. Per Bart's design decision #2 — and the fact that
//!   our "vault" today is plaintext, not encrypted — those values
//!   must never land on the forwarder's disk. They DO ship over the
//!   wire (in RAM only) inside `WorkflowPayload.inventory_vars`,
//!   which the laptop populated from the same files we're excluding
//!   here.
//! - Source control noise: `.git/`, `.gitignore` (the operator's
//!   gitignore policy doesn't apply to forward-mode shipping). We
//!   skip the *directory*, not files matching `.gitignore`.
//! - Python/editor noise: `__pycache__/`, `*.pyc`, `*.swp`, `*~`,
//!   `.DS_Store`.
//!
//! Caller can extend the exclude list via [`BundleOptions::extra_excludes`]
//! when they need to keep additional files off the forwarder.
//!
//! ## Layout in the tar
//!
//! One top-level project root. We bundle the **common ancestor** of the
//! playbook directory and the inventory directory (typically the
//! project root, e.g. the directory containing both `playbooks/` and
//! `inventory/` and `roles/`). The forwarder extracts straight into the
//! workspace dir, so the on-disk layout the playbook loader sees is
//! identical to the operator's project root — `roles/` as a sibling of
//! `playbooks/`, `group_vars/` under `inventory/`, etc. Without this,
//! standard Ansible projects break the role resolver
//! (`<pb_dir>/../roles/`).

use anyhow::{anyhow, bail, Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Inputs to [`build_workspace_tar_gz`].
#[derive(Debug, Clone)]
pub struct BundleOptions {
    /// Absolute path to the project root. Everything under it ships
    /// (modulo excludes). Typically the common ancestor of the
    /// playbook path and the inventory path so `roles/`, `group_vars/`,
    /// `host_vars/`, `files/`, `templates/`, etc. ride along.
    pub project_root: PathBuf,
    /// Operator-supplied extra exclusion patterns. Matched
    /// case-sensitively against the path's final component. Glob `*`
    /// is the only wildcard — kept simple deliberately.
    pub extra_excludes: Vec<String>,
}

/// File names / patterns NEVER shipped, no matter what.
///
/// Matched against the path's final component (basename). The leading
/// `*.` form is a suffix match.
const DEFAULT_EXCLUDE_BASENAMES: &[&str] = &[
    "vault.yml",
    "vault.yaml",
    "secrets.yml",
    "secrets.yaml",
    ".DS_Store",
];

/// Suffix-match excludes. Each entry must start with `*`; the rest is
/// the literal suffix the basename has to end with for the file to be
/// excluded.
const DEFAULT_EXCLUDE_SUFFIXES: &[&str] =
    &["*.vault", "*.pyc", "*.swp", "*~"];

/// Directory names whose contents are skipped wholesale.
const DEFAULT_EXCLUDE_DIRS: &[&str] = &[".git", "__pycache__"];

/// Build a gzipped tar containing the playbook + inventory trees,
/// minus anything matching the exclusion rules.
///
/// Returns the raw gzip bytes ready to splice into the WorkflowPayload.
/// Errors only on real I/O problems — missing files we tolerate (the
/// trees are operator-owned, and a transient symlink-to-nowhere
/// shouldn't block the whole run).
pub fn build_workspace_tar_gz(opts: &BundleOptions) -> Result<Vec<u8>> {
    if !opts.project_root.is_dir() {
        bail!(
            "project_root {} is not a directory",
            opts.project_root.display()
        );
    }

    // Stage to a buffer; the gothab tree is ~few MB which fits in RAM
    // trivially and the SSH stdin write side already buffers the whole
    // payload anyway.
    let buf = Vec::<u8>::with_capacity(1024 * 1024);
    let gz = GzEncoder::new(buf, Compression::default());
    let mut tar = tar::Builder::new(gz);
    // Don't follow symlinks — preserves intent and avoids accidentally
    // shipping whatever a symlink points to outside the tree (which
    // could include secrets stored on the operator's home dir).
    tar.follow_symlinks(false);

    let exclude = ExcludeMatcher::from_options(opts)?;

    add_tree_to_tar(&mut tar, &opts.project_root, "", &exclude)
        .with_context(|| format!("adding project tree {}", opts.project_root.display()))?;

    let gz = tar.into_inner().context("finalizing tar")?;
    let buf = gz.finish().context("finalizing gzip")?;
    Ok(buf)
}

/// Compute the deepest directory that contains both `a` and `b`.
///
/// Used by [`forward::run_forwarded`] to pick a `project_root` from the
/// playbook + inventory paths. Falls back to the filesystem root if the
/// two dirs share no common ancestor (shouldn't happen in practice on
/// Linux; both paths get canonicalized first).
pub fn common_ancestor(a: &Path, b: &Path) -> Result<PathBuf> {
    let ca = a
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", a.display()))?;
    let cb = b
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", b.display()))?;
    let a_components: Vec<_> = ca.components().collect();
    let b_components: Vec<_> = cb.components().collect();
    let mut out = PathBuf::new();
    for (x, y) in a_components.iter().zip(b_components.iter()) {
        if x == y {
            out.push(x.as_os_str());
        } else {
            break;
        }
    }
    if out.as_os_str().is_empty() {
        bail!(
            "no common ancestor between {} and {}",
            a.display(),
            b.display()
        );
    }
    Ok(out)
}

/// Walk one directory tree, appending every non-excluded file (and the
/// dir entries leading to them) under `tar_prefix`.
fn add_tree_to_tar<W: Write>(
    tar: &mut tar::Builder<W>,
    root: &Path,
    tar_prefix: &str,
    exclude: &ExcludeMatcher,
) -> Result<()> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", root.display()))?;

    for entry in WalkDir::new(&canonical_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !exclude.should_skip_walk_entry(e))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Single transient I/O failure (e.g. a file vanished
                // mid-walk) shouldn't kill the whole bundle.
                tracing::warn!(error = %e, "skipping unreachable entry during bundle walk");
                continue;
            }
        };
        let path = entry.path();
        if path == canonical_root {
            // Don't emit an entry for the root itself — the prefix
            // handles that.
            continue;
        }
        let rel = path
            .strip_prefix(&canonical_root)
            .map_err(|_| anyhow!("walkdir produced path outside root: {}", path.display()))?;
        let tar_path = if tar_prefix.is_empty() {
            rel.to_path_buf()
        } else {
            Path::new(tar_prefix).join(rel)
        };

        // Exclude check for files (dir-prune already happened via
        // filter_entry).
        if entry.file_type().is_file() {
            let basename = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if exclude.should_skip_file(basename) {
                tracing::debug!(
                    file = %rel.display(),
                    "excluding from workspace bundle (secret / noise)"
                );
                continue;
            }
            tar.append_path_with_name(path, &tar_path)
                .with_context(|| format!("tar append {}", path.display()))?;
        } else if entry.file_type().is_dir() {
            tar.append_path_with_name(path, &tar_path)
                .with_context(|| format!("tar append dir {}", path.display()))?;
        }
        // Symlinks intentionally dropped — see `follow_symlinks(false)`
        // at the builder level. We could append the symlink as-is,
        // but that requires the target to exist on the forwarder
        // which is rarely true. Dropping is safer.
    }
    Ok(())
}

/// Cached set of basenames / suffixes / dir names that exclude a file
/// from the bundle.
struct ExcludeMatcher {
    basenames: BTreeSet<String>,
    suffixes: Vec<String>,
    dir_names: BTreeSet<String>,
}

impl ExcludeMatcher {
    fn from_options(opts: &BundleOptions) -> Result<Self> {
        let mut basenames: BTreeSet<String> = DEFAULT_EXCLUDE_BASENAMES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut suffixes: Vec<String> = DEFAULT_EXCLUDE_SUFFIXES
            .iter()
            .map(|s| s.trim_start_matches('*').to_string())
            .collect();
        let dir_names: BTreeSet<String> = DEFAULT_EXCLUDE_DIRS
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        for pat in &opts.extra_excludes {
            if let Some(suf) = pat.strip_prefix('*') {
                suffixes.push(suf.to_string());
            } else if pat.contains('*') {
                bail!(
                    "extra_exclude {pat:?}: only `*<suffix>` and plain \
                     basenames are supported (no globs)"
                );
            } else {
                basenames.insert(pat.clone());
            }
        }

        Ok(Self {
            basenames,
            suffixes,
            dir_names,
        })
    }

    /// Used as `filter_entry` predicate: if true, the entire subtree
    /// rooted at this entry is pruned. Only applied to directories.
    fn should_skip_walk_entry(&self, entry: &walkdir::DirEntry) -> bool {
        if !entry.file_type().is_dir() {
            return false;
        }
        let name = match entry.file_name().to_str() {
            Some(s) => s,
            None => return false,
        };
        self.dir_names.contains(name)
    }

    fn should_skip_file(&self, basename: &str) -> bool {
        if self.basenames.contains(basename) {
            return true;
        }
        for suf in &self.suffixes {
            if basename.ends_with(suf) {
                return true;
            }
        }
        false
    }
}

/// Untar a gzipped workspace bundle into `dest`. Used by `cmd_remote_run`
/// on the forwarder to materialize the tree before re-parsing the
/// playbook. `dest` must already exist and be empty.
pub fn extract_workspace_tar_gz(tar_gz: &[u8], dest: &Path) -> Result<()> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    let gz = GzDecoder::new(Cursor::new(tar_gz));
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(dest)
        .with_context(|| format!("untarring workspace into {}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a sample playbook tree on disk and return the
    /// (playbook_dir, inventory_dir) tuple inside a TempDir.
    fn sample_tree() -> (TempDir, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let pb_root = tmp.path().join("ansible");
        fs::create_dir_all(pb_root.join("playbooks")).unwrap();
        fs::create_dir_all(pb_root.join("roles/common/tasks")).unwrap();
        fs::create_dir_all(pb_root.join("inventory/group_vars/all")).unwrap();
        fs::create_dir_all(pb_root.join(".git/objects")).unwrap();
        fs::create_dir_all(pb_root.join("roles/common/__pycache__")).unwrap();

        fs::write(pb_root.join("playbooks/site.yml"), b"- hosts: all\n").unwrap();
        fs::write(
            pb_root.join("roles/common/tasks/main.yml"),
            b"- name: hi\n  ansible.builtin.debug: { msg: hi }\n",
        )
        .unwrap();
        fs::write(
            pb_root.join("inventory/production.yml"),
            b"all:\n  hosts: { h1: {} }\n",
        )
        .unwrap();
        // Secrets that MUST be excluded:
        fs::write(
            pb_root.join("inventory/group_vars/all/vault.yml"),
            b"db_password: super-secret\n",
        )
        .unwrap();
        // Noise that should also be excluded:
        fs::write(pb_root.join(".git/objects/blob"), b"git noise").unwrap();
        fs::write(
            pb_root.join("roles/common/__pycache__/cache.pyc"),
            b"py noise",
        )
        .unwrap();
        fs::write(pb_root.join("playbooks/.swp"), b"editor noise").unwrap();
        fs::write(pb_root.join("roles/common/tasks/main.pyc"), b"py").unwrap();
        // Return (TempDir, project_root, playbooks_dir).
        // Tests that want the inventory dir derive it from project_root.
        let pb_dir = pb_root.join("playbooks");
        (tmp, pb_root, pb_dir)
    }

    fn list_tar_entries(bytes: &[u8]) -> Vec<String> {
        use flate2::read::GzDecoder;
        use std::io::Cursor;
        let gz = GzDecoder::new(Cursor::new(bytes));
        let mut a = tar::Archive::new(gz);
        a.entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect()
    }

    #[test]
    fn bundle_excludes_vault_yml() {
        let (_tmp, root, _pb_dir) = sample_tree();
        let opts = BundleOptions {
            project_root: root,
            extra_excludes: vec![],
        };
        let bytes = build_workspace_tar_gz(&opts).unwrap();
        let entries = list_tar_entries(&bytes);
        let joined = entries.join("\n");
        assert!(
            !joined.contains("vault.yml"),
            "vault.yml must be excluded from bundle; got:\n{joined}"
        );
        // Sanity: the non-secret bits are present at their original
        // sibling positions (no playbook/ or inventory/ wrapper prefix —
        // we preserve the project layout so role resolution survives).
        assert!(
            joined.contains("playbooks/site.yml"),
            "site.yml should be in the bundle; got:\n{joined}"
        );
        assert!(
            joined.contains("inventory/production.yml"),
            "inventory yml should be present; got:\n{joined}"
        );
        assert!(
            joined.contains("roles/common/tasks/main.yml"),
            "roles tree should be in the bundle (sibling of playbooks/); got:\n{joined}"
        );
    }

    #[test]
    fn bundle_excludes_git_and_pycache_dirs() {
        let (_tmp, root, _pb) = sample_tree();
        let opts = BundleOptions {
            project_root: root,
            extra_excludes: vec![],
        };
        let bytes = build_workspace_tar_gz(&opts).unwrap();
        let joined = list_tar_entries(&bytes).join("\n");
        assert!(
            !joined.contains(".git"),
            "`.git/` subtree should be pruned; got:\n{joined}"
        );
        assert!(
            !joined.contains("__pycache__"),
            "`__pycache__/` should be pruned; got:\n{joined}"
        );
    }

    #[test]
    fn bundle_excludes_pyc_swp_by_suffix() {
        let (_tmp, root, _pb) = sample_tree();
        let opts = BundleOptions {
            project_root: root,
            extra_excludes: vec![],
        };
        let bytes = build_workspace_tar_gz(&opts).unwrap();
        let joined = list_tar_entries(&bytes).join("\n");
        assert!(
            !joined.contains("main.pyc"),
            "`*.pyc` should be excluded by suffix; got:\n{joined}"
        );
        assert!(
            !joined.contains(".swp"),
            "`*.swp` should be excluded; got:\n{joined}"
        );
    }

    #[test]
    fn extra_excludes_basename_and_suffix() {
        let (_tmp, root, pb_dir) = sample_tree();
        fs::write(pb_dir.join("local-only.yml"), b"private").unwrap();
        fs::write(pb_dir.join("site.yml.bak"), b"backup").unwrap();
        let opts = BundleOptions {
            project_root: root,
            extra_excludes: vec!["local-only.yml".into(), "*.bak".into()],
        };
        let bytes = build_workspace_tar_gz(&opts).unwrap();
        let joined = list_tar_entries(&bytes).join("\n");
        assert!(!joined.contains("local-only.yml"));
        assert!(!joined.contains("site.yml.bak"));
    }

    #[test]
    fn extra_exclude_rejects_general_globs() {
        let (_tmp, root, _pb) = sample_tree();
        let opts = BundleOptions {
            project_root: root,
            extra_excludes: vec!["foo*bar".into()],
        };
        let err = build_workspace_tar_gz(&opts).unwrap_err();
        assert!(format!("{err:#}").contains("only `*<suffix>`"));
    }

    #[test]
    fn round_trip_extract_recreates_tree_without_secrets() {
        let (_tmp, root, _pb) = sample_tree();
        let opts = BundleOptions {
            project_root: root,
            extra_excludes: vec![],
        };
        let bytes = build_workspace_tar_gz(&opts).unwrap();
        let dest = TempDir::new().unwrap();
        extract_workspace_tar_gz(&bytes, dest.path()).unwrap();
        assert!(dest.path().join("playbooks/site.yml").exists());
        assert!(dest
            .path()
            .join("roles/common/tasks/main.yml")
            .exists());
        assert!(dest.path().join("inventory/production.yml").exists());
        assert!(
            !dest
                .path()
                .join("inventory/group_vars/all/vault.yml")
                .exists(),
            "secrets must not be reconstructable on the forwarder",
        );
        assert!(!dest.path().join(".git").exists());
    }

    #[test]
    fn errors_when_project_root_missing() {
        let opts = BundleOptions {
            project_root: PathBuf::from("/nonexistent/forward-bundle-test"),
            extra_excludes: vec![],
        };
        assert!(build_workspace_tar_gz(&opts).is_err());
    }

    /// `common_ancestor` is the load-bearing piece — it has to find the
    /// project root that contains both `playbooks/` and `inventory/` so
    /// the bundle includes their sibling `roles/`.
    #[test]
    fn common_ancestor_finds_project_root() {
        let (_tmp, root, pb_dir) = sample_tree();
        let inv_dir = root.join("inventory");
        let ancestor = common_ancestor(&pb_dir, &inv_dir).unwrap();
        // `canonicalize` may resolve symlinks on macOS (`/tmp` → `/private/tmp`),
        // so compare against the canonicalized root.
        assert_eq!(ancestor, root.canonicalize().unwrap());
    }
}
