//! Task-tag filter for `--tags` / `--skip-tags`.
//!
//! Tag filtering is a controller-side gate applied at task dispatch time:
//! the orchestrator consults [`TagFilter::should_run`] before fanning a
//! task out to its targets, and tasks the filter rejects are dropped
//! entirely for the run (no register binding, no notify, no per-host
//! state change).
//!
//! The semantics aim to match Ansible's documented behavior. The full
//! decision matrix:
//!
//! | Task tags          | `--tags` | `--skip-tags` | Run? |
//! |--------------------|----------|---------------|------|
//! | `[]`               | (none)   | (none)        | ✓    |
//! | `[foo]`            | (none)   | (none)        | ✓    |
//! | `[never]`          | (none)   | (none)        | ✗    |
//! | `[never, foo]`     | (none)   | (none)        | ✗    |
//! | `[never, foo]`     | foo      | (none)        | ✓    |
//! | `[always]`         | foo      | (none)        | ✓    |
//! | `[always]`         | (none)   | always        | ✗    |
//! | `[]`               | (none)   | untagged      | ✗    |
//! | `[foo]`            | (none)   | untagged      | ✓    |
//! | `[]`               | untagged | (none)        | ✓    |
//! | `[foo]`            | untagged | (none)        | ✗    |
//! | `[foo]`            | all      | (none)        | ✓    |
//! | anything           | (any)    | all           | ✗    |
//!
//! Recognized magic tags:
//! - `always`: task runs unless explicitly excluded via `--skip-tags always`.
//! - `never`: task is skipped unless one of its tags is explicitly listed
//!   in `--tags`.
//! - `all` (CLI selector only): "everything"; equivalent to no `--tags`
//!   for the include side, or "drop everything" for the skip side.
//! - `untagged` (CLI selector only): matches tasks whose effective tag
//!   set is empty (special tags `always`/`never` don't count toward the
//!   "tagged" determination).
//!
//! Magic tag names are case-sensitive lowercase, matching Ansible.

use std::collections::BTreeSet;

/// Tag-based dispatch filter built from the CLI's `--tags` / `--skip-tags`
/// flag values. Construct once per run via [`TagFilter::from_cli`] and
/// share across plays / per-host futures by `Arc<TagFilter>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TagFilter {
    /// Tags the user opted in to via `--tags`. Empty means "no
    /// restriction" (run everything except `never`-only tasks).
    pub include: BTreeSet<String>,
    /// Tags the user opted out of via `--skip-tags`.
    pub skip: BTreeSet<String>,
}

impl TagFilter {
    /// Build a filter from raw CLI values. Each input is the post-clap
    /// `Vec<String>` (already comma-split because we use clap's
    /// `value_delimiter = ','`); we trim whitespace and reject empty
    /// strings here so `--tags ""` and `--tags " , foo"` both surface as
    /// errors instead of silently mismatching.
    pub fn from_cli(tags: &[String], skip_tags: &[String]) -> Result<Self, TagFilterError> {
        Ok(Self {
            include: clean(tags, "--tags")?,
            skip: clean(skip_tags, "--skip-tags")?,
        })
    }

    /// Did the user pass `--tags` or `--skip-tags`? If not, the filter
    /// is the identity for normally-tagged tasks (only `never` is
    /// affected) and most callers can skip the per-task check entirely.
    pub fn is_active(&self) -> bool {
        !self.include.is_empty() || !self.skip.is_empty()
    }

    /// Returns true iff a task with the given tags should run.
    pub fn should_run(&self, task_tags: &[String]) -> bool {
        let tag_set: BTreeSet<&str> = task_tags.iter().map(String::as_str).collect();
        let has_always = tag_set.contains("always");
        let has_never = tag_set.contains("never");
        // "Real" tags = anything that isn't a magic selector. `untagged`
        // is evaluated against this set.
        let has_real_tag = tag_set.iter().any(|t| !matches!(*t, "always" | "never"));

        // ---- skip side ----
        if self.skip.contains("all") {
            return false;
        }
        // Any explicit task tag listed in --skip-tags wins.
        if tag_set.iter().any(|t| self.skip.contains(*t)) {
            return false;
        }
        if !has_real_tag && self.skip.contains("untagged") {
            return false;
        }

        // ---- include side ----
        if self.include.is_empty() || self.include.contains("all") {
            // No --tags (or --tags all): run everything except
            // `never`-only tasks. `always` bypasses `never`.
            return has_always || !has_never;
        }
        // --tags supplied. `always` short-circuits past intersection.
        if has_always {
            return true;
        }
        if !has_real_tag && self.include.contains("untagged") {
            return true;
        }
        // Otherwise: at least one task tag must appear in --tags.
        // (`never` counts here — it's the documented way to opt a
        // never-tagged task into the run.)
        tag_set.iter().any(|t| self.include.contains(*t))
    }
}

/// Parse error from [`TagFilter::from_cli`] — surfaces empty or
/// whitespace-only entries that almost always indicate a typo.
#[derive(Debug, thiserror::Error)]
pub enum TagFilterError {
    #[error("{flag}: empty tag after trimming (check for stray commas)")]
    EmptyTag { flag: &'static str },
}

fn clean(raw: &[String], flag: &'static str) -> Result<BTreeSet<String>, TagFilterError> {
    let mut out = BTreeSet::new();
    for s in raw {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(TagFilterError::EmptyTag { flag });
        }
        out.insert(trimmed.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(include: &[&str], skip: &[&str]) -> TagFilter {
        TagFilter {
            include: include.iter().map(|s| (*s).to_string()).collect(),
            skip: skip.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn tags(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    // ---- rule table ----

    #[test]
    fn untagged_task_default_runs() {
        assert!(filter(&[], &[]).should_run(&tags(&[])));
    }

    #[test]
    fn plain_tagged_task_default_runs() {
        assert!(filter(&[], &[]).should_run(&tags(&["foo"])));
    }

    #[test]
    fn never_only_default_skipped() {
        assert!(!filter(&[], &[]).should_run(&tags(&["never"])));
    }

    #[test]
    fn never_plus_real_tag_default_skipped() {
        // Ansible: `never` wins under no `--tags` even if other tags
        // are present.
        assert!(!filter(&[], &[]).should_run(&tags(&["never", "foo"])));
    }

    #[test]
    fn never_opt_in_via_other_tag() {
        // `--tags foo` opts the task in.
        assert!(filter(&["foo"], &[]).should_run(&tags(&["never", "foo"])));
    }

    #[test]
    fn always_bypasses_include_filter() {
        assert!(filter(&["foo"], &[]).should_run(&tags(&["always"])));
    }

    #[test]
    fn always_can_be_skipped_explicitly() {
        assert!(!filter(&[], &["always"]).should_run(&tags(&["always"])));
    }

    #[test]
    fn skip_untagged_drops_bare_tasks() {
        assert!(!filter(&[], &["untagged"]).should_run(&tags(&[])));
    }

    #[test]
    fn skip_untagged_keeps_tagged_tasks() {
        assert!(filter(&[], &["untagged"]).should_run(&tags(&["foo"])));
    }

    #[test]
    fn include_untagged_keeps_bare_tasks() {
        assert!(filter(&["untagged"], &[]).should_run(&tags(&[])));
    }

    #[test]
    fn include_untagged_drops_tagged_tasks() {
        assert!(!filter(&["untagged"], &[]).should_run(&tags(&["foo"])));
    }

    #[test]
    fn include_all_runs_everything_normal() {
        assert!(filter(&["all"], &[]).should_run(&tags(&["foo"])));
        assert!(filter(&["all"], &[]).should_run(&tags(&[])));
        // `never`-only still skipped under --tags all (Ansible
        // documents `--tags all` as "default", which means `never`
        // is still excluded).
        assert!(!filter(&["all"], &[]).should_run(&tags(&["never"])));
    }

    #[test]
    fn skip_all_drops_everything_even_always() {
        assert!(!filter(&[], &["all"]).should_run(&tags(&[])));
        assert!(!filter(&[], &["all"]).should_run(&tags(&["foo"])));
        assert!(!filter(&[], &["all"]).should_run(&tags(&["always"])));
    }

    // ---- combined filters ----

    #[test]
    fn skip_wins_over_include_on_collision() {
        // Task tagged both foo and bar; user includes both but skips bar.
        assert!(!filter(&["foo", "bar"], &["bar"]).should_run(&tags(&["foo", "bar"])));
    }

    #[test]
    fn skip_does_not_affect_unrelated_tasks() {
        assert!(filter(&[], &["bar"]).should_run(&tags(&["foo"])));
    }

    #[test]
    fn include_requires_intersection() {
        // Task has no overlap with --tags.
        assert!(!filter(&["foo"], &[]).should_run(&tags(&["bar"])));
    }

    // ---- is_active ----

    #[test]
    fn is_active_false_when_no_flags() {
        assert!(!filter(&[], &[]).is_active());
    }

    #[test]
    fn is_active_true_when_any_flag() {
        assert!(filter(&["foo"], &[]).is_active());
        assert!(filter(&[], &["bar"]).is_active());
    }

    // ---- from_cli ----

    #[test]
    fn from_cli_basic_pair() {
        let f = TagFilter::from_cli(&["foo".into(), "bar".into()], &["baz".into()]).unwrap();
        assert_eq!(
            f.include,
            ["bar".to_string(), "foo".to_string()].into_iter().collect()
        );
        assert_eq!(f.skip, ["baz".to_string()].into_iter().collect());
    }

    #[test]
    fn from_cli_trims_whitespace() {
        let f = TagFilter::from_cli(&["  foo ".into(), "bar".into()], &[]).unwrap();
        assert_eq!(
            f.include,
            ["bar".to_string(), "foo".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn from_cli_rejects_empty_tag() {
        // E.g. `--tags foo,,bar` after value_delimiter splits.
        let err = TagFilter::from_cli(&["foo".into(), "".into()], &[]).unwrap_err();
        match err {
            TagFilterError::EmptyTag { flag } => assert_eq!(flag, "--tags"),
        }
    }

    #[test]
    fn from_cli_rejects_whitespace_only_tag() {
        let err = TagFilter::from_cli(&[], &["   ".into()]).unwrap_err();
        match err {
            TagFilterError::EmptyTag { flag } => assert_eq!(flag, "--skip-tags"),
        }
    }
}
