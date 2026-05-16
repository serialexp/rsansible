//! `OpBlockInFile` — Ansible's `blockinfile:` module.
//!
//! Idempotent multi-line block edits delimited by marker comments. The
//! agent reads the file, locates any existing block by its begin/end
//! markers, and either:
//!   * (state=present, non-empty `block`) replaces or inserts the block
//!   * (state=present, empty `block`) removes the existing block if present
//!   * (state=absent) removes the existing block if present
//! Then writes the file atomically (sibling tmpfile + rename) iff the
//! resulting bytes differ. `changed=1` only on real on-disk changes.
//!
//! Marker construction: the user-supplied `marker` is a template string
//! with the literal token `{mark}` substituted for `marker_begin` (top)
//! or `marker_end` (bottom). Defaults track Ansible: marker =
//! "# {mark} ANSIBLE MANAGED BLOCK", marker_begin = "BEGIN",
//! marker_end = "END". The substitution is plain string replacement
//! (no Jinja).
//!
//! Placement when no existing block:
//!   - `insertbefore` regex → place block right before first match
//!   - `insertafter`  regex → place block right after  last  match
//!     (Ansible: last, not first)
//!   - `insertafter == "EOF"` or neither set → append at end
//!
//! Empty `block` + state=present is treated as "remove the block if it
//! exists, otherwise no-op." Matches Ansible.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use regex::Regex;
use rsansible_wire::generated::OpBlockInFileOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

pub async fn run(ctx: &Context, seq: u32, op: OpBlockInFileOutput, check_mode: bool) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    let mode = if op.has_mode != 0 { Some(op.mode & 0o7777) } else { None };
    let create = op.create != 0;

    let state = match op.state {
        STATE_PRESENT => State::Present,
        STATE_ABSENT => State::Absent,
        other => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("blockinfile: unknown state byte {other}"),
            )
            .await;
            return Ok(());
        }
    };

    if !op.insertbefore.is_empty() && !op.insertafter.is_empty() {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            "blockinfile: insertbefore and insertafter are mutually exclusive",
        )
        .await;
        return Ok(());
    }

    let begin_marker = render_marker(&op.marker, &op.marker_begin);
    let end_marker = render_marker(&op.marker, &op.marker_end);

    let insertbefore = match compile_optional(&op.insertbefore) {
        Ok(r) => r,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("blockinfile.insertbefore: {e}"),
            )
            .await;
            return Ok(());
        }
    };
    let (insert_eof, insertafter) = if op.insertafter == "EOF" {
        (true, None)
    } else {
        match compile_optional(&op.insertafter) {
            Ok(r) => (false, r),
            Err(e) => {
                emit_error(
                    ctx,
                    seq,
                    err::BAD_REQUEST,
                    format!("blockinfile.insertafter: {e}"),
                )
                .await;
                return Ok(());
            }
        }
    };

    let path = Path::new(&op.path);
    let existing = match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                err::IO,
                format!("blockinfile: reading {}: {e}", path.display()),
            )
            .await;
            return Ok(());
        }
    };

    let original = match (&existing, state, create) {
        (Some(b), _, _) => b.clone(),
        (None, State::Absent, _) => {
            // Absent + missing → done, unchanged.
            let finished = now_unix_ns();
            ctx.emit(msg::task_done(seq, 0, false, false, started_unix_ns, finished))
                .await;
            return Ok(());
        }
        (None, State::Present, true) => Vec::new(),
        (None, State::Present, false) => {
            emit_error(
                ctx,
                seq,
                err::NOT_FOUND,
                format!(
                    "blockinfile: {} does not exist and create=false",
                    path.display()
                ),
            )
            .await;
            return Ok(());
        }
    };

    let text = match std::str::from_utf8(&original) {
        Ok(s) => s.to_string(),
        Err(e) => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("blockinfile: {} is not valid UTF-8: {e}", path.display()),
            )
            .await;
            return Ok(());
        }
    };

    let new_text = compute_new(
        &text,
        state,
        &begin_marker,
        &end_marker,
        &op.block,
        insertbefore.as_ref(),
        insertafter.as_ref(),
        insert_eof,
    );

    let file_existed = existing.is_some();
    let changed = match (&existing, &new_text) {
        (Some(old), nt) => old.as_slice() != nt.as_bytes(),
        (None, _) => true, // file is being created
    };

    if changed {
        if !check_mode {
            if let Err(e) = write_atomic(path, new_text.as_bytes(), mode, !file_existed) {
                emit_error(
                    ctx,
                    seq,
                    err::IO,
                    format!("blockinfile: writing {}: {e}", path.display()),
                )
                .await;
                return Ok(());
            }
        }
    } else if let Some(m) = mode {
        match fs::metadata(path) {
            Ok(meta) => {
                let cur = meta.permissions().mode() & 0o7777;
                if cur != m {
                    if !check_mode {
                        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(m)) {
                            emit_error(
                                ctx,
                                seq,
                                err::IO,
                                format!("blockinfile: chmod {}: {e}", path.display()),
                            )
                            .await;
                            return Ok(());
                        }
                    }
                    let finished = now_unix_ns();
                    ctx.emit(msg::task_done(seq, 0, true, false, started_unix_ns, finished))
                        .await;
                    return Ok(());
                }
            }
            Err(e) => {
                emit_error(
                    ctx,
                    seq,
                    err::IO,
                    format!("blockinfile: stat {}: {e}", path.display()),
                )
                .await;
                return Ok(());
            }
        }
    }

    let finished = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, false, started_unix_ns, finished))
        .await;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum State {
    Present,
    Absent,
}

fn compile_optional(pat: &str) -> Result<Option<Regex>, regex::Error> {
    if pat.is_empty() {
        Ok(None)
    } else {
        Regex::new(pat).map(Some)
    }
}

/// Substitute the literal token `{mark}` in `template` with `mark`.
fn render_marker(template: &str, mark: &str) -> String {
    template.replace("{mark}", mark)
}

/// Compute the new file contents. Operates line-by-line and preserves
/// LF/no-LF posture of the input where possible. New output always ends
/// with a trailing newline when non-empty (Ansible's behavior).
#[allow(clippy::too_many_arguments)]
fn compute_new(
    text: &str,
    state: State,
    begin_marker: &str,
    end_marker: &str,
    block: &str,
    insertbefore: Option<&Regex>,
    insertafter: Option<&Regex>,
    insert_eof: bool,
) -> String {
    let had_trailing_newline = text.ends_with('\n');
    let lines: Vec<&str> = if text.is_empty() {
        Vec::new()
    } else if had_trailing_newline {
        let mut v: Vec<&str> = text.split('\n').collect();
        v.pop();
        v
    } else {
        text.split('\n').collect()
    };

    // Find existing block by markers.
    let begin_idx = lines.iter().position(|l| *l == begin_marker);
    let end_idx = begin_idx.and_then(|bi| {
        lines
            .iter()
            .enumerate()
            .skip(bi + 1)
            .find(|(_, l)| **l == end_marker)
            .map(|(i, _)| i)
    });

    // Strip existing block (if any) to produce a working sequence.
    let mut working: Vec<String> = match (begin_idx, end_idx) {
        (Some(bi), Some(ei)) => {
            let mut v: Vec<String> = Vec::with_capacity(lines.len());
            v.extend(lines[..bi].iter().map(|s| (*s).to_string()));
            v.extend(lines[ei + 1..].iter().map(|s| (*s).to_string()));
            v
        }
        // Unterminated begin marker → treat as no existing block (don't
        // tamper with malformed content).
        _ => lines.iter().map(|s| (*s).to_string()).collect(),
    };

    match state {
        State::Absent => {
            return join_lines(&working, !working.is_empty() || had_trailing_newline);
        }
        State::Present => {
            // Empty block = "remove if exists" — never add.
            if block.is_empty() {
                return join_lines(&working, !working.is_empty() || had_trailing_newline);
            }

            // Build the new block lines: begin, body lines, end.
            let mut block_lines: Vec<String> =
                Vec::with_capacity(block.lines().count() + 2);
            block_lines.push(begin_marker.to_string());
            for bl in block.split('\n') {
                // split('\n') on "a\nb" yields ["a", "b"]; on "a\nb\n"
                // yields ["a", "b", ""]. Drop the trailing empty if
                // present so we don't insert a blank line before the
                // end marker.
                block_lines.push(bl.to_string());
            }
            if matches!(block_lines.last().map(String::as_str), Some("")) {
                block_lines.pop();
            }
            block_lines.push(end_marker.to_string());

            // Decide insertion index. If there was an existing block we
            // place the new block where it was; otherwise we follow
            // insertbefore/insertafter or append.
            let insert_at = match begin_idx {
                Some(bi) if end_idx.is_some() => bi,
                _ => {
                    if let Some(ib) = insertbefore {
                        working
                            .iter()
                            .position(|l| ib.is_match(l))
                            .unwrap_or(working.len())
                    } else if let Some(ia) = insertafter {
                        working
                            .iter()
                            .rposition(|l| ia.is_match(l))
                            .map(|i| i + 1)
                            .unwrap_or(working.len())
                    } else {
                        let _ = insert_eof;
                        working.len()
                    }
                }
            };
            for (offset, line) in block_lines.into_iter().enumerate() {
                working.insert(insert_at + offset, line);
            }
            join_lines(&working, true)
        }
    }
}

fn join_lines(lines: &[String], trailing_newline: bool) -> String {
    let mut s = lines.join("\n");
    if trailing_newline && !lines.is_empty() {
        s.push('\n');
    }
    s
}

fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>, created: bool) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let nonce: u64 = now_unix_ns();
    let tmp = parent.join(format!(
        ".rsansible-blockinfile.{}.{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        pid,
        nonce
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Some(m) = mode {
        fs::set_permissions(&tmp, fs::Permissions::from_mode(m))?;
    } else if !created {
        if let Ok(meta) = fs::metadata(path) {
            fs::set_permissions(&tmp, meta.permissions())?;
        }
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_present(text: &str, block: &str) -> String {
        compute_new(
            text,
            State::Present,
            "# BEGIN ANSIBLE MANAGED BLOCK",
            "# END ANSIBLE MANAGED BLOCK",
            block,
            None,
            None,
            false,
        )
    }

    #[test]
    fn append_block_to_empty_file() {
        let out = run_present("", "alpha\nbeta");
        assert_eq!(
            out,
            "# BEGIN ANSIBLE MANAGED BLOCK\nalpha\nbeta\n# END ANSIBLE MANAGED BLOCK\n"
        );
    }

    #[test]
    fn append_block_to_existing_content() {
        let out = run_present("preamble\n", "x\ny");
        assert_eq!(
            out,
            "preamble\n# BEGIN ANSIBLE MANAGED BLOCK\nx\ny\n# END ANSIBLE MANAGED BLOCK\n"
        );
    }

    #[test]
    fn replace_existing_block_in_place() {
        let initial = "head\n# BEGIN ANSIBLE MANAGED BLOCK\nold1\nold2\n# END ANSIBLE MANAGED BLOCK\ntail\n";
        let out = run_present(initial, "new1\nnew2");
        assert_eq!(
            out,
            "head\n# BEGIN ANSIBLE MANAGED BLOCK\nnew1\nnew2\n# END ANSIBLE MANAGED BLOCK\ntail\n"
        );
    }

    #[test]
    fn idempotent_replace_with_same_content() {
        let initial = "head\n# BEGIN ANSIBLE MANAGED BLOCK\na\nb\n# END ANSIBLE MANAGED BLOCK\ntail\n";
        let out = run_present(initial, "a\nb");
        assert_eq!(out, initial);
    }

    #[test]
    fn absent_removes_existing_block() {
        let initial = "head\n# BEGIN ANSIBLE MANAGED BLOCK\na\n# END ANSIBLE MANAGED BLOCK\ntail\n";
        let out = compute_new(
            initial,
            State::Absent,
            "# BEGIN ANSIBLE MANAGED BLOCK",
            "# END ANSIBLE MANAGED BLOCK",
            "",
            None,
            None,
            false,
        );
        assert_eq!(out, "head\ntail\n");
    }

    #[test]
    fn absent_when_no_block_is_noop() {
        let initial = "head\ntail\n";
        let out = compute_new(
            initial,
            State::Absent,
            "# BEGIN ANSIBLE MANAGED BLOCK",
            "# END ANSIBLE MANAGED BLOCK",
            "",
            None,
            None,
            false,
        );
        assert_eq!(out, initial);
    }

    #[test]
    fn present_empty_block_removes_existing() {
        let initial = "head\n# BEGIN ANSIBLE MANAGED BLOCK\nold\n# END ANSIBLE MANAGED BLOCK\ntail\n";
        let out = run_present(initial, "");
        assert_eq!(out, "head\ntail\n");
    }

    #[test]
    fn insertbefore_places_block_above_match() {
        let initial = "preamble\nEXIT\n";
        let out = compute_new(
            initial,
            State::Present,
            "# BEGIN",
            "# END",
            "body",
            Some(&Regex::new(r"^EXIT").unwrap()),
            None,
            false,
        );
        assert_eq!(out, "preamble\n# BEGIN\nbody\n# END\nEXIT\n");
    }

    #[test]
    fn insertafter_places_block_after_last_match() {
        let initial = "section\nx\nsection\ny\n";
        let out = compute_new(
            initial,
            State::Present,
            "# BEGIN",
            "# END",
            "body",
            None,
            Some(&Regex::new(r"^section$").unwrap()),
            false,
        );
        assert_eq!(out, "section\nx\nsection\n# BEGIN\nbody\n# END\ny\n");
    }

    #[test]
    fn render_marker_substitutes_token() {
        assert_eq!(
            render_marker("# {mark} ANSIBLE MANAGED BLOCK", "BEGIN"),
            "# BEGIN ANSIBLE MANAGED BLOCK"
        );
    }

    #[test]
    fn custom_marker_and_token() {
        let out = compute_new(
            "",
            State::Present,
            "// ---- {mark}-deploy ----".replace("{mark}", "TOP").as_str(),
            "// ---- {mark}-deploy ----".replace("{mark}", "BOT").as_str(),
            "ln1\nln2",
            None,
            None,
            false,
        );
        assert_eq!(
            out,
            "// ---- TOP-deploy ----\nln1\nln2\n// ---- BOT-deploy ----\n"
        );
    }
}
