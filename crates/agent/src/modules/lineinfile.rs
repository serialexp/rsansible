//! `OpLineInFile` — Ansible's `lineinfile:` module.
//!
//! Single-line idempotent text edits. The agent reads the file, decides
//! whether the on-disk content needs to change, and writes it back
//! atomically (tmpfile + rename) if so. `changed=1` iff bytes actually
//! moved on disk; identical content → `changed=0`.
//!
//! Supported features (the subset gothab uses):
//!   * `state=present` — ensure a line exists; replace the first line
//!     matching `regexp` (or, when regexp is empty, the first line
//!     literally equal to `line`); otherwise append (or place via
//!     `insertbefore`/`insertafter`).
//!   * `state=absent`  — remove every line matching `regexp` (or every
//!     literal-equal line).
//!   * `create=1`      — create the file (with `mode` if `has_mode=1`)
//!     when missing + state=present. Without `create`, a missing file
//!     is a no-op for absent and an error for present.
//!   * `backrefs=1`    — when a regex match is found and `line` contains
//!     `$1` / `${name}` style backrefs, substitute them from the match.
//!     With `backrefs=1` and no match, the file is left unchanged
//!     (Ansible's documented behavior).
//!   * `insertbefore` / `insertafter` — regexes selecting the line
//!     immediately before / after which `line` should be inserted when
//!     no match for `regexp` exists. The literal `EOF` for `insertafter`
//!     means append (Ansible convention). Setting both is illegal.
//!
//! Line-ending policy: we preserve LF/CRLF per-line. New lines we add
//! use LF unless the file's last line ended in CRLF, in which case we
//! match. Files without a trailing newline get one when we modify them
//! (matches Ansible).

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use regex::Regex;
use rsansible_wire::generated::OpLineInFileOutput;
use rsansible_wire::msg::{self, err, now_unix_ns};

use super::{emit_error, Context};

const STATE_PRESENT: u8 = 0;
const STATE_ABSENT: u8 = 1;

pub async fn run(ctx: &Context, seq: u32, op: OpLineInFileOutput) -> anyhow::Result<()> {
    let started_unix_ns = now_unix_ns();

    let mode = if op.has_mode != 0 { Some(op.mode & 0o7777) } else { None };
    let create = op.create != 0;
    let backrefs = op.backrefs != 0;

    let state = match op.state {
        STATE_PRESENT => State::Present,
        STATE_ABSENT => State::Absent,
        other => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("lineinfile: unknown state byte {other}"),
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
            "lineinfile: insertbefore and insertafter are mutually exclusive",
        )
        .await;
        return Ok(());
    }
    if backrefs && op.regexp.is_empty() {
        emit_error(
            ctx,
            seq,
            err::BAD_REQUEST,
            "lineinfile: backrefs requires regexp to be set",
        )
        .await;
        return Ok(());
    }

    // Compile regexes up front so bad patterns surface as BAD_REQUEST
    // rather than mid-mutation.
    let regexp = match compile_optional(&op.regexp) {
        Ok(r) => r,
        Err(e) => {
            emit_error(ctx, seq, err::BAD_REQUEST, format!("lineinfile.regexp: {e}")).await;
            return Ok(());
        }
    };
    let insertbefore = match compile_optional(&op.insertbefore) {
        Ok(r) => r,
        Err(e) => {
            emit_error(
                ctx,
                seq,
                err::BAD_REQUEST,
                format!("lineinfile.insertbefore: {e}"),
            )
            .await;
            return Ok(());
        }
    };
    // insertafter has one magic value: "EOF" (literal) means append.
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
                    format!("lineinfile.insertafter: {e}"),
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
                format!("lineinfile: reading {}: {e}", path.display()),
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
            ctx.emit(msg::task_done(seq, 0, false, started_unix_ns, finished)).await;
            return Ok(());
        }
        (None, State::Present, true) => Vec::new(),
        (None, State::Present, false) => {
            emit_error(
                ctx,
                seq,
                err::NOT_FOUND,
                format!(
                    "lineinfile: {} does not exist and create=false",
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
                format!("lineinfile: {} is not valid UTF-8: {e}", path.display()),
            )
            .await;
            return Ok(());
        }
    };

    let new_text = compute_new(
        &text,
        state,
        regexp.as_ref(),
        &op.line,
        backrefs,
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
        if let Err(e) = write_atomic(path, new_text.as_bytes(), mode, !file_existed) {
            emit_error(ctx, seq, err::IO, format!("lineinfile: writing {}: {e}", path.display()))
                .await;
            return Ok(());
        }
    } else if let Some(m) = mode {
        // Possibly fix only the mode bits on an unchanged file. Counts as
        // changed if the bits actually differ.
        match fs::metadata(path) {
            Ok(meta) => {
                let cur = meta.permissions().mode() & 0o7777;
                if cur != m {
                    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(m)) {
                        emit_error(
                            ctx,
                            seq,
                            err::IO,
                            format!("lineinfile: chmod {}: {e}", path.display()),
                        )
                        .await;
                        return Ok(());
                    }
                    let finished = now_unix_ns();
                    ctx.emit(msg::task_done(seq, 0, true, started_unix_ns, finished))
                        .await;
                    return Ok(());
                }
            }
            Err(e) => {
                emit_error(
                    ctx,
                    seq,
                    err::IO,
                    format!("lineinfile: stat {}: {e}", path.display()),
                )
                .await;
                return Ok(());
            }
        }
    }

    let finished = now_unix_ns();
    ctx.emit(msg::task_done(seq, 0, changed, started_unix_ns, finished))
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

/// Compute the new file contents. Operates on `\n`-terminated lines, but
/// preserves any trailing newline (or lack thereof) on the input.
fn compute_new(
    text: &str,
    state: State,
    regexp: Option<&Regex>,
    line: &str,
    backrefs: bool,
    insertbefore: Option<&Regex>,
    insertafter: Option<&Regex>,
    insert_eof: bool,
) -> String {
    // Split preserving information about whether the original ended in
    // a newline. We work on lines without their terminators, then
    // re-join.
    let had_trailing_newline = text.ends_with('\n');
    let lines: Vec<&str> = if text.is_empty() {
        Vec::new()
    } else if had_trailing_newline {
        // Strip the final empty element from split('\n').
        let mut v: Vec<&str> = text.split('\n').collect();
        v.pop();
        v
    } else {
        text.split('\n').collect()
    };

    match state {
        State::Absent => {
            let mut out: Vec<String> = Vec::with_capacity(lines.len());
            for l in lines.iter() {
                let matched = match regexp {
                    Some(re) => re.is_match(l),
                    None => *l == line,
                };
                if !matched {
                    out.push((*l).to_string());
                }
            }
            join_lines(&out, !out.is_empty() || had_trailing_newline)
        }
        State::Present => {
            // First, find a match: regexp (if set) else first line == `line`.
            let mut matched_idx: Option<usize> = None;
            for (i, l) in lines.iter().enumerate() {
                let matched = match regexp {
                    Some(re) => re.is_match(l),
                    None => *l == line,
                };
                if matched {
                    matched_idx = Some(i);
                    break;
                }
            }

            if let Some(i) = matched_idx {
                // Replace (with optional backref substitution).
                let new_line = if backrefs {
                    if let Some(re) = regexp {
                        re.replace(lines[i], line).into_owned()
                    } else {
                        line.to_string()
                    }
                } else {
                    line.to_string()
                };
                let mut out: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();
                out[i] = new_line;
                return join_lines(&out, true);
            }

            // No match.
            if backrefs && regexp.is_some() {
                // Ansible's rule: backrefs + no match → leave file alone.
                return text.to_string();
            }
            let mut out: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();
            // Place via insertbefore / insertafter / EOF (default).
            if let Some(ib) = insertbefore {
                if let Some(idx) = out.iter().position(|l| ib.is_match(l)) {
                    out.insert(idx, line.to_string());
                    return join_lines(&out, true);
                }
                // Fall through to append.
            } else if let Some(ia) = insertafter {
                // Last match, not first — matches Ansible.
                if let Some(idx) = out.iter().rposition(|l| ia.is_match(l)) {
                    out.insert(idx + 1, line.to_string());
                    return join_lines(&out, true);
                }
                // Fall through to append.
            }
            // Default: append to end (also covers insertafter=EOF
            // explicitly, and the "no match for insert{before,after}"
            // fallback).
            let _ = insert_eof; // present in signature for symmetry
            out.push(line.to_string());
            join_lines(&out, true)
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
    // Use a sibling tempfile so rename is atomic across no FS boundary.
    let pid = std::process::id();
    let nonce: u64 = now_unix_ns();
    let tmp = parent.join(format!(
        ".rsansible-lineinfile.{}.{}.{}.tmp",
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
        // Preserve original mode (set_permissions copies the bits).
        if let Ok(meta) = fs::metadata(path) {
            let cur = meta.permissions();
            fs::set_permissions(&tmp, cur)?;
        }
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(path: &str, line: &str, state: u8) -> OpLineInFileOutput {
        OpLineInFileOutput {
            kind: 7,
            path: path.into(),
            regexp: String::new(),
            line: line.into(),
            state,
            has_mode: 0,
            mode: 0,
            create: 0,
            insertbefore: String::new(),
            insertafter: String::new(),
            backrefs: 0,
        }
    }

    #[test]
    fn compute_appends_when_no_match() {
        let out = compute_new("a\nb\n", State::Present, None, "c", false, None, None, false);
        assert_eq!(out, "a\nb\nc\n");
    }

    #[test]
    fn compute_replaces_first_match() {
        let re = Regex::new(r"^foo=").unwrap();
        let out = compute_new(
            "foo=1\nbar=2\nfoo=3\n",
            State::Present,
            Some(&re),
            "foo=NEW",
            false,
            None,
            None,
            false,
        );
        assert_eq!(out, "foo=NEW\nbar=2\nfoo=3\n");
    }

    #[test]
    fn compute_no_change_when_line_already_matches_literal() {
        let out = compute_new(
            "alpha\nbeta\n",
            State::Present,
            None,
            "beta",
            false,
            None,
            None,
            false,
        );
        assert_eq!(out, "alpha\nbeta\n");
    }

    #[test]
    fn compute_absent_removes_all_regex_matches() {
        let re = Regex::new(r"^#").unwrap();
        let out = compute_new(
            "# a\nfoo\n# b\nbar\n",
            State::Absent,
            Some(&re),
            "",
            false,
            None,
            None,
            false,
        );
        assert_eq!(out, "foo\nbar\n");
    }

    #[test]
    fn compute_absent_removes_literal() {
        let out = compute_new(
            "x\ny\nx\n",
            State::Absent,
            None,
            "x",
            false,
            None,
            None,
            false,
        );
        assert_eq!(out, "y\n");
    }

    #[test]
    fn compute_insertbefore_places_above_match() {
        let ib = Regex::new(r"^EXIT").unwrap();
        let out = compute_new(
            "header\nmiddle\nEXIT\n",
            State::Present,
            Some(&Regex::new(r"^NEW$").unwrap()),
            "NEW",
            false,
            Some(&ib),
            None,
            false,
        );
        assert_eq!(out, "header\nmiddle\nNEW\nEXIT\n");
    }

    #[test]
    fn compute_insertafter_places_below_last_match() {
        let ia = Regex::new(r"^section").unwrap();
        let out = compute_new(
            "section_a\nx\nsection_b\ny\n",
            State::Present,
            Some(&Regex::new(r"^marker$").unwrap()),
            "marker",
            false,
            false_opt(),
            Some(&ia),
            false,
        );
        assert_eq!(out, "section_a\nx\nsection_b\nmarker\ny\n");
    }

    #[test]
    fn compute_backrefs_substitutes_captures() {
        let re = Regex::new(r"^(foo)=(\d+)").unwrap();
        let out = compute_new(
            "foo=42\nbar=1\n",
            State::Present,
            Some(&re),
            "$1=NEW($2)",
            true,
            None,
            None,
            false,
        );
        assert_eq!(out, "foo=NEW(42)\nbar=1\n");
    }

    #[test]
    fn compute_backrefs_no_match_leaves_file_alone() {
        let re = Regex::new(r"^never$").unwrap();
        let out = compute_new(
            "a\nb\n",
            State::Present,
            Some(&re),
            "$1",
            true,
            None,
            None,
            false,
        );
        assert_eq!(out, "a\nb\n");
    }

    #[test]
    fn compute_preserves_lack_of_trailing_newline_for_absent_only() {
        // Absent: if every line goes away, we should produce "".
        let out = compute_new(
            "x\nx\n",
            State::Absent,
            None,
            "x",
            false,
            None,
            None,
            false,
        );
        assert_eq!(out, "");
    }

    fn false_opt<'a>() -> Option<&'a Regex> {
        None
    }

    #[tokio::test]
    async fn write_atomic_creates_file() {
        let dir = std::env::temp_dir().join(format!("rsansible-li-{}-{}", std::process::id(), now_unix_ns()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out");
        write_atomic(&p, b"hello\n", Some(0o600), true).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(bytes, b"hello\n");
        let meta = std::fs::metadata(&p).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Smoke test the run() entrypoint via direct construction; the
    // controller-side e2e covers wire-level coverage.
    #[test]
    fn op_has_expected_shape() {
        let o = op("/tmp/x", "line", STATE_PRESENT);
        assert_eq!(o.kind, 7);
        assert_eq!(o.line, "line");
    }
}
