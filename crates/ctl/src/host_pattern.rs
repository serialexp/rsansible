//! Ansible-compatible host pattern engine.
//!
//! A *host pattern* is a comma- or colon-separated list of terms that
//! resolves against an [`Inventory`] to an ordered, deduplicated list of
//! host names. Used by both the playbook `hosts:` field and the CLI
//! `--limit` filter.
//!
//! ## Grammar
//!
//! ```text
//! pattern := term (sep term)*
//! sep     := ',' | ':'
//! term    := op? body index?
//! op      := '&' (intersection) | '!' (exclusion)   (default: union)
//! body    := '~' regex | glob_or_name
//! index   := '[' INT ']' | '[' INT? ':' INT? ']'
//! ```
//!
//! - `all` and `*` are aliases for "every host in the inventory."
//! - A name is matched against groups first; if it's a group, the term
//!   expands to that group's member list (in declaration order).
//! - A *glob* uses fnmatch semantics: `*` matches any sequence, `?` any
//!   single character, `[...]` a character class. A term containing
//!   `*`, `?`, or a non-index `[...]` is treated as a glob and matched
//!   against both host names and group names.
//! - A *regex* term starts with `~` and is matched against host and
//!   group names with Rust's `regex` crate.
//! - An *index* / *slice* at the end of a term picks a single element
//!   or sub-range of the term's expanded host list. Negative indices
//!   count from the end (Python-style). Out-of-range indices yield an
//!   empty match; out-of-range slices are clamped.
//!
//! ## Evaluation
//!
//! Terms are processed left-to-right. The first term must be a union
//! (i.e. not prefixed with `&` or `!`) — Ansible's rule is that a
//! leading `!`/`&` produces zero matches, but we surface that as a
//! parse error for clearer operator feedback.
//!
//! - Union: append the term's matches (in order) to the working set,
//!   skipping any host already present.
//! - Intersection: retain only working-set hosts also present in the
//!   term's matches.
//! - Exclusion: remove the term's matches from the working set.

use std::collections::BTreeSet;

use crate::inventory::Inventory;

/// A parsed host pattern, ready to resolve against an inventory.
#[derive(Debug, Clone)]
pub struct HostPattern {
    terms: Vec<Term>,
}

#[derive(Debug, Clone)]
struct Term {
    op: Op,
    kind: TermKind,
    index: Option<IndexSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Union,
    Intersect,
    Exclude,
}

#[derive(Debug, Clone)]
enum TermKind {
    /// `all` / `*` — every host. Distinguished from a glob `*` so that
    /// callers can short-circuit the common case.
    All,
    /// Exact host or group name. The expander expands a group; a host
    /// is returned as a single-element list; an unknown name silently
    /// yields nothing (Ansible behavior).
    Name(String),
    /// `fnmatch`-style glob matched against host *and* group names.
    Glob(regex::Regex),
    /// `~regex` matched against host *and* group names.
    Regex(regex::Regex),
}

#[derive(Debug, Clone, Copy)]
enum IndexSpec {
    Single(i64),
    Slice { start: Option<i64>, end: Option<i64> },
}

/// Errors surfaced by [`HostPattern::parse`].
#[derive(Debug, thiserror::Error)]
pub enum HostPatternError {
    #[error("empty pattern")]
    Empty,
    #[error("empty term in `{0}` (likely a stray comma or colon)")]
    EmptyTerm(String),
    #[error("leading `{prefix}` in `{pattern}`: the first term must be a union (no `&`/`!`)")]
    LeadingNonUnion { prefix: char, pattern: String },
    #[error("invalid regex `{regex}`: {source}")]
    BadRegex {
        regex: String,
        #[source]
        source: regex::Error,
    },
    #[error("invalid index `[{index}]` on `{base}`")]
    BadIndex { base: String, index: String },
    #[error("unbalanced `[` in `{0}`")]
    UnbalancedBrackets(String),
}

/// True if the given string contains no pattern metacharacters — i.e.
/// it's an exact host or group name that the validator can still
/// look up against the inventory. Used by playbook validate to keep
/// pre-pattern-grammar typo-catching for the common case while still
/// allowing the new glob/regex/index syntax.
pub fn is_plain_name(s: &str) -> bool {
    !s.chars().any(|c| matches!(c, '*' | '?' | '[' | ']' | '~' | '&' | '!' | ':' | ','))
        && !s.is_empty()
        && s != "all"
}

impl HostPattern {
    /// Parse a pattern string. The input may include whitespace around
    /// terms; whitespace inside a term is preserved (it would be unusual
    /// to have whitespace in a hostname, but we don't second-guess).
    pub fn parse(s: &str) -> Result<Self, HostPatternError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(HostPatternError::Empty);
        }

        let tokens = tokenize(trimmed, s)?;
        let mut terms = Vec::with_capacity(tokens.len());
        for (idx, tok) in tokens.into_iter().enumerate() {
            let term = parse_term(&tok, s)?;
            if idx == 0 && term.op != Op::Union {
                let prefix = match term.op {
                    Op::Intersect => '&',
                    Op::Exclude => '!',
                    Op::Union => unreachable!(),
                };
                return Err(HostPatternError::LeadingNonUnion {
                    prefix,
                    pattern: s.to_string(),
                });
            }
            terms.push(term);
        }
        Ok(Self { terms })
    }

    /// Resolve against an inventory. Returns the ordered, deduplicated
    /// host list. Empty result is legal — the caller decides whether
    /// that's an error (e.g. `--limit` preflight treats it as fatal).
    pub fn resolve(&self, inv: &Inventory) -> Vec<String> {
        let mut working: Vec<String> = Vec::new();
        let mut working_set: BTreeSet<String> = BTreeSet::new();

        for term in &self.terms {
            let mut matched = expand_term_kind(&term.kind, inv);
            if let Some(idx) = &term.index {
                matched = apply_index(&matched, idx);
            }
            match term.op {
                Op::Union => {
                    for h in matched {
                        if working_set.insert(h.clone()) {
                            working.push(h);
                        }
                    }
                }
                Op::Intersect => {
                    let m: BTreeSet<&str> = matched.iter().map(String::as_str).collect();
                    let keep: Vec<String> =
                        working.iter().filter(|h| m.contains(h.as_str())).cloned().collect();
                    working_set = keep.iter().cloned().collect();
                    working = keep;
                }
                Op::Exclude => {
                    let m: BTreeSet<&str> = matched.iter().map(String::as_str).collect();
                    working.retain(|h| !m.contains(h.as_str()));
                    working_set.retain(|h| !m.contains(h.as_str()));
                }
            }
        }
        working
    }
}

// ---------- tokenizer ----------

/// Split the top-level pattern into raw term strings. Honors bracket
/// depth so an index like `webservers[1:3]` is not split on its `:`.
fn tokenize(input: &str, original: &str) -> Result<Vec<String>, HostPatternError> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth: i32 = 0;
    for ch in input.chars() {
        match ch {
            '[' => {
                depth += 1;
                cur.push(ch);
            }
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err(HostPatternError::UnbalancedBrackets(original.to_string()));
                }
                cur.push(ch);
            }
            ',' | ':' if depth == 0 => {
                let trimmed = cur.trim();
                if trimmed.is_empty() {
                    return Err(HostPatternError::EmptyTerm(original.to_string()));
                }
                tokens.push(trimmed.to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if depth != 0 {
        return Err(HostPatternError::UnbalancedBrackets(original.to_string()));
    }
    let trimmed = cur.trim();
    if trimmed.is_empty() {
        return Err(HostPatternError::EmptyTerm(original.to_string()));
    }
    tokens.push(trimmed.to_string());
    Ok(tokens)
}

// ---------- term parser ----------

fn parse_term(tok: &str, original: &str) -> Result<Term, HostPatternError> {
    let (op, rest) = match tok.chars().next() {
        Some('&') => (Op::Intersect, &tok[1..]),
        Some('!') => (Op::Exclude, &tok[1..]),
        _ => (Op::Union, tok),
    };
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(HostPatternError::EmptyTerm(original.to_string()));
    }

    // Optional trailing index/slice. Only recognized if the bracket
    // content parses as digits/colons; otherwise it's part of a glob
    // character class.
    let (body, index) = split_index(rest)?;
    let body = body.trim();
    if body.is_empty() {
        return Err(HostPatternError::EmptyTerm(original.to_string()));
    }

    let kind = if let Some(re_src) = body.strip_prefix('~') {
        let re = regex::Regex::new(re_src).map_err(|e| HostPatternError::BadRegex {
            regex: re_src.to_string(),
            source: e,
        })?;
        TermKind::Regex(re)
    } else if body == "all" || body == "*" {
        TermKind::All
    } else if is_glob(body) {
        let re = glob_to_regex(body)?;
        TermKind::Glob(re)
    } else {
        TermKind::Name(body.to_string())
    };

    Ok(Term { op, kind, index })
}

/// Pull off a trailing `[…]` index/slice if the contents are a valid
/// integer or slice expression. Otherwise leave the input untouched
/// (the `[…]` is a glob character class).
fn split_index(s: &str) -> Result<(&str, Option<IndexSpec>), HostPatternError> {
    if !s.ends_with(']') {
        return Ok((s, None));
    }
    let open = match s.rfind('[') {
        Some(i) => i,
        None => return Ok((s, None)),
    };
    let inner = &s[open + 1..s.len() - 1];
    let base = &s[..open];

    if let Some(spec) = try_parse_index(inner) {
        return Ok((base, Some(spec)));
    }
    if let Some(spec) = try_parse_slice(inner) {
        return Ok((base, Some(spec)));
    }
    // Not an index — leave alone. Could still be a malformed glob with
    // bracket content; glob_to_regex will fail clearly if so.
    Ok((s, None))
}

fn try_parse_index(inner: &str) -> Option<IndexSpec> {
    let t = inner.trim();
    if t.is_empty() || t.contains(':') {
        return None;
    }
    t.parse::<i64>().ok().map(IndexSpec::Single)
}

fn try_parse_slice(inner: &str) -> Option<IndexSpec> {
    let t = inner.trim();
    let (a, b) = t.split_once(':')?;
    let start = parse_opt_i64(a)?;
    let end = parse_opt_i64(b)?;
    Some(IndexSpec::Slice { start, end })
}

/// Parse an optional bound: empty string → None, integer → Some(i).
/// Anything else → None (signaling "not a valid bound, don't treat
/// this as a slice").
fn parse_opt_i64(s: &str) -> Option<Option<i64>> {
    let t = s.trim();
    if t.is_empty() {
        Some(None)
    } else {
        t.parse::<i64>().ok().map(Some)
    }
}

fn is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Convert a shell-style glob to an anchored regex. Supports `*`, `?`,
/// and `[...]` character classes (with `!`/`^` for negation).
fn glob_to_regex(glob: &str) -> Result<regex::Regex, HostPatternError> {
    let mut re = String::with_capacity(glob.len() * 2 + 4);
    re.push('^');
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '[' => {
                re.push('[');
                // Negation marker translation: fnmatch uses `!` or `^`;
                // regex uses `^`.
                if let Some(&first) = chars.peek() {
                    if first == '!' || first == '^' {
                        re.push('^');
                        chars.next();
                    }
                }
                let mut closed = false;
                for nc in chars.by_ref() {
                    if nc == ']' {
                        re.push(']');
                        closed = true;
                        break;
                    }
                    // Pass through verbatim — regex char-classes accept
                    // the same range syntax (`a-z`). Escape regex meta
                    // that's meaningful inside `[…]`.
                    if matches!(nc, '\\' | '/' | '^') {
                        re.push('\\');
                    }
                    re.push(nc);
                }
                if !closed {
                    return Err(HostPatternError::UnbalancedBrackets(glob.to_string()));
                }
            }
            // Regex metacharacters that need escaping outside `[…]`.
            '.' | '+' | '(' | ')' | '|' | '{' | '}' | '\\' | '^' | '$' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    re.push('$');
    regex::Regex::new(&re).map_err(|e| HostPatternError::BadRegex {
        regex: glob.to_string(),
        source: e,
    })
}

// ---------- term expansion ----------

fn expand_term_kind(kind: &TermKind, inv: &Inventory) -> Vec<String> {
    match kind {
        TermKind::All => inv.hosts.keys().cloned().collect(),
        TermKind::Name(name) => {
            if let Some(members) = inv.groups.get(name) {
                let mut out = Vec::with_capacity(members.len());
                let mut seen = BTreeSet::new();
                for m in members {
                    if seen.insert(m.clone()) {
                        out.push(m.clone());
                    }
                }
                out
            } else if inv.hosts.contains_key(name) {
                vec![name.clone()]
            } else {
                Vec::new()
            }
        }
        TermKind::Glob(re) | TermKind::Regex(re) => expand_via_regex(re, inv),
    }
}

/// Match a regex against host names and group names. Group matches
/// expand to their members. Hosts retain inventory declaration order
/// (BTreeMap iteration order, which is lexical here); groups are
/// visited in inventory order, then their members in declaration order.
/// Within the combined output, first occurrence wins for ordering.
fn expand_via_regex(re: &regex::Regex, inv: &Inventory) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (gname, members) in &inv.groups {
        if re.is_match(gname) {
            for m in members {
                if seen.insert(m.clone()) {
                    out.push(m.clone());
                }
            }
        }
    }
    for hname in inv.hosts.keys() {
        if re.is_match(hname) && seen.insert(hname.clone()) {
            out.push(hname.clone());
        }
    }
    out
}

// ---------- index/slice application ----------

fn apply_index(list: &[String], spec: &IndexSpec) -> Vec<String> {
    if list.is_empty() {
        return Vec::new();
    }
    let len = list.len() as i64;
    match *spec {
        IndexSpec::Single(i) => {
            let idx = if i < 0 { len + i } else { i };
            if idx < 0 || idx >= len {
                Vec::new()
            } else {
                vec![list[idx as usize].clone()]
            }
        }
        IndexSpec::Slice { start, end } => {
            let raw_start = start.unwrap_or(0);
            let raw_end = end.unwrap_or(len);
            // Python-style negative handling, clamped to [0, len].
            let s = clamp_index(raw_start, len);
            let e = clamp_index(raw_end, len);
            if s >= e {
                Vec::new()
            } else {
                list[s as usize..e as usize].to_vec()
            }
        }
    }
}

fn clamp_index(i: i64, len: i64) -> i64 {
    let v = if i < 0 { len + i } else { i };
    v.clamp(0, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Host;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn host(name: &str, groups: &[&str]) -> (String, Host) {
        let mut member_of = vec!["all".to_string()];
        for g in groups {
            member_of.push((*g).to_string());
        }
        (
            name.to_string(),
            Host {
                host: format!("{name}.local"),
                port: 22,
                user: "u".into(),
                key_path: None::<PathBuf>,
                inline_vars: BTreeMap::new(),
                member_of,
            },
        )
    }

    fn fixture() -> Inventory {
        // Hosts: web1, web2, web3, db1, cache1.
        // Groups: webservers={web1,web2,web3}, dbs={db1}, caches={cache1}.
        let mut hosts = BTreeMap::new();
        for (n, gs) in [
            ("web1", &["webservers"][..]),
            ("web2", &["webservers"][..]),
            ("web3", &["webservers"][..]),
            ("db1", &["dbs"][..]),
            ("cache1", &["caches"][..]),
        ] {
            let (k, v) = host(n, gs);
            hosts.insert(k, v);
        }
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        groups.insert(
            "all".into(),
            vec!["cache1", "db1", "web1", "web2", "web3"]
                .into_iter()
                .map(String::from)
                .collect(),
        );
        groups.insert(
            "webservers".into(),
            vec!["web1", "web2", "web3"].into_iter().map(String::from).collect(),
        );
        groups.insert("dbs".into(), vec!["db1".into()]);
        groups.insert("caches".into(), vec!["cache1".into()]);
        Inventory {
            hosts,
            groups,
            all_vars: BTreeMap::new(),
            group_inline_vars: BTreeMap::new(),
        }
    }

    fn resolve(s: &str) -> Vec<String> {
        HostPattern::parse(s).unwrap().resolve(&fixture())
    }

    // ---- basic resolution ----

    #[test]
    fn bare_hostname() {
        assert_eq!(resolve("web1"), vec!["web1"]);
    }

    #[test]
    fn bare_group_expands_in_declaration_order() {
        assert_eq!(resolve("webservers"), vec!["web1", "web2", "web3"]);
    }

    #[test]
    fn all_keyword() {
        assert_eq!(
            resolve("all"),
            vec!["cache1", "db1", "web1", "web2", "web3"]
        );
    }

    #[test]
    fn star_matches_all() {
        // `*` is a glob in our parser; it matches every group and host.
        let r = resolve("*");
        assert_eq!(r, vec!["cache1", "db1", "web1", "web2", "web3"]);
    }

    #[test]
    fn unknown_name_silent_empty() {
        assert!(resolve("nope").is_empty());
    }

    // ---- glob ----

    #[test]
    fn glob_against_host_names() {
        assert_eq!(resolve("web*"), vec!["web1", "web2", "web3"]);
    }

    #[test]
    fn glob_question_mark() {
        assert_eq!(resolve("web?"), vec!["web1", "web2", "web3"]);
    }

    #[test]
    fn glob_no_matches_silent_empty() {
        assert!(resolve("nope*").is_empty());
    }

    // ---- regex ----

    #[test]
    fn regex_basic() {
        assert_eq!(resolve("~^web\\d$"), vec!["web1", "web2", "web3"]);
    }

    // ---- union / intersect / exclude ----

    #[test]
    fn union_via_comma() {
        assert_eq!(
            resolve("webservers,dbs"),
            vec!["web1", "web2", "web3", "db1"]
        );
    }

    #[test]
    fn union_via_colon() {
        assert_eq!(
            resolve("webservers:dbs"),
            vec!["web1", "web2", "web3", "db1"]
        );
    }

    #[test]
    fn union_dedups() {
        assert_eq!(resolve("webservers,web1"), vec!["web1", "web2", "web3"]);
    }

    #[test]
    fn exclude_term_drops_matches() {
        assert_eq!(resolve("webservers,!web2"), vec!["web1", "web3"]);
    }

    #[test]
    fn intersect_with_disjoint_is_empty() {
        assert!(resolve("webservers:&dbs").is_empty());
    }

    #[test]
    fn intersect_keeps_order_of_working_set() {
        // Union all, then intersect with webservers → web1,web2,web3
        // in the order they appeared in `all`.
        assert_eq!(resolve("all:&webservers"), vec!["web1", "web2", "web3"]);
    }

    #[test]
    fn exclude_and_intersect_combined() {
        // all − db1 ∩ webservers = web1,web2,web3.
        assert_eq!(
            resolve("all,!db1:&webservers"),
            vec!["web1", "web2", "web3"]
        );
    }

    #[test]
    fn glob_with_exclude() {
        assert_eq!(resolve("web*:!web2"), vec!["web1", "web3"]);
    }

    // ---- index / slice ----

    #[test]
    fn index_single() {
        assert_eq!(resolve("webservers[0]"), vec!["web1"]);
        assert_eq!(resolve("webservers[2]"), vec!["web3"]);
    }

    #[test]
    fn index_negative() {
        assert_eq!(resolve("webservers[-1]"), vec!["web3"]);
        assert_eq!(resolve("webservers[-3]"), vec!["web1"]);
    }

    #[test]
    fn index_out_of_range_empty() {
        assert!(resolve("webservers[10]").is_empty());
        assert!(resolve("webservers[-10]").is_empty());
    }

    #[test]
    fn slice_basic() {
        assert_eq!(resolve("webservers[1:3]"), vec!["web2", "web3"]);
    }

    #[test]
    fn slice_open_start() {
        assert_eq!(resolve("webservers[:2]"), vec!["web1", "web2"]);
    }

    #[test]
    fn slice_open_end() {
        assert_eq!(resolve("webservers[1:]"), vec!["web2", "web3"]);
    }

    #[test]
    fn slice_clamps() {
        assert_eq!(
            resolve("webservers[0:99]"),
            vec!["web1", "web2", "web3"]
        );
    }

    // ---- parse errors ----

    #[test]
    fn leading_exclude_errors() {
        let err = HostPattern::parse("!web1").unwrap_err();
        assert!(matches!(err, HostPatternError::LeadingNonUnion { prefix: '!', .. }));
    }

    #[test]
    fn leading_intersect_errors() {
        let err = HostPattern::parse("&web1").unwrap_err();
        assert!(matches!(err, HostPatternError::LeadingNonUnion { prefix: '&', .. }));
    }

    #[test]
    fn empty_pattern_errors() {
        assert!(matches!(HostPattern::parse("").unwrap_err(), HostPatternError::Empty));
        assert!(matches!(HostPattern::parse("   ").unwrap_err(), HostPatternError::Empty));
    }

    #[test]
    fn empty_term_errors() {
        assert!(matches!(
            HostPattern::parse("web1,,web2").unwrap_err(),
            HostPatternError::EmptyTerm(_)
        ));
        assert!(matches!(
            HostPattern::parse(",web1").unwrap_err(),
            HostPatternError::EmptyTerm(_)
        ));
    }

    #[test]
    fn bad_regex_errors() {
        let err = HostPattern::parse("~(unclosed").unwrap_err();
        assert!(matches!(err, HostPatternError::BadRegex { .. }));
    }

    #[test]
    fn unbalanced_bracket_errors() {
        // Bare unbalanced bracket at the top level (no index parsing
        // even tried because there's no closing `]`).
        let err = HostPattern::parse("webservers[0").unwrap_err();
        assert!(matches!(err, HostPatternError::UnbalancedBrackets(_)));
    }
}
