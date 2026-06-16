//! Template (minijinja) integration.
//!
//! Phase 1a needs Jinja in five places:
//!   * `when:` expressions
//!   * `loop:` strings
//!   * `set_fact:` values (scalar strings)
//!   * `assert.that:` expressions
//!   * task body fields (op argv/env/cwd/command/path/content)
//!
//! All share a single `Environment` configured here: lenient on undefined
//! (Ansible default), with two Ansible-style filters that Phase 1a
//! playbooks already need:
//!
//!   * `mandatory` — raise if the value is undefined/None
//!   * `subelements(field)` — flatten a list-of-dicts paired with each
//!     element of a named sub-list. Mirrors `with_subelements`.
//!
//! `precompile_all` walks the playbook and compiles every Jinja string
//! ahead of time so syntax errors surface at `validate`, not mid-run.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use minijinja::{Environment, Error as MjError, ErrorKind as MjKind, Value as MjValue};

use crate::playbook::{
    AssertTask, ExecOp, LoopSpec, Playbook, ShellOp, Task, TaskBody, TaskOp,
};

/// Ansible-style `omit` sentinel.
///
/// When `default(omit)` is used in a template like
/// `mode: "{{ my_mode | default(omit) }}"`, Ansible substitutes a magic
/// placeholder string that the engine then strips post-render — the
/// effect is "if `my_mode` is undefined, drop this field entirely
/// rather than passing an empty value through to the module."
///
/// rsansible follows the same trick. `omit` is registered as a global
/// in the minijinja environment whose value is this sentinel; after
/// rendering a string, `render_str` (in `orchestrator.rs`) checks for
/// an exact match and collapses it to an empty string. Since most
/// rsansible task-op fields already treat empty as "absent", this
/// gives the right semantics without per-field plumbing.
///
/// The string is intentionally weird-looking and non-repeating so it
/// never collides with real user content. It is NOT a security
/// boundary — anyone authoring a playbook with this exact literal in
/// their YAML can confuse the engine. They shouldn't.
pub const OMIT_SENTINEL: &str =
    "__rsansible_omit_placeholder_8c0a9f2d4b1e3a6d5c7f8b9a0c1d2e3f__";

/// Rewrite a Jinja source string so attribute-style numeric subscripts
/// like `item.0.name` become bracket subscripts `item[0].name`.
///
/// Why: Ansible's Jinja2 accepts both `a.0.b` and `a[0].b` as ways to
/// index into a list / tuple. minijinja's lexer does not — it
/// tokenizes `.0` as the start of a float literal and rejects the
/// surrounding expression with "unexpected float, expected identifier
/// or integer". Real-world Ansible playbooks (acme being the
/// motivating case) lean heavily on `item.0` / `item.1` after a
/// `subelements` loop, so blanket-translating that syntax saves every
/// caller from porting templates by hand.
///
/// The rewrite is **only** applied inside Jinja code blocks (`{{ ... }}`
/// and `{% ... %}`) and only outside string literals within those
/// blocks. Plain template text, comment blocks (`{# ... #}`), and
/// string contents are passed through verbatim — so a literal "1.0.0"
/// inside `{{ "1.0.0" }}` survives the rewrite.
///
/// The transform is a single state-machine pass over the source:
///   * State: `Text` (default) | `Code` (inside `{{`/`{%`) |
///     `Comment` (inside `{#`) | `Str(byte)` (inside a quoted literal).
///   * Inside `Code`, when we see `.<digits>`, we look one further
///     character ahead — if the digits are followed by something that
///     would *not* form a number continuation (`.`, end-of-block, an
///     identifier char, etc.), we emit `[<digits>]`.
///   * Inside string literals, we honor the basic backslash-escape
///     rule (consume the next byte after `\`) so `\"` and `\'` don't
///     prematurely exit the string.
///
/// Returns `Cow::Borrowed(src)` when no rewrite was needed so the hot
/// path (most strings have no `.<digit>` pattern at all) stays
/// allocation-free.
pub fn prepare_jinja_source(src: &str) -> std::borrow::Cow<'_, str> {
    // Fast path: if there's no `.` followed by a digit anywhere, nothing
    // to do. We still need to handle the case where that pattern is
    // inside a string literal, but the cost of running the state
    // machine is worth paying only when there's at least one
    // candidate.
    let bytes = src.as_bytes();
    let mut has_candidate = false;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
            has_candidate = true;
            break;
        }
        i += 1;
    }
    if !has_candidate {
        return std::borrow::Cow::Borrowed(src);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum St {
        Text,
        Code,
        Comment,
        Str(u8),
    }

    // Build the output as a `Vec<u8>` rather than a `String` so that
    // non-ASCII bytes in the source (e.g. an em-dash `e2 80 94` in a
    // template comment) round-trip verbatim. The previous code used
    // `String::push(b as char)`, which interprets each byte as a Unicode
    // codepoint and re-encodes as UTF-8 — turning every UTF-8 byte
    // ≥0x80 into its Latin-1-mishandled two-byte form (e2 → c3 a2,
    // 80 → c2 80, …). Symptom: `template:`-rendered configs arriving on
    // the agent with double-encoded non-ASCII, failing downstream
    // validators (`vmagent -dryRun` rejected the corrupted YAML).
    //
    // The state machine itself only cares about ASCII delimiters
    // (`{`, `}`, `%`, `#`, quotes, `.`, digits, `\\`), and UTF-8
    // continuation/lead bytes (≥0x80) never collide with ASCII, so
    // walking bytes is safe. Only the output accumulation needed
    // fixing. Caught in the acme live drill (scrape.yml.j2 has an
    // em-dash in a comment, and several `.<digit>` sequences elsewhere
    // that engaged the slow path).
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    let mut state = St::Text;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match state {
            St::Text => {
                if b == b'{' && i + 1 < bytes.len() {
                    let n = bytes[i + 1];
                    if n == b'{' || n == b'%' {
                        out.push(b'{');
                        out.push(n);
                        state = St::Code;
                        i += 2;
                        continue;
                    } else if n == b'#' {
                        out.push(b'{');
                        out.push(b'#');
                        state = St::Comment;
                        i += 2;
                        continue;
                    }
                }
                out.push(b);
                i += 1;
            }
            St::Comment => {
                if b == b'#' && i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                    out.push(b'#');
                    out.push(b'}');
                    state = St::Text;
                    i += 2;
                    continue;
                }
                out.push(b);
                i += 1;
            }
            St::Code => {
                // End of code block: `}}` or `%}`.
                if (b == b'}' || b == b'%') && i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                    out.push(b);
                    out.push(b'}');
                    state = St::Text;
                    i += 2;
                    continue;
                }
                if b == b'\'' || b == b'"' {
                    out.push(b);
                    state = St::Str(b);
                    i += 1;
                    continue;
                }
                if b == b'.' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                    // Check the byte *before* the dot — `.0` only makes
                    // sense as an index if there's a value to index INTO
                    // (identifier char, `]`, or `)`). At the start of an
                    // expression `.5` is a float fragment we shouldn't
                    // touch. Identifier/`]`/`)` are all ASCII, so a
                    // last-byte check is sufficient — a UTF-8
                    // continuation byte (≥0x80) won't match any of
                    // these and we correctly leave the dot alone.
                    let prev = out.last().copied();
                    let preceded_by_value = matches!(
                        prev,
                        Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b']' || c == b')'
                    );
                    if preceded_by_value {
                        // Consume digits.
                        let start = i + 1;
                        let mut end = start;
                        while end < bytes.len() && bytes[end].is_ascii_digit() {
                            end += 1;
                        }
                        out.push(b'[');
                        out.extend_from_slice(&bytes[start..end]);
                        out.push(b']');
                        i = end;
                        continue;
                    }
                }
                out.push(b);
                i += 1;
            }
            St::Str(q) => {
                if b == b'\\' && i + 1 < bytes.len() {
                    out.push(b'\\');
                    out.push(bytes[i + 1]);
                    i += 2;
                    continue;
                }
                if b == q {
                    out.push(b);
                    state = St::Code;
                    i += 1;
                    continue;
                }
                out.push(b);
                i += 1;
            }
        }
    }
    // The input was a valid `&str` and we only emit either input bytes
    // (preserving any multi-byte UTF-8 sequence intact) or injected
    // ASCII (`[`, `]`, `{`, `}`, `#`, `%`, `\\`, quotes, digits) — so
    // the result is always valid UTF-8.
    std::borrow::Cow::Owned(
        String::from_utf8(out).expect("prepare_jinja_source preserves UTF-8 validity"),
    )
}

/// Install a path-based template loader on `env` that resolves
/// `{% include "name" %}` (and any other named-template lookup) by
/// probing the given `search_dirs` in order for the first regular file
/// that matches.
///
/// Semantics:
/// - The included template is the literal string passed to
///   `{% include ... %}`; resolution is purely filesystem-based against
///   `search_dirs`. Path traversal segments (`..`, absolute paths,
///   backslashes) are rejected as `None` (template-not-found).
/// - Missing files surface as `Ok(None)`, which minijinja reports as
///   "template not found" at render time — matching Ansible's behavior
///   for missing include targets.
/// - Read errors other than NotFound surface as the underlying IO
///   error wrapped in `ErrorKind::TemplateNotFound`.
///
/// Why per-task: `Environment::set_loader` takes `&mut self`, so the
/// shared run-scoped env can't carry one. `Environment` is also not
/// `Clone`. The strategy is to spin up a fresh env via [`make_env`]
/// for any `template:` body render that might contain `{% include %}`,
/// install this loader with the role's templates dirs captured at
/// load time, and render the body against it. Other renders (`dest`,
/// `when:`, scalar fields, …) keep using the long-lived shared env.
pub fn install_include_loader(env: &mut Environment<'_>, search_dirs: Vec<std::path::PathBuf>) {
    env.set_loader(move |name| {
        // Reject obviously unsafe names. minijinja's own path_loader does
        // the same (rejects `.`, `..`, backslash); we mirror that.
        if name.is_empty() || name.contains('\\') {
            return Ok(None);
        }
        for piece in name.split('/') {
            if piece == "." || piece == ".." {
                return Ok(None);
            }
        }
        let candidate_path = std::path::Path::new(name);
        if candidate_path.is_absolute() {
            // We refuse to include absolute paths via the loader; an
            // include target should be a relative name resolved against
            // the role's templates/ directory tree.
            return Ok(None);
        }
        for base in &search_dirs {
            let cand = base.join(name);
            if cand.is_file() {
                match std::fs::read_to_string(&cand) {
                    Ok(s) => return Ok(Some(s)),
                    Err(err) => {
                        if err.kind() == std::io::ErrorKind::NotFound {
                            continue;
                        }
                        return Err(MjError::new(
                            MjKind::TemplateNotFound,
                            format!("failed to read include target {}", cand.display()),
                        )
                        .with_source(err));
                    }
                }
            }
        }
        Ok(None)
    });
}

/// Build a fresh minijinja `Environment` configured for our use.
pub fn make_env<'a>() -> Environment<'a> {
    let mut env = Environment::new();
    // Ansible playbooks rely on `undefined.attr | default(x)` returning
    // `x` — a pattern that requires undefined attribute access to *also*
    // produce undefined (chainable), not raise. minijinja's Lenient mode
    // raises on attribute access; Chainable matches Ansible's Jinja2
    // behavior. See ANSIBLE_COMPAT.md (any future entry on undefineds).
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Chainable);
    // Python-method compatibility shim. Ansible playbooks routinely call
    // Python string/dict/list methods inside Jinja expressions —
    // `s.strip()`, `s.split(",")`, `s.startswith("foo")`,
    // `d.get("k")`, `d.items()` — because Ansible's Jinja eval runs in
    // a Python context. minijinja by default rejects those as unknown
    // methods (it has equivalents as filters: `| trim`, `| split(",")`,
    // …). `pycompat::unknown_method_callback` from minijinja-contrib
    // wires up the long tail in one call. Covers str.{strip, lstrip,
    // rstrip, lower, upper, capitalize, title, count, find, rfind,
    // replace, split, splitlines, startswith, endswith, join, format,
    // is*}, dict.{get, keys, values, items}, list.count.
    env.set_unknown_method_callback(minijinja_contrib::pycompat::unknown_method_callback);
    // Preserve trailing newlines in rendered output — write_file.content
    // sources frequently end in `\n` and we don't want minijinja stripping
    // them silently. Matches Ansible's behavior.
    env.set_keep_trailing_newline(true);
    // Ansible's Jinja env defaults to `trim_blocks=True`, which strips the
    // newline immediately after a block tag (`{% if %}`, `{% endif %}`,
    // `{% for %}`, etc.). Templates authored against Ansible rely on this
    // — without it, a conditional block leaves a blank line in the
    // output. Sometimes harmless cosmetic noise, sometimes load-bearing:
    // a systemd unit file using `\`-line-continuation cannot survive a
    // blank line between continued lines, the parser truncates ExecStart
    // at the gap. Caught in the acme drill — vmalert.service.j2's
    // `{% if monitoring_cross_notifier_url != 'TBD' %}` block dropped the
    // `-notifier.url` flag silently, putting vmalert in a fatal crash
    // loop. `lstrip_blocks` stays default-false to match Ansible.
    env.set_trim_blocks(true);
    env.add_filter("mandatory", mandatory_filter);
    env.add_filter("subelements", subelements_filter);
    // Ansible-style filters; acme uses these in role templates.
    env.add_filter("b64encode", b64encode_filter);
    env.add_filter("b64decode", b64decode_filter);
    env.add_filter("from_json", from_json_filter);
    // Ansible spells the JSON encoder `to_json`; minijinja calls its
    // built-in `tojson`. Register both — the built-in is already there
    // under `tojson`, this adds the Ansible alias.
    env.add_filter("to_json", to_json_filter);
    env.add_filter("regex_replace", regex_replace_filter);
    // Ansible's set-style list filters. minijinja doesn't ship these.
    // Used heavily in acme role templates for "every peer except me":
    //   groups['pgbackrest'] | difference([inventory_hostname]) | first
    env.add_filter("difference", difference_filter);
    env.add_filter("intersect", intersect_filter);
    env.add_filter("union", union_filter);
    env.add_filter("symmetric_difference", symmetric_difference_filter);
    env.add_filter("unique", unique_filter);
    env.add_filter("flatten", flatten_filter);
    // Ansible-style regex tests, used with `select`/`reject`/`when`:
    //   - `match`  — Python's re.match (anchored at the start).
    //   - `search` — Python's re.search (anywhere in the string).
    //   - `regex`  — Ansible's alias for `search`.
    // Caught in the acme valkey verify task:
    //   {{ lines | select('match', '^role:') | list | first | ... }}
    // minijinja's built-in tests don't include these.
    env.add_test("match", regex_match_test);
    env.add_test("search", regex_search_test);
    env.add_test("regex", regex_search_test);
    // Register-shape tests: in Ansible `r is changed` / `r is failed`
    // / `r is succeeded` / `r is skipped` are first-class. They look
    // at the named attribute on the register dict; if the value isn't
    // a register-shaped dict, they return false rather than erroring
    // (matches Ansible's laxness — playbooks routinely test these
    // against possibly-undefined values).
    env.add_test("changed", register_is_changed_test);
    env.add_test("failed", register_is_failed_test);
    env.add_test("succeeded", register_is_succeeded_test);
    env.add_test("success", register_is_succeeded_test);
    env.add_test("skipped", register_is_skipped_test);
    env.add_test("skip", register_is_skipped_test);
    env.add_filter("extract", extract_filter);
    // Ansible's `random` filter — `{{ 99 | random }}` returns an int
    // in [0, 99). When applied to a sequence it picks a random element.
    // No seed/salt args supported (Ansible's optional `start`/`step`
    // args fall through to mandatory-default semantics that acme
    // doesn't use). See ANSIBLE_COMPAT.md.
    env.add_filter("random", random_filter);
    // `omit` global: see OMIT_SENTINEL doc above. Ansible playbooks rely
    // on the spelling `default(omit)` to make optional fields truly
    // optional rather than getting a stringified empty value.
    env.add_global("omit", MjValue::from(OMIT_SENTINEL));
    // Controller-side I/O. See CLAUDE.md for the `controller_` /
    // `target_` prefix convention — these read/run on the machine
    // invoking rsansible, NOT on the target host. `lookup` is the
    // Ansible-compatibility shim and forwards to these.
    //
    // The cache is per-`Environment` and therefore per-`run()`:
    // identical calls within one rsansible invocation execute once
    // and reuse the result. See LookupCache for rationale.
    let cache: LookupCache = Arc::new(Mutex::new(HashMap::new()));
    {
        let cache = cache.clone();
        env.add_function(
            "controller_read_file",
            move |path: String| -> Result<MjValue, MjError> {
                controller_read_file_impl(&cache, path)
            },
        );
    }
    {
        let cache = cache.clone();
        env.add_function(
            "controller_shell_stdout",
            move |cmd: String| -> Result<MjValue, MjError> {
                controller_shell_stdout_impl(&cache, cmd)
            },
        );
    }
    {
        let cache = cache.clone();
        env.add_function(
            "controller_env",
            move |name: String| -> Result<MjValue, MjError> {
                controller_env_impl(&cache, name)
            },
        );
    }
    {
        let cache = cache.clone();
        env.add_function(
            "lookup",
            move |plugin: String,
                  args: minijinja::value::Rest<MjValue>|
                  -> Result<MjValue, MjError> {
                lookup_shim_impl(&cache, plugin, args)
            },
        );
    }
    env
}

/// Per-run memoization for the controller-side lookups.
///
/// **See `ANSIBLE_COMPAT.md` §1.** rsansible caches `file` and `env`
/// lookups per-run; Ansible does not cache its `lookup` plugins by
/// default. `shell_stdout` is NOT cached (matches Ansible).
///
/// Wired in: `make_env()` constructs one `LookupCache` per
/// `Environment`, then captures clones of the `Arc` into each
/// minijinja function closure. Since rsansible builds exactly one
/// `Environment` per `run()` (see `orchestrator::run`), every cache
/// lives for the duration of one invocation and dies with it. There
/// is no global state.
///
/// **Why cache at all.** Two `controller_shell_stdout('date +%s')`
/// calls in the same `loop:` should agree. An expensive
/// `controller_read_file('/etc/ssh/some.pub')` rendered once per host
/// across a 50-host inventory should hit disk once, not fifty times.
/// And — most importantly — a `lookup('pipe', 'pass show secret')`
/// inside a `for_each:` shouldn't unlock the user's password store
/// once per iteration.
///
/// **What we cache.** Only successful results. Errors re-run; the
/// cost of re-erroring is bounded (each call is fast), and caching
/// a stale error would be more confusing than the redundant work.
///
/// **What we don't cache.** Nothing across `run()` boundaries — the
/// cache dies with the `Environment`. Nothing across processes.
///
/// **Divergence from Ansible.** Ansible's `file`/`pipe`/`env` lookups
/// are not cached by default; ours are. This is intentional. The
/// semantics rsansible users want from these lookups is "what is the
/// value of this thing at the time the run started," not "what is
/// the value at the moment of this particular render." If a playbook
/// genuinely needs uncached re-evaluation (e.g. a timer), the right
/// fix is a dedicated `now()`-style helper, not bypassing the cache.
///
/// **Race window.** The mutex is released between the cache check
/// and the I/O, so two parallel host-renderings can both miss and
/// both execute. The cache write itself doesn't race (Mutex), but
/// the side-effecting work might fire twice in the worst case. For
/// pure reads (file, env) that's harmless; for `shell_stdout` with
/// side effects it's a real but small footgun. A proper single-flight
/// (lock-per-key) implementation is overkill for v1 — if this bites,
/// switch to a `HashMap<K, Arc<OnceCell<V>>>` pattern.
type LookupCache = Arc<Mutex<HashMap<CacheKey, MjValue>>>;

#[derive(Hash, Eq, PartialEq, Clone)]
enum CacheKey {
    ReadFile(String),
    Env(String),
    // NOTE: no ShellStdout variant. `controller_shell_stdout` is
    // intentionally NOT cached — see its doc comment. If we add an
    // opt-in caching flag later, the variant goes here.
}

fn cache_get(cache: &LookupCache, key: &CacheKey) -> Option<MjValue> {
    cache.lock().expect("LookupCache poisoned").get(key).cloned()
}

fn cache_put(cache: &LookupCache, key: CacheKey, value: MjValue) {
    cache
        .lock()
        .expect("LookupCache poisoned")
        .insert(key, value);
}

/// `value | mandatory` — pass through if defined, raise otherwise.
/// Matches Ansible's filter of the same name.
fn mandatory_filter(value: MjValue) -> Result<MjValue, MjError> {
    if value.is_undefined() || value.is_none() {
        return Err(MjError::new(
            MjKind::UndefinedError,
            "mandatory: variable is not defined",
        ));
    }
    Ok(value)
}

/// `users | subelements('keys')` → `[(user, key0), (user, key1), …]`.
///
/// Input is a sequence of mappings; each mapping must contain `field`,
/// itself a sequence. Output is a sequence of two-element sequences
/// `[parent, child]`, mirroring Ansible's `with_subelements`.
fn subelements_filter(value: MjValue, field: String) -> Result<MjValue, MjError> {
    let parents: Vec<MjValue> = value.try_iter()?.collect();
    let mut out: Vec<MjValue> = Vec::new();
    for parent in parents {
        let children = parent.get_attr(&field)?;
        if children.is_undefined() {
            return Err(MjError::new(
                MjKind::UndefinedError,
                format!("subelements: parent has no field {field:?}"),
            ));
        }
        for child in children.try_iter()? {
            out.push(MjValue::from(vec![parent.clone(), child]));
        }
    }
    Ok(MjValue::from(out))
}

/// `key | extract(container, morekeys=None)` — drill into a container.
///
/// Ansible idiom. Typical use:
///
/// ```jinja
/// {{ groups['web'] | map('extract', hostvars, 'ansible_host') | list }}
/// ```
///
/// — for each `hostname` in `groups['web']`, look up
/// `hostvars[hostname]['ansible_host']`. `morekeys` (a single string,
/// integer, or list of either) lets you descend further into the
/// resolved value without chaining filters.
///
/// On any miss (key absent, index out of range, intermediate value not
/// indexable) we return undefined — same as native minijinja attribute
/// access, and equivalent to Ansible's lenient default.
fn extract_filter(
    key: MjValue,
    container: MjValue,
    morekeys: Option<MjValue>,
) -> Result<MjValue, MjError> {
    let first = lookup_one(&container, &key)?;
    let Some(more) = morekeys else { return Ok(first) };
    // `morekeys` accepts a single scalar or a list of scalars. Ansible's
    // docs say "string or list" but in practice integers also work for
    // list indexing.
    let extra: Vec<MjValue> = if more.kind() == minijinja::value::ValueKind::Seq {
        more.try_iter()?.collect()
    } else {
        vec![more]
    };
    let mut current = first;
    for k in extra {
        current = lookup_one(&current, &k)?;
    }
    Ok(current)
}

/// Single-step container lookup used by `extract_filter`. Handles both
/// dict-key and sequence-index access uniformly.
fn lookup_one(container: &MjValue, key: &MjValue) -> Result<MjValue, MjError> {
    // Sequence indexing: accept integer keys.
    if container.kind() == minijinja::value::ValueKind::Seq {
        // `as_usize` returns None for floats / negatives / non-integers.
        if let Ok(i) = i64::try_from(key.clone()) {
            // Negative indexing mirrors Python/Ansible.
            let len = container.len().unwrap_or(0) as i64;
            let idx = if i < 0 { len + i } else { i };
            if idx < 0 || idx >= len {
                return Ok(MjValue::UNDEFINED);
            }
            return container.get_item_by_index(idx as usize);
        }
    }
    // Dict / object: try by string key first (the common case),
    // then fall back to the raw value (for non-string keys like ints).
    if let Some(s) = key.as_str() {
        return Ok(container.get_attr(s)?);
    }
    container.get_item(key)
}

/// `value | b64encode` — base64-encode a string. Ansible accepts strings
/// only (its docs note "for binary use the `base64` shell filter"); we
/// match that. Bytes-by-bytes round-trip with `b64decode`.
/// `value | random` — Ansible's `random` filter.
///
/// - On an integer N (>=0): returns a uniformly random integer in [0, N).
///   `{{ 9999 | random }}` is the acme idiom for unique IDs.
/// - On a sequence: returns one randomly selected element.
///
/// We don't implement the optional `start:` / `step:` / `seed:` kwargs —
/// acme doesn't use them and Ansible's docs explicitly recommend
/// `set_fact` + a deterministic generator if you need reproducibility.
fn random_filter(value: MjValue) -> Result<MjValue, MjError> {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    if let Some(n) = value.as_i64() {
        if n < 0 {
            return Err(MjError::new(
                MjKind::InvalidOperation,
                format!("random: integer argument must be >= 0, got {n}"),
            ));
        }
        if n == 0 {
            // Ansible returns 0 here; mirror that rather than panicking
            // on an empty range.
            return Ok(MjValue::from(0i64));
        }
        let r: i64 = rng.gen_range(0..n);
        return Ok(MjValue::from(r));
    }
    if let Some(seq) = value.as_object().and_then(|o| o.try_iter()) {
        let items: Vec<MjValue> = seq.collect();
        if items.is_empty() {
            return Err(MjError::new(
                MjKind::InvalidOperation,
                "random: cannot pick from an empty sequence",
            ));
        }
        let idx = rng.gen_range(0..items.len());
        return Ok(items[idx].clone());
    }
    Err(MjError::new(
        MjKind::InvalidOperation,
        format!("random: expected an integer or a sequence, got {:?}", value.kind()),
    ))
}

fn b64encode_filter(value: MjValue) -> Result<MjValue, MjError> {
    use base64::Engine as _;
    let s = value.as_str().ok_or_else(|| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("b64encode: expected a string, got {:?}", value.kind()),
        )
    })?;
    Ok(MjValue::from(
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes()),
    ))
}

/// `value | b64decode` — base64-decode a string and return the result as
/// a UTF-8 string. Non-UTF-8 output errors out (matches Ansible — for
/// raw bytes, acme pipes through `copy:` with a pre-encoded file).
fn b64decode_filter(value: MjValue) -> Result<MjValue, MjError> {
    use base64::Engine as _;
    let s = value.as_str().ok_or_else(|| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("b64decode: expected a string, got {:?}", value.kind()),
        )
    })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| {
            MjError::new(MjKind::InvalidOperation, format!("b64decode: {e}"))
        })?;
    let text = String::from_utf8(bytes).map_err(|e| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("b64decode: result is not valid UTF-8: {e}"),
        )
    })?;
    Ok(MjValue::from(text))
}

/// `value | from_json` — parse a string as JSON. Ansible's filter; lets
/// templates consume registered command stdout that emitted JSON.
fn from_json_filter(value: MjValue) -> Result<MjValue, MjError> {
    let s = value.as_str().ok_or_else(|| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("from_json: expected a string, got {:?}", value.kind()),
        )
    })?;
    let json: serde_json::Value = serde_json::from_str(s).map_err(|e| {
        MjError::new(MjKind::InvalidOperation, format!("from_json: {e}"))
    })?;
    Ok(MjValue::from_serialize(&json))
}

/// `value | to_json` — Ansible alias for minijinja's built-in `tojson`.
/// Returns the value as a compact JSON string. We deliberately do not
/// accept an `indent` arg (the built-in `tojson` does); acme doesn't
/// use it. Add if needed.
fn to_json_filter(value: MjValue) -> Result<MjValue, MjError> {
    let s = serde_json::to_string(&value).map_err(|e| {
        MjError::new(MjKind::InvalidOperation, format!("to_json: {e}"))
    })?;
    Ok(MjValue::from(s))
}

/// `value | regex_replace(pattern, replacement)` — `regex::Regex::replace_all`
/// applied to a string. Pattern is Rust regex syntax (close to PCRE for
/// the cases acme uses); replacement supports `$1` / `${name}`
/// backrefs.
///
/// Ansible's filter also accepts an optional `multiline` / `ignorecase`
/// flag; we don't yet (acme doesn't use them). Easy to add via the
/// `(?i)` / `(?m)` inline flags in the meantime.
/// Helper for the register-shape tests. Look up a named bool-valued
/// attribute on a value; return `Ok(false)` for anything that isn't a
/// register dict with the attribute. Matches Ansible's laxness — `r
/// is changed` on a non-register or undefined value returns false, not
/// an error.
fn register_bool_attr(value: &MjValue, attr: &str) -> bool {
    let Ok(v) = value.get_attr(attr) else { return false };
    if v.is_undefined() || v.is_none() {
        return false;
    }
    v.is_true()
}

fn register_is_changed_test(value: MjValue) -> Result<bool, MjError> {
    Ok(register_bool_attr(&value, "changed"))
}

fn register_is_failed_test(value: MjValue) -> Result<bool, MjError> {
    Ok(register_bool_attr(&value, "failed"))
}

fn register_is_succeeded_test(value: MjValue) -> Result<bool, MjError> {
    // `is succeeded` is the inverse of `is failed`, but: an entirely
    // undefined value isn't "succeeded" either. Ansible's contract is
    // "the register exists AND failed is not true". Both checks.
    if value.is_undefined() || value.is_none() {
        return Ok(false);
    }
    // If `failed` is explicitly true, not succeeded.
    if register_bool_attr(&value, "failed") {
        return Ok(false);
    }
    // If `skipped` is true, also not succeeded (Ansible treats skipped
    // separately).
    if register_bool_attr(&value, "skipped") {
        return Ok(false);
    }
    Ok(true)
}

fn register_is_skipped_test(value: MjValue) -> Result<bool, MjError> {
    Ok(register_bool_attr(&value, "skipped"))
}

/// Coerce a minijinja value to a `Vec<MjValue>` for the set-style
/// filters. Accepts any iterable (lists, tuples, generators) and
/// errors loudly on scalars rather than silently treating them as
/// single-element sequences.
fn to_seq(value: &MjValue, filter_name: &str) -> Result<Vec<MjValue>, MjError> {
    value
        .try_iter()
        .map(|it| it.collect::<Vec<_>>())
        .map_err(|e| {
            MjError::new(
                MjKind::InvalidOperation,
                format!("{filter_name}: expected a sequence, got {:?}: {e}", value.kind()),
            )
        })
}

/// Stable-ordered de-dup using a string-form key. We can't put `MjValue`
/// in a `HashSet` (no Hash impl), so we project to its `Debug`-formatted
/// representation. That's good enough for the comparison shapes Ansible
/// playbooks use (strings, ints, simple maps) — values that look the
/// same under `Debug` get folded together.
fn value_key(v: &MjValue) -> String {
    format!("{v:?}")
}

fn difference_filter(value: MjValue, other: MjValue) -> Result<MjValue, MjError> {
    let a = to_seq(&value, "difference")?;
    let b = to_seq(&other, "difference")?;
    let exclude: std::collections::HashSet<String> = b.iter().map(value_key).collect();
    let out: Vec<MjValue> = a.into_iter().filter(|v| !exclude.contains(&value_key(v))).collect();
    Ok(MjValue::from(out))
}

fn intersect_filter(value: MjValue, other: MjValue) -> Result<MjValue, MjError> {
    let a = to_seq(&value, "intersect")?;
    let b = to_seq(&other, "intersect")?;
    let keep: std::collections::HashSet<String> = b.iter().map(value_key).collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let out: Vec<MjValue> = a
        .into_iter()
        .filter(|v| {
            let k = value_key(v);
            keep.contains(&k) && seen.insert(k)
        })
        .collect();
    Ok(MjValue::from(out))
}

fn union_filter(value: MjValue, other: MjValue) -> Result<MjValue, MjError> {
    let a = to_seq(&value, "union")?;
    let b = to_seq(&other, "union")?;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<MjValue> = Vec::with_capacity(a.len() + b.len());
    for v in a.into_iter().chain(b.into_iter()) {
        if seen.insert(value_key(&v)) {
            out.push(v);
        }
    }
    Ok(MjValue::from(out))
}

fn symmetric_difference_filter(value: MjValue, other: MjValue) -> Result<MjValue, MjError> {
    let a = to_seq(&value, "symmetric_difference")?;
    let b = to_seq(&other, "symmetric_difference")?;
    let a_keys: std::collections::HashSet<String> = a.iter().map(value_key).collect();
    let b_keys: std::collections::HashSet<String> = b.iter().map(value_key).collect();
    let mut out: Vec<MjValue> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for v in a.iter().chain(b.iter()) {
        let k = value_key(v);
        let in_a = a_keys.contains(&k);
        let in_b = b_keys.contains(&k);
        if in_a != in_b && seen.insert(k) {
            out.push(v.clone());
        }
    }
    Ok(MjValue::from(out))
}

fn unique_filter(value: MjValue) -> Result<MjValue, MjError> {
    let a = to_seq(&value, "unique")?;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let out: Vec<MjValue> = a.into_iter().filter(|v| seen.insert(value_key(v))).collect();
    Ok(MjValue::from(out))
}

fn flatten_filter(value: MjValue) -> Result<MjValue, MjError> {
    let a = to_seq(&value, "flatten")?;
    let mut out: Vec<MjValue> = Vec::new();
    for v in a {
        match v.try_iter() {
            Ok(it) => out.extend(it),
            // Scalars in a flatten input pass through.
            Err(_) => out.push(v),
        }
    }
    Ok(MjValue::from(out))
}

/// Ansible's `match` test: `re.match(pattern, value)`-shaped — the
/// pattern is anchored at the start of the string. A non-string
/// `value` is a false test (rather than an error) to match Ansible's
/// laxness, but a bad pattern is a hard error so playbooks find their
/// typos.
fn regex_match_test(value: MjValue, pattern: String) -> Result<bool, MjError> {
    let Some(s) = value.as_str() else { return Ok(false) };
    let re = regex::Regex::new(&pattern).map_err(|e| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("match: invalid pattern {pattern:?}: {e}"),
        )
    })?;
    // re.match() anchors at the start, but the engine still scans for a
    // first-position match — we get the same semantics by checking
    // shortest_match() against the start, or equivalently by inserting
    // a leading `\A` and using is_match. Easier: use find() and check
    // that the match starts at 0.
    Ok(match re.find(s) {
        Some(m) => m.start() == 0,
        None => false,
    })
}

/// Ansible's `search` test (and `regex` alias): `re.search(pattern,
/// value)`-shaped — the pattern can match anywhere in the string.
fn regex_search_test(value: MjValue, pattern: String) -> Result<bool, MjError> {
    let Some(s) = value.as_str() else { return Ok(false) };
    let re = regex::Regex::new(&pattern).map_err(|e| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("search: invalid pattern {pattern:?}: {e}"),
        )
    })?;
    Ok(re.is_match(s))
}

fn regex_replace_filter(
    value: MjValue,
    pattern: String,
    replacement: String,
) -> Result<MjValue, MjError> {
    let s = value.as_str().ok_or_else(|| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("regex_replace: expected a string, got {:?}", value.kind()),
        )
    })?;
    let re = regex::Regex::new(&pattern).map_err(|e| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("regex_replace: invalid pattern {pattern:?}: {e}"),
        )
    })?;
    Ok(MjValue::from(re.replace_all(s, replacement.as_str()).into_owned()))
}

// =========================================================================
// Controller-side I/O — see CLAUDE.md "controller_ / target_ prefix" section.
//
// These run on the machine invoking rsansible (the controller), at
// template-render time. The agent never sees the path/command — only
// the resolved string. That's the whole point: secrets stay on the
// controller, paths reference the controller's filesystem.
//
// There's no caching: a `controller_shell_stdout('date +%s')` called
// inside a `loop:` will fire once per iteration. That's the right
// default — caching here would silently make playbooks non-determ
// across iterations — but means expensive lookups should be hoisted
// into a `set_fact:` at the top of the play.
// =========================================================================

/// Read a UTF-8 file from the controller's filesystem.
///
/// Canonical replacement for Ansible's `lookup('file', path)`. Errors
/// loudly on missing files, permission denied, or non-UTF-8 content
/// (use `controller_read_file_b64` — not yet implemented — when we
/// need binary blobs in templates).
///
/// Results are memoized per-run; see LookupCache.
fn controller_read_file_impl(
    cache: &LookupCache,
    path: String,
) -> Result<MjValue, MjError> {
    let key = CacheKey::ReadFile(path.clone());
    if let Some(v) = cache_get(cache, &key) {
        return Ok(v);
    }
    let bytes = std::fs::read(&path).map_err(|e| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("controller_read_file({path:?}): {e}"),
        )
    })?;
    let s = String::from_utf8(bytes).map_err(|e| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("controller_read_file({path:?}): not valid UTF-8: {e}"),
        )
    })?;
    let v = MjValue::from(s);
    cache_put(cache, key, v.clone());
    Ok(v)
}

/// Run a command on the controller via `sh -c` and capture stdout.
///
/// Canonical replacement for Ansible's `lookup('pipe', cmd)`. Trailing
/// newlines on stdout are trimmed (matches Ansible). A non-zero exit
/// is an error and surfaces stderr in the message; stderr is otherwise
/// discarded. There's no stdin and no timeout — if you need either,
/// reach for `shell:` on the target instead, or factor the command
/// into a `set_fact:` once.
///
/// **NOT cached.** Unlike `controller_read_file` / `controller_env`,
/// shell commands can be intentionally non-deterministic — `uuidgen`,
/// `date +%s%N`, `openssl rand`, `mktemp` are all real usage patterns
/// that depend on a fresh value every call. Silently caching would
/// break those playbooks subtly and divergently from Ansible.
///
/// If you want one-shot semantics ("expensive lookup, reuse the
/// result"), hoist it into `set_fact:` at the top of the play. That's
/// the Ansible idiom and stays visible at the call site.
///
/// The `cache` parameter is retained for signature uniformity with
/// the other two canonicals (the closures in `make_env` capture it
/// either way) and so that if we later add an opt-in caching flag —
/// e.g. `controller_shell_stdout(cmd, cache=true)` — the plumbing
/// is already there.
fn controller_shell_stdout_impl(
    _cache: &LookupCache,
    cmd: String,
) -> Result<MjValue, MjError> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map_err(|e| {
            MjError::new(
                MjKind::InvalidOperation,
                format!("controller_shell_stdout({cmd:?}): spawn failed: {e}"),
            )
        })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(MjError::new(
            MjKind::InvalidOperation,
            format!(
                "controller_shell_stdout({cmd:?}): exit {:?}: {}",
                out.status.code(),
                stderr.trim()
            ),
        ));
    }
    let stdout = String::from_utf8(out.stdout).map_err(|e| {
        MjError::new(
            MjKind::InvalidOperation,
            format!("controller_shell_stdout({cmd:?}): non-UTF-8 stdout: {e}"),
        )
    })?;
    // Ansible trims a single trailing newline; we trim any run of
    // \r/\n — same observable result for the common case, less
    // surprising for `printf 'foo\n\n'`.
    Ok(MjValue::from(
        stdout.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

/// Read an environment variable from the controller's process env.
///
/// Canonical replacement for Ansible's `lookup('env', name)`. Returns
/// the empty string if the var is unset — same as Ansible's lenient
/// default. Use `controller_env('FOO') | mandatory` to force a
/// missing-var to error.
///
/// Memoized per-run. Process env doesn't change mid-run in practice
/// (and shouldn't), so caching here is a small win on lookup volume
/// rather than a correctness fix.
fn controller_env_impl(cache: &LookupCache, name: String) -> Result<MjValue, MjError> {
    let key = CacheKey::Env(name.clone());
    if let Some(v) = cache_get(cache, &key) {
        return Ok(v);
    }
    // std::env::var errors on non-UTF-8 or missing; Ansible's behavior
    // is "missing = empty string, non-UTF-8 = empty string." Match it.
    let v = MjValue::from(std::env::var(&name).unwrap_or_default());
    cache_put(cache, key, v.clone());
    Ok(v)
}

/// Ansible-compat shim for `lookup(plugin, ...args)`.
///
/// Translates the god-function spelling into the appropriate
/// `controller_*` canonical function. Pure translation — no business
/// logic lives here. Fresh rsansible playbooks should reach for the
/// canonical names directly.
///
/// Caching happens inside each canonical, so calls via the shim get
/// the same memoization as direct calls — and identical underlying
/// operations cache-hit each other regardless of which spelling the
/// playbook used.
///
/// Unknown plugin names error loudly with the supported list — this
/// is a deliberate divergence from Ansible's silent-undefined.
/// See `ANSIBLE_COMPAT.md` §3.
fn lookup_shim_impl(
    cache: &LookupCache,
    plugin: String,
    args: minijinja::value::Rest<MjValue>,
) -> Result<MjValue, MjError> {
    let supported = "supported plugins: file, pipe, env";
    // Pull arg[0] as a string with a plugin-aware error message.
    let arg0_str = |field: &str| -> Result<String, MjError> {
        let v = args.get(0).ok_or_else(|| {
            MjError::new(
                MjKind::InvalidOperation,
                format!(
                    "lookup({plugin:?}): missing required argument ({field})"
                ),
            )
        })?;
        v.as_str()
            .ok_or_else(|| {
                MjError::new(
                    MjKind::InvalidOperation,
                    format!("lookup({plugin:?}): {field} must be a string"),
                )
            })
            .map(|s| s.to_string())
    };
    match plugin.as_str() {
        "file" => controller_read_file_impl(cache, arg0_str("path")?),
        "pipe" => controller_shell_stdout_impl(cache, arg0_str("command")?),
        "env" => controller_env_impl(cache, arg0_str("name")?),
        other => Err(MjError::new(
            MjKind::InvalidOperation,
            format!("lookup({other:?}): unknown plugin ({supported})"),
        )),
    }
}

/// Compile every Jinja string in the playbook so syntax errors surface
/// before any host is contacted.
pub fn precompile_all(pb: &Playbook) -> Result<()> {
    let env = make_env();
    for (pi, play) in pb.plays.iter().enumerate() {
        for (ti, task) in play.tasks.iter().enumerate() {
            check_task(&env, task).map_err(|e| {
                anyhow!(
                    "play[{pi}] {:?} task[{ti}] {:?}: {e}",
                    play.name,
                    task.name
                )
            })?;
        }
        for (hi, h) in play.handlers.iter().enumerate() {
            check_task(&env, h).map_err(|e| {
                anyhow!(
                    "play[{pi}] {:?} handler[{hi}] {:?}: {e}",
                    play.name,
                    h.name
                )
            })?;
        }
    }
    Ok(())
}

fn check_task(env: &Environment, task: &Task) -> Result<()> {
    if let Some(expr) = &task.when {
        env.compile_expression(&crate::template::prepare_jinja_source(&expr))
            .map_err(|e| anyhow!("when: {e}"))?;
    }
    if let Some(LoopSpec::Expr(s)) = &task.loop_spec {
        // Treat the loop expression as a template — they're sometimes
        // bare `{{ var }}` and sometimes more complex `{{ a + b }}`.
        env.template_from_str(&crate::template::prepare_jinja_source(&s)).map_err(|e| anyhow!("loop: {e}"))?;
    }
    if let Some(d) = &task.delegate_to {
        env.template_from_str(&crate::template::prepare_jinja_source(&d))
            .map_err(|e| anyhow!("delegate_to: {e}"))?;
    }
    for (i, n) in task.notify.iter().enumerate() {
        env.template_from_str(&crate::template::prepare_jinja_source(&n))
            .map_err(|e| anyhow!("notify[{i}]: {e}"))?;
    }
    match &task.body {
        TaskBody::Op(op) => check_op(env, op)?,
        TaskBody::Assert(a) => check_assert(env, a)?,
        TaskBody::Fail(f) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&f.msg))
                .map_err(|e| anyhow!("fail.msg: {e}"))?;
        }
        TaskBody::Debug(d) => {
            match &d.msg {
                None => {}
                Some(crate::playbook::DebugMsg::One(s)) => {
                    env.template_from_str(&crate::template::prepare_jinja_source(&s))
                        .map_err(|e| anyhow!("debug.msg: {e}"))?;
                }
                Some(crate::playbook::DebugMsg::Many(lines)) => {
                    for (i, s) in lines.iter().enumerate() {
                        env.template_from_str(&crate::template::prepare_jinja_source(&s))
                            .map_err(|e| anyhow!("debug.msg[{i}]: {e}"))?;
                    }
                }
            }
            if let Some(s) = &d.var {
                env.template_from_str(&crate::template::prepare_jinja_source(&s))
                    .map_err(|e| anyhow!("debug.var: {e}"))?;
            }
        }
        TaskBody::SetFact(m) => {
            for (k, v) in &m.0 {
                if let serde_yaml::Value::String(s) = v {
                    env.template_from_str(&crate::template::prepare_jinja_source(&s))
                        .map_err(|e| anyhow!("set_fact.{k}: {e}"))?;
                }
            }
        }
        TaskBody::Pause(p) => {
            // Pre-compile any Jinja in `seconds:` / `minutes:` so bad
            // templates surface at load time, not at the wakeup point.
            if let Some(s) = &p.seconds {
                env.template_from_str(&crate::template::prepare_jinja_source(&s))
                    .map_err(|e| anyhow!("pause.seconds: {e}"))?;
            }
            if let Some(s) = &p.minutes {
                env.template_from_str(&crate::template::prepare_jinja_source(&s))
                    .map_err(|e| anyhow!("pause.minutes: {e}"))?;
            }
        }
        TaskBody::ImportTasks(_) => {
            // Should already have been flattened away. Leave as a soft
            // skip rather than a hard failure to keep `precompile_all`
            // safe to call on partially-loaded playbooks in tests.
        }
        TaskBody::IncludeRole(ir) => {
            // Should already have been expanded; precompile any Jinja in
            // the vars-block so a bad template in the include's vars
            // surfaces here rather than at runtime.
            for (k, v) in &ir.vars {
                if let serde_yaml::Value::String(s) = v {
                    env.template_from_str(&crate::template::prepare_jinja_source(&s))
                        .map_err(|e| anyhow!("include_role.vars.{k}: {e}"))?;
                }
            }
        }
        TaskBody::Meta(_) => {
            // `meta: flush_handlers` has no body fields to compile.
        }
        TaskBody::Block(b) => {
            // Recurse into each sub-list so Jinja in inner tasks
            // (when:, loop:, body fields) precompiles too. The block
            // container's own `when:` / `loop:` were handled above as
            // task-level fields.
            for (i, child) in b.tasks.iter().enumerate() {
                check_task(env, child)
                    .map_err(|e| anyhow!("block.tasks[{i}] {:?}: {e}", child.name))?;
            }
            for (i, child) in b.rescue.iter().enumerate() {
                check_task(env, child)
                    .map_err(|e| anyhow!("rescue[{i}] {:?}: {e}", child.name))?;
            }
            for (i, child) in b.always.iter().enumerate() {
                check_task(env, child)
                    .map_err(|e| anyhow!("always[{i}] {:?}: {e}", child.name))?;
            }
        }
    }
    Ok(())
}

fn check_op(env: &Environment, op: &TaskOp) -> Result<()> {
    match op {
        TaskOp::Shell(ShellOp::Simple(s)) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&s))
                .map_err(|e| anyhow!("shell: {e}"))?;
        }
        TaskOp::Shell(ShellOp::Detailed { command, .. }) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&command))
                .map_err(|e| anyhow!("shell.command: {e}"))?;
        }
        TaskOp::Exec(ExecOp {
            argv, env: e_env, cwd, stdin, ..
        }) => {
            for (i, a) in argv.iter().enumerate() {
                env.template_from_str(&crate::template::prepare_jinja_source(&a))
                    .map_err(|e| anyhow!("exec.argv[{i}]: {e}"))?;
            }
            for (k, v) in e_env {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("exec.env.{k}: {e}"))?;
            }
            if let Some(c) = cwd {
                env.template_from_str(&crate::template::prepare_jinja_source(&c))
                    .map_err(|e| anyhow!("exec.cwd: {e}"))?;
            }
            env.template_from_str(&crate::template::prepare_jinja_source(&stdin))
                .map_err(|e| anyhow!("exec.stdin: {e}"))?;
        }
        TaskOp::Command(c) => {
            if let Some(raw) = c.raw_cmd.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&raw))
                    .map_err(|e| anyhow!("command.cmd: {e}"))?;
            } else {
                for (i, a) in c.argv.iter().enumerate() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&a))
                        .map_err(|e| anyhow!("command.argv[{i}]: {e}"))?;
                }
            }
            env.template_from_str(&crate::template::prepare_jinja_source(&c.chdir))
                .map_err(|e| anyhow!("command.chdir: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&c.creates))
                .map_err(|e| anyhow!("command.creates: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&c.removes))
                .map_err(|e| anyhow!("command.removes: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&c.stdin))
                .map_err(|e| anyhow!("command.stdin: {e}"))?;
        }
        TaskOp::WriteFile(w) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&w.path))
                .map_err(|e| anyhow!("write_file.path: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&w.content))
                .map_err(|e| anyhow!("write_file.content: {e}"))?;
            if let Some(v) = w.validate.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("write_file.validate: {e}"))?;
            }
        }
        TaskOp::Template(t) => {
            // `src:` was resolved at load time; `dest:` is Jinja-able
            // at task time, and the loaded `.j2` body itself is also
            // compiled here so a syntax error in the template surfaces
            // at validate-time rather than at first task dispatch.
            env.template_from_str(&crate::template::prepare_jinja_source(&t.dest))
                .map_err(|e| anyhow!("template.dest: {e}"))?;
            if let Some(body) = t.body.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&body)).map_err(|e| {
                    anyhow!("template src {:?}: {e}", t.src)
                })?;
            }
            if let Some(v) = t.validate.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("template.validate: {e}"))?;
            }
        }
        TaskOp::Copy(c) => {
            // `src:` form — body is raw bytes from disk, no Jinja.
            // `content:` form — content is a Jinja-renderable string,
            // pre-compile it so syntax errors surface at validate time
            // rather than at first dispatch.
            env.template_from_str(&crate::template::prepare_jinja_source(&c.dest))
                .map_err(|e| anyhow!("copy.dest: {e}"))?;
            if let Some(content) = c.content.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&content))
                    .map_err(|e| anyhow!("copy.content: {e}"))?;
            }
            if let Some(v) = c.validate.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("copy.validate: {e}"))?;
            }
        }
        TaskOp::GatherFacts => {
            // Implicit op — no user-supplied fields to compile.
        }
        TaskOp::Stat(s) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&s.path))
                .map_err(|e| anyhow!("stat.path: {e}"))?;
        }
        TaskOp::File(f) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&f.path))
                .map_err(|e| anyhow!("file.path: {e}"))?;
            if let Some(o) = &f.owner {
                env.template_from_str(&crate::template::prepare_jinja_source(&o))
                    .map_err(|e| anyhow!("file.owner: {e}"))?;
            }
            if let Some(g) = &f.group {
                env.template_from_str(&crate::template::prepare_jinja_source(&g))
                    .map_err(|e| anyhow!("file.group: {e}"))?;
            }
        }
        TaskOp::WaitFor(w) => {
            if let Some(h) = &w.host {
                env.template_from_str(&crate::template::prepare_jinja_source(&h))
                    .map_err(|e| anyhow!("wait_for.host: {e}"))?;
            }
            if let Some(p) = &w.path {
                env.template_from_str(&crate::template::prepare_jinja_source(&p))
                    .map_err(|e| anyhow!("wait_for.path: {e}"))?;
            }
        }
        TaskOp::LineInFile(l) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&l.path))
                .map_err(|e| anyhow!("lineinfile.path: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&l.line))
                .map_err(|e| anyhow!("lineinfile.line: {e}"))?;
            if let Some(v) = l.validate.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("lineinfile.validate: {e}"))?;
            }
            // regexp / insertbefore / insertafter are regex patterns —
            // we don't Jinja-render those (acme doesn't use Jinja
            // inside regex patterns, and `{{...}}` would be ambiguous
            // with regex syntax). If we ever need it, add it here.
        }
        TaskOp::BlockInFile(b) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&b.path))
                .map_err(|e| anyhow!("blockinfile.path: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&b.block))
                .map_err(|e| anyhow!("blockinfile.block: {e}"))?;
            if let Some(v) = b.validate.as_deref() {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("blockinfile.validate: {e}"))?;
            }
            // marker/marker_begin/marker_end pass through as raw
            // strings; the agent does the literal `{mark}` substitution
            // itself (not Jinja). insertbefore/insertafter are regex
            // patterns — same rationale as lineinfile.
        }
        TaskOp::Systemd(s) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&s.name))
                .map_err(|e| anyhow!("systemd.name: {e}"))?;
        }
        TaskOp::Package(p) => {
            let label = p.manager.label();
            for n in &p.names {
                env.template_from_str(&crate::template::prepare_jinja_source(&n))
                    .map_err(|e| anyhow!("{label}.name: {e}"))?;
            }
            if !p.default_release.is_empty() {
                env.template_from_str(&crate::template::prepare_jinja_source(&p.default_release))
                    .map_err(|e| anyhow!("{label}.default_release: {e}"))?;
            }
            if !p.virtualenv.is_empty() {
                env.template_from_str(&crate::template::prepare_jinja_source(&p.virtualenv))
                    .map_err(|e| anyhow!("{label}.virtualenv: {e}"))?;
            }
            if !p.virtualenv_command.is_empty() {
                env.template_from_str(&crate::template::prepare_jinja_source(&p.virtualenv_command))
                    .map_err(|e| anyhow!("{label}.virtualenv_command: {e}"))?;
            }
        }
        TaskOp::Repository(r) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&r.repo))
                .map_err(|e| anyhow!("repository.repo: {e}"))?;
            if !r.filename.is_empty() {
                env.template_from_str(&crate::template::prepare_jinja_source(&r.filename))
                    .map_err(|e| anyhow!("repository.filename: {e}"))?;
            }
        }
        TaskOp::Group(g) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&g.name))
                .map_err(|e| anyhow!("group.name: {e}"))?;
        }
        TaskOp::User(u) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&u.name))
                .map_err(|e| anyhow!("user.name: {e}"))?;
            if let Some(s) = &u.shell {
                env.template_from_str(&crate::template::prepare_jinja_source(&s))
                    .map_err(|e| anyhow!("user.shell: {e}"))?;
            }
            if let Some(h) = &u.home {
                env.template_from_str(&crate::template::prepare_jinja_source(&h))
                    .map_err(|e| anyhow!("user.home: {e}"))?;
            }
            if !u.primary_group.is_empty() {
                env.template_from_str(&crate::template::prepare_jinja_source(&u.primary_group))
                    .map_err(|e| anyhow!("user.group: {e}"))?;
            }
            for (i, g) in u.groups.iter().enumerate() {
                env.template_from_str(&crate::template::prepare_jinja_source(&g))
                    .map_err(|e| anyhow!("user.groups[{i}]: {e}"))?;
            }
        }
        TaskOp::AuthorizedKey(a) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&a.user))
                .map_err(|e| anyhow!("authorized_key.user: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&a.key))
                .map_err(|e| anyhow!("authorized_key.key: {e}"))?;
        }
        TaskOp::Getent(g) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&g.database))
                .map_err(|e| anyhow!("getent.database: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&g.key))
                .map_err(|e| anyhow!("getent.key: {e}"))?;
            if !g.split.is_empty() {
                env.template_from_str(&crate::template::prepare_jinja_source(&g.split))
                    .map_err(|e| anyhow!("getent.split: {e}"))?;
            }
        }
        TaskOp::Hostname(h) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&h.name))
                .map_err(|e| anyhow!("hostname.name: {e}"))?;
        }
        TaskOp::Timezone(z) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&z.name))
                .map_err(|e| anyhow!("timezone.name: {e}"))?;
        }
        TaskOp::Ufw(u) => {
            // All string fields may carry Jinja — the parse-time
            // enum checks for rule/direction/proto are skipped when
            // the value is templated, so the syntax check is the
            // last chance to catch a malformed `{{ ... }}` before
            // dispatch.
            for (label, val) in [
                ("ufw.rule", &u.rule),
                ("ufw.direction", &u.direction),
                ("ufw.proto", &u.proto),
                ("ufw.from_ip", &u.from_ip),
                ("ufw.from_port", &u.from_port),
                ("ufw.to_ip", &u.to_ip),
                ("ufw.to_port", &u.to_port),
                ("ufw.interface", &u.interface),
                ("ufw.comment", &u.comment),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("{label}: {e}"))?;
                }
            }
        }
        TaskOp::AsyncStatus(a) => {
            // `jid` is Jinja: typically `{{ start_task.ansible_job_id }}`.
            env.template_from_str(&crate::template::prepare_jinja_source(&a.jid))
                .map_err(|e| anyhow!("async_status.jid: {e}"))?;
        }
        TaskOp::Iptables(i) => {
            // Every string knob on iptables is potentially Jinja
            // (chain, ports, addresses, jump targets, comment all
            // commonly come from inventory). Precompile each so a bad
            // template surfaces at load time, not at the partition
            // task firing in the middle of a drill.
            for (label, val) in [
                ("iptables.table", &i.table),
                ("iptables.chain", &i.chain),
                ("iptables.protocol", &i.protocol),
                ("iptables.source", &i.source),
                ("iptables.destination", &i.destination),
                ("iptables.source_port", &i.source_port),
                ("iptables.destination_port", &i.destination_port),
                ("iptables.in_interface", &i.in_interface),
                ("iptables.out_interface", &i.out_interface),
                ("iptables.jump", &i.jump),
                ("iptables.ctstate", &i.ctstate),
                ("iptables.comment", &i.comment),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("{label}: {e}"))?;
                }
            }
        }
        TaskOp::Uri(u) => {
            // url, header values, and body are Jinja-rendered at task
            // time. Header keys are not (header names aren't useful Jinja
            // targets and `:` in a name would be ambiguous anyway).
            env.template_from_str(&crate::template::prepare_jinja_source(&u.url))
                .map_err(|e| anyhow!("uri.url: {e}"))?;
            for (k, v) in &u.headers {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("uri.headers.{k}: {e}"))?;
            }
            if !u.body.is_empty() {
                env.template_from_str(&crate::template::prepare_jinja_source(&u.body))
                    .map_err(|e| anyhow!("uri.body: {e}"))?;
            }
            for label in ["client_cert", "client_key", "ca_path"] {
                let val = match label {
                    "client_cert" => &u.client_cert,
                    "client_key" => &u.client_key,
                    "ca_path" => &u.ca_path,
                    _ => unreachable!(),
                };
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("uri.{label}: {e}"))?;
                }
            }
        }
        TaskOp::OpenSslPrivkey(p) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&p.path))
                .map_err(|e| anyhow!("openssl_privatekey.path: {e}"))?;
        }
        TaskOp::OpenSslCsrPipe(c) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&c.privatekey_path))
                .map_err(|e| anyhow!("openssl_csr_pipe.privatekey_path: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&c.common_name))
                .map_err(|e| anyhow!("openssl_csr_pipe.common_name: {e}"))?;
            for (i, s) in c.subject_alt_name.iter().enumerate() {
                env.template_from_str(&crate::template::prepare_jinja_source(&s))
                    .map_err(|e| anyhow!("openssl_csr_pipe.subject_alt_name[{i}]: {e}"))?;
            }
            // key_usage / extended_key_usage are validated against
            // closed enums (parse_key_usage / parse_extended_key_usage);
            // Jinja inside those strings would only confuse the matcher.
        }
        TaskOp::X509CertificatePipe(c) => {
            // csr_content / privatekey_content come from previous-task
            // registers via Jinja in real playbooks.
            env.template_from_str(&crate::template::prepare_jinja_source(&c.csr_content))
                .map_err(|e| anyhow!("x509_certificate_pipe.csr_content: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&c.privatekey_content))
                .map_err(|e| anyhow!("x509_certificate_pipe.privatekey_content: {e}"))?;
        }
        TaskOp::PostgresqlQuery(p) => {
            // query, db, login_user, login_password, login_host all
            // support Jinja (Patroni clusters template hostnames from
            // facts; passwords come from vault). positional_args items
            // are also templatable. Sockets / ports usually aren't but
            // we render anyway for symmetry.
            env.template_from_str(&crate::template::prepare_jinja_source(&p.query))
                .map_err(|e| anyhow!("postgresql_query.query: {e}"))?;
            for (label, val) in [
                ("db", &p.db),
                ("login_user", &p.login_user),
                ("login_password", &p.login_password),
                ("login_unix_socket", &p.login_unix_socket),
                ("login_host", &p.login_host),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("postgresql_query.{label}: {e}"))?;
                }
            }
            for (i, a) in p.positional_args.iter().enumerate() {
                env.template_from_str(&crate::template::prepare_jinja_source(&a))
                    .map_err(|e| anyhow!("postgresql_query.positional_args[{i}]: {e}"))?;
            }
        }
        TaskOp::PostgresqlExt(p) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&p.name))
                .map_err(|e| anyhow!("postgresql_ext.name: {e}"))?;
            for (label, val) in [
                ("version", &p.version),
                ("schema", &p.ext_schema),
                ("db", &p.db),
                ("login_user", &p.login_user),
                ("login_password", &p.login_password),
                ("login_unix_socket", &p.login_unix_socket),
                ("login_host", &p.login_host),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("postgresql_ext.{label}: {e}"))?;
                }
            }
        }
        TaskOp::PostgresqlUser(u) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&u.name))
                .map_err(|e| anyhow!("postgresql_user.name: {e}"))?;
            for (label, val) in [
                ("password", &u.password),
                ("role_attr_flags", &u.role_attr_flags),
                ("db", &u.db),
                ("login_user", &u.login_user),
                ("login_password", &u.login_password),
                ("login_unix_socket", &u.login_unix_socket),
                ("login_host", &u.login_host),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("postgresql_user.{label}: {e}"))?;
                }
            }
        }
        TaskOp::PostgresqlDb(d) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&d.name))
                .map_err(|e| anyhow!("postgresql_db.name: {e}"))?;
            for (label, val) in [
                ("owner", &d.owner),
                ("encoding", &d.encoding),
                ("lc_collate", &d.lc_collate),
                ("lc_ctype", &d.lc_ctype),
                ("template", &d.template),
                ("login_user", &d.login_user),
                ("login_password", &d.login_password),
                ("login_unix_socket", &d.login_unix_socket),
                ("login_host", &d.login_host),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("postgresql_db.{label}: {e}"))?;
                }
            }
        }
        TaskOp::PostgresqlMembership(m) => {
            for g in &m.groups {
                env.template_from_str(&crate::template::prepare_jinja_source(&g))
                    .map_err(|e| anyhow!("postgresql_membership.groups[]: {e}"))?;
            }
            for t in &m.target_roles {
                env.template_from_str(&crate::template::prepare_jinja_source(&t))
                    .map_err(|e| anyhow!("postgresql_membership.target_roles[]: {e}"))?;
            }
            for (label, val) in [
                ("db", &m.db),
                ("login_user", &m.login_user),
                ("login_password", &m.login_password),
                ("login_unix_socket", &m.login_unix_socket),
                ("login_host", &m.login_host),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("postgresql_membership.{label}: {e}"))?;
                }
            }
        }
        TaskOp::GetUrl(g) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&g.url))
                .map_err(|e| anyhow!("get_url.url: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&g.dest))
                .map_err(|e| anyhow!("get_url.dest: {e}"))?;
            for (label, val) in [
                ("checksum", &g.checksum),
                ("owner", &g.owner),
                ("group", &g.group),
                ("client_cert", &g.client_cert),
                ("client_key", &g.client_key),
                ("ca_path", &g.ca_path),
            ] {
                if !val.is_empty() {
                    env.template_from_str(&crate::template::prepare_jinja_source(&val))
                        .map_err(|e| anyhow!("get_url.{label}: {e}"))?;
                }
            }
            for (k, v) in &g.headers {
                env.template_from_str(&crate::template::prepare_jinja_source(&v))
                    .map_err(|e| anyhow!("get_url.headers[{k}]: {e}"))?;
            }
        }
        TaskOp::Slurp(s) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&s.src))
                .map_err(|e| anyhow!("slurp.src: {e}"))?;
        }
        TaskOp::Unarchive(u) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&u.src))
                .map_err(|e| anyhow!("unarchive.src: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&u.dest))
                .map_err(|e| anyhow!("unarchive.dest: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&u.creates))
                .map_err(|e| anyhow!("unarchive.creates: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&u.owner))
                .map_err(|e| anyhow!("unarchive.owner: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&u.group))
                .map_err(|e| anyhow!("unarchive.group: {e}"))?;
            for (i, p) in u.include.iter().enumerate() {
                env.template_from_str(&crate::template::prepare_jinja_source(&p))
                    .map_err(|e| anyhow!("unarchive.include[{i}]: {e}"))?;
            }
            for (i, p) in u.exclude.iter().enumerate() {
                env.template_from_str(&crate::template::prepare_jinja_source(&p))
                    .map_err(|e| anyhow!("unarchive.exclude[{i}]: {e}"))?;
            }
        }
        TaskOp::Tempfile(t) => {
            env.template_from_str(&crate::template::prepare_jinja_source(&t.prefix))
                .map_err(|e| anyhow!("tempfile.prefix: {e}"))?;
            env.template_from_str(&crate::template::prepare_jinja_source(&t.suffix))
                .map_err(|e| anyhow!("tempfile.suffix: {e}"))?;
            if let Some(p) = &t.path {
                env.template_from_str(&crate::template::prepare_jinja_source(&p))
                    .map_err(|e| anyhow!("tempfile.path: {e}"))?;
            }
        }
    }
    Ok(())
}

fn check_assert(env: &Environment, a: &AssertTask) -> Result<()> {
    for (i, expr) in a.that.iter().enumerate() {
        env.compile_expression(&crate::template::prepare_jinja_source(&expr))
            .map_err(|e| anyhow!("assert.that[{i}]: {e}"))?;
    }
    if let Some(msg) = &a.fail_msg {
        env.template_from_str(&crate::template::prepare_jinja_source(&msg))
            .map_err(|e| anyhow!("assert.fail_msg: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minijinja::context;

    #[test]
    fn env_builds() {
        let env = make_env();
        let tmpl = env.template_from_str("hello {{ name }}").unwrap();
        let out = tmpl.render(context! { name => "world" }).unwrap();
        assert_eq!(out, "hello world");
    }

    /// Regression: Ansible's Jinja env defaults to `trim_blocks=True`,
    /// which strips the newline immediately after a block tag
    /// (`{% if %}`, `{% endif %}`, `{% for %}`, …). Pre-fix
    /// `make_env()` did not set this, so a conditional block in a
    /// template left a blank line in the output. Cosmetic in most
    /// files, load-bearing in some: caught in the acme drill when
    /// `vmalert.service.j2`'s `{% if monitoring_cross_notifier_url
    /// != 'TBD' %}` block produced a blank line between two
    /// `\`-continued ExecStart args. systemd's parser cannot bridge
    /// a `\`-line followed by a blank line; ExecStart was truncated
    /// at the gap, the `-notifier.url=…` flag silently dropped, and
    /// vmalert died on startup with "config contains alerting rules
    /// but neither -notifier.url nor -notifier.config nor
    /// -notifier.blackhole aren't set". ~3 hours of crash-looping
    /// before someone noticed.
    #[test]
    fn make_env_trims_newline_after_block_tags_to_match_ansible() {
        let env = make_env();
        let src = "before\n{% if true %}\ninside\n{% endif %}\nafter\n";
        let tmpl = env.template_from_str(src).unwrap();
        let out = tmpl.render(context! {}).unwrap();
        // With trim_blocks the `\n` immediately after `{% if true %}`
        // and `{% endif %}` is stripped, leaving the natural
        // continuation of the body. Without trim_blocks, we'd see two
        // extra blank lines in the output.
        assert_eq!(out, "before\ninside\nafter\n");
    }

    /// Regression: when `prepare_jinja_source` engages the slow path
    /// (anything containing `.<digit>`), non-ASCII bytes in the source
    /// must NOT be re-encoded. The buggy version did `out.push(b as
    /// char)` per source byte, which interprets each byte as a Unicode
    /// codepoint and re-encodes as UTF-8 — corrupting every em-dash,
    /// every accented character, every emoji.
    ///
    /// Caught in the acme drill: vmagent's scrape.yml.j2 had
    /// `version: 1.0`-style sequences (engaging the slow path) and an
    /// em-dash in a comment. The em-dash (`e2 80 94`) arrived on the
    /// agent as `c3 a2 c2 80 c2 94`, causing `vmagent -dryRun` to
    /// reject the staged file with "yaml: control characters are not
    /// allowed". A round-trip test confined to ASCII would have missed
    /// it — the test must include both a multi-byte UTF-8 character
    /// AND a `.<digit>` to trigger the slow path.
    #[test]
    fn prepare_jinja_source_preserves_non_ascii_in_slow_path() {
        // `1.0` engages the slow path; em-dash `—` (U+2014, e2 80 94)
        // is the canary. If the bug regresses, the dash bytes get
        // doubled to `c3 a2 c2 80 c2 94`.
        let src = "# vmagent scrape — version 1.0";
        let out = prepare_jinja_source(src);
        assert_eq!(
            out.as_bytes(),
            src.as_bytes(),
            "slow path must preserve non-ASCII bytes verbatim; \
             got {:x?}, expected {:x?}",
            out.as_bytes(),
            src.as_bytes()
        );
    }

    /// Regression: a template body containing non-ASCII UTF-8 (em-dash,
    /// U+2014, bytes `e2 80 94`) must round-trip verbatim through
    /// minijinja's render path. Caught in the acme drill — vmagent
    /// scrape.yml.j2 has em-dash in a comment, and the rendered output
    /// was arriving on the agent as `c3 a2 c2 80 c2 94` (Latin-1-as-
    /// UTF-8 double encoding), making `vmagent -dryRun` reject it with
    /// "yaml: control characters are not allowed".
    #[test]
    fn render_preserves_non_ascii_utf8_bytes() {
        let env = make_env();
        let src = "vmagent scrape config — Prometheus format";
        let tmpl = env.template_from_str(src).unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(
            out.as_bytes(),
            src.as_bytes(),
            "minijinja must round-trip em-dash bytes verbatim; got {:x?}",
            out.as_bytes()
        );
    }

    /// Regression: minijinja rejects Ansible-flavored attribute-style
    /// numeric subscripts (`item.0.name`) as "unexpected float";
    /// `prepare_jinja_source` rewrites them to bracket form so the
    /// real-world Ansible idiom keeps working.
    #[test]
    fn prepare_jinja_source_rewrites_attr_numeric_subscript() {
        let out = prepare_jinja_source("{{ item.0.name }}");
        assert_eq!(out, "{{ item[0].name }}");
        // Chained subscripts.
        let out = prepare_jinja_source("{{ a.0.1.b }}");
        assert_eq!(out, "{{ a[0][1].b }}");
        // After `]` (subscript chain).
        let out = prepare_jinja_source("{{ a[0].1 }}");
        assert_eq!(out, "{{ a[0][1] }}");
    }

    /// String literals inside Jinja blocks must NOT be rewritten —
    /// the rewrite is identifier-attribute syntax only.
    #[test]
    fn prepare_jinja_source_leaves_string_literals_alone() {
        let out = prepare_jinja_source(r#"{{ "1.0.0" }}"#);
        assert_eq!(out, r#"{{ "1.0.0" }}"#);
        let out = prepare_jinja_source(r#"{{ 'v.0.beta' }}"#);
        assert_eq!(out, r#"{{ 'v.0.beta' }}"#);
        // Even when mixed in the same expression.
        let out = prepare_jinja_source(r#"{{ item.0 + "x.0" }}"#);
        assert_eq!(out, r#"{{ item[0] + "x.0" }}"#);
    }

    /// Plain text outside Jinja blocks must pass through verbatim
    /// (the rewrite only applies inside `{{ ... }}` / `{% ... %}`).
    #[test]
    fn prepare_jinja_source_leaves_plain_text_alone() {
        let out = prepare_jinja_source("version 1.0.0\nitem.0 not jinja");
        assert_eq!(out, "version 1.0.0\nitem.0 not jinja");
    }

    /// End-to-end through minijinja: a template that uses the
    /// Ansible-style indexing must render once we run it through the
    /// preprocessor.
    #[test]
    fn prepare_jinja_source_enables_ansible_subscript_through_minijinja() {
        let env = make_env();
        let prepared = prepare_jinja_source("{{ item.0.name }}");
        let tmpl = env
            .template_from_str(&prepared)
            .expect("template compile must succeed after preprocessing");
        let out = tmpl
            .render(context! { item => vec![
                context! { name => "alice" },
            ] })
            .unwrap();
        assert_eq!(out, "alice");
    }

    /// Regression: acme's `patroni.yml.j2` uses
    /// `{% include "patroni-common.yml.j2" %}` to factor out shared
    /// chunks. Resolution must walk a per-task `search_dirs` list
    /// (role's `templates/` first, then playbook-level fallbacks).
    /// Without `multi_template` and `install_include_loader` wired in,
    /// minijinja rejects `include` as an unknown statement.
    #[test]
    fn install_include_loader_resolves_against_search_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let templates_dir = tmp.path().join("templates");
        std::fs::create_dir(&templates_dir).unwrap();
        std::fs::write(
            templates_dir.join("greeting.j2"),
            "hello {{ name }}",
        )
        .unwrap();

        let mut env: Environment<'static> = make_env();
        install_include_loader(&mut env, vec![templates_dir.clone()]);
        let tmpl = env
            .template_from_str(r#"{% include "greeting.j2" %}!"#)
            .expect("outer template compiles");
        let out = tmpl.render(context! { name => "world" }).unwrap();
        assert_eq!(out, "hello world!");
    }

    /// Loader must reject path-traversal segments and absolute paths
    /// in the include target — same defense minijinja's own
    /// path_loader uses.
    #[test]
    fn install_include_loader_rejects_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let templates_dir = tmp.path().join("templates");
        std::fs::create_dir(&templates_dir).unwrap();
        std::fs::write(templates_dir.join("ok.j2"), "ok").unwrap();

        let mut env: Environment<'static> = make_env();
        install_include_loader(&mut env, vec![templates_dir.clone()]);

        for bad in [r#"{% include "../etc/passwd" %}"#, r#"{% include "/etc/passwd" %}"#] {
            let tmpl = env.template_from_str(bad).unwrap();
            let err = tmpl.render(context! {}).unwrap_err();
            assert!(
                format!("{err}").contains("not found"),
                "expected template-not-found for {bad:?}, got {err}",
            );
        }
    }

    /// Loader probes the dirs in order: an earlier dir wins over a
    /// later one. Matches the role-then-playbook-fallback ordering
    /// in `template_search_base_dirs`.
    #[test]
    fn install_include_loader_probes_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("a");
        let second = tmp.path().join("b");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        std::fs::write(first.join("shared.j2"), "FIRST").unwrap();
        std::fs::write(second.join("shared.j2"), "SECOND").unwrap();

        let mut env: Environment<'static> = make_env();
        install_include_loader(&mut env, vec![first, second]);
        let tmpl = env
            .template_from_str(r#"{% include "shared.j2" %}"#)
            .unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(out, "FIRST");
    }

    #[test]
    fn mandatory_filter_passes_defined() {
        let env = make_env();
        let tmpl = env.template_from_str("{{ x | mandatory }}").unwrap();
        let out = tmpl.render(context! { x => "yes" }).unwrap();
        assert_eq!(out, "yes");
    }

    #[test]
    fn mandatory_filter_errors_on_undefined() {
        let env = make_env();
        let tmpl = env.template_from_str("{{ x | mandatory }}").unwrap();
        let err = tmpl.render(context! {}).unwrap_err();
        assert!(format!("{err}").contains("mandatory"));
    }

    #[test]
    fn subelements_filter_basic() {
        let env = make_env();
        let tmpl = env
            .template_from_str(
                "{% for u, k in users | subelements('keys') %}{{ u.name }}:{{ k }};{% endfor %}",
            )
            .unwrap();
        let users = serde_json::json!([
            {"name": "alice", "keys": ["a1", "a2"]},
            {"name": "bob", "keys": ["b1"]}
        ]);
        let out = tmpl.render(context! { users => users }).unwrap();
        assert_eq!(out, "alice:a1;alice:a2;bob:b1;");
    }

    #[test]
    fn extract_filter_dict_key() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ "alice" | extract(users) }}"#)
            .unwrap();
        let users = serde_json::json!({"alice": "a@example", "bob": "b@example"});
        let out = tmpl.render(context! { users => users }).unwrap();
        assert_eq!(out, "a@example");
    }

    #[test]
    fn extract_filter_nested_via_morekeys_string() {
        let env = make_env();
        let tmpl = env
            .template_from_str(
                r#"{{ "alice" | extract(hostvars, "ansible_host") }}"#,
            )
            .unwrap();
        let hostvars = serde_json::json!({
            "alice": {"ansible_host": "10.0.0.1"},
            "bob":   {"ansible_host": "10.0.0.2"},
        });
        let out = tmpl.render(context! { hostvars => hostvars }).unwrap();
        assert_eq!(out, "10.0.0.1");
    }

    #[test]
    fn extract_filter_morekeys_list_path() {
        let env = make_env();
        let tmpl = env
            .template_from_str(
                r#"{{ "alice" | extract(hostvars, ["nested", "deep"]) }}"#,
            )
            .unwrap();
        let hostvars = serde_json::json!({
            "alice": {"nested": {"deep": "found"}}
        });
        let out = tmpl.render(context! { hostvars => hostvars }).unwrap();
        assert_eq!(out, "found");
    }

    #[test]
    fn extract_filter_seq_index() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ 1 | extract(xs) }}"#)
            .unwrap();
        let xs = serde_json::json!(["a", "b", "c"]);
        let out = tmpl.render(context! { xs => xs }).unwrap();
        assert_eq!(out, "b");
    }

    #[test]
    fn extract_filter_in_map_over_group() {
        // The canonical Ansible idiom this filter exists to support.
        let env = make_env();
        let tmpl = env
            .template_from_str(
                "{{ groups.web | map('extract', hostvars, 'ansible_host') | join(',') }}",
            )
            .unwrap();
        let groups = serde_json::json!({"web": ["alice", "bob"]});
        let hostvars = serde_json::json!({
            "alice": {"ansible_host": "10.0.0.1"},
            "bob":   {"ansible_host": "10.0.0.2"},
        });
        let out = tmpl
            .render(context! { groups => groups, hostvars => hostvars })
            .unwrap();
        assert_eq!(out, "10.0.0.1,10.0.0.2");
    }

    #[test]
    fn extract_filter_missing_key_renders_undefined_lenient() {
        // Lenient undefined → empty rendered output, no error.
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"[{{ "missing" | extract(users) }}]"#)
            .unwrap();
        let users = serde_json::json!({"alice": "a@example"});
        let out = tmpl.render(context! { users => users }).unwrap();
        assert_eq!(out, "[]");
    }

    // ---------- controller_* I/O + lookup compat shim ----------

    #[test]
    fn controller_read_file_reads_utf8_contents() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("greeting.txt");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"hello, world\n")
            .unwrap();
        let env = make_env();
        let src = format!(
            r#"{{{{ controller_read_file({:?}) }}}}"#,
            path.to_str().unwrap()
        );
        let tmpl = env.template_from_str(&src).unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(out, "hello, world\n");
    }

    #[test]
    fn controller_read_file_errors_loudly_on_missing() {
        let env = make_env();
        let tmpl = env
            .template_from_str(
                r#"{{ controller_read_file("/definitely/does/not/exist/zzz") }}"#,
            )
            .unwrap();
        let err = tmpl.render(context! {}).unwrap_err().to_string();
        assert!(
            err.contains("controller_read_file") && err.contains("/definitely/does/not/exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn controller_shell_stdout_captures_and_trims() {
        let env = make_env();
        // printf 'foo\n\n' → trailing newlines trimmed.
        let tmpl = env
            .template_from_str(r#"[{{ controller_shell_stdout("printf 'foo\n\n'") }}]"#)
            .unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(out, "[foo]");
    }

    #[test]
    fn controller_shell_stdout_surfaces_nonzero_exit() {
        let env = make_env();
        let tmpl = env
            .template_from_str(
                r#"{{ controller_shell_stdout("echo nope 1>&2; exit 7") }}"#,
            )
            .unwrap();
        let err = tmpl.render(context! {}).unwrap_err().to_string();
        assert!(
            err.contains("exit") && err.contains("nope"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn controller_env_reads_unset_as_empty() {
        // Pick a name nothing else in this process should have set.
        let env = make_env();
        let tmpl = env
            .template_from_str(
                r#"[{{ controller_env("RSANSIBLE_TEST_DEFINITELY_UNSET_XYZ") }}]"#,
            )
            .unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn controller_env_reads_set_value() {
        // SAFETY: this test mutates process env. Use a name unique
        // enough not to clash with other tests running in the same
        // process under cargo's test harness.
        std::env::set_var("RSANSIBLE_TEST_CONTROLLER_ENV_SET", "yes-it-is");
        let env = make_env();
        let tmpl = env
            .template_from_str(
                r#"{{ controller_env("RSANSIBLE_TEST_CONTROLLER_ENV_SET") }}"#,
            )
            .unwrap();
        let out = tmpl.render(context! {}).unwrap();
        std::env::remove_var("RSANSIBLE_TEST_CONTROLLER_ENV_SET");
        assert_eq!(out, "yes-it-is");
    }

    #[test]
    fn lookup_file_shim_forwards_to_controller_read_file() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("note.txt");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"shim works")
            .unwrap();
        let env = make_env();
        let src = format!(r#"{{{{ lookup("file", {:?}) }}}}"#, path.to_str().unwrap());
        let tmpl = env.template_from_str(&src).unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(out, "shim works");
    }

    #[test]
    fn lookup_pipe_shim_forwards_to_controller_shell_stdout() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ lookup("pipe", "printf hello") }}"#)
            .unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(out, "hello");
    }

    #[test]
    fn lookup_env_shim_forwards_to_controller_env() {
        std::env::set_var("RSANSIBLE_TEST_LOOKUP_ENV_SHIM", "via-lookup");
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ lookup("env", "RSANSIBLE_TEST_LOOKUP_ENV_SHIM") }}"#)
            .unwrap();
        let out = tmpl.render(context! {}).unwrap();
        std::env::remove_var("RSANSIBLE_TEST_LOOKUP_ENV_SHIM");
        assert_eq!(out, "via-lookup");
    }

    #[test]
    fn lookup_unknown_plugin_errors_with_supported_list() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ lookup("vault", "secret/whatever") }}"#)
            .unwrap();
        let err = tmpl.render(context! {}).unwrap_err().to_string();
        assert!(
            err.contains("vault") && err.contains("supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn lookup_missing_arg_errors_with_field_name() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ lookup("file") }}"#)
            .unwrap();
        let err = tmpl.render(context! {}).unwrap_err().to_string();
        assert!(
            err.contains("path") && err.contains("missing"),
            "unexpected error: {err}"
        );
    }

    // ---------- per-run lookup cache ----------

    #[test]
    fn controller_shell_stdout_does_not_cache() {
        // Shell commands may be intentionally non-deterministic
        // (`uuidgen`, `date +%s%N`, etc.). Caching would silently
        // break those use cases — and diverge from Ansible's
        // `lookup('pipe', ...)` default. This test pins the no-cache
        // contract: a counter-incrementing command must produce
        // different outputs across calls in the same render.
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("counter");
        std::fs::write(&counter, b"").unwrap();
        let cmd = format!(
            r#"sh -c 'echo x >> {p}; wc -l < {p} | tr -d " "'"#,
            p = counter.to_str().unwrap()
        );
        let env = make_env();
        let src = format!(
            "{{{{ controller_shell_stdout({cmd:?}) }}}}-\
             {{{{ controller_shell_stdout({cmd:?}) }}}}-\
             {{{{ controller_shell_stdout({cmd:?}) }}}}",
            cmd = cmd
        );
        let tmpl = env.template_from_str(&src).unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(
            out, "1-2-3",
            "shell_stdout MUST NOT cache; each call must re-run"
        );
        let lines = std::fs::read_to_string(&counter).unwrap();
        assert_eq!(lines.lines().count(), 3);
    }

    #[test]
    fn controller_read_file_caches_after_mutation() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mut.txt");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"first")
            .unwrap();
        let env = make_env();
        let path_s = path.to_str().unwrap();
        let src = format!(
            r#"{{{{ controller_read_file({path:?}) }}}}/{{{{ controller_read_file({path:?}) }}}}"#,
            path = path_s
        );
        let tmpl = env.template_from_str(&src).unwrap();
        // Read once, mutate, read again. The cached value wins.
        let _ = tmpl.render(context! {}).unwrap(); // populate cache
        std::fs::write(&path, b"second").unwrap();
        let out = tmpl.render(context! {}).unwrap();
        assert_eq!(out, "first/first", "expected cached value");
    }

    #[test]
    fn lookup_file_shares_cache_with_canonical_read_file() {
        // `lookup("file", path)` and `controller_read_file(path)`
        // should hit the same cache slot — same logical operation,
        // different spelling. We verify by reading once via the
        // canonical, mutating the file, then reading via the shim:
        // the shim should see the cached (original) content.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.txt");
        std::fs::write(&path, b"original").unwrap();
        let path_s = path.to_str().unwrap();
        let env = make_env();
        // Populate the cache through the canonical.
        let _: String = env
            .template_from_str(&format!(r#"{{{{ controller_read_file({path_s:?}) }}}}"#))
            .unwrap()
            .render(context! {})
            .unwrap();
        // Mutate underneath.
        std::fs::write(&path, b"mutated").unwrap();
        // The shim should return the cached original, not the mutated value.
        let out = env
            .template_from_str(&format!(r#"{{{{ lookup("file", {path_s:?}) }}}}"#))
            .unwrap()
            .render(context! {})
            .unwrap();
        assert_eq!(out, "original", "shim should hit the canonical's cache");
    }

    #[test]
    fn lookup_cache_separate_per_make_env() {
        // Each make_env() builds a fresh cache for the cached
        // canonicals. Two independent Envs reading the same file
        // should each see the current contents at *their* first read.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vary.txt");
        let path_s = path.to_str().unwrap().to_string();

        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"first-run")
            .unwrap();
        let env_a = make_env();
        let out_a = env_a
            .template_from_str(&format!(r#"{{{{ controller_read_file({path_s:?}) }}}}"#))
            .unwrap()
            .render(context! {})
            .unwrap();

        std::fs::write(&path, b"second-run").unwrap();
        let env_b = make_env();
        let out_b = env_b
            .template_from_str(&format!(r#"{{{{ controller_read_file({path_s:?}) }}}}"#))
            .unwrap()
            .render(context! {})
            .unwrap();

        assert_eq!(out_a, "first-run");
        assert_eq!(
            out_b, "second-run",
            "second env should NOT see the first env's cache"
        );
    }

    #[test]
    fn b64encode_round_trip_through_b64decode() {
        let env = make_env();
        let tmpl = env
            .template_from_str("{{ s | b64encode | b64decode }}")
            .unwrap();
        let out = tmpl
            .render(context! { s => "hello world" })
            .unwrap();
        assert_eq!(out, "hello world");
    }

    #[test]
    fn b64encode_known_value() {
        let env = make_env();
        let tmpl = env.template_from_str("{{ s | b64encode }}").unwrap();
        let out = tmpl.render(context! { s => "rsansible" }).unwrap();
        // base64(rsansible) = cnNhbnNpYmxl
        assert_eq!(out, "cnNhbnNpYmxl");
    }

    #[test]
    fn b64decode_rejects_garbage() {
        let env = make_env();
        let tmpl = env.template_from_str("{{ s | b64decode }}").unwrap();
        let err = tmpl
            .render(context! { s => "not-actually-base64!" })
            .unwrap_err();
        assert!(format!("{err}").contains("b64decode"), "got: {err}");
    }

    #[test]
    fn from_json_returns_structured_value() {
        let env = make_env();
        let tmpl = env
            .template_from_str("{{ (s | from_json).a }}-{{ (s | from_json).b }}")
            .unwrap();
        let out = tmpl
            .render(context! { s => r#"{"a": "x", "b": 42}"# })
            .unwrap();
        assert_eq!(out, "x-42");
    }

    #[test]
    fn from_json_propagates_parse_errors() {
        let env = make_env();
        let tmpl = env
            .template_from_str("{{ s | from_json }}")
            .unwrap();
        let err = tmpl
            .render(context! { s => "not json" })
            .unwrap_err();
        assert!(format!("{err}").contains("from_json"), "got: {err}");
    }

    #[test]
    fn to_json_compact_output() {
        let env = make_env();
        let tmpl = env.template_from_str("{{ v | to_json }}").unwrap();
        let v = serde_json::json!({"a": 1, "b": [true, null]});
        let out = tmpl.render(context! { v => v }).unwrap();
        // serde_json's default key ordering is whatever the input has;
        // since we feed an ordered JSON literal, "a" comes first.
        assert_eq!(out, r#"{"a":1,"b":[true,null]}"#);
    }

    #[test]
    fn to_json_roundtrips_through_from_json() {
        let env = make_env();
        let tmpl = env
            .template_from_str("{{ (v | to_json | from_json).a }}")
            .unwrap();
        let v = serde_json::json!({"a": "round"});
        let out = tmpl.render(context! { v => v }).unwrap();
        assert_eq!(out, "round");
    }

    #[test]
    fn pycompat_string_methods_available() {
        // Smoke-test that the most common Python string methods Ansible
        // playbooks reach for are recognized as Jinja methods. The
        // long-tail catalog lives in `minijinja-contrib`; we just verify
        // the callback is wired and the most-used ones round-trip.
        let env = make_env();
        let cases = [
            (r#"{{ s.strip() }}"#, "  hello  ", "hello"),
            (r#"{{ s.lower() }}"#, "HELLO", "hello"),
            (r#"{{ s.upper() }}"#, "hello", "HELLO"),
            (r#"{{ s.startswith('he') }}"#, "hello", "true"),
            (r#"{{ s.endswith('lo') }}"#, "hello", "true"),
            (r#"{{ s.replace('l', 'L') }}"#, "hello", "heLLo"),
            (r#"{{ s.split(',') | length }}"#, "a,b,c", "3"),
        ];
        for (tpl, input, expected) in cases {
            let t = env.template_from_str(tpl).unwrap();
            let got = t.render(context! { s => input }).unwrap();
            assert_eq!(got, expected, "template={tpl} input={input:?}");
        }
    }

    #[test]
    fn pycompat_until_expression_compiles() {
        // The exact `until:` shape that surfaced this gap in acme's
        // drill-restore.yml: `drill_state.stdout.strip() != 'activating'`.
        // We compile-and-eval as an expression here because that's how
        // the orchestrator evaluates `until:` (see `eval_when`).
        let env = make_env();
        let expr = env
            .compile_expression("drill_state.stdout.strip() != 'activating'")
            .unwrap();
        let view = context! {
            drill_state => context! { stdout => "  inactive\n" }
        };
        assert!(expr.eval(view).unwrap().is_true());
        let view = context! {
            drill_state => context! { stdout => "activating" }
        };
        assert!(!expr.eval(view).unwrap().is_true());
    }

    #[test]
    fn regex_replace_basic_substitution() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ s | regex_replace('foo', 'bar') }}"#)
            .unwrap();
        let out = tmpl.render(context! { s => "foo and foo" }).unwrap();
        assert_eq!(out, "bar and bar");
    }

    #[test]
    fn regex_replace_with_capture_group_backref() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ s | regex_replace('(\d+)-(\d+)', '$2/$1') }}"#)
            .unwrap();
        let out = tmpl.render(context! { s => "12-34" }).unwrap();
        assert_eq!(out, "34/12");
    }

    #[test]
    fn regex_replace_invalid_pattern_errors() {
        let env = make_env();
        let tmpl = env
            .template_from_str(r#"{{ s | regex_replace('[unclosed', 'x') }}"#)
            .unwrap();
        let err = tmpl.render(context! { s => "anything" }).unwrap_err();
        assert!(format!("{err}").contains("regex_replace"), "got: {err}");
    }

    #[test]
    fn regex_replace_inline_flags_for_case_insensitive() {
        let env = make_env();
        // Ansible's `ignorecase=True` arg isn't supported; in the meantime
        // the inline `(?i)` flag does the same thing.
        let tmpl = env
            .template_from_str(r#"{{ s | regex_replace('(?i)foo', 'bar') }}"#)
            .unwrap();
        let out = tmpl.render(context! { s => "FOO Foo foo" }).unwrap();
        assert_eq!(out, "bar bar bar");
    }

    #[test]
    fn precompile_catches_bad_when_expression() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      when: "1 ===== 2"
      shell: echo
"#,
        )
        .unwrap();
        let err = precompile_all(&pb).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("when"), "got: {msg}");
    }

    #[test]
    fn precompile_catches_bad_template_in_shell() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      shell: "echo {{ unclosed"
"#,
        )
        .unwrap();
        let err = precompile_all(&pb).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("shell"), "got: {msg}");
    }

    #[test]
    fn precompile_catches_bad_template_body() {
        // `template:` deserializes with body=None (the body is normally
        // populated by the loader after locating the .j2 file). For
        // this test we inject a bad body by hand.
        let mut pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      template:
        src: foo.j2
        dest: /tmp/out
"#,
        )
        .unwrap();
        // Reach into the parsed structure and stash a malformed Jinja
        // template body. `precompile_all` should surface it with the
        // src in the error message.
        if let TaskBody::Op(TaskOp::Template(t)) =
            &mut pb.plays[0].tasks[0].body
        {
            t.body = Some("hi {{ unclosed".into());
        } else {
            panic!("expected TaskOp::Template");
        }
        let err = precompile_all(&pb).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("foo.j2"), "got: {msg}");
    }

    #[test]
    fn precompile_accepts_clean_template_body() {
        let mut pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      template:
        src: foo.j2
        dest: /tmp/out
"#,
        )
        .unwrap();
        if let TaskBody::Op(TaskOp::Template(t)) =
            &mut pb.plays[0].tasks[0].body
        {
            t.body = Some("hi {{ name | default('world') }}\n".into());
        } else {
            panic!("expected TaskOp::Template");
        }
        precompile_all(&pb).unwrap();
    }

    /// Regression for the acme valkey verify task that did
    /// `{{ lines | select('match', '^role:') | list | first | default(...) }}`:
    /// minijinja shipped without `match`/`search`/`regex` tests, so the
    /// `select('match', ...)` call raised "unknown test" at render
    /// time and the debug task failed across all valkey nodes. Pin
    /// the test registrations.
    /// Regression for the acme pgbackrest.conf template that did
    /// `groups['pgbackrest'] | difference([inventory_hostname]) | first`
    /// to pick the peer node. minijinja shipped without `difference`
    /// (or `intersect`/`union`/`symmetric_difference`/`unique`/`flatten`).
    /// Pin the registrations.
    /// Regression for the acme pgbackrest-restore-drill task
    /// `when: pgbackrest_drill_dockerfile is changed`: minijinja
    /// shipped without `is changed` / `is failed` / `is succeeded` /
    /// `is skipped` register tests. The when: render hit
    /// "unknown test: test changed is unknown" and stopped the play.
    #[test]
    fn register_tests_read_register_attributes() {
        let env = make_env();
        let ctx = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([
            ("r_changed".into(), serde_json::json!({"changed": true, "failed": false, "skipped": false, "rc": 0})),
            ("r_failed".into(), serde_json::json!({"changed": false, "failed": true, "rc": 1})),
            ("r_skipped".into(), serde_json::json!({"changed": false, "failed": false, "skipped": true})),
            ("r_clean".into(), serde_json::json!({"changed": false, "failed": false, "skipped": false, "rc": 0})),
        ]);
        for (expr, expected, why) in [
            ("r_changed is changed", "y", "changed register"),
            ("r_clean is changed", "n", "unchanged register"),
            ("r_failed is failed", "y", "failed register"),
            ("r_clean is failed", "n", "ok register"),
            ("r_clean is succeeded", "y", "ok register"),
            ("r_failed is succeeded", "n", "failed register"),
            ("r_skipped is succeeded", "n", "skipped is not succeeded"),
            ("r_skipped is skipped", "y", "skipped register"),
            ("r_clean is skipped", "n", "non-skipped register"),
            // Undefined → false for all three (Ansible's laxness):
            ("nope is changed", "n", "undefined → not changed"),
            ("nope is failed", "n", "undefined → not failed"),
            ("nope is succeeded", "n", "undefined → not succeeded"),
        ] {
            let src = format!("{{{{ 'y' if {expr} else 'n' }}}}");
            let out = env.render_str(&src, &ctx).unwrap_or_else(|e| {
                panic!("{why}: render failed: {e}; expr={expr}")
            });
            assert_eq!(out, expected, "{why}: expr={expr}");
        }
    }

    #[test]
    fn difference_filter_excludes_elements_present_in_other() {
        let env = make_env();
        let ctx = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([
            ("hosts".into(), serde_json::json!(["db-1", "db-2"])),
            ("me".into(), serde_json::json!("db-1")),
        ]);
        let out = env
            .render_str(
                "{{ hosts | difference([me]) | first }}",
                &ctx,
            )
            .unwrap();
        assert_eq!(out, "db-2");
    }

    #[test]
    fn intersect_filter_keeps_common_elements_in_first_order() {
        let env = make_env();
        let ctx = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([
            ("a".into(), serde_json::json!([1, 2, 3, 4])),
            ("b".into(), serde_json::json!([3, 2, 5])),
        ]);
        let out = env
            .render_str("{{ a | intersect(b) | join(',') }}", &ctx)
            .unwrap();
        assert_eq!(out, "2,3");
    }

    #[test]
    fn union_filter_dedupes_across_inputs() {
        let env = make_env();
        let ctx = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([
            ("a".into(), serde_json::json!([1, 2, 3])),
            ("b".into(), serde_json::json!([3, 4, 5])),
        ]);
        let out = env
            .render_str("{{ a | union(b) | join(',') }}", &ctx)
            .unwrap();
        assert_eq!(out, "1,2,3,4,5");
    }

    #[test]
    fn unique_filter_dedupes_preserving_order() {
        let env = make_env();
        let ctx = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([(
            "xs".into(),
            serde_json::json!([3, 1, 2, 1, 3, 4]),
        )]);
        let out = env.render_str("{{ xs | unique | join(',') }}", &ctx).unwrap();
        assert_eq!(out, "3,1,2,4");
    }

    #[test]
    fn regex_match_test_anchors_at_start() {
        let env = make_env();
        let ctx = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([(
            "lines".to_string(),
            serde_json::json!(["role:master", "loading:0", "connected_slaves:1"]),
        )]);
        let out = env
            .render_str(
                "{{ lines | select('match', '^role:') | list | first }}",
                &ctx,
            )
            .expect("select('match', ...) must render");
        assert_eq!(out, "role:master");

        // Anchored at start — `master_role` (substring "role" not at
        // position 0) must not match.
        let ctx2 = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([(
            "s".to_string(),
            serde_json::json!("master_role:1"),
        )]);
        let out = env
            .render_str(
                "{{ 'yes' if s is match('role:') else 'no' }}",
                &ctx2,
            )
            .unwrap();
        assert_eq!(out, "no", "match must anchor at start of string");
    }

    #[test]
    fn regex_search_test_finds_anywhere() {
        let env = make_env();
        let ctx = std::collections::BTreeMap::<String, serde_json::Value>::from_iter([(
            "s".to_string(),
            serde_json::json!("master_role:1"),
        )]);
        // `search` matches anywhere, `regex` is the alias.
        let out = env
            .render_str(
                "{{ 'yes' if s is search('role:') else 'no' }}",
                &ctx,
            )
            .unwrap();
        assert_eq!(out, "yes");
        let out = env
            .render_str(
                "{{ 'yes' if s is regex('role:') else 'no' }}",
                &ctx,
            )
            .unwrap();
        assert_eq!(out, "yes");
    }

    #[test]
    fn precompile_accepts_clean_playbook() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: greet
      register: r
      shell: "echo {{ inventory_hostname }}"
    - name: gated
      when: "r.rc == 0"
      shell: "echo ok"
"#,
        )
        .unwrap();
        precompile_all(&pb).unwrap();
    }
}
