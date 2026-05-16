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

use anyhow::{anyhow, Result};
use minijinja::{Environment, Error as MjError, ErrorKind as MjKind, Value as MjValue};

use crate::playbook::{
    AssertTask, ExecOp, LoopSpec, Playbook, ShellOp, Task, TaskBody, TaskOp, WriteFileOp,
};

/// Build a fresh minijinja `Environment` configured for our use.
pub fn make_env<'a>() -> Environment<'a> {
    let mut env = Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    // Preserve trailing newlines in rendered output — write_file.content
    // sources frequently end in `\n` and we don't want minijinja stripping
    // them silently. Matches Ansible's behavior.
    env.set_keep_trailing_newline(true);
    env.add_filter("mandatory", mandatory_filter);
    env.add_filter("subelements", subelements_filter);
    // Ansible-style filters; gothab uses these in role templates.
    env.add_filter("b64encode", b64encode_filter);
    env.add_filter("b64decode", b64decode_filter);
    env.add_filter("from_json", from_json_filter);
    // Ansible spells the JSON encoder `to_json`; minijinja calls its
    // built-in `tojson`. Register both — the built-in is already there
    // under `tojson`, this adds the Ansible alias.
    env.add_filter("to_json", to_json_filter);
    env.add_filter("regex_replace", regex_replace_filter);
    env
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

/// `value | b64encode` — base64-encode a string. Ansible accepts strings
/// only (its docs note "for binary use the `base64` shell filter"); we
/// match that. Bytes-by-bytes round-trip with `b64decode`.
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
/// raw bytes, gothab pipes through `copy:` with a pre-encoded file).
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
/// accept an `indent` arg (the built-in `tojson` does); gothab doesn't
/// use it. Add if needed.
fn to_json_filter(value: MjValue) -> Result<MjValue, MjError> {
    let s = serde_json::to_string(&value).map_err(|e| {
        MjError::new(MjKind::InvalidOperation, format!("to_json: {e}"))
    })?;
    Ok(MjValue::from(s))
}

/// `value | regex_replace(pattern, replacement)` — `regex::Regex::replace_all`
/// applied to a string. Pattern is Rust regex syntax (close to PCRE for
/// the cases gothab uses); replacement supports `$1` / `${name}`
/// backrefs.
///
/// Ansible's filter also accepts an optional `multiline` / `ignorecase`
/// flag; we don't yet (gothab doesn't use them). Easy to add via the
/// `(?i)` / `(?m)` inline flags in the meantime.
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
        env.compile_expression(expr)
            .map_err(|e| anyhow!("when: {e}"))?;
    }
    if let Some(LoopSpec::Expr(s)) = &task.loop_spec {
        // Treat the loop expression as a template — they're sometimes
        // bare `{{ var }}` and sometimes more complex `{{ a + b }}`.
        env.template_from_str(s).map_err(|e| anyhow!("loop: {e}"))?;
    }
    if let Some(d) = &task.delegate_to {
        env.template_from_str(d)
            .map_err(|e| anyhow!("delegate_to: {e}"))?;
    }
    for (i, n) in task.notify.iter().enumerate() {
        env.template_from_str(n)
            .map_err(|e| anyhow!("notify[{i}]: {e}"))?;
    }
    match &task.body {
        TaskBody::Op(op) => check_op(env, op)?,
        TaskBody::Assert(a) => check_assert(env, a)?,
        TaskBody::Fail(f) => {
            env.template_from_str(&f.msg)
                .map_err(|e| anyhow!("fail.msg: {e}"))?;
        }
        TaskBody::Debug(d) => {
            if let Some(s) = &d.msg {
                env.template_from_str(s)
                    .map_err(|e| anyhow!("debug.msg: {e}"))?;
            }
            if let Some(s) = &d.var {
                env.template_from_str(s)
                    .map_err(|e| anyhow!("debug.var: {e}"))?;
            }
        }
        TaskBody::SetFact(m) => {
            for (k, v) in &m.0 {
                if let serde_yaml::Value::String(s) = v {
                    env.template_from_str(s)
                        .map_err(|e| anyhow!("set_fact.{k}: {e}"))?;
                }
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
                    env.template_from_str(s)
                        .map_err(|e| anyhow!("include_role.vars.{k}: {e}"))?;
                }
            }
        }
        TaskBody::Meta(_) => {
            // `meta: flush_handlers` has no body fields to compile.
        }
    }
    Ok(())
}

fn check_op(env: &Environment, op: &TaskOp) -> Result<()> {
    match op {
        TaskOp::Shell(ShellOp::Simple(s)) => {
            env.template_from_str(s)
                .map_err(|e| anyhow!("shell: {e}"))?;
        }
        TaskOp::Shell(ShellOp::Detailed { command, .. }) => {
            env.template_from_str(command)
                .map_err(|e| anyhow!("shell.command: {e}"))?;
        }
        TaskOp::Exec(ExecOp {
            argv, env: e_env, cwd, stdin, ..
        }) => {
            for (i, a) in argv.iter().enumerate() {
                env.template_from_str(a)
                    .map_err(|e| anyhow!("exec.argv[{i}]: {e}"))?;
            }
            for (k, v) in e_env {
                env.template_from_str(v)
                    .map_err(|e| anyhow!("exec.env.{k}: {e}"))?;
            }
            if let Some(c) = cwd {
                env.template_from_str(c)
                    .map_err(|e| anyhow!("exec.cwd: {e}"))?;
            }
            env.template_from_str(stdin)
                .map_err(|e| anyhow!("exec.stdin: {e}"))?;
        }
        TaskOp::Command(c) => {
            for (i, a) in c.argv.iter().enumerate() {
                env.template_from_str(a)
                    .map_err(|e| anyhow!("command.argv[{i}]: {e}"))?;
            }
            env.template_from_str(&c.chdir)
                .map_err(|e| anyhow!("command.chdir: {e}"))?;
            env.template_from_str(&c.creates)
                .map_err(|e| anyhow!("command.creates: {e}"))?;
            env.template_from_str(&c.removes)
                .map_err(|e| anyhow!("command.removes: {e}"))?;
            env.template_from_str(&c.stdin)
                .map_err(|e| anyhow!("command.stdin: {e}"))?;
        }
        TaskOp::WriteFile(WriteFileOp { path, content, .. }) => {
            env.template_from_str(path)
                .map_err(|e| anyhow!("write_file.path: {e}"))?;
            env.template_from_str(content)
                .map_err(|e| anyhow!("write_file.content: {e}"))?;
        }
        TaskOp::Template(t) => {
            // `src:` was resolved at load time; `dest:` is Jinja-able
            // at task time, and the loaded `.j2` body itself is also
            // compiled here so a syntax error in the template surfaces
            // at validate-time rather than at first task dispatch.
            env.template_from_str(&t.dest)
                .map_err(|e| anyhow!("template.dest: {e}"))?;
            if let Some(body) = t.body.as_deref() {
                env.template_from_str(body).map_err(|e| {
                    anyhow!("template src {:?}: {e}", t.src)
                })?;
            }
        }
        TaskOp::Copy(c) => {
            // `src:` is resolved at load time; `body` is raw bytes that
            // ship verbatim and need no Jinja compilation. Only `dest:`
            // is templatable.
            env.template_from_str(&c.dest)
                .map_err(|e| anyhow!("copy.dest: {e}"))?;
        }
        TaskOp::GatherFacts => {
            // Implicit op — no user-supplied fields to compile.
        }
        TaskOp::Stat(s) => {
            env.template_from_str(&s.path)
                .map_err(|e| anyhow!("stat.path: {e}"))?;
        }
        TaskOp::File(f) => {
            env.template_from_str(&f.path)
                .map_err(|e| anyhow!("file.path: {e}"))?;
            if let Some(o) = &f.owner {
                env.template_from_str(o)
                    .map_err(|e| anyhow!("file.owner: {e}"))?;
            }
            if let Some(g) = &f.group {
                env.template_from_str(g)
                    .map_err(|e| anyhow!("file.group: {e}"))?;
            }
        }
        TaskOp::WaitFor(w) => {
            if let Some(h) = &w.host {
                env.template_from_str(h)
                    .map_err(|e| anyhow!("wait_for.host: {e}"))?;
            }
            if let Some(p) = &w.path {
                env.template_from_str(p)
                    .map_err(|e| anyhow!("wait_for.path: {e}"))?;
            }
        }
        TaskOp::LineInFile(l) => {
            env.template_from_str(&l.path)
                .map_err(|e| anyhow!("lineinfile.path: {e}"))?;
            env.template_from_str(&l.line)
                .map_err(|e| anyhow!("lineinfile.line: {e}"))?;
            // regexp / insertbefore / insertafter are regex patterns —
            // we don't Jinja-render those (gothab doesn't use Jinja
            // inside regex patterns, and `{{...}}` would be ambiguous
            // with regex syntax). If we ever need it, add it here.
        }
        TaskOp::BlockInFile(b) => {
            env.template_from_str(&b.path)
                .map_err(|e| anyhow!("blockinfile.path: {e}"))?;
            env.template_from_str(&b.block)
                .map_err(|e| anyhow!("blockinfile.block: {e}"))?;
            // marker/marker_begin/marker_end pass through as raw
            // strings; the agent does the literal `{mark}` substitution
            // itself (not Jinja). insertbefore/insertafter are regex
            // patterns — same rationale as lineinfile.
        }
        TaskOp::Systemd(s) => {
            env.template_from_str(&s.name)
                .map_err(|e| anyhow!("systemd.name: {e}"))?;
        }
        TaskOp::Package(p) => {
            let label = p.manager.label();
            for n in &p.names {
                env.template_from_str(n)
                    .map_err(|e| anyhow!("{label}.name: {e}"))?;
            }
            if !p.default_release.is_empty() {
                env.template_from_str(&p.default_release)
                    .map_err(|e| anyhow!("{label}.default_release: {e}"))?;
            }
        }
        TaskOp::Ufw(u) => {
            // Most ufw fields are rendered as raw strings (proto, direction
            // are gated by parse-time allowlists; rule/state are tokens).
            // The fields that *could* carry Jinja are ip/port/comment/iface.
            for (label, val) in [
                ("ufw.from_ip", &u.from_ip),
                ("ufw.from_port", &u.from_port),
                ("ufw.to_ip", &u.to_ip),
                ("ufw.to_port", &u.to_port),
                ("ufw.interface", &u.interface),
                ("ufw.comment", &u.comment),
            ] {
                if !val.is_empty() {
                    env.template_from_str(val)
                        .map_err(|e| anyhow!("{label}: {e}"))?;
                }
            }
        }
        TaskOp::Uri(u) => {
            // url, header values, and body are Jinja-rendered at task
            // time. Header keys are not (header names aren't useful Jinja
            // targets and `:` in a name would be ambiguous anyway).
            env.template_from_str(&u.url)
                .map_err(|e| anyhow!("uri.url: {e}"))?;
            for (k, v) in &u.headers {
                env.template_from_str(v)
                    .map_err(|e| anyhow!("uri.headers.{k}: {e}"))?;
            }
            if !u.body.is_empty() {
                env.template_from_str(&u.body)
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
                    env.template_from_str(val)
                        .map_err(|e| anyhow!("uri.{label}: {e}"))?;
                }
            }
        }
        TaskOp::OpenSslPrivkey(p) => {
            env.template_from_str(&p.path)
                .map_err(|e| anyhow!("openssl_privatekey.path: {e}"))?;
        }
        TaskOp::OpenSslCsrPipe(c) => {
            env.template_from_str(&c.privatekey_path)
                .map_err(|e| anyhow!("openssl_csr_pipe.privatekey_path: {e}"))?;
            env.template_from_str(&c.common_name)
                .map_err(|e| anyhow!("openssl_csr_pipe.common_name: {e}"))?;
            for (i, s) in c.subject_alt_name.iter().enumerate() {
                env.template_from_str(s)
                    .map_err(|e| anyhow!("openssl_csr_pipe.subject_alt_name[{i}]: {e}"))?;
            }
            // key_usage / extended_key_usage are validated against
            // closed enums (parse_key_usage / parse_extended_key_usage);
            // Jinja inside those strings would only confuse the matcher.
        }
        TaskOp::X509CertificatePipe(c) => {
            // csr_content / privatekey_content come from previous-task
            // registers via Jinja in real playbooks.
            env.template_from_str(&c.csr_content)
                .map_err(|e| anyhow!("x509_certificate_pipe.csr_content: {e}"))?;
            env.template_from_str(&c.privatekey_content)
                .map_err(|e| anyhow!("x509_certificate_pipe.privatekey_content: {e}"))?;
        }
        TaskOp::PostgresqlQuery(p) => {
            // query, db, login_user, login_password, login_host all
            // support Jinja (Patroni clusters template hostnames from
            // facts; passwords come from vault). positional_args items
            // are also templatable. Sockets / ports usually aren't but
            // we render anyway for symmetry.
            env.template_from_str(&p.query)
                .map_err(|e| anyhow!("postgresql_query.query: {e}"))?;
            for (label, val) in [
                ("db", &p.db),
                ("login_user", &p.login_user),
                ("login_password", &p.login_password),
                ("login_unix_socket", &p.login_unix_socket),
                ("login_host", &p.login_host),
            ] {
                if !val.is_empty() {
                    env.template_from_str(val)
                        .map_err(|e| anyhow!("postgresql_query.{label}: {e}"))?;
                }
            }
            for (i, a) in p.positional_args.iter().enumerate() {
                env.template_from_str(a)
                    .map_err(|e| anyhow!("postgresql_query.positional_args[{i}]: {e}"))?;
            }
        }
        TaskOp::PostgresqlExt(p) => {
            env.template_from_str(&p.name)
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
                    env.template_from_str(val)
                        .map_err(|e| anyhow!("postgresql_ext.{label}: {e}"))?;
                }
            }
        }
        TaskOp::GetUrl(g) => {
            env.template_from_str(&g.url)
                .map_err(|e| anyhow!("get_url.url: {e}"))?;
            env.template_from_str(&g.dest)
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
                    env.template_from_str(val)
                        .map_err(|e| anyhow!("get_url.{label}: {e}"))?;
                }
            }
            for (k, v) in &g.headers {
                env.template_from_str(v)
                    .map_err(|e| anyhow!("get_url.headers[{k}]: {e}"))?;
            }
        }
        TaskOp::Slurp(s) => {
            env.template_from_str(&s.src)
                .map_err(|e| anyhow!("slurp.src: {e}"))?;
        }
        TaskOp::Unarchive(u) => {
            env.template_from_str(&u.src)
                .map_err(|e| anyhow!("unarchive.src: {e}"))?;
            env.template_from_str(&u.dest)
                .map_err(|e| anyhow!("unarchive.dest: {e}"))?;
            env.template_from_str(&u.creates)
                .map_err(|e| anyhow!("unarchive.creates: {e}"))?;
            env.template_from_str(&u.owner)
                .map_err(|e| anyhow!("unarchive.owner: {e}"))?;
            env.template_from_str(&u.group)
                .map_err(|e| anyhow!("unarchive.group: {e}"))?;
            for (i, p) in u.include.iter().enumerate() {
                env.template_from_str(p)
                    .map_err(|e| anyhow!("unarchive.include[{i}]: {e}"))?;
            }
            for (i, p) in u.exclude.iter().enumerate() {
                env.template_from_str(p)
                    .map_err(|e| anyhow!("unarchive.exclude[{i}]: {e}"))?;
            }
        }
    }
    Ok(())
}

fn check_assert(env: &Environment, a: &AssertTask) -> Result<()> {
    for (i, expr) in a.that.iter().enumerate() {
        env.compile_expression(expr)
            .map_err(|e| anyhow!("assert.that[{i}]: {e}"))?;
    }
    if let Some(msg) = &a.msg {
        env.template_from_str(msg)
            .map_err(|e| anyhow!("assert.msg: {e}"))?;
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
