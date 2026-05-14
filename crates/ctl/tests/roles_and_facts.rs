//! End-to-end Phase 2b test: roles, facts, templates.
//!
//! Three unit-flavored tests (no docker) and one 3-container e2e that
//! exercises `roles:` flattening, role defaults precedence, the
//! `template:` task, and the implicit `Gathering Facts` task.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use rsansible_ctl::{
    inventory::{Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook::{self, TaskBody, TaskOp},
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

#[test]
fn roles_defaults_visible_after_load() -> Result<()> {
    let pb_path = examples_dir().join("roles_and_facts.yaml");
    let pb = playbook::load(&pb_path).context("load")?;
    let play = &pb.plays[0];
    // The role's defaults should have been merged into play.role_defaults.
    let svc = play
        .role_defaults
        .get("service_name")
        .ok_or_else(|| anyhow!("expected service_name default, got {:?}", play.role_defaults))?;
    assert_eq!(svc, &serde_json::json!("rsansible-demo"));
    let port = play
        .role_defaults
        .get("service_port")
        .ok_or_else(|| anyhow!("expected service_port default"))?;
    assert_eq!(port, &serde_json::json!(8080));
    Ok(())
}

#[test]
fn role_tasks_prepended_to_play_tasks() -> Result<()> {
    let pb_path = examples_dir().join("roles_and_facts.yaml");
    let pb = playbook::load(&pb_path).context("load")?;
    let play = &pb.plays[0];
    // The role contributes (after import flattening): a shell task from
    // install.yml + a template task. Then the play's own assert task.
    let names: Vec<&str> = play.tasks.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "simulate package install",
            "ship static asset",
            "render web config",
            "assert facts visible",
            // include_role: expansion: synthetic set_fact + write_file
            // pulled in from roles/web/tasks/extra.yml.
            "set vars for include_role \"web\"",
            "write extra marker",
        ],
        "role tasks should be prepended (in flatten order) before play tasks",
    );
    // The copy task's body should have been resolved from the role's
    // files/ dir.
    let copy_task = &play.tasks[1];
    let TaskBody::Op(TaskOp::Copy(c)) = &copy_task.body else {
        return Err(anyhow!(
            "expected Copy body, got {:?}",
            copy_task.body
        ));
    };
    let body = c.body.as_deref().ok_or_else(|| anyhow!("copy body not loaded"))?;
    assert_eq!(
        std::str::from_utf8(body).unwrap(),
        "rsansible-demo: static asset shipped by copy:\n",
        "copy src should have been read from roles/web/files/static-asset.txt",
    );
    // The template task's body should have been resolved from the role's
    // templates/ dir.
    let render_task = &play.tasks[2];
    let TaskBody::Op(TaskOp::Template(t)) = &render_task.body else {
        return Err(anyhow!(
            "expected Template body, got {:?}",
            render_task.body
        ));
    };
    let body = t
        .body
        .as_deref()
        .ok_or_else(|| anyhow!("template body should be populated at load time"))?;
    assert!(
        body.contains("service={{ service_name }}"),
        "template body missing service= line; got: {body:?}"
    );
    Ok(())
}

#[test]
fn role_handler_is_prepended() -> Result<()> {
    let pb_path = examples_dir().join("roles_and_facts.yaml");
    let pb = playbook::load(&pb_path).context("load")?;
    let play = &pb.plays[0];
    let names: Vec<&str> = play.handlers.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["bump marker"]);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn three_container_roles_and_facts_run() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    // Respect RUST_LOG so callers can flip on the timing target:
    //   RUST_LOG=rsansible::timing=debug cargo test ... -- --ignored --nocapture
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let containers = start_three_containers().await?;
    let inv = build_inventory(&containers);

    let pb_path = examples_dir().join("roles_and_facts.yaml");
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.max_concurrent_hosts = 8;
    let report = orchestrator::run(spec).await.context("orchestrator")?;
    eprintln!("report = {report:#?}");

    assert!(!report.stopped_early, "should have completed end-to-end");
    for (name, outcome) in &report.host_outcomes {
        assert_eq!(
            *outcome,
            HostOutcome::Ok,
            "host {name} should be Ok, got {outcome:?}"
        );
    }
    assert_eq!(report.host_outcomes.len(), 3);

    for (i, c) in containers.iter().enumerate() {
        let host_name = format!("host{}", i + 1);
        // The rendered template (role default substituted).
        let body = read_file(c, "/tmp/rsansible-role-template")?;
        assert!(
            body.starts_with("service=rsansible-demo\nport=8080\n"),
            "{host_name}: template start wrong: {body:?}"
        );
        assert!(
            body.contains("distro="),
            "{host_name}: template missing distro= line: {body:?}"
        );
        assert!(
            body.contains(&format!("host={host_name}")),
            "{host_name}: template host line wrong: {body:?}"
        );
        // The static asset shipped via `copy:` lands verbatim.
        let asset = read_file(c, "/tmp/rsansible-role-static")?;
        assert_eq!(
            asset, "rsansible-demo: static asset shipped by copy:\n",
            "{host_name}: copy: didn't deliver bytes verbatim: {asset:?}"
        );
        // Handler fired at end-of-play because the template changed.
        let fired = read_file(c, "/tmp/rsansible-handler-fired")?;
        assert_eq!(
            fired, "fired=rsansible-demo\n",
            "{host_name}: handler marker wrong: {fired:?}"
        );
        // include_role with tasks_from: + vars: produced this marker.
        // The vars block supplies extra_msg via the synthetic set_fact,
        // and the spliced write_file renders it.
        let marker = read_file(c, "/tmp/rsansible-include-role")?;
        assert_eq!(
            marker, "rsansible-demo include_role v1\n",
            "{host_name}: include_role marker wrong: {marker:?}"
        );
    }
    Ok(())
}

fn read_file(c: &SshdContainer, path: &str) -> Result<String> {
    let out = c.docker_exec(&["cat", path])?;
    if !out.status.success() {
        return Err(anyhow!(
            "missing {path}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn start_three_containers() -> Result<Vec<SshdContainer>> {
    let mut set: tokio::task::JoinSet<Result<SshdContainer>> = tokio::task::JoinSet::new();
    for _ in 0..3 {
        set.spawn(async { SshdContainer::start().await });
    }
    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        out.push(joined.map_err(|e| anyhow!("container task panicked: {e}"))??);
    }
    Ok(out)
}

fn build_inventory(containers: &[SshdContainer]) -> Inventory {
    let mut hosts = BTreeMap::new();
    let mut all_members: Vec<String> = Vec::new();
    let web_members: Vec<String> = (0..containers.len())
        .map(|i| format!("host{}", i + 1))
        .collect();
    for (i, c) in containers.iter().enumerate() {
        let name = format!("host{}", i + 1);
        hosts.insert(
            name.clone(),
            Host {
                host: "127.0.0.1".into(),
                port: c.host_port,
                user: c.user.clone(),
                key_path: Some(c.key_path.clone()),
                inline_vars: BTreeMap::new(),
                member_of: vec!["all".to_string(), "web".to_string()],
            },
        );
        all_members.push(name);
    }
    let mut groups = BTreeMap::new();
    groups.insert("all".to_string(), all_members);
    groups.insert("web".to_string(), web_members);
    Inventory {
        hosts,
        groups,
        all_vars: BTreeMap::new(),
        group_inline_vars: BTreeMap::new(),
    }
}

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace layout")
        .join("examples")
}
