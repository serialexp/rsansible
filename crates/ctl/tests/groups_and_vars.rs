//! End-to-end Phase 2a test: variables, groups, vault.
//!
//! Two unit-flavored tests (no docker), and one 3-container e2e that
//! exercises group selectors, every precedence layer, `groups[]`/`hostvars[]`
//! lookups, vault decryption, and `play.vars`.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use rsansible_ctl::{
    inventory::{self, Host, Inventory},
    orchestrator::{self, HostOutcome, RunSpec},
    playbook, vault,
};

use common::{locate_agent_binary, should_skip_docker_tests, sshd::SshdContainer};

#[test]
fn vault_decrypts_correctly() -> Result<()> {
    let secrets = std::fs::read(examples_dir().join("group_vars/web/secrets.yml"))
        .context("reading example vault file")?;
    let pt = vault::decrypt(&secrets, "testpass").context("vault decrypt")?;
    let s = String::from_utf8(pt).context("decrypted not UTF-8")?;
    assert!(
        s.contains("deployment_key:"),
        "expected `deployment_key:` in plaintext, got: {s:?}"
    );
    Ok(())
}

#[test]
fn unknown_group_in_hosts_fails_validate() -> Result<()> {
    let inv = inventory::parse(
        r#"
all:
  vars:
    ansible_user: u
  children:
    web:
      hosts:
        h1: { ansible_host: 1.1.1.1 }
"#,
    )?;
    let pb = playbook::parse(
        r#"
- name: bogus
  hosts: [nope]
  tasks:
    - name: t
      shell: echo
"#,
    )?;
    let err = playbook::validate(&pb, Some(&inv)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("nope"), "got: {msg}");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn three_container_groups_and_vars_run() -> Result<()> {
    if should_skip_docker_tests() {
        eprintln!("skipping: RSANSIBLE_SKIP_DOCKER_TESTS=1 or docker missing");
        return Ok(());
    }
    let agent_bytes = std::fs::read(locate_agent_binary()?)?;
    let containers = start_three_containers().await?;

    // Build the inventory programmatically — the example file uses
    // placeholder ports + a generic `deploy` user via group_vars/all,
    // but the test containers each have unique ports + a known SSH user.
    // Override the per-host coords here.
    let inv = build_inventory(&containers);

    // Discover group_vars/host_vars + vault from disk (paths relative to
    // examples/).
    let inv_dir = examples_dir();
    let vault_pw =
        vault::resolve_password_from(Some(&inv_dir.join(".vault-pass")))?.expect("vault pw");
    // load_with_vars looks for group_vars/ and host_vars/ next to the
    // inventory file. We have an inventory file path, but we want to
    // keep our run-time-built `inv` (with the container ports) and
    // borrow only the on-disk vars. So load both: throw away the on-disk
    // inv, keep the vars.
    let dummy_inv_path = inv_dir.join("groups_and_vars.inventory.yml");
    let (_disk_inv, inv_vars) =
        inventory::load_with_vars(&dummy_inv_path, Some(&vault_pw))?;

    let pb_path = inv_dir.join("groups_and_vars.yaml");
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading {}", pb_path.display()))?;
    playbook::validate(&pb, Some(&inv)).context("validate")?;
    rsansible_ctl::template::precompile_all(&pb).context("precompile")?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.inventory_vars = inv_vars;
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
        // all_vars layer (overridden by build_inventory's host.user — but
        // since we set ansible_user as an explicit inline var for the
        // test user, the marker will reflect THAT).
        let body = read_file(c, "/tmp/rsansible-allvar")?;
        assert!(body.starts_with("user="), "expected user=…, got {body:?}");

        // group_vars/web layer
        let body = read_file(c, "/tmp/rsansible-groupvar")?;
        assert_eq!(body, "region=us-east-1 role=frontend\n", "{host_name}: groupvar wrong");

        // host_vars/host1 layer — host1 has instance_marker=alpha;
        // others fall back to default('none').
        let body = read_file(c, "/tmp/rsansible-hostvar")?;
        if host_name == "host1" {
            assert_eq!(body, "marker=alpha\n", "host1: marker should be alpha");
        } else {
            assert_eq!(body, "marker=none\n", "{host_name}: marker should be none");
        }

        // world-scoped (groups[] / hostvars[])
        let body = read_file(c, "/tmp/rsansible-world")?;
        // first host is host1 by inventory order; its region is us-east-1.
        assert_eq!(
            body, "first=host1 first_region=us-east-1\n",
            "{host_name}: world lookup wrong"
        );

        // vault-decrypted secret
        let body = read_file(c, "/tmp/rsansible-vault")?;
        assert!(
            body.contains("key=hunter2-rsa-keymaterial"),
            "{host_name}: vault marker wrong: {body:?}"
        );

        // play.vars
        let body = read_file(c, "/tmp/rsansible-playvar")?;
        assert_eq!(body, "flavor=smoke\n", "{host_name}: play.vars wrong");
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
    // Three hosts in the `web` group. We set `ansible_user` and the key
    // path inline per host to override the example's `deploy` user.
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
