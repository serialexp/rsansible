//! Same postgres leader/follower setup as `postgres.rs`, refactored
//! around **roles-as-functions**.
//!
//! The key idea: a "role" is just a function that takes a `&Plan` (or
//! `&Node`), a description of what it should set up, and returns typed
//! handles to the resources it created. There is no role search path,
//! no `roles/` directory convention, no `tasks/main.yml` indirection,
//! no `defaults/` / `vars/` / `meta/` directories — a role is a
//! function with parameters and a return type, exactly like any other
//! piece of Rust.
//!
//! Compare line-for-line against `examples/postgres.rs` to see what
//! the abstraction buys:
//!  - Per-host resource bundles are typed (`PgBaseline`), not stashed
//!    in a `HashMap<String, ResourceRef<…>>` that loses the rest of
//!    the handles.
//!  - The leader/follower "phase" logic reads as composition of role
//!    calls rather than two-pass-collect-then-iterate.
//!  - Adding a new resource to the baseline (say, a wal-archiving
//!    cronjob) means adding a field to `PgBaseline` and the returning
//!    function — every consumer that needs it picks it up by name,
//!    not by alphabetical order.

use rsansible_declarative_spike::*;
use std::collections::HashMap;

// ============================================================
// Roles
// ============================================================

/// Typed bundle of handles returned by `postgres_baseline`. Consumers
/// reference specific resources by name (`.svc`, `.hba`) rather than
/// fishing them out of a map.
struct PgBaseline {
    #[allow(dead_code)]
    pkg: ResourceRef<Package>,
    #[allow(dead_code)]
    hba: ResourceRef<File>,
    svc: ResourceRef<Service>,
}

/// Role: package + pg_hba + service for one postgres node.
fn postgres_baseline(plan: &Plan, host: &Host) -> PgBaseline {
    let node = plan.node(host);

    let pkg = node.package(Package {
        name: "postgresql-15".into(),
        state: PackageState::Present,
        become_: Some(BecomeUser::Root),
        ..Default::default()
    });

    let hba = node.file(File {
        path: "/etc/postgresql/15/main/pg_hba.conf".into(),
        content: PgHba.render(),
        owner: Some("postgres".into()),
        group: Some("postgres".into()),
        mode: Some(0o640),
        become_: Some(BecomeUser::Root),
        after: deps![pkg],
        ..Default::default()
    });

    let svc = node.service(Service {
        name: "postgresql".into(),
        running: true,
        enabled: true,
        reload_on: deps![hba],
        after: deps![pkg],
        become_: Some(BecomeUser::Root),
        ..Default::default()
    });

    PgBaseline { pkg, hba, svc }
}

/// Role: postgres_baseline applied to every host in a group, keyed by
/// host name for cross-phase lookup.
///
/// Note: also works with a single host — the group is just a generic
/// `Iterator<Item = &Host>`.
fn postgres_baseline_group<'a>(
    plan: &Plan,
    hosts: impl IntoIterator<Item = &'a Host>,
) -> HashMap<String, PgBaseline> {
    hosts
        .into_iter()
        .map(|h| (h.name().to_string(), postgres_baseline(plan, h)))
        .collect()
}

/// Role: replication user on a single leader node.
fn replication_user(
    plan: &Plan,
    leader: &Host,
    leader_base: &PgBaseline,
    vault: &Vault,
) -> ResourceRef<PostgresqlUser> {
    plan.node(leader).postgresql_user(PostgresqlUser {
        name: "replicator".into(),
        password: vault.require("replicator_pw").clone(),
        flags: vec![RoleFlag::Replication, RoleFlag::Login],
        become_: Some(BecomeUser::Named("postgres".into())),
        after: deps![leader_base.svc],
    })
}

/// Role: pg_basebackup bootstrap on one follower node, against a
/// known-leader IP and a known replication user.
fn bootstrap_follower(
    plan: &Plan,
    follower: &Host,
    follower_base: &PgBaseline,
    repl_user: &ResourceRef<PostgresqlUser>,
    leader_ip: &Output<std::net::IpAddr>,
) -> ResourceRef<InlineModule> {
    let cmd = out!(leader_ip => |ip| Shell::new(format!(
        "pg_basebackup -h {ip} -U replicator -D /var/lib/postgresql/15/main"
    )));

    plan.node(follower).module(InlineModule {
        name: "pg_basebackup".into(),
        check: ChangeCheck::PathExists("/var/lib/postgresql/15/main/PG_VERSION".into()),
        apply: cmd,
        triggers: deps![repl_user, follower_base.svc],
        become_: Some(BecomeUser::Named("postgres".into())),
        after: vec![],
    })
}

// ============================================================
// Templates used by the roles
// ============================================================

struct PgHba;
impl Template for PgHba {
    fn render(&self) -> Output<String> {
        Output::ready(
            "local   all             all                                     peer\n\
             host    all             all             127.0.0.1/32            scram-sha-256\n\
             host    replication     replicator      10.0.0.0/24             scram-sha-256\n"
                .into(),
        )
    }
}

// ============================================================
// Main — composition of role calls
// ============================================================

/// The user-defined inventory function. Demonstrates that the function
/// IS the entry point — it can return `Inventory::from_toml(…)`, build
/// one by hand, or do whatever combination it likes.
fn inventory() -> Result<Inventory, Box<dyn std::error::Error>> {
    // In a real plan, this might be:
    //     Inventory::from_toml("inventory.toml")
    // For the spike, the from_toml stub returns empty, so we hand-build.
    let mut inv = Inventory::default();
    inv.add_host("postgres-leader", "10.0.0.10");
    inv.add_host("postgres-follower-1", "10.0.0.11");
    inv.add_host("postgres-follower-2", "10.0.0.12");
    for h in [
        "postgres-leader",
        "postgres-follower-1",
        "postgres-follower-2",
    ] {
        inv.add_to_group("postgres", h);
    }
    inv.add_to_group("postgres-followers", "postgres-follower-1");
    inv.add_to_group("postgres-followers", "postgres-follower-2");
    Ok(inv)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let inv = inventory()?;
    let mut vault = Vault::from_file("vault.yaml")?;
    vault.put("replicator_pw", "hunter2");

    let plan = Plan::new();

    // Baseline for every postgres node.
    let bases = postgres_baseline_group(&plan, inv.group("postgres"));

    // Leader-only: replication user.
    let leader = inv.host("postgres-leader").expect("leader in inventory");
    let repl_user = replication_user(&plan, leader, &bases[leader.name()], &vault);

    // Followers: bootstrap from leader.
    let leader_ip = leader.facts().default_ipv4();
    for follower in inv.group("postgres-followers") {
        bootstrap_follower(
            &plan,
            follower,
            &bases[follower.name()],
            &repl_user,
            &leader_ip,
        );
    }

    println!(
        "postgres-with-roles plan: {} resources across {} hosts",
        plan.resource_count(),
        bases.len(),
    );
    Ok(())
}
