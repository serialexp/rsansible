//! Cross-host coordination example: postgres leader + N followers.
//!
//! What this stress-tests that nginx didn't:
//! - **Cross-host edges** — followers depend on the leader's IP (a fact
//!   only knowable after gathering against the leader). Passing the
//!   `Output<IpAddr>` into the follower's resource IS the edge.
//! - **`InlineModule` escape hatch** — `pg_basebackup` isn't yet a
//!   typed module, so we hand-roll it with required `check` / `apply`
//!   / `triggers` ceremony.
//! - **Secrets** — `vault.get(…)` returns `Secret<String>`, which the
//!   PostgresqlUser struct takes typed (no string template indirection).
//! - **The `out!` macro** — used to build the follower's apply command
//!   from the deferred `leader_ip` value.

use rsansible_declarative_spike::*;

/// Static pg_hba content. Not parameterized in this example, so the
/// trivial `InlineTemplate` is enough.
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spike inventory — real version would be Inventory::load("hosts.toml").
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

    let mut vault = Vault::default();
    vault.put("replicator_pw", "hunter2");

    let plan = Plan::new();

    // ----------------------------------------------------------------
    // Baseline that every postgres node needs: package, config, service.
    // ----------------------------------------------------------------
    let mut svc_by_host: std::collections::HashMap<String, ResourceRef<Service>> =
        Default::default();

    for host in inv.group("postgres") {
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

        svc_by_host.insert(host.name().to_string(), svc);
    }

    // ----------------------------------------------------------------
    // Leader-only: create the replication user.
    // ----------------------------------------------------------------
    let leader = inv.host("postgres-leader").expect("leader in inventory");
    let leader_node = plan.node(leader);
    let leader_svc = svc_by_host[leader.name()];

    let repl_user = leader_node.postgresql_user(PostgresqlUser {
        name: "replicator".into(),
        password: vault.require("replicator_pw").clone(),
        flags: vec![RoleFlag::Replication, RoleFlag::Login],
        become_: Some(BecomeUser::Named("postgres".into())),
        after: deps![leader_svc],
    });

    // ----------------------------------------------------------------
    // Followers: pg_basebackup from leader. The leader's IP is a
    // fact-derived Output<IpAddr> — the engine schedules the
    // fact-gather on the leader before any of these followers run.
    // ----------------------------------------------------------------
    let leader_ip = leader.facts().default_ipv4();

    for follower in inv.group("postgres-followers") {
        let node = plan.node(follower);
        let svc = svc_by_host[follower.name()];

        // The out! macro sugars the .apply() across a deferred input.
        // `leader_ip` is borrowed (not consumed), so it can be used
        // for every follower in the loop without explicit cloning.
        let cmd = out!(leader_ip => |ip| Shell::new(format!(
            "pg_basebackup -h {ip} -U replicator -D /var/lib/postgresql/15/main"
        )));

        node.module(InlineModule {
            name: "pg_basebackup".into(),
            // Idempotency: the bootstrap is complete iff PG_VERSION
            // exists in the data directory.
            check: ChangeCheck::PathExists(
                "/var/lib/postgresql/15/main/PG_VERSION".into(),
            ),
            apply: cmd,
            // Re-run if the leader's user was recreated OR if our local
            // postgres service was reinstalled.
            triggers: deps![repl_user, svc],
            become_: Some(BecomeUser::Named("postgres".into())),
            after: vec![],
        });
    }

    println!(
        "postgres plan: {} resources declared across 3 hosts",
        plan.resource_count()
    );
    Ok(())
}
