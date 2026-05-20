//! Manual smoke driver for `forward::run_forwarded`.
//!
//! Drives the local-side shim against `ssh localhost`. Requires:
//!   - `ssh localhost` works without password (key auth via `ssh-add`).
//!   - `/tmp/forward-smoke-pb.yml` and `/tmp/forward-smoke-inv.yml`
//!     exist with a trivial playbook + inventory.
//!   - `target/debug/rsansible` and `target/debug/rsansible-agent`
//!     are built (cargo build will produce these as a side effect).
//!
//! Not run by `cargo test` — examples build but don't auto-execute.
//! Invoke explicitly: `cargo run -p rsansible-ctl --example forward_smoke`.
use rsansible_ctl::forward::{run_forwarded, ForwardArgs, ForwarderTarget};
use rsansible_ctl::inventory;
use rsansible_ctl::wire_cost::WireStrategy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let user = std::env::var("USER").unwrap_or_else(|_| "bart".into());
    let inv_path = std::path::PathBuf::from("/tmp/forward-smoke-inv.yml");
    let (inv, inv_vars) = inventory::load_with_vars(&inv_path, None)?;
    let args = ForwardArgs {
        playbook_path: "/tmp/forward-smoke-pb.yml".into(),
        inventory_path: inv_path,
        inventory: inv,
        inventory_vars: inv_vars,
        ctl_binary_path: "target/release/rsansible".into(),
        agent_binary_path: "target/release/rsansible-agent".into(),
        forwarder: ForwarderTarget {
            name: "localhost".into(),
            user,
            host: "localhost".into(),
            port: 22,
        },
        extra_vars: Default::default(),
        tags: vec![],
        skip_tags: vec![],
        limit: vec![],
        check_mode: false,
        wire_strategy: WireStrategy::Auto,
        max_concurrent_hosts: 1,
        no_cache: false,
    };
    let report = run_forwarded(args).await?;
    let failed = report
        .host_outcomes
        .values()
        .filter(|o| o.failed())
        .count();
    println!(
        "REPORT: tasks_ok={} failed_hosts={} stopped_early={} timing.op_count={}",
        report.tasks_ok, failed, report.stopped_early, report.timing.op_count
    );
    if failed > 0 || report.stopped_early {
        std::process::exit(1);
    }
    Ok(())
}
