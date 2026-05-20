//! Back-channel smoke driver for forward mode.
//!
//! Runs a playbook with TWO `connection: local` hosts against a
//! `ssh localhost` forwarder. The forwarder hostname is `localhost`,
//! so the host literally named `localhost` is auto-promoted to a
//! forwarder-self `Local` agent. The OTHER host (`laptop`) is
//! `connection: local` but is NOT the forwarder, so the orchestrator
//! dispatches its tasks over the back-channel unix socket — meaning
//! they execute on the operator's actual laptop via the in-process
//! `local-agent` listener.
//!
//! Expected: both hosts succeed, the listener logs an accepted
//! connection for the `laptop` host.
//!
//! Requires the same setup as `forward_smoke`:
//!   - `ssh localhost` works without password.
//!   - `target/release/rsansible{,-agent}` built.
//!   - `/tmp/forward-bc-smoke-pb.yml` and `/tmp/forward-bc-smoke-inv.yml`
//!     exist with the fixture content.
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
    let inv_path = std::path::PathBuf::from("/tmp/forward-bc-smoke-inv.yml");
    let (inv, inv_vars) = inventory::load_with_vars(&inv_path, None)?;
    let args = ForwardArgs {
        playbook_path: "/tmp/forward-bc-smoke-pb.yml".into(),
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
        max_concurrent_hosts: 2,
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
