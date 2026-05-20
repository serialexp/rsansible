//! rsansible — controller CLI.
//!
//! Subcommands:
//!   * `validate` — parse + semantically check a playbook (and inventory,
//!     if given) without contacting any host. Always offline.
//!   * `run`     — push the agent to each host, drive the playbook through
//!     the orchestrator's per-task / per-play barrier loop, report results.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rsansible_ctl::{
    extra_vars, forward, inventory,
    orchestrator::{self, RunSpec},
    playbook, template, vault,
};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "rsansible",
    version,
    about = "Ansible-shaped configuration management with a pushed single-binary agent."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Parse and validate a playbook (and optional inventory) — no SSH.
    Validate {
        /// Inventory file. Optional: without it we skip host-name checks.
        #[arg(short, long)]
        inventory: Option<PathBuf>,
        /// Path to a file containing the Ansible Vault password. Falls
        /// back to `$ANSIBLE_VAULT_PASSWORD_FILE`. Without one, vault
        /// files are skipped with a warning.
        #[arg(long)]
        vault_password_file: Option<PathBuf>,
        /// Playbook file (YAML).
        playbook: PathBuf,
    },
    /// Run a playbook against the inventory.
    Run {
        /// Inventory file.
        #[arg(short, long)]
        inventory: PathBuf,
        /// Path to the agent binary to push. Must be a musl-static Linux
        /// build (`just build-agent-musl` produces one).
        #[arg(short = 'a', long)]
        agent_binary: PathBuf,
        /// Max concurrent SSH dials during the connect phase.
        #[arg(long, default_value_t = 50)]
        concurrency: usize,
        /// Path to a file containing the Ansible Vault password. Falls
        /// back to `$ANSIBLE_VAULT_PASSWORD_FILE`. Without one, vault
        /// files are skipped with a warning.
        #[arg(long)]
        vault_password_file: Option<PathBuf>,
        /// Variable overrides — repeatable. Accepts `key=value` (always
        /// stringified), `@path/to/file.yml` (loads a YAML map), or
        /// `{"json": "object"}` (JSON/YAML object literal). Highest-
        /// precedence variable source — wins over inventory, facts,
        /// play vars, set_facts, and registers.
        #[arg(short = 'e', long = "extra-vars", value_name = "key=value|@file|{json}")]
        extra_vars: Vec<String>,
        /// Run only tasks tagged with one of these (Ansible-style).
        /// Repeatable; values are also comma-split. Magic tag `always`
        /// is honored on tasks (keeps them running through `--tags`),
        /// and the special selectors `all` / `untagged` work too.
        #[arg(long = "tags", value_delimiter = ',', value_name = "tag")]
        tags: Vec<String>,
        /// Skip tasks tagged with one of these. Repeatable;
        /// comma-splitting and the `all` / `untagged` selectors mirror
        /// `--tags`.
        #[arg(long = "skip-tags", value_delimiter = ',', value_name = "tag")]
        skip_tags: Vec<String>,
        /// Only run on hosts matching this pattern (Ansible-style).
        /// Repeatable; values are also comma-split. Supports exact
        /// names, globs (`web*`), regex (`~^web\d$`), intersection
        /// (`:&pat`), exclusion (`:!pat` or `!pat`), and group
        /// index/slice (`web[0]`, `web[1:3]`, `web[-1]`).
        #[arg(long = "limit", value_delimiter = ',', value_name = "pattern")]
        limit: Vec<String>,
        /// Override the ship-blind / probe-first heuristic that
        /// modules generating file content (e.g. `openssl_privatekey`)
        /// use to choose between sending bytes directly vs. statting
        /// first. `auto` (default) consults per-host RTT × bandwidth.
        /// `blind` skips the stat probe; `probe` always probes.
        #[arg(long = "wire-strategy", value_enum, default_value = "auto")]
        wire_strategy: WireStrategyArg,
        /// Run in check (dry-run) mode: no changes are made to target
        /// hosts. Modules report what they *would* change. `shell` /
        /// `exec` and mutating `uri` verbs are skipped; per-task
        /// `check_mode: false` overrides both directions.
        #[arg(long)]
        check: bool,
        /// Enable forward mode: push the controller binary to a host
        /// near the targets and drive the run from there. Collapses
        /// per-op SSH RTT on long-haul links. `connection: local` is
        /// preserved as "the operator's laptop" via a back-channel.
        /// Requires SSH agent forwarding to be functional from the
        /// forwarder out to peer targets.
        #[arg(long = "forward")]
        forward: bool,
        /// Inventory hostname to forward through. Overrides the
        /// `rsansible_forward_host` magic var (which itself overrides
        /// the default of "first targeted host"). Implies `--forward`.
        #[arg(long = "forward-host", value_name = "HOSTNAME")]
        forward_host: Option<String>,
        /// Forward mode: bypass the `/tmp/rsansible-cache/` binary
        /// cache on the forwarder and re-push the ctl + agent
        /// binaries every run. Slower (~7s/binary on long-haul links)
        /// but leaves nothing behind once the SSH session ends.
        /// Without this flag, binaries are content-addressed by
        /// SHA-256 in `/tmp/rsansible-cache/` and reused across runs.
        #[arg(long = "no-cache")]
        no_cache: bool,
        /// Print a phase-by-phase breakdown of orchestrator time at
        /// the end of the run. The collector is always on (~30ns per
        /// phase entry — well below noise); this flag just controls
        /// whether the breakdown is printed. Use when investigating
        /// "why did this run take N seconds" — the breakdown
        /// attributes time to `merge_hostvars`, `eval_when`,
        /// `resolve_target` (become + delegate_to + pool slot),
        /// `body_dispatch`, etc. See `crate::timing` for what each
        /// phase covers.
        #[arg(long = "timing")]
        timing: bool,
        /// Playbook file (YAML).
        playbook: PathBuf,
    },
    /// Forward-mode internal entry point. Invoked by the local shim over
    /// SSH on the forwarder host: reads a WorkflowPayload JSON blob from
    /// stdin, runs the orchestrator in-DC, writes a RunReport JSON blob
    /// to stdout. Hidden from `--help` because operators never call this
    /// directly. See `crates/ctl/src/forward.rs` for the wire format.
    #[command(hide = true)]
    RemoteRun {
        /// Path to the agent binary the local shim placed on disk next
        /// to this controller binary. Must be musl-static Linux x86_64.
        #[arg(long)]
        agent_binary: PathBuf,
        /// Workspace dir where the controller materializes the
        /// playbook + inventory bytes shipped in the WorkflowPayload.
        /// The local shim creates this dir before invoking remote-run
        /// and removes it after the SSH session closes.
        #[arg(long)]
        workspace: PathBuf,
    },
    /// Forward-mode internal entry point on the operator's LAPTOP.
    /// Two roles:
    ///   * `--listen <path>` (default mode) binds a unix socket and
    ///     accepts back-channel connections from the remote forwarder.
    ///     For each connection: in-process agent loop if BECOME is
    ///     none, sudo'd subprocess (`--inner`) if BECOME is `as <user>`.
    ///   * `--inner` runs the agent loop on this process's stdin/stdout.
    ///     Used as the sudo'd subprocess target — not invoked directly.
    /// Hidden from `--help` because operators never call this directly.
    #[command(hide = true)]
    LocalAgent {
        /// Unix socket path to listen on. The local shim creates this
        /// before invoking local-agent and reverse-forwards it over
        /// SSH `-R` to the remote forwarder.
        #[arg(long, conflicts_with = "inner")]
        listen: Option<PathBuf>,
        /// Inner mode: drive the agent loop on stdin/stdout. The
        /// listener spawns this under `sudo -n -u <user>` for the
        /// As(user) become path.
        #[arg(long)]
        inner: bool,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum WireStrategyArg {
    Auto,
    Blind,
    Probe,
}

impl From<WireStrategyArg> for rsansible_ctl::wire_cost::WireStrategy {
    fn from(a: WireStrategyArg) -> Self {
        match a {
            WireStrategyArg::Auto => rsansible_ctl::wire_cost::WireStrategy::Auto,
            WireStrategyArg::Blind => rsansible_ctl::wire_cost::WireStrategy::Blind,
            WireStrategyArg::Probe => rsansible_ctl::wire_cost::WireStrategy::Probe,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Validate {
            inventory,
            vault_password_file,
            playbook,
        } => match cmd_validate(inventory, vault_password_file, playbook).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Cmd::RemoteRun {
            agent_binary,
            workspace,
        } => match forward::cmd_remote_run(agent_binary, workspace).await {
            Ok(report) => {
                if report.any_failed() || report.stopped_early {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Cmd::LocalAgent { listen, inner } => {
            let result = if inner {
                rsansible_ctl::local_agent::cmd_local_agent_inner().await
            } else if let Some(sock) = listen {
                rsansible_ctl::local_agent::cmd_local_agent_listen(sock).await
            } else {
                Err(anyhow::anyhow!(
                    "local-agent requires either --listen <socket> or --inner"
                ))
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Run {
            inventory,
            agent_binary,
            concurrency,
            vault_password_file,
            extra_vars,
            tags,
            skip_tags,
            limit,
            wire_strategy,
            check,
            forward,
            forward_host,
            no_cache,
            timing,
            playbook,
        } => match cmd_run(
            inventory,
            agent_binary,
            concurrency,
            vault_password_file,
            extra_vars,
            tags,
            skip_tags,
            limit,
            wire_strategy,
            check,
            // `--forward-host X` implies `--forward` — both shapes
            // are the operator saying "I want forward mode."
            forward || forward_host.is_some(),
            forward_host,
            no_cache,
            timing,
            playbook,
        )
        .await
        {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}

async fn cmd_validate(
    inv_path: Option<PathBuf>,
    vault_pw_path: Option<PathBuf>,
    pb_path: PathBuf,
) -> Result<()> {
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading playbook {}", pb_path.display()))?;
    let vault_pw = vault::resolve_password_from(vault_pw_path.as_deref())?;
    let inv_pair = inv_path
        .as_ref()
        .map(|p| inventory::load_with_vars(p, vault_pw.as_deref()))
        .transpose()
        .with_context(|| format!("loading inventory {:?}", inv_path))?;
    let inv = inv_pair.as_ref().map(|(inv, _)| inv);
    playbook::validate(&pb, inv)?;
    template::precompile_all(&pb)?;
    println!(
        "ok: {} plays, {} tasks total{}",
        pb.plays.len(),
        pb.plays.iter().map(|p| p.tasks.len()).sum::<usize>(),
        match inv {
            Some(i) => format!(", {} hosts in inventory", i.hosts.len()),
            None => String::new(),
        }
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_run(
    inv_path: PathBuf,
    agent_binary_path: PathBuf,
    concurrency: usize,
    vault_pw_path: Option<PathBuf>,
    extra_vars_args: Vec<String>,
    tags: Vec<String>,
    skip_tags: Vec<String>,
    limit: Vec<String>,
    wire_strategy: WireStrategyArg,
    check_mode: bool,
    forward_mode: bool,
    forward_host: Option<String>,
    no_cache: bool,
    print_timing: bool,
    pb_path: PathBuf,
) -> Result<ExitCode> {
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading playbook {}", pb_path.display()))?;
    let vault_pw = vault::resolve_password_from(vault_pw_path.as_deref())?;
    let (inv, inv_vars) = inventory::load_with_vars(&inv_path, vault_pw.as_deref())
        .with_context(|| format!("loading inventory {}", inv_path.display()))?;
    playbook::validate(&pb, Some(&inv))?;
    template::precompile_all(&pb)?;

    let extra = extra_vars::parse_all(&extra_vars_args)
        .context("parsing --extra-vars")?;

    let agent_bytes = std::fs::read(&agent_binary_path)
        .with_context(|| format!("reading agent binary {}", agent_binary_path.display()))?;

    // Forward mode: instead of running the orchestrator locally, ship
    // ourselves over SSH to a forwarder and run there. We construct the
    // same shape of inputs (playbook + inventory paths, flags) and let
    // `forward::run_forwarded` do the heavy lifting. Forwarder selection
    // honors CLI > magic var > first targeted host (see
    // `forward::select_forwarder`).
    if forward_mode {
        return cmd_run_forwarded(
            pb_path,
            inv_path,
            agent_binary_path,
            inv,
            inv_vars,
            forward_host,
            extra,
            tags,
            skip_tags,
            limit,
            check_mode,
            wire_strategy,
            concurrency,
            no_cache,
            print_timing,
        )
        .await;
    }

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.inventory_vars = inv_vars;
    spec.max_concurrent_hosts = concurrency.max(1);
    spec.extra_vars = extra;
    spec.tags = tags;
    spec.skip_tags = skip_tags;
    spec.limit = limit;
    spec.wire_strategy = wire_strategy.into();
    spec.check_mode = check_mode;
    // Surface playbook_dir / inventory_dir to templates. Canonicalize so
    // `{{ playbook_dir }}/../foo` resolves cleanly regardless of how the
    // user spelled the original path.
    spec.playbook_dir = pb_path
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().into_owned()));
    spec.inventory_dir = inv_path
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().into_owned()));
    if check_mode {
        eprintln!("*** running in check mode — no changes will be made ***");
    }
    let report = orchestrator::run(spec)
        .await
        .context("orchestrator failed")?;

    // Summary to stderr; machine-readable exit code reflects success/fail.
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut unreachable = 0usize;
    let mut skipped = 0usize;
    for (host, outcome) in &report.host_outcomes {
        match outcome {
            orchestrator::HostOutcome::Ok => {
                ok += 1;
                eprintln!("  {host}: ok");
            }
            orchestrator::HostOutcome::Failed { task, reason } => {
                failed += 1;
                eprintln!("  {host}: FAILED at task {task:?}: {reason}");
            }
            orchestrator::HostOutcome::Unreachable { reason } => {
                unreachable += 1;
                eprintln!("  {host}: UNREACHABLE: {reason}");
            }
            orchestrator::HostOutcome::NotTargeted => {
                skipped += 1;
            }
        }
    }
    let early = if report.stopped_early { " (stopped early)" } else { "" };
    if report.check_mode {
        eprintln!(
            "summary: ok={ok} failed={failed} unreachable={unreachable} not_targeted={skipped} \
             tasks_run={tr} would-change={wc} skipped-by-check={sc}{early}",
            tr = report.tasks_ok,
            wc = report.tasks_changed,
            sc = report.tasks_skipped,
        );
    } else {
        eprintln!(
            "summary: ok={ok} failed={failed} unreachable={unreachable} not_targeted={skipped} \
             tasks_run={tr} changed={ch}{early}",
            tr = report.tasks_ok,
            ch = report.tasks_changed,
        );
    }
    // Wire-time breakdown. `agent` is real work the agent did; `rtt` is
    // skew-corrected outbound+inbound time the operator spent waiting
    // for bits to move; the sum of those two per-op equals each op's
    // wall time. `wall` is the sum across ALL ops, NOT the run's
    // wall-clock duration (tasks on different hosts overlap), so the
    // % numbers describe "across the work the orchestrator dispatched,
    // where did the time go" — they answer "is this run agent-bound or
    // wire-bound?" not "how long did the run take."
    let t = &report.timing;
    if t.op_count > 0 {
        let wall = t.wall_ns_total.max(1) as f64;
        let agent_pct = (t.agent_ns_total as f64 / wall) * 100.0;
        let rtt_ns = t.round_trip_ns_total();
        let rtt_pct = (rtt_ns as f64 / wall) * 100.0;
        eprintln!(
            "timing: ops={ops} agent={agent:.2}s rtt={rtt:.2}s wall={wall_s:.2}s \
             (agent={agent_pct:.1}% rtt={rtt_pct:.1}%)",
            ops = t.op_count,
            agent = t.agent_ns_total as f64 / 1e9,
            rtt = rtt_ns as f64 / 1e9,
            wall_s = t.wall_ns_total as f64 / 1e9,
        );
    }
    if print_timing {
        eprintln!("timing breakdown:");
        eprint!("{}", report.timing_breakdown.format());
        let per_op = report.timing.per_op_breakdown();
        if !per_op.is_empty() {
            eprint!("{}", per_op);
        }
    }
    if failed + unreachable > 0 || report.stopped_early {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Forward-mode entry point reached when `--forward` (or the implying
/// `--forward-host`) is set on the `run` subcommand. Picks the
/// forwarder, builds [`forward::ForwardArgs`], hands off to
/// [`forward::run_forwarded`], and prints the same summary/timing
/// shape the local-run path uses — the operator sees one consistent
/// output format regardless of which side the orchestrator actually
/// ran on.
#[allow(clippy::too_many_arguments)]
async fn cmd_run_forwarded(
    pb_path: PathBuf,
    inv_path: PathBuf,
    agent_binary_path: PathBuf,
    inv: rsansible_ctl::inventory::Inventory,
    inv_vars: rsansible_ctl::inventory::InventoryVars,
    cli_forward_host: Option<String>,
    extra_vars_parsed: std::collections::BTreeMap<String, serde_json::Value>,
    tags: Vec<String>,
    skip_tags: Vec<String>,
    limit: Vec<String>,
    check_mode: bool,
    wire_strategy: WireStrategyArg,
    concurrency: usize,
    no_cache: bool,
    print_timing: bool,
) -> Result<ExitCode> {
    // For forwarder selection we use the full inventory hosts as the
    // "target" set. Per-play `hosts:` filtering happens inside the
    // orchestrator on the forwarder; the forwarder doesn't change
    // mid-run, so picking from the full inventory at CLI time is fine
    // (and avoids re-implementing per-play target resolution here).
    let target_hosts: std::collections::BTreeSet<String> =
        inv.hosts.keys().cloned().collect();
    let forwarder = forward::select_forwarder(
        &inv,
        &inv.all_vars,
        &target_hosts,
        cli_forward_host.as_deref(),
    )?;
    eprintln!(
        "forward mode: dispatching through {} ({}@{}:{})",
        forwarder.name, forwarder.user, forwarder.host, forwarder.port,
    );

    // The ctl binary we ship to the forwarder is THIS process's argv[0].
    // Whichever rsansible binary is on the operator's PATH goes over the
    // wire — no separate "remote build" step. (v1 caveat: that binary
    // must be musl-static Linux x86_64; cross-OS forwarders fail at
    // the agent Hello probe.)
    let ctl_self_path = std::env::current_exe()
        .context("locating own binary to ship to the forwarder")?;

    let args = forward::ForwardArgs {
        playbook_path: pb_path,
        inventory_path: inv_path,
        inventory: inv,
        inventory_vars: inv_vars,
        ctl_binary_path: ctl_self_path,
        agent_binary_path,
        forwarder,
        extra_vars: extra_vars_parsed,
        tags,
        skip_tags,
        limit,
        check_mode,
        wire_strategy: wire_strategy.into(),
        max_concurrent_hosts: concurrency.max(1),
        no_cache,
    };
    let report = forward::run_forwarded(args)
        .await
        .context("forward-mode run failed")?;

    print_run_summary(&report);
    if print_timing {
        eprintln!("timing breakdown:");
        eprint!("{}", report.timing_breakdown.format());
        let per_op = report.timing.per_op_breakdown();
        if !per_op.is_empty() {
            eprint!("{}", per_op);
        }
    }
    if report.any_failed() || report.stopped_early {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Print the same per-host + timing summary the local-run path writes
/// to stderr, factored out so forward mode can reuse it without
/// duplicating the formatting strings.
fn print_run_summary(report: &orchestrator::RunReport) {
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut unreachable = 0usize;
    let mut skipped = 0usize;
    for (host, outcome) in &report.host_outcomes {
        match outcome {
            orchestrator::HostOutcome::Ok => {
                ok += 1;
                eprintln!("  {host}: ok");
            }
            orchestrator::HostOutcome::Failed { task, reason } => {
                failed += 1;
                eprintln!("  {host}: FAILED at task {task:?}: {reason}");
            }
            orchestrator::HostOutcome::Unreachable { reason } => {
                unreachable += 1;
                eprintln!("  {host}: UNREACHABLE: {reason}");
            }
            orchestrator::HostOutcome::NotTargeted => {
                skipped += 1;
            }
        }
    }
    let early = if report.stopped_early { " (stopped early)" } else { "" };
    if report.check_mode {
        eprintln!(
            "summary: ok={ok} failed={failed} unreachable={unreachable} not_targeted={skipped} \
             tasks_run={tr} would-change={wc} skipped-by-check={sc}{early}",
            tr = report.tasks_ok,
            wc = report.tasks_changed,
            sc = report.tasks_skipped,
        );
    } else {
        eprintln!(
            "summary: ok={ok} failed={failed} unreachable={unreachable} not_targeted={skipped} \
             tasks_run={tr} changed={ch}{early}",
            tr = report.tasks_ok,
            ch = report.tasks_changed,
        );
    }
    let t = &report.timing;
    if t.op_count > 0 {
        let wall = t.wall_ns_total.max(1) as f64;
        let agent_pct = (t.agent_ns_total as f64 / wall) * 100.0;
        let rtt_ns = t.round_trip_ns_total();
        let rtt_pct = (rtt_ns as f64 / wall) * 100.0;
        eprintln!(
            "timing: ops={ops} agent={agent:.2}s rtt={rtt:.2}s wall={wall_s:.2}s \
             (agent={agent_pct:.1}% rtt={rtt_pct:.1}%)",
            ops = t.op_count,
            agent = t.agent_ns_total as f64 / 1e9,
            rtt = rtt_ns as f64 / 1e9,
            wall_s = t.wall_ns_total as f64 / 1e9,
        );
    }
}
