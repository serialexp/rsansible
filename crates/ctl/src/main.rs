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
    extra_vars, inventory,
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
        /// Playbook file (YAML).
        playbook: PathBuf,
    },
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
        Cmd::Run {
            inventory,
            agent_binary,
            concurrency,
            vault_password_file,
            extra_vars,
            playbook,
        } => match cmd_run(
            inventory,
            agent_binary,
            concurrency,
            vault_password_file,
            extra_vars,
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

async fn cmd_run(
    inv_path: PathBuf,
    agent_binary_path: PathBuf,
    concurrency: usize,
    vault_pw_path: Option<PathBuf>,
    extra_vars_args: Vec<String>,
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

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.inventory_vars = inv_vars;
    spec.max_concurrent_hosts = concurrency.max(1);
    spec.extra_vars = extra;
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
    eprintln!(
        "summary: ok={ok} failed={failed} unreachable={unreachable} not_targeted={skipped}{}",
        if report.stopped_early {
            " (stopped early)"
        } else {
            ""
        }
    );
    if failed + unreachable > 0 || report.stopped_early {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}
