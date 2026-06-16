//! Forward mode — relocate the controller next to the targets.
//!
//! The operator still runs `rsansible run …` from their laptop. With
//! `--forward`, the local binary pushes a musl-static copy of itself to a
//! chosen forwarder (default: first targeted host), ships the workflow over
//! SSH, and drives a remote `rsansible remote-run` process — which now sees
//! in-DC RTT to peer targets instead of the operator's long-haul RTT.
//!
//! Wire (controller↔controller):
//! - **Local → remote stdin:** one JSON-encoded [`WorkflowPayload`] blob.
//!   Remote reads to EOF, parses, runs the orchestrator.
//! - **Remote → local stdout:** one JSON-encoded [`RunReport`] blob.
//!   Local reads to EOF, parses, prints summary + timing.
//! - **Remote → local stderr:** tracing output, free-form. SSH passes it
//!   through transparently; the operator's terminal sees remote logs
//!   interleaved with local logs as if they were one process.
//!
//! Same binary on both sides (we just shipped it), so we don't need a
//! versioned wire — bumping the binary bumps both endpoints together.
//! Plain JSON keeps the wire human-debuggable for the v1 surface; if the
//! payload size ever becomes a problem we can swap in a binary codec
//! without touching call sites.
//!
//! See `crates/ctl/src/orchestrator.rs::RunReport` for what comes back.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::forward_bundle::{self, BundleOptions};
use crate::forward_push;
use crate::inventory::{Inventory, InventoryVars};
use crate::orchestrator::{self, RunReport, RunSpec};
use crate::wire_cost::WireStrategy;
use crate::{playbook, template};

/// Everything the remote `remote-run` process needs to reconstruct a
/// [`RunSpec`] and drive a run from inside the DC.
///
/// Hybrid shape:
/// - `workspace_tar_gz` carries the playbook + inventory directory trees
///   minus secrets — roles, group_vars (non-vault), files, templates,
///   includes. The forwarder extracts this and re-parses the playbook
///   on-disk with the same loader the laptop would have used; [`Playbook`]
///   is `Deserialize`-only by construction (custom impls all over the
///   task_op tree don't roundtrip through derived `Serialize`), so
///   re-parsing on the other side is the honest move.
/// - `inventory` + `inventory_vars` carry the laptop-resolved inventory
///   AST. Crucially this includes any vault/secret values the laptop
///   decrypted from files we EXCLUDED from the tarball (see
///   [`crate::forward_bundle`]). The forwarder uses these directly
///   instead of re-running `load_with_vars` — secrets stay in RAM, off
///   the forwarder's disk.
/// - The relative paths point at the entry files INSIDE the extracted
///   workspace (e.g. `"playbook/site.yml"`, `"inventory/inventory.yml"`).
///
/// [`RunSpec`]: crate::orchestrator::RunSpec
/// [`Playbook`]: crate::playbook::Playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowPayload {
    /// Gzipped tar of the playbook + inventory directory trees, with the
    /// secret-exclusion rules from [`crate::forward_bundle`] applied.
    /// The forwarder extracts this into its per-run workspace dir
    /// before re-loading the playbook.
    pub workspace_tar_gz: Vec<u8>,
    /// Path to the playbook entry file relative to the extracted
    /// workspace root. Typically of the form `"playbook/<basename>"`.
    pub playbook_relative_path: String,
    /// Path to the inventory entry file relative to the extracted
    /// workspace root. Typically of the form `"inventory/<basename>"`.
    /// Forwarder uses this only for `RunSpec.inventory_dir` (the parsed
    /// `Inventory` ships in the payload directly).
    pub inventory_relative_path: String,
    /// Laptop-resolved inventory, including any secrets the laptop
    /// decrypted from files excluded from the tarball.
    pub inventory: Inventory,
    /// On-disk var files (group_vars/*, host_vars/*) resolved on the
    /// laptop. Includes plaintext values from any `vault.yml` we kept
    /// off the forwarder's disk.
    pub inventory_vars: InventoryVars,
    /// `--extra-vars` (`-e`) overrides from the CLI. Becomes the
    /// `extra_vars` seed on every `HostCtx`.
    #[serde(default)]
    pub extra_vars: BTreeMap<String, serde_json::Value>,
    /// `--tags` selectors. Empty = run everything except `never`-only tasks.
    #[serde(default)]
    pub tags: Vec<String>,
    /// `--skip-tags` selectors. Empty = no skip filter.
    #[serde(default)]
    pub skip_tags: Vec<String>,
    /// `--limit` host-pattern terms. Empty = no host filter.
    #[serde(default)]
    pub limit: Vec<String>,
    /// `--check` dry-run flag.
    #[serde(default)]
    pub check_mode: bool,
    /// `--wire-strategy` override. `Auto` defers to the per-host heuristic.
    #[serde(default)]
    pub wire_strategy: WireStrategy,
    /// Cap on concurrent SSH dials during the initial connect phase.
    /// The remote runs against the same inventory size so reusing the
    /// local cap is the sensible default.
    pub max_concurrent_hosts: usize,
    /// Inventory hostname of the forwarder itself. The remote uses this
    /// to auto-promote that host to a `Local` connection (no SSH-to-self).
    /// Empty when the forwarder isn't in the target inventory.
    #[serde(default)]
    pub forwarder_hostname: String,
    /// Filesystem path on the forwarder of the back-channel unix socket.
    /// SSH `-R` reverse-forwards this from the laptop's `local-agent
    /// --listen` socket. `ConnMode::Local` hosts (i.e. tasks with
    /// `connection: local`) dispatch over this socket rather than
    /// spawning a local agent on the forwarder — preserving the
    /// "connection: local always means the laptop" semantics.
    /// Empty string when forward mode is opting out of back-channel
    /// support (e.g. a playbook that has no `connection: local` tasks);
    /// in that case the remote falls back to `open_local` for any
    /// Local-mode host, which is wrong-but-loud if a `connection: local`
    /// task ever hits.
    #[serde(default)]
    pub back_channel_socket: String,
}

/// Entry point for the hidden `rsansible remote-run` subcommand.
///
/// The local-side shim has already SSH'd in, written this binary to a
/// tmpdir on the forwarder, and is now feeding a [`WorkflowPayload`] JSON
/// blob on our stdin. We materialize playbook + inventory bytes back into
/// the same tmpdir, point the existing on-disk loaders at them, run the
/// orchestrator, and emit one JSON [`RunReport`] on stdout. Tracing keeps
/// writing to stderr; SSH passes it back to the operator transparently.
///
/// The agent binary is supplied via `--agent-binary` on the remote-run
/// command line (the local shim writes it to disk alongside this binary
/// and passes the path). We do NOT ship the agent bytes inside
/// [`WorkflowPayload`] — keeps the JSON small, lets the local shim hand
/// off the bytes via the same mechanism it uses for the controller binary.
pub async fn cmd_remote_run(
    agent_binary_path: PathBuf,
    workspace_dir: PathBuf,
) -> Result<RunReport> {
    // Slurp the entire workflow off stdin. Blocking read is fine here:
    // remote-run is single-purpose, nothing else needs the runtime
    // attention during this prelude. Bound by tokio's blocking pool.
    let payload_bytes = tokio::task::spawn_blocking(|| {
        let mut buf = Vec::with_capacity(64 * 1024);
        std::io::copy(&mut std::io::stdin().lock(), &mut buf)
            .context("reading WorkflowPayload from stdin")?;
        Ok::<_, anyhow::Error>(buf)
    })
    .await
    .context("stdin reader task panicked")??;

    let payload: WorkflowPayload = serde_json::from_slice(&payload_bytes)
        .context("decoding WorkflowPayload JSON from stdin")?;

    // Extract the workspace tarball into the per-run workspace so the
    // playbook loader can do its path-based discovery (roles/,
    // group_vars/, includes) the same way it would on the operator's
    // laptop. Inventory is shipped resolved in the payload (along with
    // any secrets the laptop decrypted from files we deliberately kept
    // out of the tarball) — we don't re-parse inventory here.
    std::fs::create_dir_all(&workspace_dir)
        .with_context(|| format!("creating workspace {}", workspace_dir.display()))?;
    forward_bundle::extract_workspace_tar_gz(&payload.workspace_tar_gz, &workspace_dir)
        .context("extracting workspace tarball")?;

    let pb_path = safe_join(&workspace_dir, &payload.playbook_relative_path)?;
    if !pb_path.is_file() {
        bail!(
            "playbook entry {} not found inside workspace tarball",
            payload.playbook_relative_path
        );
    }
    let inv_path = safe_join(&workspace_dir, &payload.inventory_relative_path)?;
    // The inventory file itself may or may not exist in the bundle —
    // we don't depend on it (the resolved Inventory is in the payload),
    // but we still surface `inventory_dir` to templates that read
    // `{{ inventory_dir }}/...`, so the path needs to resolve.

    // Re-parse the playbook with the same loader the local controller
    // would have used. Same parser → same validation errors → same
    // diagnostics surface back to the operator.
    let pb = playbook::load(&pb_path)
        .with_context(|| format!("loading playbook {}", pb_path.display()))?;
    let inv = payload.inventory.clone();
    let inv_vars = payload.inventory_vars.clone();
    playbook::validate(&pb, Some(&inv))?;
    template::precompile_all(&pb)?;

    let agent_bytes = std::fs::read(&agent_binary_path).with_context(|| {
        format!("reading agent binary {}", agent_binary_path.display())
    })?;

    let mut spec = RunSpec::new(inv, pb, agent_bytes);
    spec.inventory_vars = inv_vars;
    spec.max_concurrent_hosts = payload.max_concurrent_hosts.max(1);
    spec.extra_vars = payload.extra_vars;
    spec.tags = payload.tags;
    spec.skip_tags = payload.skip_tags;
    spec.limit = payload.limit;
    spec.wire_strategy = payload.wire_strategy;
    spec.check_mode = payload.check_mode;
    spec.playbook_dir = pb_path
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().into_owned()));
    spec.inventory_dir = inv_path
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().into_owned()));
    // Forward-mode wiring: if the laptop populated a back-channel socket
    // path, propagate it. Without the socket path the orchestrator
    // treats this run as a regular (non-forwarded) run on this host,
    // which is the right fallback for back-compat / tests.
    if !payload.back_channel_socket.is_empty() {
        spec.forward_mode = Some(orchestrator::ForwardModeContext {
            forwarder_hostname: payload.forwarder_hostname.clone(),
            back_channel_socket: PathBuf::from(&payload.back_channel_socket),
        });
    }

    let t_orch_start = std::time::Instant::now();
    let report = orchestrator::run(spec)
        .await
        .context("orchestrator failed")?;
    tracing::info!(
        elapsed_ms = t_orch_start.elapsed().as_millis() as u64,
        "remote-run phase: orchestrator returned",
    );

    let t_emit = std::time::Instant::now();
    let out = serde_json::to_vec(&report).context("encoding RunReport JSON")?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&out)
        .context("writing RunReport to stdout")?;
    stdout.flush().context("flushing stdout")?;
    drop(stdout);
    tracing::info!(
        elapsed_ms = t_emit.elapsed().as_millis() as u64,
        report_bytes = out.len(),
        "remote-run phase: RunReport written + flushed to stdout",
    );

    // Anything below this log line that holds the process open shows up
    // as time-after-write on the laptop side: agent subprocess Drop,
    // pool teardown, back-channel cleanup, the bash trap's `rm -rf`,
    // ssh session shutdown. Splitting the log lets us see how long the
    // function takes to actually return.
    tracing::info!("remote-run phase: returning from cmd_remote_run");
    Ok(report)
}

/// Resolve `rel` inside `base` and refuse anything that escapes the
/// workspace. WorkflowPayload comes off the wire — even though we
/// shipped it ourselves a moment ago, treating it as untrusted input
/// is cheap insurance against a malformed payload coaxing remote-run
/// into writing to `/etc/passwd`. No absolute paths, no `..`
/// segments, no symlink resolution surprises.
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return Err(anyhow!("payload contained absolute path {rel:?}"));
    }
    for c in rel_path.components() {
        match c {
            std::path::Component::Normal(_) => {}
            other => {
                return Err(anyhow!(
                    "payload path {rel:?} contains disallowed component {other:?}"
                ));
            }
        }
    }
    Ok(base.join(rel_path))
}

/// The magic var name a playbook or inventory can set to pin the
/// forwarder host without passing `--forward-host` on the CLI. See
/// [`select_forwarder`] for precedence; in short, CLI > magic var >
/// first targeted host.
pub const FORWARD_HOST_VAR: &str = "rsansible_forward_host";

/// Per-host magic var: dial address to use when the controller is
/// running INSIDE the target network (i.e. on the forwarder). Lets a
/// single inventory carry both the laptop's reach-from-outside address
/// (`ansible_host`) and the forwarder's reach-from-inside address
/// (this var). Forward mode swaps `Host.host` to this value just before
/// shipping the inventory; non-forward runs ignore it.
///
/// Companion to [`INTERNAL_HOST_PORT_VAR`] for the matching port.
/// See ANSIBLE_COMPAT.md §11 — deliberate divergence (Ansible has no
/// equivalent native magic var).
pub const INTERNAL_HOST_VAR: &str = "internal_ansible_host";
/// Per-host magic var: dial port companion to [`INTERNAL_HOST_VAR`].
/// Absent → keep the existing port (typically 22).
pub const INTERNAL_HOST_PORT_VAR: &str = "internal_ansible_port";

/// Rewrite each host's connection address to its `internal_ansible_host`
/// (and `internal_ansible_port`) when those magic vars are set, so the
/// forwarder dials peers over the in-network address instead of the
/// public one. Called on the laptop AFTER forwarder selection (so
/// selection still uses public addresses we can actually reach) and
/// BEFORE the inventory is serialized into the WorkflowPayload.
///
/// Hosts without the magic var keep their existing `host` / `port`.
/// Non-string `internal_ansible_host` and non-integer
/// `internal_ansible_port` are errors — better to fail loudly than to
/// silently keep the public address.
///
/// Lookup order, per host (first hit wins):
/// 1. The host's `inline_vars` (the per-host mapping inline in
///    inventory YAML — same spot where `ansible_host` itself lives).
/// 2. The host's on-disk `host_vars/<name>.yml` (`inv_vars.host_vars`).
///
/// Both spots are honored because operators typically split host
/// metadata across them: connection coords inline, everything else
/// (subnet/role/vswitch_ip…) in host_vars. Either is a valid home for
/// `internal_ansible_host`; v1 doesn't yet consult group_vars but
/// that can layer on top if a real use case shows up.
pub fn apply_internal_host_overrides(
    inventory: &mut Inventory,
    inventory_vars: &InventoryVars,
) -> Result<()> {
    for (name, host) in inventory.hosts.iter_mut() {
        let host_disk_vars = inventory_vars.host_vars.get(name);

        let internal_host = host
            .inline_vars
            .get(INTERNAL_HOST_VAR)
            .or_else(|| host_disk_vars.and_then(|v| v.get(INTERNAL_HOST_VAR)));
        if let Some(v) = internal_host {
            let s = v.as_str().ok_or_else(|| {
                anyhow!(
                    "host {name:?}: {INTERNAL_HOST_VAR} must be a string, got {v:?}"
                )
            })?;
            host.host = s.to_string();
        }

        let internal_port = host
            .inline_vars
            .get(INTERNAL_HOST_PORT_VAR)
            .or_else(|| host_disk_vars.and_then(|v| v.get(INTERNAL_HOST_PORT_VAR)));
        if let Some(v) = internal_port {
            let p = v.as_u64().ok_or_else(|| {
                anyhow!(
                    "host {name:?}: {INTERNAL_HOST_PORT_VAR} must be an integer, got {v:?}"
                )
            })?;
            if p == 0 || p > u16::MAX as u64 {
                bail!(
                    "host {name:?}: {INTERNAL_HOST_PORT_VAR} {p} is out of range (1..=65535)"
                );
            }
            host.port = p as u16;
        }
    }
    Ok(())
}

/// Choose the forwarder hostname for a forward-mode run.
///
/// Precedence (highest first):
/// 1. `cli_forward_host` — what the operator passed on `--forward-host`.
/// 2. `inventory_all_vars[FORWARD_HOST_VAR]` — the magic var, sourced
///    from inventory's top-level `all.vars`. Per-play / per-host
///    overrides are NOT consulted here — the forwarder is chosen ONCE
///    per run, before the orchestrator even starts.
/// 3. The first host in `target_hosts` (sorted; `BTreeSet` ordering).
///    "First" is deterministic — repeated invocations against the
///    same inventory pick the same forwarder.
///
/// Errors:
/// - `target_hosts` is empty.
/// - The chosen name isn't actually in `inventory.hosts`.
/// - The chosen host's `ansible_connection` is `local` (forwarding to
///   the laptop is meaningless — we ARE the laptop). The right move
///   in that case is to run without `--forward`.
pub fn select_forwarder(
    inventory: &crate::inventory::Inventory,
    inventory_all_vars: &std::collections::BTreeMap<String, serde_json::Value>,
    target_hosts: &std::collections::BTreeSet<String>,
    cli_forward_host: Option<&str>,
) -> Result<ForwarderTarget> {
    let name: String = if let Some(s) = cli_forward_host {
        s.to_string()
    } else if let Some(v) = inventory_all_vars.get(FORWARD_HOST_VAR) {
        v.as_str()
            .ok_or_else(|| {
                anyhow!(
                    "inventory magic var {FORWARD_HOST_VAR} must be a string, got {v:?}"
                )
            })?
            .to_string()
    } else {
        target_hosts
            .iter()
            .next()
            .ok_or_else(|| anyhow!("no target hosts — nothing to forward through"))?
            .clone()
    };

    let host = inventory.hosts.get(&name).ok_or_else(|| {
        anyhow!(
            "forward host {name:?} is not in the inventory \
             (set via {})",
            if cli_forward_host.is_some() {
                "--forward-host"
            } else if inventory_all_vars.contains_key(FORWARD_HOST_VAR) {
                FORWARD_HOST_VAR
            } else {
                "first-targeted-host fallback"
            },
        )
    })?;

    // Forwarding TO the laptop is a no-op (and the orchestrator's
    // forwarder-self auto-promote would route everything to Local
    // anyway). Bail loudly so the operator drops `--forward` instead
    // of silently doing the wrong thing. The check looks at both the
    // host's inline `ansible_connection` and the inventory-wide all_vars
    // fallback — we don't traverse group_vars here because the magic
    // var is supposed to be a coarse "where do I dial" hint, and any
    // inventory shape that ends up with `connection: local` at the
    // host level surfaces it via one of these two places.
    let conn_at_host = host
        .inline_vars
        .get("ansible_connection")
        .or_else(|| inventory_all_vars.get("ansible_connection"))
        .and_then(|v| v.as_str());
    if conn_at_host == Some("local") {
        bail!(
            "forward host {name:?} has `ansible_connection: local` — forwarding \
             to the laptop is a no-op, drop `--forward`"
        );
    }

    Ok(ForwarderTarget {
        name,
        user: host.user.clone(),
        host: host.host.clone(),
        port: host.port,
    })
}

/// Address the local shim uses to dial the forwarder over SSH.
///
/// The `name` is the inventory hostname the operator (or the forwarder
/// selection logic) chose; the `user` / `host` / `port` are the
/// SSH-dial coordinates resolved from inventory. `name` is also what we
/// stamp into `WorkflowPayload::forwarder_hostname` so the remote knows
/// which inventory entry refers to itself.
#[derive(Debug, Clone)]
pub struct ForwarderTarget {
    pub name: String,
    pub user: String,
    pub host: String,
    pub port: u16,
}

/// Inputs to [`run_forwarded`]. Mirrors `cmd_run`'s shape — file paths
/// and flags rather than a pre-built `RunSpec`, because we ship the raw
/// playbook + inventory YAML bytes to the forwarder and let it re-parse
/// with the same loaders. Trying to round-trip a parsed `Playbook`
/// through serde isn't safe (see `WorkflowPayload` doc).
#[derive(Debug, Clone)]
pub struct ForwardArgs {
    pub playbook_path: PathBuf,
    pub inventory_path: PathBuf,
    /// Laptop-resolved inventory. Shipped verbatim to the forwarder so
    /// the forwarder doesn't need to re-load — and so any secrets the
    /// laptop decrypted from files excluded from the workspace tarball
    /// (vault.yml etc.) ship through the wire in RAM rather than
    /// landing on the forwarder's disk.
    pub inventory: Inventory,
    /// Laptop-resolved on-disk var files. Same logic as `inventory`.
    pub inventory_vars: InventoryVars,
    /// Path to a musl-static `rsansible` binary on the local machine.
    /// Shipped to the forwarder and exec'd there as `remote-run`. Falls
    /// back to argv[0] when the operator's running rsansible binary is
    /// already musl-static; the CLI layer makes that determination.
    pub ctl_binary_path: PathBuf,
    /// Path to the musl-static agent binary on the local machine.
    /// Shipped to the forwarder so it can spawn agents against peer
    /// targets the same way the laptop normally would.
    pub agent_binary_path: PathBuf,
    pub forwarder: ForwarderTarget,
    pub extra_vars: BTreeMap<String, serde_json::Value>,
    pub tags: Vec<String>,
    pub skip_tags: Vec<String>,
    pub limit: Vec<String>,
    pub check_mode: bool,
    pub wire_strategy: WireStrategy,
    pub max_concurrent_hosts: usize,
    /// `--no-cache`: bypass `/tmp/rsansible-cache/` and re-push the
    /// binaries on every run into a per-run tmpdir on the forwarder.
    /// Slower (~7s/binary on a long-haul link) but leaves nothing
    /// behind once the SSH session ends. The cached path is the
    /// default because /tmp is already ephemeral on every system we
    /// care about and the binaries are bit-identical to the laptop's
    /// copy.
    pub no_cache: bool,
}

/// Drive a run from the laptop with the controller relocated to the
/// forwarder.
///
/// Wire layout on the SSH session's stdin:
/// 1. `ctl_bytes` (length known at script-build time).
/// 2. `agent_bytes` (ditto).
/// 3. `workflow_json` bytes, terminated by stdin close.
///
/// The remote bash one-liner consumes (1) and (2) with `head -c N` into
/// temp files, then `exec`s the remote controller — so the rest of stdin
/// (the workflow JSON) flows straight into `remote-run`'s stdin. The
/// remote controller's stdout (the JSON `RunReport`) flows back over the
/// SSH session's stdout to us. Tracing on the remote goes to stderr,
/// which we inherit so the operator sees remote logs interleaved with
/// local logs in real time.
///
/// No back-channel agent yet — `connection: local` tasks would dispatch
/// to the forwarder host as if they were local-to-it. Step 6 of the
/// forward-mode plan wires the laptop-back-as-agent path. v0 is useful
/// for any playbook that doesn't use `connection: local`.
pub async fn run_forwarded(mut args: ForwardArgs) -> Result<RunReport> {
    // Swap each peer's `host`/`port` to the internal-network address
    // (`internal_ansible_host` / `internal_ansible_port`) before the
    // inventory ships to the forwarder. The laptop already picked the
    // forwarder using public addresses; the forwarder now dials peers
    // over the in-network address. See `apply_internal_host_overrides`.
    apply_internal_host_overrides(&mut args.inventory, &args.inventory_vars)
        .context("applying internal_ansible_host overrides")?;

    // Resolve the project root as the common ancestor of the playbook
    // and inventory paths. Standard Ansible layouts have `roles/` as a
    // sibling of `playbooks/` and `group_vars/` under `inventory/` —
    // bundling each path's directory in isolation breaks the role
    // resolver. Common-ancestor bundling preserves the on-disk shape
    // the loader expects.
    let pb_abs = args
        .playbook_path
        .canonicalize()
        .with_context(|| format!("canonicalizing playbook path {}", args.playbook_path.display()))?;
    let inv_abs = args
        .inventory_path
        .canonicalize()
        .with_context(|| {
            format!("canonicalizing inventory path {}", args.inventory_path.display())
        })?;
    let pb_dir = pb_abs
        .parent()
        .ok_or_else(|| anyhow!("playbook path has no parent: {}", pb_abs.display()))?;
    let inv_dir = inv_abs
        .parent()
        .ok_or_else(|| anyhow!("inventory path has no parent: {}", inv_abs.display()))?;
    let project_root = forward_bundle::common_ancestor(pb_dir, inv_dir)
        .context("finding project root for forward-mode bundling")?;

    let pb_rel = pb_abs
        .strip_prefix(&project_root)
        .with_context(|| {
            format!(
                "playbook {} is not inside project root {}",
                pb_abs.display(),
                project_root.display()
            )
        })?
        .to_string_lossy()
        .into_owned();
    let inv_rel = inv_abs
        .strip_prefix(&project_root)
        .with_context(|| {
            format!(
                "inventory {} is not inside project root {}",
                inv_abs.display(),
                project_root.display()
            )
        })?
        .to_string_lossy()
        .into_owned();

    let t_bundle_start = std::time::Instant::now();
    let workspace_tar_gz = forward_bundle::build_workspace_tar_gz(&BundleOptions {
        project_root,
        extra_excludes: Vec::new(),
    })
    .context("building forward-mode workspace tarball")?;
    tracing::info!(
        tar_bytes = workspace_tar_gz.len(),
        elapsed_ms = t_bundle_start.elapsed().as_millis() as u64,
        "forward-mode phase: built workspace tar.gz",
    );

    // Back-channel sockets: predictable paths chosen up front so we can
    // splice them into `ssh -R` BEFORE the remote bash script runs. A
    // random hex suffix avoids collisions between concurrent
    // forward-mode runs on the same operator / forwarder. The local
    // socket is owned by the in-process `local-agent` listener we
    // spawn just below; the remote socket is what SSH `-R`
    // reverse-forwards from the laptop's local socket — `connection:
    // local` dispatches on the forwarder open it as if it were a
    // local-on-forwarder unix socket, and the kernel + sshd splice
    // bytes back to the laptop's listener.
    let bc_suffix: u64 = rand::random();
    let local_sock = std::env::temp_dir()
        .join(format!("rsansible-bc-{bc_suffix:016x}-local.sock"));
    let remote_sock_path =
        format!("/tmp/rsansible-bc-{bc_suffix:016x}-remote.sock");

    // Best-effort: in case a previous crashed run left a stale socket
    // with the SAME random suffix (cosmically unlikely but cheap).
    let _ = tokio::fs::remove_file(&local_sock).await;

    // Spawn the back-channel listener in-process. It binds the local
    // socket, accepts connections forever, and runs the agent loop per
    // connection. We abort the task at the end of the run.
    let listener_sock = local_sock.clone();
    let listener_task = tokio::spawn(async move {
        if let Err(e) = crate::local_agent::cmd_local_agent_listen(listener_sock).await {
            tracing::warn!(error = %format!("{e:#}"), "back-channel listener exited with error");
        }
    });

    // Wait for the socket file to appear so SSH `-R` doesn't race the
    // bind. We retry a handful of times before giving up — the listener
    // does ~one syscall to bind so this almost always succeeds on the
    // first poll.
    for _ in 0..50 {
        if local_sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if !local_sock.exists() {
        listener_task.abort();
        bail!(
            "back-channel listener did not bind {} in time",
            local_sock.display()
        );
    }

    let payload = WorkflowPayload {
        workspace_tar_gz,
        playbook_relative_path: pb_rel,
        inventory_relative_path: inv_rel,
        inventory: args.inventory,
        inventory_vars: args.inventory_vars,
        extra_vars: args.extra_vars,
        tags: args.tags,
        skip_tags: args.skip_tags,
        limit: args.limit,
        check_mode: args.check_mode,
        wire_strategy: args.wire_strategy,
        max_concurrent_hosts: args.max_concurrent_hosts,
        forwarder_hostname: args.forwarder.name.clone(),
        // Step 6d: tell the remote orchestrator where on the
        // forwarder's filesystem to find the back-channel socket.
        // SSH `-R` is what makes that path exist; see the `ssh` argv
        // below.
        back_channel_socket: remote_sock_path.clone(),
    };
    let payload_json =
        serde_json::to_vec(&payload).context("encoding WorkflowPayload JSON")?;

    let t_read_start = std::time::Instant::now();
    let ctl_bytes = std::fs::read(&args.ctl_binary_path).with_context(|| {
        format!("reading controller binary {}", args.ctl_binary_path.display())
    })?;
    let agent_bytes = std::fs::read(&args.agent_binary_path).with_context(|| {
        format!("reading agent binary {}", args.agent_binary_path.display())
    })?;
    tracing::info!(
        ctl_bytes = ctl_bytes.len(),
        agent_bytes = agent_bytes.len(),
        elapsed_ms = t_read_start.elapsed().as_millis() as u64,
        "forward-mode phase: read local binaries",
    );

    // Open a long-lived OpenSSH ControlMaster up-front. Every
    // subsequent `ssh` invocation in this run (cache probe, optional
    // pushes, main session) will pass `-o ControlPath=<master>` so it
    // multiplexes over this single TCP connection as a channel
    // instead of paying a fresh TCP+KEX+auth handshake. Critical on
    // high-RTT links (JP↔FI: 285ms RTT → ~1.5s per handshake) where
    // running three independent ssh processes would otherwise
    // serialize three handshakes.
    let base_dial = forward_push::ForwarderDial {
        user: args.forwarder.user.clone(),
        host: args.forwarder.host.clone(),
        port: args.forwarder.port,
        control_path: None,
    };
    let t_mux = std::time::Instant::now();
    let mux = forward_push::ControlMaster::open(base_dial)
        .await
        .context("opening ssh ControlMaster to forwarder")?;
    tracing::info!(
        elapsed_ms = t_mux.elapsed().as_millis() as u64,
        "forward-mode phase: ControlMaster ready",
    );
    let dial = mux.dial().clone();

    // Pre-stage the binaries (or not). The cached path probes the
    // forwarder for which hashes are already in `/tmp/rsansible-cache/`,
    // pushes any misses in parallel, and returns the absolute remote
    // paths the bash script will `exec`. The no-cache path returns
    // `None`, meaning "fall back to the inline-stream-over-main-ssh"
    // approach the v1 implementation used.
    let staged = if args.no_cache {
        tracing::info!(
            "forward-mode phase: --no-cache, will stream binaries over main ssh stdin",
        );
        None
    } else {
        let binaries = vec![
            forward_push::BinaryToStage {
                kind: forward_push::BinaryKind::Ctl,
                local_path: args.ctl_binary_path.clone(),
                bytes: ctl_bytes.clone(),
            },
            forward_push::BinaryToStage {
                kind: forward_push::BinaryKind::Agent,
                local_path: args.agent_binary_path.clone(),
                bytes: agent_bytes.clone(),
            },
        ];
        let t_stage = std::time::Instant::now();
        let staged_vec = forward_push::stage_binaries(&dial, binaries)
            .await
            .context("staging binaries on forwarder cache")?;
        let hits = staged_vec.iter().filter(|s| s.cache_hit).count();
        tracing::info!(
            elapsed_ms = t_stage.elapsed().as_millis() as u64,
            cache_hits = hits,
            cache_misses = staged_vec.len() - hits,
            "forward-mode phase: binary staging complete",
        );
        Some(staged_vec)
    };

    // Spawn `ssh -A` against the forwarder. The bash one-liner either
    // (a) execs from the cached remote paths immediately (cached path),
    // or (b) consumes the two binaries off stdin via `head -c N` into a
    // tmpdir then execs (--no-cache path). In both cases the remaining
    // stdin (workflow JSON) flows into the controller without us having
    // to multiplex anything.
    //
    // `-o BatchMode=yes` ensures we never hang waiting for a password
    // prompt; the operator must have key auth set up (which is the
    // entire premise of "magic feel — point at a host you have ssh
    // access to"). `-A` enables agent forwarding so peer SSH from the
    // forwarder can use the operator's loaded keys.
    let script = match &staged {
        Some(staged) => build_cached_bash_script(
            &staged[0].remote_path,
            &staged[1].remote_path,
        ),
        None => build_remote_bash_script(ctl_bytes.len(), agent_bytes.len()),
    };
    let dest = format!("{}@{}", args.forwarder.user, args.forwarder.host);
    // SSH joins argv after the host into one space-delimited string and
    // hands the result to the remote shell. If we pass `bash -c <script>`
    // as three argv entries, the remote shell re-splits the script on
    // spaces and only the FIRST whitespace-token survives as `bash -c`'s
    // argument (the rest become `$0`, `$1`, … — and `bash -c set`
    // happily prints every shell variable). Pre-quote the script and
    // pass `bash -c '<quoted-script>'` as a single argv entry; ssh
    // forwards it verbatim and the remote shell parses one command.
    let quoted = shlex::try_quote(&script)
        .context("shell-quoting remote bash script (internal: should never fail)")?;
    let remote_cmd = format!("bash -c {quoted}");
    // `-R remote:local` reverse-forwards a unix socket from the
    // forwarder back to the laptop. The remote sshd creates
    // `remote_sock_path` (and removes it on session teardown);
    // connecting to it tunnels through this same SSH session back to
    // `local_sock`, which our in-process listener owns.
    //
    // `-o StreamLocalBindUnlink=yes` tells sshd to remove a stale
    // remote socket before binding — defensive against a previous
    // crashed run with the same suffix (cosmically unlikely but the
    // option costs nothing).
    let r_arg = format!(
        "{}:{}",
        remote_sock_path,
        local_sock.display()
    );
    let t_spawn = std::time::Instant::now();
    let mut ssh_cmd = tokio::process::Command::new("ssh");
    ssh_cmd
        .arg("-A")
        .arg("-R")
        .arg(&r_arg)
        .arg("-o")
        .arg("StreamLocalBindUnlink=yes")
        .arg("-o")
        .arg("BatchMode=yes");
    if let Some(cp) = &dial.control_path {
        // Multiplex the main session over the master opened above —
        // skips a fresh TCP+KEX+auth handshake (~1.5s on JP↔FI).
        ssh_cmd
            .arg("-o")
            .arg(format!("ControlPath={}", cp.display()));
    }
    let mut child = ssh_cmd
        .arg("-p")
        .arg(args.forwarder.port.to_string())
        .arg(&dest)
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Inherit stderr: the remote controller's tracing flows directly
        // to the operator's terminal in real time. Future step 8 swaps
        // this for structured log frames if we want client-side
        // tracing-subscriber filtering to apply to remote events.
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning ssh")?;
    tracing::info!(
        elapsed_ms = t_spawn.elapsed().as_millis() as u64,
        "forward-mode phase: ssh process spawned",
    );

    // Streams in: ctl, agent, workflow JSON. Stream them all then close.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("ssh child has no stdin"))?;
    let ctl_len = ctl_bytes.len();
    let agent_len = agent_bytes.len();
    let payload_len = payload_json.len();
    // Skip the inline ctl/agent writes when we already staged the
    // binaries via the cache path — in that case the bash script
    // execs from cached paths and only expects the workflow JSON on
    // stdin.
    let stream_binaries = staged.is_none();
    let stdin_writer = async move {
        if stream_binaries {
            let t_ctl = std::time::Instant::now();
            stdin
                .write_all(&ctl_bytes)
                .await
                .context("writing ctl binary to ssh stdin")?;
            tracing::info!(
                bytes = ctl_len,
                elapsed_ms = t_ctl.elapsed().as_millis() as u64,
                mb_per_s = (ctl_len as f64 / 1_048_576.0)
                    / t_ctl.elapsed().as_secs_f64().max(0.001),
                "forward-mode phase: ctl bytes written to ssh stdin",
            );
            let t_agent = std::time::Instant::now();
            stdin
                .write_all(&agent_bytes)
                .await
                .context("writing agent binary to ssh stdin")?;
            tracing::info!(
                bytes = agent_len,
                elapsed_ms = t_agent.elapsed().as_millis() as u64,
                mb_per_s = (agent_len as f64 / 1_048_576.0)
                    / t_agent.elapsed().as_secs_f64().max(0.001),
                "forward-mode phase: agent bytes written to ssh stdin",
            );
        }
        let t_payload = std::time::Instant::now();
        stdin
            .write_all(&payload_json)
            .await
            .context("writing WorkflowPayload to ssh stdin")?;
        tracing::info!(
            bytes = payload_len,
            elapsed_ms = t_payload.elapsed().as_millis() as u64,
            "forward-mode phase: workflow payload written to ssh stdin",
        );
        // Both shutdown() and drop are needed: shutdown flushes the
        // tokio internal buffer; drop closes the underlying pipe FD,
        // which is what ultimately makes ssh send SSH_MSG_CHANNEL_EOF
        // to the server. Without the explicit drop, the FD lives until
        // the async block's frame is dropped — which doesn't happen
        // until try_join completes, which doesn't happen until stdout
        // reaches EOF, which can't happen until the remote sees EOF on
        // stdin. Classic deadlock.
        let t_close = std::time::Instant::now();
        stdin.shutdown().await.context("closing ssh stdin")?;
        drop(stdin);
        tracing::info!(
            elapsed_ms = t_close.elapsed().as_millis() as u64,
            "forward-mode phase: ssh stdin closed (EOF sent to remote)",
        );
        Ok::<(), anyhow::Error>(())
    };

    // Stream out: the RunReport JSON to EOF.
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("ssh child has no stdout"))?;
    let mut report_bytes = Vec::with_capacity(8 * 1024);
    let t_read_start = std::time::Instant::now();
    let stdout_reader = async {
        stdout
            .read_to_end(&mut report_bytes)
            .await
            .context("reading RunReport from ssh stdout")?;
        Ok::<(), anyhow::Error>(())
    };

    // Run stdin write + stdout read concurrently; either failing aborts
    // the other via the try_join macro.
    tokio::try_join!(stdin_writer, stdout_reader)?;
    tracing::info!(
        report_bytes = report_bytes.len(),
        elapsed_ms = t_read_start.elapsed().as_millis() as u64,
        "forward-mode phase: stdout drained (write+read complete)",
    );

    let status = child.wait().await.context("waiting on ssh child")?;

    // The remote exits non-zero whenever there are failed hosts OR the
    // run stopped early — but it still writes a complete RunReport to
    // stdout BEFORE exiting. So prefer the parsed report when it's
    // present; only treat the non-zero status as fatal if no report
    // came out (genuine ssh / bash failure before remote-run got going).
    let report: RunReport = match serde_json::from_slice::<RunReport>(&report_bytes) {
        Ok(r) => r,
        Err(parse_err) => {
            if !status.success() {
                bail!(
                    "forward-mode ssh failed: {status} (no RunReport produced; \
                     see forwarder stderr above for diagnostic)"
                );
            }
            return Err(anyhow!(parse_err)
                .context("decoding RunReport JSON from remote-run stdout"));
        }
    };

    // Tear down the back-channel listener. The accept loop is happy to
    // run forever; we abort it once the SSH session is gone so the
    // tokio runtime can exit. The local socket file is cleaned up too
    // — the listener doesn't unlink on its own (no chance after abort).
    listener_task.abort();
    let _ = tokio::fs::remove_file(&local_sock).await;

    Ok(report)
}

/// Build the bash one-liner the forwarder runs.
///
/// Reads `ctl_size` bytes for the controller binary and `agent_size`
/// bytes for the agent from stdin into a fresh tmpdir, marks them
/// executable, makes the workspace dir, then `exec`s the controller
/// against remote-run. `exec` replaces bash so the remaining stdin
/// (the workflow JSON) flows into the controller process. `set -e`
/// + a trap on EXIT cover the unhappy path.
///
/// Per Bart's #7 — no caching, leaves nothing behind — the tmpdir is
/// scoped to this run and torn down on any exit (success, failure,
/// signal). Operator gets the same "Ansible-style: leaves nothing"
/// guarantee.
/// Build the bash one-liner for the **cached** path.
///
/// Binaries are already at `cached_ctl_path` and `cached_agent_path`
/// inside `/tmp/rsansible-cache/` on the forwarder (placed there by
/// [`forward_push::stage_binaries`] before this script runs). All
/// we need is a per-run workspace dir for the extracted tarball and
/// then exec the cached ctl. The workspace dir IS cleaned up on
/// exit — only the binaries are cached, never workflow payload
/// artefacts.
fn build_cached_bash_script(cached_ctl_path: &str, cached_agent_path: &str) -> String {
    // Shell-quote the cache paths so a (hypothetical) future hash
    // scheme that introduces non-alphanumeric chars can't break out
    // of the quoting. Today these are `/tmp/rsansible-cache/<64-hex>`
    // so it doesn't matter; tomorrow's Claude will thank us.
    let ctl_q = shell_quote(cached_ctl_path);
    let agent_q = shell_quote(cached_agent_path);
    format!(
        r#"set -euo pipefail
TMP=$(mktemp -d -t rsansible.XXXXXXXX)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/ws"
exec {ctl_q} remote-run --agent-binary {agent_q} --workspace "$TMP/ws"
"#
    )
}

/// Minimal single-quote shell quoting for paths the bash script will
/// receive as argv tokens. `'foo'` is literal; embedded `'` becomes
/// `'\''`. Pure helper — `shlex::try_quote` works too but pulls a
/// `Cow` allocation we don't need here.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn build_remote_bash_script(ctl_size: usize, agent_size: usize) -> String {
    // `head -c N` is in coreutils everywhere we care about. `mktemp -d`
    // is universally available. We single-quote the script body via a
    // raw string so no shell expansion happens at format-time, then
    // splice the two sizes in via {} substitution — neither value is
    // attacker-controlled (we read them from local fs sizes), and
    // both are integers so there's no quoting hazard.
    format!(
        r#"set -euo pipefail
TMP=$(mktemp -d -t rsansible.XXXXXXXX)
trap 'rm -rf "$TMP"' EXIT
head -c {ctl_size} > "$TMP/ctl"
head -c {agent_size} > "$TMP/agent"
chmod 0700 "$TMP/ctl" "$TMP/agent"
mkdir "$TMP/ws"
exec "$TMP/ctl" remote-run --agent-binary "$TMP/agent" --workspace "$TMP/ws"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Host, Inventory};
    use std::collections::{BTreeMap, BTreeSet};

    fn host(name: &str, h: &str) -> (String, Host) {
        (
            name.to_string(),
            Host {
                host: h.to_string(),
                port: 22,
                user: "deploy".to_string(),
                key_path: None,
                inline_vars: BTreeMap::new(),
                member_of: vec!["all".into()],
            },
        )
    }

    fn inv_with(hosts: Vec<(String, Host)>) -> Inventory {
        let mut inv = Inventory {
            hosts: BTreeMap::new(),
            groups: BTreeMap::new(),
            all_vars: BTreeMap::new(),
            group_inline_vars: BTreeMap::new(),
        };
        for (n, h) in hosts {
            inv.hosts.insert(n, h);
        }
        inv
    }

    #[test]
    fn select_forwarder_cli_flag_wins() {
        let inv = inv_with(vec![host("a", "10.0.0.1"), host("b", "10.0.0.2")]);
        let mut all_vars = BTreeMap::new();
        all_vars.insert(
            FORWARD_HOST_VAR.to_string(),
            serde_json::Value::String("a".into()),
        );
        let targets: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        // CLI says "b" — overrides the magic var pointing at "a".
        let f = select_forwarder(&inv, &all_vars, &targets, Some("b")).unwrap();
        assert_eq!(f.name, "b");
        assert_eq!(f.host, "10.0.0.2");
    }

    #[test]
    fn select_forwarder_magic_var_used_when_no_cli() {
        let inv = inv_with(vec![host("a", "10.0.0.1"), host("b", "10.0.0.2")]);
        let mut all_vars = BTreeMap::new();
        all_vars.insert(
            FORWARD_HOST_VAR.to_string(),
            serde_json::Value::String("b".into()),
        );
        let targets: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let f = select_forwarder(&inv, &all_vars, &targets, None).unwrap();
        assert_eq!(f.name, "b", "magic var should win over first-target fallback");
    }

    #[test]
    fn select_forwarder_falls_back_to_first_targeted_host() {
        // BTreeSet ordering — `a` sorts before `b`, so `a` is "first".
        let inv = inv_with(vec![host("a", "10.0.0.1"), host("b", "10.0.0.2")]);
        let all_vars = BTreeMap::new();
        let targets: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let f = select_forwarder(&inv, &all_vars, &targets, None).unwrap();
        assert_eq!(f.name, "a");
    }

    #[test]
    fn select_forwarder_errors_when_chosen_host_not_in_inventory() {
        let inv = inv_with(vec![host("a", "10.0.0.1")]);
        let all_vars = BTreeMap::new();
        let targets: BTreeSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        let e =
            select_forwarder(&inv, &all_vars, &targets, Some("nonexistent")).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("nonexistent"), "msg = {msg}");
        assert!(
            msg.contains("--forward-host"),
            "diagnostic should mention which knob set the host: {msg}"
        );
    }

    #[test]
    fn select_forwarder_errors_when_no_target_hosts() {
        let inv = inv_with(vec![host("a", "10.0.0.1")]);
        let all_vars = BTreeMap::new();
        let targets: BTreeSet<String> = BTreeSet::new();
        let e = select_forwarder(&inv, &all_vars, &targets, None).unwrap_err();
        assert!(format!("{e:#}").contains("no target hosts"));
    }

    #[test]
    fn select_forwarder_rejects_local_connection_host() {
        let mut h = host("a", "127.0.0.1").1;
        h.inline_vars.insert(
            "ansible_connection".into(),
            serde_json::Value::String("local".into()),
        );
        let inv = inv_with(vec![("a".to_string(), h)]);
        let all_vars = BTreeMap::new();
        let targets: BTreeSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        let e = select_forwarder(&inv, &all_vars, &targets, None).unwrap_err();
        assert!(
            format!("{e:#}").contains("ansible_connection: local"),
            "should bail with a clear diagnostic",
        );
    }

    #[test]
    fn select_forwarder_rejects_local_connection_via_all_vars() {
        let inv = inv_with(vec![host("a", "127.0.0.1")]);
        let mut all_vars = BTreeMap::new();
        all_vars.insert(
            "ansible_connection".into(),
            serde_json::Value::String("local".into()),
        );
        let targets: BTreeSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        assert!(select_forwarder(&inv, &all_vars, &targets, None).is_err());
    }

    #[test]
    fn internal_host_override_swaps_host_and_port() {
        let mut h = host("db-2", "135.181.132.117").1;
        h.inline_vars.insert(
            "internal_ansible_host".into(),
            serde_json::Value::String("10.0.0.6".into()),
        );
        h.inline_vars.insert(
            "internal_ansible_port".into(),
            serde_json::Value::Number(2222.into()),
        );
        // A second host with no override should be left alone — proves
        // the swap is opt-in, not all-or-nothing.
        let untouched = host("app-1", "135.181.x.x");

        let mut inv = inv_with(vec![("db-2".into(), h), untouched]);
        apply_internal_host_overrides(&mut inv, &InventoryVars::default()).unwrap();
        let db2 = inv.hosts.get("db-2").unwrap();
        assert_eq!(db2.host, "10.0.0.6");
        assert_eq!(db2.port, 2222);
        let app1 = inv.hosts.get("app-1").unwrap();
        assert_eq!(app1.host, "135.181.x.x", "untouched host must keep public addr");
        assert_eq!(app1.port, 22);
    }

    #[test]
    fn internal_host_override_only_host_no_port() {
        let mut h = host("db-2", "135.181.x.x").1;
        h.inline_vars.insert(
            "internal_ansible_host".into(),
            serde_json::Value::String("10.0.0.6".into()),
        );
        let mut inv = inv_with(vec![("db-2".into(), h)]);
        apply_internal_host_overrides(&mut inv, &InventoryVars::default()).unwrap();
        let db2 = inv.hosts.get("db-2").unwrap();
        assert_eq!(db2.host, "10.0.0.6");
        // Port unchanged — the override is per-field, not all-or-nothing.
        assert_eq!(db2.port, 22);
    }

    #[test]
    fn internal_host_override_rejects_non_string_value() {
        let mut h = host("db-2", "1.2.3.4").1;
        h.inline_vars.insert(
            "internal_ansible_host".into(),
            serde_json::Value::Number(42.into()),
        );
        let mut inv = inv_with(vec![("db-2".into(), h)]);
        let err = apply_internal_host_overrides(&mut inv, &InventoryVars::default()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must be a string"), "{msg}");
        assert!(msg.contains("db-2"), "diagnostic should name the host: {msg}");
    }

    #[test]
    fn internal_host_override_reads_from_host_vars() {
        // Matches the acme shape: host_vars/db-2.yml carries the
        // internal IP, inventory's inline mapping only has the public.
        let h = host("db-2", "135.181.x.x").1;
        let mut inv = inv_with(vec![("db-2".into(), h)]);
        let mut inv_vars = InventoryVars::default();
        let mut hv = BTreeMap::new();
        hv.insert(
            "internal_ansible_host".to_string(),
            serde_json::Value::String("10.10.0.12".into()),
        );
        inv_vars.host_vars.insert("db-2".into(), hv);
        apply_internal_host_overrides(&mut inv, &inv_vars).unwrap();
        assert_eq!(inv.hosts["db-2"].host, "10.10.0.12");
    }

    #[test]
    fn internal_host_override_inline_beats_host_vars() {
        // Inline mapping must win over host_vars — same precedence
        // direction as ansible_host itself.
        let mut h = host("db-2", "135.181.x.x").1;
        h.inline_vars.insert(
            "internal_ansible_host".into(),
            serde_json::Value::String("10.10.0.99".into()),
        );
        let mut inv = inv_with(vec![("db-2".into(), h)]);
        let mut inv_vars = InventoryVars::default();
        let mut hv = BTreeMap::new();
        hv.insert(
            "internal_ansible_host".to_string(),
            serde_json::Value::String("10.10.0.12".into()),
        );
        inv_vars.host_vars.insert("db-2".into(), hv);
        apply_internal_host_overrides(&mut inv, &inv_vars).unwrap();
        assert_eq!(
            inv.hosts["db-2"].host, "10.10.0.99",
            "inline-vars value must win over host_vars value"
        );
    }

    #[test]
    fn internal_host_override_rejects_out_of_range_port() {
        let mut h = host("db-2", "1.2.3.4").1;
        h.inline_vars.insert(
            "internal_ansible_port".into(),
            serde_json::Value::Number(70000.into()),
        );
        let mut inv = inv_with(vec![("db-2".into(), h)]);
        let err = apply_internal_host_overrides(&mut inv, &InventoryVars::default()).unwrap_err();
        assert!(format!("{err:#}").contains("out of range"));
    }

    #[test]
    fn select_forwarder_rejects_non_string_magic_var() {
        let inv = inv_with(vec![host("a", "10.0.0.1")]);
        let mut all_vars = BTreeMap::new();
        all_vars.insert(
            FORWARD_HOST_VAR.to_string(),
            serde_json::Value::Number(42.into()),
        );
        let targets: BTreeSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        let e = select_forwarder(&inv, &all_vars, &targets, None).unwrap_err();
        assert!(format!("{e:#}").contains("must be a string"));
    }

    /// JSON round-trip for the payload — guards against accidental
    /// non-serializable additions slipping in. Also smoke-checks that
    /// the shipped `Inventory` + `InventoryVars` come out structurally
    /// identical (they're the secrets-bearing channel, so silent loss
    /// would be a security regression).
    #[test]
    fn workflow_payload_roundtrips_through_json() {
        let mut inv = Inventory {
            hosts: BTreeMap::new(),
            groups: BTreeMap::new(),
            all_vars: BTreeMap::new(),
            group_inline_vars: BTreeMap::new(),
        };
        inv.hosts.insert(
            "h1".to_string(),
            Host {
                host: "10.0.0.1".to_string(),
                port: 22,
                user: "deploy".to_string(),
                key_path: None,
                inline_vars: BTreeMap::new(),
                member_of: vec!["all".into()],
            },
        );
        inv.groups.insert("all".into(), vec!["h1".into()]);

        let mut inv_vars = InventoryVars::default();
        inv_vars
            .group_vars
            .entry("all".to_string())
            .or_default()
            .insert(
                "db_password".to_string(),
                serde_json::Value::String("hunter2".into()),
            );

        let p = WorkflowPayload {
            workspace_tar_gz: vec![0x1f, 0x8b, 0x08, 0x00],
            playbook_relative_path: "playbook/site.yml".into(),
            inventory_relative_path: "inventory/inventory.yml".into(),
            inventory: inv,
            inventory_vars: inv_vars,
            extra_vars: {
                let mut m = BTreeMap::new();
                m.insert(
                    "env".to_string(),
                    serde_json::Value::String("staging".into()),
                );
                m
            },
            tags: vec!["nginx".into()],
            skip_tags: vec![],
            limit: vec!["webservers".into()],
            check_mode: false,
            wire_strategy: WireStrategy::Auto,
            max_concurrent_hosts: 10,
            forwarder_hostname: "h1".into(),
            back_channel_socket: "/tmp/rsansible-bc/agent.sock".into(),
        };
        let s = serde_json::to_string(&p).unwrap();
        let r: WorkflowPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(r.workspace_tar_gz, p.workspace_tar_gz);
        assert_eq!(r.playbook_relative_path, p.playbook_relative_path);
        assert_eq!(r.inventory_relative_path, p.inventory_relative_path);
        assert_eq!(r.inventory, p.inventory);
        assert_eq!(r.inventory_vars, p.inventory_vars);
        assert_eq!(r.tags, p.tags);
        assert_eq!(r.limit, p.limit);
        assert_eq!(r.max_concurrent_hosts, p.max_concurrent_hosts);
        assert_eq!(r.forwarder_hostname, p.forwarder_hostname);
        assert_eq!(r.back_channel_socket, p.back_channel_socket);
        assert_eq!(
            r.extra_vars.get("env"),
            Some(&serde_json::Value::String("staging".into()))
        );
        // Secret survived the wire trip.
        assert_eq!(
            r.inventory_vars
                .group_vars
                .get("all")
                .and_then(|m| m.get("db_password")),
            Some(&serde_json::Value::String("hunter2".into())),
        );
    }

    /// The remote bash script must consume exactly the two binary
    /// blobs we declared, leaving the rest of stdin intact for the
    /// exec'd controller. Lock down the shape so a careless edit
    /// doesn't accidentally consume the workflow JSON or skip a byte.
    #[test]
    fn remote_bash_script_includes_both_sizes_and_execs_controller() {
        let s = build_remote_bash_script(12_000_000, 4_000_000);
        // Sizes spliced in literally so head -c reads the right count.
        assert!(s.contains("head -c 12000000 > \"$TMP/ctl\""));
        assert!(s.contains("head -c 4000000 > \"$TMP/agent\""));
        // exec, not just run — bash hands off stdin to the controller.
        assert!(s.contains("exec \"$TMP/ctl\" remote-run"));
        // No-leftovers discipline: trap RAM the tmpdir on EXIT.
        assert!(s.contains("trap 'rm -rf \"$TMP\"' EXIT"));
        assert!(s.contains("set -euo pipefail"));
    }

    /// Path traversal in the imported-files map must be rejected. The
    /// payload comes off the wire (we shipped it, but a buggy or
    /// adversarial caller might not), so a `../` segment shouldn't be
    /// quietly resolved against `/etc/`.
    #[test]
    fn safe_join_rejects_parent_dir_escape() {
        let base = Path::new("/tmp/ws");
        assert!(safe_join(base, "../escape").is_err());
        assert!(safe_join(base, "a/../../escape").is_err());
    }

    #[test]
    fn safe_join_rejects_absolute_paths() {
        let base = Path::new("/tmp/ws");
        assert!(safe_join(base, "/etc/passwd").is_err());
    }

    #[test]
    fn safe_join_allows_nested_relative_paths() {
        let base = Path::new("/tmp/ws");
        let joined = safe_join(base, "group_vars/all/vars.yml").unwrap();
        assert_eq!(joined, Path::new("/tmp/ws/group_vars/all/vars.yml"));
    }

    /// `serde_json::from_str` accepts a minimal blob — defaulted fields
    /// stay defaulted. Lets us extend the payload over time without
    /// forcing a coordinated update of every test fixture.
    #[test]
    fn workflow_payload_accepts_minimal_input() {
        let s = r#"{
            "workspace_tar_gz": [],
            "playbook_relative_path": "playbook/site.yml",
            "inventory_relative_path": "inventory/inventory.yml",
            "inventory": {
                "hosts": {},
                "groups": {},
                "all_vars": {},
                "group_inline_vars": {}
            },
            "inventory_vars": { "group_vars": {}, "host_vars": {} },
            "max_concurrent_hosts": 1
        }"#;
        let r: WorkflowPayload = serde_json::from_str(s).unwrap();
        assert!(r.tags.is_empty());
        assert!(r.limit.is_empty());
        assert!(!r.check_mode);
        assert_eq!(r.max_concurrent_hosts, 1);
    }
}
