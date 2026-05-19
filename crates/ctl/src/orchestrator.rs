//! Barrier loop + fail-fast policy + per-host execution context.
//!
//! Two strategies, both exposed through the same entry point:
//!
//! * **`per_task`** (default): for each task, fan out across every healthy
//!   targeted host in parallel, then await all of them. Apply on_failure
//!   policy. Only then move to the next task. Each host's work for the
//!   task — `when:` evaluation, template rendering, loop iteration, body
//!   dispatch — happens on the host's own future; the orchestrator just
//!   awaits the bundle.
//! * **`per_play`**: each host runs the entire play's task list at its
//!   own pace; hosts execute in parallel but there is only one barrier,
//!   at the end of the play.
//!
//! Each host carries a `HostCtx` (registers, set_facts, inventory vars)
//! threaded through every task. `HostCtx` is owned by the orchestrator
//! between barriers and transferred into each per-host async task for the
//! duration of that task's execution, then transferred back.
//!
//! Connection lifecycle is unchanged from v0: one SSH/agent per host for
//! the whole run; `Bye` at the end.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use minijinja::Environment;
use rsansible_wire::{
    generated::{Message, TaskDoneOutput},
    msg::{bye, now_unix_ns, task_dispatch},
    read_frame, write_frame, Op,
};
use serde_json::Value as JsonValue;
use tokio::sync::{Mutex as TokioMutex, Notify, OnceCell, RwLock as TokioRwLock, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::become_::{self, BecomeKey};
use crate::exec_ctx::{build_template_ctx, yaml_to_json, HostCtx, RegisterValue, WorldVars};
use crate::inventory::{Host, Inventory, InventoryVars};
use crate::playbook::{
    AssertTask, AsyncStatusOp, BlockInFileOp, BlockSpec, CopyOp, DebugTask, ExecOp, FailTask,
    FileOp, GetUrlOp, GetentOp, HostSelector, HostnameOp, IptablesOp,
    LineInFileOp, LoopSpec, MetaAction, OnFailure, OpenSslCsrPipeOp, OpenSslPrivkeyOp, PackageOp,
    AuthorizedKeyOp, GroupOp, PauseTask, Play, Playbook, PostgresqlDbOp, PostgresqlExtOp,
    PostgresqlMembershipOp, PostgresqlQueryOp, PostgresqlUserOp,
    RepositoryOp, SetFactMap, ShellOp, SlurpOp, UserOp,
    StatOp, Strategy, SystemdOp, Task, TaskBody, TaskOp, TempfileKind, TempfileOp, UfwOp,
    UnarchiveOp, UriOp, WaitForOp, WriteFileOp, X509CertificatePipeOp,
};
use crate::pool::{AgentPool, PoolHandle};
use crate::ssh::{AgentConn, ConnectOptions};
use crate::template;

/// Shared handle to a host's agent connection.
///
/// We wrap each `AgentConn` in `Arc<Mutex<Option<AgentConn>>>` so that any
/// task future can borrow any host's connection (needed for `delegate_to`).
/// The inner `Option` is `None` when the conn has been dropped because the
/// host was marked failed; lockers see the `None` and return a Failed
/// outcome instead of deadlocking.
pub(crate) type ConnHandle = Arc<TokioMutex<Option<AgentConn>>>;

const DEFAULT_MAX_CONCURRENT_HOSTS: usize = 50;
/// Cap aggregated stdout+stderr per task at 1 MiB to avoid OOM on a
/// runaway command. Truncated output is suffixed with a marker.
const MAX_CAPTURED_BYTES: usize = 1024 * 1024;

/// Why a particular host ended up in this state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOutcome {
    /// Every task targeted at this host completed (or was skipped) without
    /// a failure.
    Ok,
    /// At least one task failed.
    Failed { task: String, reason: String },
    /// Could not be reached at the start of the run.
    Unreachable { reason: String },
    /// Excluded because no play targeted this host.
    NotTargeted,
}

impl HostOutcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, HostOutcome::Ok)
    }
    pub fn failed(&self) -> bool {
        matches!(
            self,
            HostOutcome::Failed { .. } | HostOutcome::Unreachable { .. }
        )
    }
}

/// What the orchestrator was asked to do.
pub struct RunSpec {
    pub inventory: Inventory,
    /// On-disk vars discovered next to the inventory (group_vars/, host_vars/).
    /// Empty by default; callers that load from disk pass the result of
    /// [`crate::inventory::load_with_vars`] here.
    pub inventory_vars: InventoryVars,
    pub playbook: Playbook,
    pub agent_binary: Arc<Vec<u8>>,
    /// Cap on concurrent SSH dials during the initial connect phase.
    pub max_concurrent_hosts: usize,
    /// CLI `--extra-vars` (`-e`) overrides. Highest-precedence variable
    /// source — seeded into every `HostCtx.extra_vars` at run start.
    /// Empty by default.
    pub extra_vars: BTreeMap<String, JsonValue>,
    /// CLI `--tags` selectors. Empty = run everything except
    /// `never`-only tasks. See [`crate::tags::TagFilter`].
    pub tags: Vec<String>,
    /// CLI `--skip-tags` selectors. Empty = no filter.
    pub skip_tags: Vec<String>,
    /// CLI `--limit` host-pattern terms. Empty = no host filter.
    /// Each entry is a pattern in the same grammar as `hosts:` —
    /// globs, regex, intersection (`:&`), exclusion (`:!` / `!`),
    /// index/slice (`web[0]`). Repetitions are union-joined.
    pub limit: Vec<String>,
    /// Override for the ship-blind vs probe-first heuristic used by
    /// modules that generate file content (e.g. `openssl_privatekey`).
    /// `Auto` (default) consults the per-host RTT × bandwidth model;
    /// `Blind` / `Probe` force one branch globally — useful for
    /// debugging and benchmarks.
    pub wire_strategy: crate::wire_cost::WireStrategy,
    /// CLI `--check` (dry-run). When true, agent modules skip
    /// mutations (reporting what they *would* change), `shell`/`exec`
    /// are skipped outright, and mutating `uri` verbs are skipped.
    /// Per-task `check_mode: false` reverses this for individual
    /// tasks; per-task `check_mode: true` forces check mode for that
    /// task even when the CLI flag is unset.
    pub check_mode: bool,
    /// Absolute path to the directory containing the playbook source file.
    /// Surfaced to templates as `{{ playbook_dir }}` (matches Ansible).
    pub playbook_dir: Option<String>,
    /// Absolute path to the directory containing the inventory source file.
    /// Surfaced to templates as `{{ inventory_dir }}`.
    pub inventory_dir: Option<String>,
}

impl RunSpec {
    pub fn new(inventory: Inventory, playbook: Playbook, agent_binary: Vec<u8>) -> Self {
        Self {
            inventory,
            inventory_vars: InventoryVars::default(),
            playbook,
            agent_binary: Arc::new(agent_binary),
            max_concurrent_hosts: DEFAULT_MAX_CONCURRENT_HOSTS,
            extra_vars: BTreeMap::new(),
            tags: Vec::new(),
            skip_tags: Vec::new(),
            limit: Vec::new(),
            wire_strategy: crate::wire_cost::WireStrategy::default(),
            check_mode: false,
            playbook_dir: None,
            inventory_dir: None,
        }
    }
}

/// The final outcome of a run.
#[derive(Debug)]
pub struct RunReport {
    pub host_outcomes: BTreeMap<String, HostOutcome>,
    pub stopped_early: bool,
    /// True iff the run was executed in `--check` (dry-run) mode. Surfaced
    /// to main so the summary line can distinguish "would change" from
    /// real changes.
    pub check_mode: bool,
    /// Total task-on-host successful invocations that reported
    /// `changed=true` (including would-change under `--check`).
    pub tasks_changed: u64,
    /// Total task-on-host successful invocations where the module
    /// declined to mutate state because of `--check` (or because the
    /// module has no probe — exec/shell/mutating uri).
    pub tasks_skipped: u64,
    /// Total task-on-host successful invocations regardless of changed/skipped.
    pub tasks_ok: u64,
    /// End-of-run snapshot of the per-run timing aggregator. Counts
    /// every wire round-trip (task dispatches + idempotency probes)
    /// and the time spent on each side of the wire. Zero values are
    /// the default for tests / paths that never dispatched a wire op.
    /// See `crate::run_metrics` for what each field measures.
    pub timing: crate::run_metrics::RunMetricsSnapshot,
}

impl RunReport {
    pub fn any_failed(&self) -> bool {
        self.host_outcomes.values().any(|o| o.failed())
    }
}

/// Top-level entry point.
pub async fn run(spec: RunSpec) -> Result<RunReport> {
    let RunSpec {
        inventory,
        inventory_vars,
        playbook,
        agent_binary,
        max_concurrent_hosts,
        extra_vars,
        tags,
        skip_tags,
        limit,
        wire_strategy,
        check_mode,
        playbook_dir,
        inventory_dir,
    } = spec;
    // Plumbed through to per-task dispatch so privkey (and any future
    // composite-dispatch op) can override the auto heuristic. Cheap to
    // clone — a 3-variant enum.
    // wire_strategy is copied onto each HostCtx below (run-scoped, but
    // HostCtx is what's threaded through dispatch). Keep the destructured
    // binding for clarity.

    // `--tags` / `--skip-tags` resolve to a filter consulted at task
    // dispatch time. Empty + empty = identity (the common case);
    // building it once and Arc-cloning it into per-host futures keeps
    // the per-task hot path branch-free.
    let tag_filter = Arc::new(
        crate::tags::TagFilter::from_cli(&tags, &skip_tags)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    );

    // `--limit` resolves to a host-pattern filter applied at two
    // points: a one-shot preflight against the full inventory (zero
    // matches → typo, bail before any SSH dial) and a per-play
    // intersection right before dispatch. When the user didn't pass
    // `--limit`, the filter is the identity and both calls are no-ops.
    let limit_filter = crate::limit::LimitFilter::from_cli(&limit)
        .map_err(|e| anyhow::anyhow!("--limit: {e}"))?;
    if limit_filter.is_active() {
        let matched = limit_filter.preflight(&inventory);
        if matched.is_empty() {
            anyhow::bail!("--limit pattern matches no hosts in the inventory");
        }
    }

    // Build the per-host inventory_vars views + the shared WorldVars
    // once at startup. Both are stable for the run.
    let world = Arc::new({
        let mut w = build_world_vars(&inventory, &inventory_vars);
        w.playbook_dir = playbook_dir.clone();
        w.inventory_dir = inventory_dir.clone();
        w
    });

    // Connect phase host set: union of every play's host set,
    // intersected with --limit. We don't dial hosts that `--limit` is
    // filtering out — the connect phase is the expensive bit.
    let target_hosts: BTreeSet<String> = if limit_filter.is_active() {
        let allowed: BTreeSet<String> =
            limit_filter.preflight(&inventory).into_iter().collect();
        compute_all_targeted_hosts(&playbook, &inventory)
            .intersection(&allowed)
            .cloned()
            .collect()
    } else {
        compute_all_targeted_hosts(&playbook, &inventory)
    };

    let mut outcomes: BTreeMap<String, HostOutcome> = inventory
        .hosts
        .keys()
        .map(|h| {
            let st = if target_hosts.contains(h) {
                HostOutcome::Ok
            } else {
                HostOutcome::NotTargeted
            };
            (h.clone(), st)
        })
        .collect();

    // Connect phase — parallel-bounded. Per-host transport is decided
    // up front by scanning the playbook for `connection: local` plays;
    // SSH is the default. See `resolve_host_connection_modes`. Each
    // host gets one `AgentPool` whose `BecomeKey::None` slot is
    // seeded by the initial connect; further slots (one per distinct
    // `BecomeKey::As(user)`) spawn lazily at dispatch time.
    let conn_modes =
        resolve_host_connection_modes(&playbook, &inventory, &world, &target_hosts)?;
    let mut pools_raw: BTreeMap<String, (AgentPool, ConnHandle)> = BTreeMap::new();
    let semaphore = Arc::new(Semaphore::new(max_concurrent_hosts.max(1)));
    let mut set: JoinSet<(String, Result<(AgentPool, ConnHandle)>)> = JoinSet::new();
    for name in &target_hosts {
        let host = inventory
            .hosts
            .get(name)
            .cloned()
            .expect("target host was resolved from inventory");
        let bin = agent_binary.clone();
        let sem = semaphore.clone();
        let name_owned = name.clone();
        let mode = *conn_modes.get(name).unwrap_or(&ConnMode::Ssh);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");
            let r = match mode {
                ConnMode::Ssh => {
                    let opts = ConnectOptions::from_host(&host);
                    AgentPool::open_ssh(&opts, &bin)
                        .await
                        .with_context(|| format!("connecting to {name_owned}"))
                }
                ConnMode::Local => AgentPool::open_local(name_owned.clone(), &bin)
                    .await
                    .with_context(|| {
                        format!("spawning local agent for {name_owned}")
                    }),
            };
            (name_owned, r)
        });
    }
    while let Some(joined) = set.join_next().await {
        let (name, r) = joined.context("connect task panicked")?;
        match r {
            Ok(pair) => {
                info!(host = %name, "connected");
                pools_raw.insert(name, pair);
            }
            Err(e) => {
                warn!(host = %name, error = %format!("{e:#}"), "connect failed");
                outcomes.insert(
                    name,
                    HostOutcome::Unreachable {
                        reason: format!("{e:#}"),
                    },
                );
            }
        }
    }

    // Wrap each pool in Arc<Mutex<…>> so per-host task futures can
    // borrow it for `get_or_spawn` (and so `delegate_to` can reach
    // other hosts' pools). The map itself never mutates after this
    // point.
    let mut none_handles: BTreeMap<String, ConnHandle> = BTreeMap::new();
    let pools: Arc<BTreeMap<String, PoolHandle>> = Arc::new(
        pools_raw
            .into_iter()
            .map(|(n, (pool, none_handle))| {
                none_handles.insert(n.clone(), none_handle);
                (n, Arc::new(TokioMutex::new(pool)))
            })
            .collect(),
    );

    // Run-shared timing accumulator. Lock-free atomics; cloned into
    // every per-host ctx so per-host walkers can record without
    // synchronizing. Snapshotted into `RunReport` at end-of-run.
    let run_metrics = Arc::new(crate::run_metrics::RunMetrics::default());

    // Build per-host execution contexts. Lives across the whole run so
    // set_facts and registers persist across plays (Ansible-faithful).
    let mut ctxs: BTreeMap<String, HostCtx> = BTreeMap::new();
    for (name, _pool_handle) in pools.iter() {
        let host = inventory.hosts.get(name).expect("conn host in inventory");
        let mut ctx = make_initial_ctx(name, host, &world, &extra_vars);
        // Seed wire-cost from the measured Ping/Pong RTT on this host's
        // initial agent channel, capped to u32::MAX ms (60s+ would
        // already be disastrous). Bandwidth comes from an optional
        // inventory var `wire_bandwidth_bytes_per_s`; missing/invalid
        // → keep the conservative default seeded by HostCtx::new.
        if let Some(none_handle) = none_handles.get(name) {
            let guard = none_handle.lock().await;
            if let Some(conn) = guard.as_ref() {
                let rtt_ms = (conn.clock_rtt_ns / 1_000_000).min(u32::MAX as u64) as u32;
                ctx.wire_cost.rtt_ms = rtt_ms;
            }
        }
        if let Some(JsonValue::Number(n)) =
            ctx.inventory_vars.get("wire_bandwidth_bytes_per_s")
        {
            if let Some(bw) = n.as_u64() {
                ctx.wire_cost.bw_bytes_per_s = bw.min(u32::MAX as u64) as u32;
            }
        }
        // Run-scoped override for the ship-blind/probe heuristic.
        // Same value across every host but stashed per-ctx because
        // HostCtx is the only thing threaded through dispatch.
        ctx.wire_strategy = wire_strategy;
        // Run-scoped dry-run flag — same value across every host.
        // Per-task `check_mode:` overrides this at dispatch time.
        ctx.check_mode = check_mode;
        // Run-shared timing aggregator. Cloning the Arc is the only
        // per-host setup needed; updates inside dispatch are
        // atomic-only.
        ctx.run_metrics = run_metrics.clone();
        ctxs.insert(name.clone(), ctx);
    }

    let mut report = RunReport {
        host_outcomes: outcomes,
        stopped_early: false,
        check_mode,
        tasks_changed: 0,
        tasks_skipped: 0,
        tasks_ok: 0,
        // Filled at end-of-run by snapshotting `run_metrics` once
        // every per-host walker has joined. Zero here is a sentinel,
        // not a measurement.
        timing: crate::run_metrics::RunMetricsSnapshot::default(),
    };

    let next_seq = Arc::new(AtomicU32::new(1));
    let env = Arc::new(template::make_env());

    'plays: for play in &playbook.plays {
        // Live-host filter: hosts that connected AND haven't been marked
        // failed under a prior play's mark_host_failed/stop policy.
        let play_targets: Vec<String> = limit_filter
            .apply(&inventory, &resolve_play_targets(&play.hosts, &inventory))
            .into_iter()
            .filter(|n| {
                pools.contains_key(n)
                    && matches!(report.host_outcomes.get(n), Some(HostOutcome::Ok))
            })
            .collect();

        // Per-play WorldVars: same groups + hostvars as the base, but with
        // role_defaults overlaid at the bottom (lowest precedence) of each
        // host's view, so `hostvars[other].some_default` resolves while
        // inventory_vars still wins over a default with the same key.
        let world_for_play = Arc::new(build_world_vars_for_play(&world, play));

        // Set per-host role_defaults from the play's merged role defaults.
        // Cleared and re-seeded on every play (no carry-over).
        apply_role_defaults_layer(play, &play_targets, &mut ctxs);

        // Implicit `Gathering Facts` task (Ansible-faithful default). Runs
        // before play.vars rendering so play.vars can reference facts.
        // Failures don't halt the play — Ansible's behavior.
        gather_facts_for_play(
            play,
            &play_targets,
            &pools,
            &mut ctxs,
            &mut report,
            &next_seq,
            &env,
            &world_for_play,
            &tag_filter,
        )
        .await?;

        // Layer the play's vars onto every live ctx (clearing the previous
        // play's vars first). play.vars render against the
        // (role_defaults ∪ inventory_vars ∪ facts) view per host.
        apply_play_vars(play, &play_targets, &mut ctxs, &env, &world_for_play);
        info!(
            play = %play.name,
            strategy = ?play.strategy,
            on_failure = ?play.on_failure,
            hosts = play_targets.len(),
            "starting play",
        );
        if play_targets.is_empty() {
            info!(play = %play.name, "no live target hosts; skipping");
            continue;
        }
        let stopped = match play.strategy {
            Strategy::PerTask => {
                run_play_per_task(
                    play,
                    &play_targets,
                    &pools,
                    &mut ctxs,
                    &mut report,
                    &next_seq,
                    &env,
                    &world_for_play,
                    &tag_filter,
                )
                .await?
            }
            Strategy::PerPlay => {
                run_play_per_play(
                    play,
                    &play_targets,
                    &pools,
                    &mut ctxs,
                    &mut report,
                    &next_seq,
                    &env,
                    &world_for_play,
                    &tag_filter,
                )
                .await?
            }
        };
        if stopped {
            warn!(play = %play.name, "on_failure=stop triggered; halting playbook");
            report.stopped_early = true;
            break 'plays;
        }
    }

    // Best-effort Bye. Iterate every host's pool; for each slot,
    // lock its handle, take the conn out, send Bye, drop. Hosts /
    // slots whose conn was dropped earlier (failed under
    // mark_host_failed) have inner = None and are skipped.
    for (name, pool_handle) in pools.iter() {
        let pool = pool_handle.lock().await;
        for key in pool.keys().cloned().collect::<Vec<_>>() {
            // Each slot owns its own ConnHandle inside the pool.
            // The pool API exposes get_or_spawn (which would re-spawn
            // a missing slot) — for Bye we don't want that, so we
            // re-lookup via the keys() snapshot.
            if let Some(slot_handle) = pool.slot(&key) {
                let mut guard = slot_handle.lock().await;
                if let Some(mut conn) = guard.take() {
                    if let Err(e) = write_frame(&mut conn.stream, &bye()).await {
                        warn!(host = %name, become = %key.label(), "Bye send failed: {e:#}");
                    } else {
                        debug!(host = %name, become = %key.label(), "Bye sent");
                    }
                }
            }
        }
    }

    // Snapshot the run-shared timing accumulator now that every
    // walker has joined. Reads are Relaxed but there is no more
    // concurrent write — the strategy futures are all awaited above.
    report.timing = run_metrics.snapshot();

    Ok(report)
}

fn make_initial_ctx(
    name: &str,
    host: &Host,
    world: &WorldVars,
    extra_vars: &BTreeMap<String, JsonValue>,
) -> HostCtx {
    let mut ctx = HostCtx::new(name.to_string());
    // Seed inventory_vars from the world-scoped per-host map (precedence
    // steps 1..=4 already resolved by build_world_vars).
    if let Some(view) = world.hostvars.get(name) {
        for (k, v) in view {
            ctx.inventory_vars.insert(k.clone(), v.clone());
        }
    }
    // CLI `-e` / `--extra-vars` — same value across every host, highest
    // precedence at render time.
    ctx.extra_vars = extra_vars.clone();
    // Always make sure the four canonical connection coords are present
    // (build_world_vars normally seeds them too, but this protects against
    // an empty world e.g. in unit tests).
    ctx.inventory_vars
        .entry("ansible_host".into())
        .or_insert_with(|| JsonValue::String(host.host.clone()));
    ctx.inventory_vars
        .entry("ansible_port".into())
        .or_insert_with(|| JsonValue::from(host.port));
    ctx.inventory_vars
        .entry("ansible_user".into())
        .or_insert_with(|| JsonValue::String(host.user.clone()));
    ctx
}

/// Compute the run-scoped `WorldVars`: per-host resolved inventory_vars
/// (precedence steps 1..=4) and the group → hosts map. Done once at
/// startup; every render uses these.
fn build_world_vars(inv: &Inventory, vars: &InventoryVars) -> WorldVars {
    let mut hostvars: BTreeMap<String, BTreeMap<String, JsonValue>> = BTreeMap::new();
    for (name, host) in &inv.hosts {
        let mut view: BTreeMap<String, JsonValue> = BTreeMap::new();
        // 1. all_vars (inline at all.vars)
        for (k, v) in &inv.all_vars {
            view.insert(k.clone(), v.clone());
        }
        // 1b. on-disk group_vars/all (treated as an extension of all_vars).
        if let Some(av) = vars.group_vars.get("all") {
            for (k, v) in av {
                view.insert(k.clone(), v.clone());
            }
        }
        // 2. group_vars (inline + on-disk) in declaration order. `all` is
        //    already covered above; skip it here to avoid double-applying.
        for g in &host.member_of {
            if g == "all" {
                continue;
            }
            if let Some(gv) = inv.group_inline_vars.get(g) {
                for (k, v) in gv {
                    view.insert(k.clone(), v.clone());
                }
            }
            if let Some(gv) = vars.group_vars.get(g) {
                for (k, v) in gv {
                    view.insert(k.clone(), v.clone());
                }
            }
        }
        // 3. host_vars (on-disk)
        if let Some(hv) = vars.host_vars.get(name) {
            for (k, v) in hv {
                view.insert(k.clone(), v.clone());
            }
        }
        // 4. host inline vars (from the inventory YAML, non-connection keys)
        for (k, v) in &host.inline_vars {
            view.insert(k.clone(), v.clone());
        }
        // Always expose the four connection coords as resolved here, so
        // templates referencing `{{ ansible_host }}` see the merged value.
        view.insert(
            "ansible_host".into(),
            JsonValue::String(host.host.clone()),
        );
        view.insert("ansible_port".into(), JsonValue::from(host.port));
        view.insert(
            "ansible_user".into(),
            JsonValue::String(host.user.clone()),
        );
        if let Some(p) = &host.key_path {
            view.insert(
                "ansible_ssh_private_key_file".into(),
                JsonValue::String(p.to_string_lossy().into_owned()),
            );
        }
        hostvars.insert(name.clone(), view);
    }
    WorldVars {
        groups: inv.groups.clone(),
        hostvars,
        playbook_dir: None,
        inventory_dir: None,
    }
}

/// Clear any prior play's `role_defaults` from each host's ctx and seed
/// the current play's merged defaults. Lowest-precedence user-defined
/// source — sits below `inventory_vars`.
fn apply_role_defaults_layer(
    play: &Play,
    targets: &[String],
    ctxs: &mut BTreeMap<String, HostCtx>,
) {
    for name in targets {
        let Some(ctx) = ctxs.get_mut(name) else { continue };
        ctx.role_defaults.clear();
        for (k, v) in &play.role_defaults {
            ctx.role_defaults.insert(k.clone(), v.clone());
        }
    }
}

/// Build a per-play `WorldVars`: same groups + hostvars as the base,
/// but with `role_defaults` overlaid at the bottom of each host's view
/// so `hostvars[other].some_default` resolves while inventory_vars still
/// wins over any defaults that share a key.
fn build_world_vars_for_play(base: &WorldVars, play: &Play) -> WorldVars {
    if play.role_defaults.is_empty() {
        return base.clone();
    }
    let mut hostvars = base.hostvars.clone();
    for view in hostvars.values_mut() {
        for (k, v) in &play.role_defaults {
            view.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    WorldVars {
        groups: base.groups.clone(),
        hostvars,
        playbook_dir: base.playbook_dir.clone(),
        inventory_dir: base.inventory_dir.clone(),
    }
}

/// Rebuild `world.hostvars` overlaying each host's **dynamic** state
/// (facts → play_vars → set_facts → registers → extra_vars +
/// `inventory_hostname`) on top of the inventory-derived base. Lets
/// templates reach into another host's *current* state via
/// `{{ hostvars[<peer>].some_register }}` — required by clustering
/// playbooks (etcd peer URLs, pgbackrest pubkey mesh, valkey
/// sentinel discovery, …).
///
/// Precedence inside each peer's view mirrors `build_template_ctx`,
/// EXCLUDING the layers that don't make sense cross-host:
///   - `iter_item` — render-local; one host's loop item must not leak
///     into another host's `hostvars[…]` lookup.
///   - `task_vars` — scoped to the task currently dispatching on the
///     OWNING host, not on the host doing the lookup.
///   - `ansible_failed_*` — block-rescue arm state; visible only
///     locally to the host whose rescue arm is running.
///   - `groups` / `hostvars` themselves — world-scoped, would recurse.
///
/// Refresh point: this is called **between tasks** in the per_task
/// strategy. At that point all `HostCtx`s are back in `ctxs` (the
/// fanout temporarily owns them by-value and re-inserts via
/// `apply_per_host_result` before the next task), so no locking is
/// needed. The resulting snapshot is what every host's per-task
/// fanout sees for `hostvars[<peer>]`. This matches Ansible's
/// per-task barrier semantics: hosts see each other's state as it
/// was at the start of the current task, not mid-flight.
///
/// For `run_play_per_play` we publish a parallel snapshot
/// (`Arc<RwLock<HostCtx>>` per host, written at each task barrier
/// on the owning walker) and call [`merge_dynamic_hostvars_locked`]
/// instead — the in-fanout ctxs map is not at-rest in that strategy
/// so a direct snapshot here would race.
fn merge_dynamic_hostvars(
    base: &WorldVars,
    ctxs: &BTreeMap<String, HostCtx>,
) -> WorldVars {
    let mut hostvars = base.hostvars.clone();
    for (name, ctx) in ctxs {
        let view = hostvars
            .entry(name.clone())
            .or_insert_with(BTreeMap::new);
        // Overlay in precedence order (low → high). Each layer
        // overwrites the prior for shared keys.
        for (k, v) in &ctx.facts {
            view.insert(k.clone(), v.clone());
        }
        for (k, v) in &ctx.play_vars {
            view.insert(k.clone(), v.clone());
        }
        for (k, v) in &ctx.set_facts {
            view.insert(k.clone(), v.clone());
        }
        for (k, v) in &ctx.registers {
            view.insert(k.clone(), v.to_json());
        }
        for (k, v) in &ctx.extra_vars {
            view.insert(k.clone(), v.clone());
        }
        // Always present so `{{ hostvars[h].inventory_hostname }}`
        // works (used by e.g. the etcd config template to build
        // `name=URL` pairs from a group iteration).
        view.insert(
            "inventory_hostname".into(),
            JsonValue::String(ctx.host_name.clone()),
        );
    }
    WorldVars {
        groups: base.groups.clone(),
        hostvars,
        playbook_dir: base.playbook_dir.clone(),
        inventory_dir: base.inventory_dir.clone(),
    }
}

/// Per-walker hostvars snapshot for the `per_play` strategy.
///
/// Each host's walker owns its working `HostCtx` by-value (as in
/// per_task), but ALSO publishes a clone into a shared
/// `Arc<RwLock<HostCtx>>` after each completed task. Peer reads
/// happen here: this function read-locks every entry in
/// `peer_views`, overlays the same field precedence as
/// [`merge_dynamic_hostvars`], and returns a fresh `WorldVars`
/// suitable for the next task render.
///
/// `self_name` / `self_ctx` lets the caller substitute the
/// currently-running host's view with the live working ctx instead
/// of the lagging snapshot. This matters when a task on host A
/// references `hostvars['a'].x` — A wants its own freshest value,
/// not what it last published.
///
/// Semantics differ slightly from per_task: peer views reflect the
/// peer's most-recently-completed task, not "all-hosts at start of
/// task K." Eventual rather than barrier-consistent. Documented in
/// CLAUDE.md under "Dynamic hostvars".
async fn merge_dynamic_hostvars_locked(
    base: &WorldVars,
    peer_views: &BTreeMap<String, Arc<TokioRwLock<HostCtx>>>,
    self_name: &str,
    self_ctx: &HostCtx,
) -> WorldVars {
    let mut hostvars = base.hostvars.clone();
    for (name, view_lock) in peer_views {
        let view = hostvars
            .entry(name.clone())
            .or_insert_with(BTreeMap::new);
        // Inline overlay so the borrow of `self_ctx` / `view_lock.read()`
        // lives only as long as needed without juggling Option<RwLockReadGuard>.
        let overlay = |ctx: &HostCtx, view: &mut BTreeMap<String, JsonValue>| {
            for (k, v) in &ctx.facts {
                view.insert(k.clone(), v.clone());
            }
            for (k, v) in &ctx.play_vars {
                view.insert(k.clone(), v.clone());
            }
            for (k, v) in &ctx.set_facts {
                view.insert(k.clone(), v.clone());
            }
            for (k, v) in &ctx.registers {
                view.insert(k.clone(), v.to_json());
            }
            for (k, v) in &ctx.extra_vars {
                view.insert(k.clone(), v.clone());
            }
            view.insert(
                "inventory_hostname".into(),
                JsonValue::String(ctx.host_name.clone()),
            );
        };
        if name == self_name {
            overlay(self_ctx, view);
        } else {
            let guard = view_lock.read().await;
            overlay(&*guard, view);
        }
    }
    WorldVars {
        groups: base.groups.clone(),
        hostvars,
        playbook_dir: base.playbook_dir.clone(),
        inventory_dir: base.inventory_dir.clone(),
    }
}

/// Render `play.vars` against each host's (role_defaults ∪ inventory_vars
/// ∪ facts) view and store the result in `ctx.play_vars`. Clears prior
/// plays' vars first.
fn apply_play_vars(
    play: &Play,
    targets: &[String],
    ctxs: &mut BTreeMap<String, HostCtx>,
    env: &Arc<Environment<'static>>,
    world: &WorldVars,
) {
    for name in targets {
        let Some(ctx) = ctxs.get_mut(name) else { continue };
        ctx.play_vars.clear();
        if play.vars.is_empty() {
            continue;
        }
        // Render against a ctx that exposes role_defaults + inventory_vars
        // + facts (no set_facts/registers/play_vars). Ansible allows
        // play.vars to reference role defaults and gathered facts but not
        // task-time state.
        let mut scratch = HostCtx::new(name.clone());
        scratch.role_defaults = ctx.role_defaults.clone();
        scratch.inventory_vars = ctx.inventory_vars.clone();
        scratch.facts = ctx.facts.clone();
        // extra_vars is run-start state, visible everywhere including
        // play.vars rendering (Ansible's behavior).
        scratch.extra_vars = ctx.extra_vars.clone();
        let view = build_template_ctx(&scratch, world);
        for (k, v) in &play.vars {
            let val = match v {
                serde_yaml::Value::String(s) => match render_str(env, s, &view) {
                    Ok(rendered) => {
                        let trimmed = rendered.trim();
                        if looks_jsonish(trimmed) {
                            serde_json::from_str::<JsonValue>(trimmed)
                                .unwrap_or(JsonValue::String(rendered))
                        } else {
                            JsonValue::String(rendered)
                        }
                    }
                    Err(e) => {
                        warn!(host = %name, play = %play.name, var = %k, "play.vars render failed: {e:#}");
                        continue;
                    }
                },
                other => match yaml_to_json(other.clone()) {
                    Ok(j) => j,
                    Err(e) => {
                        warn!(host = %name, play = %play.name, var = %k, "play.vars coerce failed: {e:#}");
                        continue;
                    }
                },
            };
            ctx.play_vars.insert(k.clone(), val);
        }
    }
}

/// Render `task.vars:` against the host's current view and write each
/// entry into `ctx.task_vars`. Each entry is rendered with all
/// previously-rendered entries already visible, so cross-references
/// between vars work (subject to BTreeMap key ordering — same caveat
/// as `apply_play_vars`).
fn apply_task_vars(
    vars: &BTreeMap<String, serde_yaml::Value>,
    ctx: &mut HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> anyhow::Result<()> {
    for (k, v) in vars {
        let view = build_template_ctx(ctx, world);
        let val = match v {
            serde_yaml::Value::String(s) => {
                let rendered = render_str(env, s, &view)
                    .with_context(|| format!("render task var {k:?}"))?;
                let trimmed = rendered.trim();
                if looks_jsonish(trimmed) {
                    serde_json::from_str::<JsonValue>(trimmed)
                        .unwrap_or(JsonValue::String(rendered))
                } else {
                    JsonValue::String(rendered)
                }
            }
            other => yaml_to_json(other.clone())
                .with_context(|| format!("coerce task var {k:?}"))?,
        };
        ctx.task_vars.insert(k.clone(), val);
    }
    Ok(())
}

// ---------- implicit gather_facts ----------

/// Transient register name the implicit gather task writes into. The
/// orchestrator drains it into `ctx.facts` and removes it before user
/// tasks run, so it's never visible in user templates.
const GATHER_FACTS_REGISTER: &str = "__rsansible_gather_facts__";

/// Synthetic `Gathering Facts` task — name is Ansible-conventional.
fn make_gather_facts_task() -> Task {
    Task {
        name: "Gathering Facts".to_string(),
        body: TaskBody::Op(TaskOp::GatherFacts),
        when: None,
        register: Some(GATHER_FACTS_REGISTER.to_string()),
        loop_spec: None,
        loop_control: None,
        // Tag with `always` so `--tags foo` doesn't accidentally drop
        // the implicit fact-gather (matches Ansible). Users who really
        // want to skip it can pass `--skip-tags always`.
        tags: vec!["always".to_string()],
        delegate_to: None,
        delegate_facts: false,
        run_once: false,
        notify: Vec::new(),
        role_dir: None,
        // Fact-gathering must always run as whoever the agent was
        // launched as — never sudo-wrapped (the agent runs the helper
        // in-process). Explicit `Some(false)` so a play-level
        // `become: true` doesn't accidentally wrap it.
        become_: Some(false),
        become_user: None,
        ignore_errors: None,
        // Fact-gathering reads /proc and produces facts; no side
        // effects. Always run for real even under `--check`.
        check_mode: Some(false),
        async_seconds: None,
        poll_seconds: None,
        retries: None,
        delay: None,
        until: None,
        changed_when: None,
        failed_when: None,
        no_log: None,
        vars: std::collections::BTreeMap::new(),
            environment: std::collections::BTreeMap::new(),
    }
}

/// Run the implicit `Gathering Facts` task against every live host in
/// parallel (regardless of the play's `strategy:` — each host gathers
/// its own facts; there's no broadcast). The stdout is parsed as a JSON
/// object and merged into `ctx.facts`. Failures are logged but don't
/// fail the play — matches Ansible.
async fn gather_facts_for_play(
    play: &Play,
    targets: &[String],
    pools: &Arc<BTreeMap<String, PoolHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
    tag_filter: &Arc<crate::tags::TagFilter>,
) -> Result<()> {
    if !play.gather_facts {
        return Ok(());
    }
    let task = make_gather_facts_task();
    // The synthetic gather task carries `tags: ["always"]`. Under
    // `--skip-tags always` (the documented Ansible escape hatch) the
    // filter rejects it; respect that.
    if !tag_filter.should_run(&task.tags) {
        info!(play = %play.name, "skipping implicit gather_facts (tag filter)");
        return Ok(());
    }
    let live: Vec<String> = targets
        .iter()
        .filter(|n| matches!(report.host_outcomes.get(*n), Some(HostOutcome::Ok)))
        .cloned()
        .collect();
    if live.is_empty() {
        return Ok(());
    }
    info!(play = %play.name, hosts = live.len(), "gathering facts");
    let mut set: JoinSet<PerHostTaskResult> = JoinSet::new();
    for name in &live {
        let own_pool = pools.get(name).expect("live host has pool").clone();
        let ctx = ctxs
            .remove(name)
            .unwrap_or_else(|| HostCtx::new(name.clone()));
        let task = task.clone();
        let seq_src = next_seq.clone();
        let env = env.clone();
        let world = world.clone();
        let pools_for = pools.clone();
        set.spawn(async move {
            // Synthetic single-task dispatch: no run_once coordination
            // needed (gather_facts is fan-out on every host, no blocks).
            let coord = RunOnceCoord::empty();
            let mut slot_counter: u32 = 0;
            run_task_on_one_host(
                &task,
                own_pool,
                pools_for,
                ctx,
                seq_src,
                env,
                world,
                coord,
                &mut slot_counter,
                /*is_runner=*/ true,
            )
            .await
        });
    }
    while let Some(joined) = set.join_next().await {
        let mut r = joined.context("gather_facts task panicked")?;
        // Drain the transient register; user code never sees it.
        let reg = r.ctx.registers.remove(GATHER_FACTS_REGISTER);
        match &r.outcome {
            HostTaskOutcome::Ok { .. } => {
                if let Some(reg) = reg {
                    match reg.json {
                        Some(JsonValue::Object(map)) => {
                            for (k, v) in map {
                                r.ctx.facts.insert(k, v);
                            }
                        }
                        Some(other) => {
                            warn!(
                                host = %r.name,
                                "gather_facts: stdout was JSON but not an object: {other:?}; ignoring"
                            );
                        }
                        None => {
                            warn!(
                                host = %r.name,
                                "gather_facts: stdout did not parse as JSON; ignoring"
                            );
                        }
                    }
                }
                debug!(host = %r.name, "facts gathered");
            }
            HostTaskOutcome::Skipped => {}
            HostTaskOutcome::Failed { reason, .. } => {
                warn!(
                    host = %r.name,
                    "gather_facts failed (continuing; play.gather_facts is best-effort): {reason}"
                );
            }
        }
        ctxs.insert(r.name, r.ctx);
    }
    Ok(())
}

// ---------- per-task strategy ----------

async fn run_play_per_task(
    play: &Play,
    targets: &[String],
    pools: &Arc<BTreeMap<String, PoolHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
    tag_filter: &Arc<crate::tags::TagFilter>,
) -> Result<bool> {
    for task in &play.tasks {
        // Refresh `world.hostvars` from every host's current state
        // BEFORE this task fans out. Any registers / set_facts / facts
        // a prior task established are now visible cross-host via
        // `{{ hostvars[<peer>].… }}`. See `merge_dynamic_hostvars` for
        // precedence + rationale.
        let world = Arc::new(merge_dynamic_hostvars(world, ctxs));

        // `meta: flush_handlers` is not dispatched to hosts — it's a
        // control-flow marker that drains the per-host pending queue.
        if let TaskBody::Meta(MetaAction::FlushHandlers) = &task.body {
            let stop =
                flush_handlers(play, targets, pools, ctxs, report, next_seq, env, &world).await?;
            if stop {
                return Ok(true);
            }
            continue;
        }

        // `--tags` / `--skip-tags` filter. Tag-skipped tasks are dropped
        // entirely — no per-host dispatch, no register binding, no
        // notify side-effects.
        if !tag_filter.should_run(&task.tags) {
            info!(
                play = %play.name,
                task = %task.name,
                tags = ?task.tags,
                "skipped (tag filter)",
            );
            continue;
        }

        // Live hosts for this task (skip ones already marked failed).
        let live: Vec<String> = targets
            .iter()
            .filter(|n| matches!(report.host_outcomes.get(*n), Some(HostOutcome::Ok)))
            .cloned()
            .collect();
        if live.is_empty() {
            info!(play = %play.name, task = %task.name, "no live hosts; skipping task");
            break;
        }

        let any_failed = if task.run_once {
            run_task_once_per_task(task, &live, pools, ctxs, report, next_seq, env, &world, play)
                .await?
        } else {
            run_task_fanout(task, &live, pools, ctxs, report, next_seq, env, &world, play).await?
        };

        if any_failed && play.on_failure == OnFailure::Stop {
            return Ok(true);
        }
    }
    // Implicit end-of-play flush. Same refresh discipline as the
    // task loop — handlers can also reference `{{ hostvars[…] }}`.
    let world = Arc::new(merge_dynamic_hostvars(world, ctxs));
    let stop = flush_handlers(play, targets, pools, ctxs, report, next_seq, env, &world).await?;
    Ok(stop)
}

/// Fan a task out across every live host, in parallel.
async fn run_task_fanout(
    task: &Task,
    live: &[String],
    pools: &Arc<BTreeMap<String, PoolHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
    play: &Play,
) -> Result<bool> {
    let mut set: JoinSet<PerHostTaskResult> = JoinSet::new();
    // Allocate a per-fanout coord covering this task's subtree. For
    // leaf tasks the coord has one slot (unused). For block tasks the
    // coord covers every nested task — that's what makes `run_once:`
    // on inner block tasks work under the per_task strategy. The first
    // live host is the designated runner for any `run_once:` inside.
    let coord = RunOnceCoord::allocate(std::slice::from_ref(task));
    let runner_name = live.first().cloned();
    for name in live {
        let own_pool = pools.get(name).expect("live host has pool").clone();
        let ctx = ctxs
            .remove(name)
            .unwrap_or_else(|| HostCtx::new(name.clone()));
        let task = task.clone();
        let seq_src = next_seq.clone();
        let env = env.clone();
        let world = world.clone();
        let pools_for = pools.clone();
        let coord = coord.clone();
        let is_runner = runner_name.as_deref() == Some(name.as_str());
        let name_owned = name.clone();
        set.spawn(async move {
            let _ = name_owned;
            let mut slot_counter: u32 = 0;
            // Always go through `dispatch_one_task` for the entry-level
            // task: that's the function that increments the counter
            // past the task's own slot before recursing into a block.
            // Calling `run_task_on_one_host` directly would leave the
            // counter at slot 0 (the block's own slot), so the first
            // inner task would look up the wrong cell.
            dispatch_one_task(
                &task,
                own_pool,
                pools_for,
                ctx,
                seq_src,
                env,
                world,
                coord,
                &mut slot_counter,
                is_runner,
            )
            .await
        });
    }
    let mut any_failed = false;
    while let Some(joined) = set.join_next().await {
        let r = joined.context("per-host task panicked")?;
        let host_failed = apply_per_host_result(play, task, r, pools, ctxs, report).await;
        any_failed = any_failed || host_failed;
    }
    Ok(any_failed)
}

/// run_once under per_task: pick one runner, execute, broadcast result to
/// every other live host's ctx.
async fn run_task_once_per_task(
    task: &Task,
    live: &[String],
    pools: &Arc<BTreeMap<String, PoolHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
    play: &Play,
) -> Result<bool> {
    // Pick the runner. We don't pre-resolve delegate_to here — the
    // originating host's ctx is what feeds template rendering, so the
    // resolution happens inside run_task_on_one_host. The runner is the
    // first live host (deterministic by inventory order).
    let runner = live[0].clone();
    let other_targets: Vec<String> = live.iter().filter(|n| **n != runner).cloned().collect();

    debug!(
        play = %play.name,
        task = %task.name,
        runner = %runner,
        others = other_targets.len(),
        "run_once dispatch",
    );

    let own_pool = pools.get(&runner).expect("runner has pool").clone();
    let ctx = ctxs
        .remove(&runner)
        .unwrap_or_else(|| HostCtx::new(runner.clone()));
    // Single-task dispatch — `run_once: true` on a `block:` is rejected
    // at parse time, so this task is a leaf. An empty coord suffices;
    // run_once broadcast is handled by this function's body via the
    // `other_targets` loop below.
    let coord = RunOnceCoord::empty();
    let mut slot_counter: u32 = 0;
    let result = run_task_on_one_host(
        task,
        own_pool,
        pools.clone(),
        ctx,
        next_seq.clone(),
        env.clone(),
        world.clone(),
        coord,
        &mut slot_counter,
        /*is_runner=*/ true,
    )
    .await;

    // Snapshot what should be broadcast before we move `result.ctx` back.
    let register_for_broadcast = task
        .register
        .as_ref()
        .and_then(|n| result.ctx.registers.get(n).cloned());
    let set_facts_snapshot: BTreeMap<String, JsonValue> = match &task.body {
        TaskBody::SetFact(_) => result.ctx.set_facts.clone(),
        _ => BTreeMap::new(),
    };
    let notify_snapshot: BTreeSet<String> = task.notify.iter().cloned().collect();
    let notify_fired = matches!(result.outcome, HostTaskOutcome::Ok { .. })
        && !task.notify.is_empty()
        && register_for_broadcast
            .as_ref()
            .map(|r| r.changed)
            .unwrap_or(true);

    let runner_failed = apply_per_host_result(play, task, result, pools, ctxs, report).await;
    // Broadcast to other live hosts (regardless of runner outcome — if it
    // failed they all see the failed register too, mirroring Ansible).
    for other in &other_targets {
        let Some(ctx) = ctxs.get_mut(other) else {
            continue;
        };
        if let (Some(name), Some(rv)) = (task.register.as_ref(), register_for_broadcast.as_ref()) {
            ctx.registers.insert(name.clone(), rv.clone());
        }
        if matches!(&task.body, TaskBody::SetFact(_)) && !runner_failed {
            for (k, v) in &set_facts_snapshot {
                ctx.set_facts.insert(k.clone(), v.clone());
            }
        }
        if notify_fired {
            for n in &notify_snapshot {
                // Render against the *other host's* ctx — the templated
                // notify name should reflect that host's view of vars.
                let rendered = match render_str(env, n, &build_template_ctx(ctx, world)) {
                    Ok(s) => s,
                    Err(_) => n.clone(),
                };
                ctx.pending_handlers.insert(rendered);
            }
        }
    }
    Ok(runner_failed)
}

// ---------- per-play strategy ----------

async fn run_play_per_play(
    play: &Play,
    targets: &[String],
    pools: &Arc<BTreeMap<String, PoolHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
    tag_filter: &Arc<crate::tags::TagFilter>,
) -> Result<bool> {
    // Snapshot the live target set; per-host futures don't see each other.
    let live: Vec<String> = targets
        .iter()
        .filter(|n| matches!(report.host_outcomes.get(*n), Some(HostOutcome::Ok)))
        .cloned()
        .collect();
    if live.is_empty() {
        return Ok(false);
    }

    // One coord shared across every per-host walker. Covers the full
    // play.tasks tree in pre-order DFS: top-level tasks AND every task
    // nested inside `block:` arms. `run_once: true` is honored at any
    // depth — runner host fills its slot's OnceCell, every non-runner
    // walker awaits the cell and broadcasts the result without
    // re-executing the body.
    let coord = RunOnceCoord::allocate(&play.tasks);

    // Per-host snapshot map for dynamic `hostvars[<peer>]` lookups.
    // Each walker publishes its working ctx into its own slot at every
    // task barrier; peer walkers read-lock these slots when building
    // their next-task world. See `merge_dynamic_hostvars_locked` for
    // the semantic (eventual peer consistency under per_play).
    let peer_views: Arc<BTreeMap<String, Arc<TokioRwLock<HostCtx>>>> = Arc::new(
        live.iter()
            .map(|n| {
                let initial = ctxs.get(n).cloned().unwrap_or_else(|| HostCtx::new(n.clone()));
                (n.clone(), Arc::new(TokioRwLock::new(initial)))
            })
            .collect(),
    );

    let on_failure = play.on_failure;
    let handlers: Arc<Vec<Task>> = Arc::new(play.handlers.clone());
    let mut set: JoinSet<PerPlayHostResult> = JoinSet::new();
    for name in &live {
        let tasks: Vec<Task> = play.tasks.clone();
        let play_name = play.name.clone();
        let seq_src = next_seq.clone();
        let env = env.clone();
        let base_world = world.clone();
        let pools_for = pools.clone();
        let own_pool = pools.get(name).expect("live host has pool").clone();
        let ctx = ctxs
            .remove(name)
            .unwrap_or_else(|| HostCtx::new(name.clone()));
        let coord_for_host = coord.clone();
        let name_owned = name.clone();
        let handlers = handlers.clone();
        let live_names = live.clone();
        let tag_filter = tag_filter.clone();
        let peer_views = peer_views.clone();
        set.spawn(async move {
            let mut ctx = ctx;
            let mut first_failure: Option<(String, String)> = None;
            let is_runner = name_owned == live_names[0];
            let mut slot_counter: u32 = 0;
            for (i, task) in tasks.iter().enumerate() {
                let _ = i; // index retained for diagnostics if needed
                // Refresh the per-walker `WorldVars` from the published
                // peer snapshots before every task. This is per_play's
                // analogue of per_task's between-task barrier refresh,
                // but eventual: peer slots reflect their owner's most
                // recently completed task, not a global barrier.
                let local_world = Arc::new(
                    merge_dynamic_hostvars_locked(
                        &base_world,
                        &peer_views,
                        &name_owned,
                        &ctx,
                    )
                    .await,
                );
                // Every task in the tree owns a coord slot; advance
                // through skipped/meta/tag-filtered tasks so the
                // counter stays in lockstep with hosts that didn't
                // skip them.
                let advance_past_task = |counter: &mut u32, coord: &RunOnceCoord| {
                    let slot = *counter;
                    let size = coord.subtree_size(slot);
                    *counter = slot + size;
                };
                // Meta tasks: flush handlers inline.
                if let TaskBody::Meta(MetaAction::FlushHandlers) = &task.body {
                    advance_past_task(&mut slot_counter, &coord_for_host);
                    let stop_handler_failure = run_handlers_one_host(
                        &handlers,
                        own_pool.clone(),
                        pools_for.clone(),
                        &mut ctx,
                        seq_src.clone(),
                        env.clone(),
                        local_world.clone(),
                        &play_name,
                    )
                    .await;
                    if let Some((hn, reason)) = stop_handler_failure {
                        if first_failure.is_none() {
                            first_failure = Some((hn, reason));
                        }
                        if matches!(on_failure, OnFailure::Stop | OnFailure::MarkHostFailed) {
                            break;
                        }
                    }
                    continue;
                }

                // `--tags` / `--skip-tags` filter. Tag-skipped tasks are
                // dropped entirely; the matching `OnceCell` slot stays
                // unused (a tag-skipped run_once task simply doesn't run
                // on any host).
                if !tag_filter.should_run(&task.tags) {
                    advance_past_task(&mut slot_counter, &coord_for_host);
                    if name_owned == live_names[0] {
                        // Log once per filtered task — only the first
                        // host emits; others would be redundant noise.
                        info!(
                            play = %play_name,
                            task = %task.name,
                            tags = ?task.tags,
                            "skipped (tag filter)",
                        );
                    }
                    continue;
                }

                let r: PerHostTaskResult = dispatch_one_task(
                    task,
                    own_pool.clone(),
                    pools_for.clone(),
                    ctx,
                    seq_src.clone(),
                    env.clone(),
                    local_world.clone(),
                    coord_for_host.clone(),
                    &mut slot_counter,
                    is_runner,
                )
                .await;
                ctx = r.ctx;
                // Publish working ctx to this host's RwLock so peer
                // walkers see the post-task state on their next refresh.
                {
                    if let Some(slot) = peer_views.get(&name_owned) {
                        let mut guard = slot.write().await;
                        *guard = ctx.clone();
                    }
                }
                match &r.outcome {
                    HostTaskOutcome::Ok { .. } | HostTaskOutcome::Skipped => {}
                    HostTaskOutcome::Failed { reason, .. } => {
                        if first_failure.is_none() {
                            first_failure = Some((task.name.clone(), reason.clone()));
                        }
                        if matches!(on_failure, OnFailure::Stop | OnFailure::MarkHostFailed) {
                            break;
                        }
                    }
                }
                if !r.conn_alive {
                    // Conn died; mark every slot in this host's pool
                    // dead so any subsequent delegate hop (and the
                    // best-effort Bye) sees `None` rather than trying
                    // to spawn fresh agents on a host the orchestrator
                    // has already given up on.
                    let pool = own_pool.lock().await;
                    pool.kill_all().await;
                    drop(pool);
                    break;
                }
                info!(host = %name_owned, play = %play_name, task = %task.name, "task done");
            }
            // End-of-play implicit flush for this host (only if not already
            // bailed under a fatal on_failure).
            if first_failure.is_none()
                || matches!(on_failure, OnFailure::Continue)
            {
                let flush_world = Arc::new(
                    merge_dynamic_hostvars_locked(
                        &base_world,
                        &peer_views,
                        &name_owned,
                        &ctx,
                    )
                    .await,
                );
                if let Some((hn, reason)) = run_handlers_one_host(
                    &handlers,
                    own_pool.clone(),
                    pools_for.clone(),
                    &mut ctx,
                    seq_src.clone(),
                    env.clone(),
                    flush_world,
                    &play_name,
                )
                .await
                {
                    if first_failure.is_none() {
                        first_failure = Some((hn, reason));
                    }
                }
            }
            PerPlayHostResult {
                name: name_owned,
                ctx,
                first_failure,
            }
        });
    }

    let mut any_failed = false;
    while let Some(joined) = set.join_next().await {
        let r = joined.context("per-host play task panicked")?;
        if let Some((task, reason)) = &r.first_failure {
            any_failed = true;
            report.host_outcomes.insert(
                r.name.clone(),
                HostOutcome::Failed {
                    task: task.clone(),
                    reason: reason.clone(),
                },
            );
            // Drop every conn in the host's pool under
            // mark_host_failed / stop so they don't carry into the
            // next play.
            if matches!(on_failure, OnFailure::MarkHostFailed | OnFailure::Stop) {
                if let Some(pool_handle) = pools.get(&r.name) {
                    let pool = pool_handle.lock().await;
                    pool.kill_all().await;
                    debug!(host = %r.name, "dropping pool conns (on_failure={:?})", on_failure);
                }
            }
        }
        ctxs.insert(r.name, r.ctx);
    }

    Ok(any_failed && on_failure == OnFailure::Stop)
}

/// Snapshot stashed in a per-task OnceCell so non-runner hosts under
/// per_play+run_once can broadcast the runner's result into their own ctx
/// without re-executing the body.
#[derive(Clone)]
struct RunOnceResult {
    register: Option<RegisterValue>,
    set_facts: BTreeMap<String, JsonValue>,
    success: bool,
    outcome: HostTaskOutcome,
}

fn clone_outcome(o: &HostTaskOutcome) -> HostTaskOutcome {
    match o {
        HostTaskOutcome::Ok { changed, skipped } => HostTaskOutcome::Ok {
            changed: *changed,
            skipped: *skipped,
        },
        HostTaskOutcome::Skipped => HostTaskOutcome::Skipped,
        HostTaskOutcome::Failed { reason, register } => HostTaskOutcome::Failed {
            reason: reason.clone(),
            register: register.clone(),
        },
    }
}

struct PerPlayHostResult {
    name: String,
    ctx: HostCtx,
    first_failure: Option<(String, String)>,
}

// ---------- single-host single-task driver ----------

#[derive(Debug, Clone)]
enum HostTaskOutcome {
    Ok {
        /// Module reported `changed=true` (or under `--check`, would have
        /// changed). Used for the end-of-run summary.
        changed: bool,
        /// Module declined to mutate under `--check`, or skipped outright
        /// (exec/shell/mutating uri). Distinct from `changed=false` —
        /// see RunReport docs.
        skipped: bool,
    },
    Skipped,
    Failed {
        reason: String,
        /// Register-shape result of the failing task (if any). The
        /// `block:` executor uses this to populate
        /// `ansible_failed_result` during rescue arm execution so
        /// recovery tasks can branch on the failed task's exit code,
        /// stderr, etc. (`{{ ansible_failed_result.rc }}` etc.).
        ///
        /// `None` for failures with no register payload — e.g.
        /// `when:` render errors, `delegate_to:` render errors,
        /// loop-spec render errors. The rescue arm still runs in
        /// those cases; `ansible_failed_result` is simply Undefined.
        register: Option<RegisterValue>,
    },
}

struct PerHostTaskResult {
    name: String,
    ctx: HostCtx,
    outcome: HostTaskOutcome,
    /// Whether the *originating host's* conn is still usable. False when
    /// the host's own conn died mid-task (independently of any delegate
    /// hop). Callers reflect this into the conns map.
    conn_alive: bool,
}

/// Execute one task on one host, including loop expansion and delegation.
///
/// `own_pool` is this host's per-host [`AgentPool`]; if `task.delegate_to`
/// is set and resolves to another host, the body runs against *that*
/// host's pool. Register/set_fact/notify side effects still land on this
/// host's ctx (Ansible semantics).
///
/// The pool slot (i.e. which agent process handles the wire ops) is
/// chosen per-body-call from the task's effective [`BecomeKey`]. Loop
/// iterations re-resolve become per item so a `become_user: "{{ item }}"`
/// pattern routes each iteration to its matching slot.
async fn run_task_on_one_host(
    task: &Task,
    own_pool: PoolHandle,
    pools: Arc<BTreeMap<String, PoolHandle>>,
    mut ctx: HostCtx,
    next_seq: Arc<AtomicU32>,
    env: Arc<Environment<'static>>,
    world: Arc<WorldVars>,
    coord: RunOnceCoord,
    slot_counter: &mut u32,
    is_runner: bool,
) -> PerHostTaskResult {
    let name = ctx.host_name.clone();

    // Task-scoped `vars:` come into effect *before* anything else
    // (including `when:`). Each entry is rendered in BTreeMap order
    // against a ctx that already sees earlier-rendered task_vars, so
    // playbooks can chain `vars:` entries that reference each other
    // (alphabetical key ordering controls the chain — matches the
    // same constraint that play.vars already lives with). Clears
    // any prior task's slot so vars never bleed across tasks.
    ctx.task_vars.clear();
    if !task.vars.is_empty() {
        if let Err(e) = apply_task_vars(&task.vars, &mut ctx, &env, &world) {
            return PerHostTaskResult {
                name,
                ctx,
                outcome: HostTaskOutcome::Failed {
                    reason: format!("vars: {e:#}"),
                    register: None,
                },
                conn_alive: true,
            };
        }
    }

    // when: evaluation — bypasses everything else if false.
    match eval_when(&env, task.when.as_deref(), &ctx, &world) {
        Ok(true) => {}
        Ok(false) => {
            if let Some(reg) = &task.register {
                ctx.record_register(reg, RegisterValue::skipped_marker());
            }
            debug!(host = %name, task = %task.name, "skipped (when=false)");
            return PerHostTaskResult {
                name,
                ctx,
                outcome: HostTaskOutcome::Skipped,
                conn_alive: true,
            };
        }
        Err(e) => {
            let reason = format!("when: {e:#}");
            return PerHostTaskResult {
                name,
                ctx,
                outcome: HostTaskOutcome::Failed { reason, register: None },
                conn_alive: true,
            };
        }
    }

    // Block dispatch: a `block:` task is a controller-side grouping,
    // not a body to dispatch. Hand off to the block driver, which
    // handles loop expansion + the block→rescue→always state machine.
    // (when: was already evaluated above; loop is the block driver's
    // job since the block-level loop iterates the whole triple per
    // item.)
    //
    // We Box::pin the recursive call because Rust requires
    // recursive async functions to introduce indirection — without
    // it the compiler can't size the returned Future (it would
    // contain itself transitively via run_block_on_one_host →
    // run_task_list_on_host → run_task_on_one_host → here).
    if let TaskBody::Block(block) = &task.body {
        return Box::pin(run_block_on_one_host(
            task,
            block,
            own_pool,
            pools,
            ctx,
            next_seq,
            env,
            world,
            coord,
            slot_counter,
            is_runner,
        ))
        .await;
    }

    // Resolve loop items (None → run once with no iter_item).
    let items: Vec<JsonValue> = match resolve_loop_items(&env, task.loop_spec.as_ref(), &ctx, &world) {
        Ok(items) => items,
        Err(e) => {
            return PerHostTaskResult {
                name,
                ctx,
                outcome: HostTaskOutcome::Failed {
                    reason: format!("loop: {e:#}"),
                    register: None,
                },
                conn_alive: true,
            };
        }
    };
    let loop_var = task
        .loop_control
        .as_ref()
        .and_then(|lc| lc.loop_var.clone())
        .unwrap_or_else(|| "item".to_string());

    // Helper closure: resolve the BecomeKey + target pool + slot
    // ConnHandle for this body call, in one shot. Per-iteration
    // resolution (rather than hoisting outside the loop) so that
    // `become_user: "{{ item }}"` or `delegate_to: "{{ item.host }}"`
    // see the current iter_item context.
    //
    // We don't materialize this as a free `async fn` because that
    // would force all the borrowed pieces (env, world, pools,
    // own_pool, task) to be passed explicitly and would lose
    // ergonomics; instead we inline an async block at each call site
    // via the `resolve_target!` macro below.
    macro_rules! resolve_target {
        ($ctx:expr) => {{
            let ctx_ref: &HostCtx = $ctx;
            let res: Result<ConnHandle, String> = async {
                let eff = become_::effective(task, ctx_ref, &env, &world)
                    .map_err(|e| format!("become resolve: {e:#}"))?;
                let key = BecomeKey::from_effective(&eff);
                let target_pool = match &task.delegate_to {
                    None => own_pool.clone(),
                    Some(expr) => {
                        let view = build_template_ctx(ctx_ref, &world);
                        let rendered = render_str(&env, expr, &view)
                            .map_err(|e| format!("delegate_to render: {e:#}"))?;
                        pools.get(&rendered).cloned().ok_or_else(|| {
                            format!("delegate_to references unknown host {rendered:?}")
                        })?
                    }
                };
                let mut p = target_pool.lock().await;
                p.get_or_spawn(&key)
                    .await
                    .map_err(|e| format!("spawn agent for {}: {e:#}", key.label()))
            }
            .await;
            res
        }};
    }

    let mut own_conn_alive = true;

    if task.loop_spec.is_none() {
        // Single execution.
        let target = match resolve_target!(&ctx) {
            Ok(t) => t,
            Err(reason) => {
                return PerHostTaskResult {
                    name,
                    ctx,
                    outcome: HostTaskOutcome::Failed { reason, register: None },
                    conn_alive: true,
                };
            }
        };
        let exec =
            run_body_with_retries(task, &target, &mut ctx, &env, &world, &next_seq).await;
        let outcome = match exec {
            BodyResult::Ok { register, changed, skipped } => {
                if let Some(reg_name) = &task.register {
                    ctx.record_register(reg_name, register);
                }
                enqueue_notifies(task, changed, false, &mut ctx, &env, &world);
                HostTaskOutcome::Ok { changed, skipped }
            }
            BodyResult::Failed { reason, register, conn_alive } => {
                // Bind `register` to the failed task's register-shape
                // result if any. We need to record it onto the host's
                // register dict (when `task.register` is set) AND
                // surface it back to the per-host result so the
                // block-rescue arm can populate `ansible_failed_result`
                // (the rescue runner reads it off HostTaskOutcome::
                // Failed.register regardless of whether the failing
                // task had a `register:` clause of its own).
                if let (Some(reg_name), Some(rv)) = (&task.register, &register) {
                    ctx.record_register(reg_name, rv.clone());
                }
                ctx.failed = true;
                // Conn liveness only flips own_conn_alive when the dead
                // conn IS this host's. A failed delegate hop doesn't kill
                // the originator.
                if !conn_alive && task.delegate_to.is_none() {
                    own_conn_alive = false;
                }
                HostTaskOutcome::Failed { reason, register }
            }
        };
        let outcome = maybe_ignore_failure(task, outcome, &name);
        return PerHostTaskResult {
            name,
            ctx,
            outcome,
            conn_alive: own_conn_alive,
        };
    }

    // Looped execution. We always run all iterations and aggregate.
    let mut iter_registers: Vec<RegisterValue> = Vec::with_capacity(items.len());
    let mut any_failed: Option<String> = None;
    for item in items {
        ctx.iter_item = Some((loop_var.clone(), item));
        if !own_conn_alive && task.delegate_to.is_none() {
            iter_registers.push(RegisterValue {
                failed: true,
                rc: -1,
                stderr: "conn dropped before this iteration".into(),
                ..Default::default()
            });
            continue;
        }
        let target = match resolve_target!(&ctx) {
            Ok(t) => t,
            Err(reason) => {
                if any_failed.is_none() {
                    any_failed = Some(reason.clone());
                }
                iter_registers.push(RegisterValue {
                    failed: true,
                    rc: -1,
                    stderr: reason,
                    ..Default::default()
                });
                continue;
            }
        };
        let exec =
            run_body_with_retries(task, &target, &mut ctx, &env, &world, &next_seq).await;
        match exec {
            BodyResult::Ok { register, changed: _, skipped: _ } => {
                iter_registers.push(register);
            }
            BodyResult::Failed { reason, register, conn_alive } => {
                if any_failed.is_none() {
                    any_failed = Some(reason.clone());
                }
                iter_registers.push(register.unwrap_or_else(|| RegisterValue {
                    failed: true,
                    rc: -1,
                    stderr: reason.clone(),
                    ..Default::default()
                }));
                if !conn_alive && task.delegate_to.is_none() {
                    own_conn_alive = false;
                }
            }
        }
    }
    ctx.iter_item = None;
    let any_changed = iter_registers.iter().any(|r| r.changed);
    let all_skipped = !iter_registers.is_empty() && iter_registers.iter().all(|r| r.skipped);
    let any_iter_failed = iter_registers.iter().any(|r| r.failed);
    let aggregate = RegisterValue {
        changed: any_changed,
        failed: any_iter_failed,
        results: Some(iter_registers),
        ..Default::default()
    };
    let aggregate_for_failure = aggregate.clone();
    if let Some(reg_name) = &task.register {
        ctx.record_register(reg_name, aggregate);
    }
    let outcome = match any_failed {
        None => {
            enqueue_notifies(task, any_changed, false, &mut ctx, &env, &world);
            HostTaskOutcome::Ok { changed: any_changed, skipped: all_skipped }
        }
        Some(reason) => {
            ctx.failed = true;
            // Surface the per-iteration aggregate as the register on
            // the failure outcome so block-rescue can populate
            // `ansible_failed_result.results[*]` (and `.failed`).
            HostTaskOutcome::Failed {
                reason,
                register: Some(aggregate_for_failure),
            }
        }
    };
    let outcome = maybe_ignore_failure(task, outcome, &name);
    PerHostTaskResult {
        name,
        ctx,
        outcome,
        conn_alive: own_conn_alive,
    }
}

// ---------- run_once coordination ----------

/// Cross-host coordination for `run_once: true` tasks — including tasks
/// nested inside a `block:`.
///
/// The per-play (or per-fanout) dispatcher pre-walks the task tree in
/// pre-order DFS and allocates one [`OnceCell`] per Task slot. Every
/// per-host walker that traverses the same tree shares the same
/// `RunOnceCoord` (the cells are `Arc`-wrapped). Each walker carries a
/// local `slot_counter: u32` that advances as it visits tasks in the
/// same pre-order. So all walkers reach the same slot index for the
/// same task, even across nested blocks.
///
/// When a walker hits a `run_once: true` task it consults
/// [`Self::cell`]: the designated runner host fills the cell with its
/// result; every other host awaits the cell and broadcasts the
/// runner's register/set_facts/notifies into its own ctx without
/// re-executing the body.
///
/// `subtree_sizes[i]` is the pre-order subtree size for the task at
/// slot `i` (including the task itself). Used to compensate the local
/// counter when a task short-circuits — `when:`-skipped, render-error,
/// loop-spec-error, etc. — without recursing into its block children.
/// Without this, hosts that took the early-exit path would desync
/// their counter from hosts that walked into the block.
///
/// Parse-time enforcement keeps the rules manageable: `run_once:` on a
/// `block:` is rejected, so a run_once slot can never have child slots.
/// That's why the runner/non-runner branches only need to handle a
/// single task body, not a subtree.

/// Per-slot signalling cell for run_once coordination.
///
/// We need a primitive where ONE task (the runner) sets a value, and
/// MANY other tasks (non-runners) await that value externally — and
/// the wake has to come from the setter, not from inside the awaiter.
///
/// `tokio::sync::OnceCell` alone doesn't satisfy this: `get_or_init`
/// with a `pending()` future LOCKS the cell's init slot, so the
/// runner's later `.set()` returns `Err` (silently swallowed) and the
/// non-runner's pending future never wakes. Combining `OnceCell` with
/// a `Notify` fixes it: `OnceCell` keeps the set-once + take-the-value
/// semantics; `Notify` carries the external wake.
struct RunOnceSlot {
    cell: OnceCell<RunOnceResult>,
    notify: Notify,
}

impl RunOnceSlot {
    fn new() -> Self {
        Self {
            cell: OnceCell::new(),
            notify: Notify::new(),
        }
    }

    /// Publish the result and wake every current waiter. No-op (silent)
    /// if a value has already been published — same semantics callers
    /// relied on with the bare `OnceCell::set` we used previously.
    fn publish(&self, value: RunOnceResult) {
        if self.cell.set(value).is_ok() {
            // Only notify on the actual transition empty→set. Future
            // waiters that subscribe after the publish will see the
            // value on their initial check inside `wait` and won't
            // need a notification.
            self.notify.notify_waiters();
        }
    }

    /// Block until a value has been published, then return a clone.
    ///
    /// Register interest on the Notify BEFORE checking the cell, so we
    /// can't miss a publish that lands between our check and our await
    /// — `Notify::notified()` is a permit; if `notify_waiters` fires
    /// before our `.await`, the permit is already there and `.await`
    /// returns immediately.
    async fn wait(&self) -> RunOnceResult {
        loop {
            let notified = self.notify.notified();
            if let Some(v) = self.cell.get() {
                return v.clone();
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
struct RunOnceCoord {
    cells: Arc<Vec<Arc<RunOnceSlot>>>,
    subtree_sizes: Arc<Vec<u32>>,
}

impl RunOnceCoord {
    /// Pre-walk `tasks` in pre-order DFS, assigning one slot per
    /// visited Task (including tasks nested in `block:` arms). Returns
    /// a coord whose `cells[i]` is a fresh slot and whose
    /// `subtree_sizes[i]` is the pre-order subtree size of the task at
    /// slot `i`.
    fn allocate(tasks: &[Task]) -> Self {
        let mut sizes = Vec::new();
        collect_subtree_sizes(tasks, &mut sizes);
        let n = sizes.len();
        Self {
            cells: Arc::new((0..n).map(|_| Arc::new(RunOnceSlot::new())).collect()),
            subtree_sizes: Arc::new(sizes),
        }
    }

    /// Empty coord — for synthetic dispatch paths that don't traverse
    /// a task tree (gather_facts, handler dispatch, test helpers).
    /// Slot lookups return `None` and the counter never advances past
    /// the (empty) vec; callers must not invoke run_once dispatch
    /// against an empty coord.
    fn empty() -> Self {
        Self {
            cells: Arc::new(Vec::new()),
            subtree_sizes: Arc::new(Vec::new()),
        }
    }

    fn cell(&self, slot: u32) -> Option<Arc<RunOnceSlot>> {
        self.cells.get(slot as usize).cloned()
    }

    /// Subtree size for the task at `slot`. Returns 1 if the slot is
    /// out-of-bounds (defensive — shouldn't happen on a well-formed
    /// coord, but means an empty coord behaves like "every task is a
    /// leaf" for compensation purposes).
    fn subtree_size(&self, slot: u32) -> u32 {
        self.subtree_sizes.get(slot as usize).copied().unwrap_or(1)
    }
}

/// Pre-order DFS visit: for each task in `tasks`, push a placeholder,
/// recurse into the block arms if any, then fix up the placeholder
/// with the visited count.
fn collect_subtree_sizes(tasks: &[Task], out: &mut Vec<u32>) {
    for task in tasks {
        let self_idx = out.len();
        out.push(0); // placeholder; filled in after children visited.
        if let TaskBody::Block(block) = &task.body {
            collect_subtree_sizes(&block.tasks, out);
            collect_subtree_sizes(&block.rescue, out);
            collect_subtree_sizes(&block.always, out);
        }
        out[self_idx] = (out.len() - self_idx) as u32;
    }
}

/// Dispatch a single task, applying run_once coordination if the task
/// has `run_once: true` and a slot in the coord. Otherwise delegates
/// straight to [`run_task_on_one_host`]. Always advances
/// `slot_counter` past this task's subtree before returning, so that
/// hosts that early-exited (when:false, render error, etc.) stay
/// counter-synchronized with hosts that walked the full subtree.
async fn dispatch_one_task(
    task: &Task,
    own_pool: PoolHandle,
    pools: Arc<BTreeMap<String, PoolHandle>>,
    ctx: HostCtx,
    next_seq: Arc<AtomicU32>,
    env: Arc<Environment<'static>>,
    world: Arc<WorldVars>,
    coord: RunOnceCoord,
    slot_counter: &mut u32,
    is_runner: bool,
) -> PerHostTaskResult {
    let slot = *slot_counter;
    let subtree_size = coord.subtree_size(slot);
    // Self counted now; nested-block subtree slots are consumed by the
    // recursive dispatch_one_task calls inside run_block_on_one_host.
    *slot_counter = slot + 1;

    let result = if task.run_once {
        match coord.cell(slot) {
            Some(cell) => {
                if is_runner {
                    let r = Box::pin(run_task_on_one_host(
                        task,
                        own_pool,
                        pools,
                        ctx,
                        next_seq,
                        env,
                        world,
                        coord.clone(),
                        slot_counter,
                        is_runner,
                    ))
                    .await;
                    // Publish to cell so non-runners can broadcast.
                    let register_val = task
                        .register
                        .as_ref()
                        .and_then(|n| r.ctx.registers.get(n).cloned());
                    let set_facts_snap: BTreeMap<String, JsonValue> = match &task.body {
                        TaskBody::SetFact(_) => r.ctx.set_facts.clone(),
                        _ => BTreeMap::new(),
                    };
                    let success = matches!(r.outcome, HostTaskOutcome::Ok { .. });
                    cell.publish(RunOnceResult {
                        register: register_val,
                        set_facts: set_facts_snap,
                        success,
                        outcome: clone_outcome(&r.outcome),
                    });
                    r
                } else {
                    // Non-runner: wait for the runner to publish, then
                    // apply broadcast effects locally. Note: we go
                    // through the slot's own `wait` method (OnceCell +
                    // Notify) rather than `OnceCell::get_or_init` —
                    // the latter would lock the init slot with our
                    // pending future, so the runner's `.set()` would
                    // silently fail and we'd hang forever.
                    let waited = cell.wait().await;
                    let mut ctx = ctx;
                    let name = ctx.host_name.clone();
                    if let (Some(reg_name), Some(rv)) =
                        (task.register.as_ref(), waited.register.as_ref())
                    {
                        ctx.registers.insert(reg_name.clone(), rv.clone());
                    }
                    if matches!(&task.body, TaskBody::SetFact(_)) && waited.success {
                        for (k, v) in &waited.set_facts {
                            ctx.set_facts.insert(k.clone(), v.clone());
                        }
                    }
                    if waited.success
                        && !task.notify.is_empty()
                        && waited
                            .register
                            .as_ref()
                            .map(|r| r.changed)
                            .unwrap_or(true)
                    {
                        for n in &task.notify {
                            let rendered = match render_str(
                                &env,
                                n,
                                &build_template_ctx(&ctx, &world),
                            ) {
                                Ok(s) => s,
                                Err(_) => n.clone(),
                            };
                            ctx.pending_handlers.insert(rendered);
                        }
                    }
                    PerHostTaskResult {
                        name,
                        ctx,
                        outcome: clone_outcome(&waited.outcome),
                        conn_alive: true,
                    }
                }
            }
            // No cell in the coord for this slot — fall back to
            // executing on every host. Should only happen for
            // synthetic dispatch (empty coord); normal play dispatch
            // pre-allocates one cell per task.
            None => Box::pin(run_task_on_one_host(
                task,
                own_pool,
                pools,
                ctx,
                next_seq,
                env,
                world,
                coord.clone(),
                slot_counter,
                is_runner,
            ))
            .await,
        }
    } else {
        Box::pin(run_task_on_one_host(
            task,
            own_pool,
            pools,
            ctx,
            next_seq,
            env,
            world,
            coord.clone(),
            slot_counter,
            is_runner,
        ))
        .await
    };

    // Compensate for early-exit paths that didn't recurse into a block:
    // when:false, vars: render error, loop-spec render error, etc.
    // After this call, the counter MUST be at slot+subtree_size so the
    // next sibling task's slot lookup is correct on every host.
    let expected_end = slot + subtree_size;
    if *slot_counter < expected_end {
        *slot_counter = expected_end;
    }

    result
}

// ---------- block / rescue / always driver ----------

/// Result of walking a task list on one host. Returned by
/// `run_task_list_on_host`; consumed by the block driver to decide
/// whether to fire `rescue` and to thread `ansible_failed_*` into the
/// rescue arm.
struct TaskListResult {
    /// Per-host state after every task in the list ran (or after the
    /// first failure caused an early break).
    ctx: HostCtx,
    /// False if any task within the list left this host's connection
    /// dead. Caller (block driver) propagates outward.
    conn_alive: bool,
    /// First non-recoverable failure observed in the list: the failing
    /// task's name, its reason string, and its register-shape result
    /// (if any). `None` means every task either succeeded, was
    /// skipped, or had its failure absorbed by an inner
    /// `ignore_errors:`. The block driver uses this to populate
    /// `ansible_failed_task` / `ansible_failed_result` before the
    /// rescue arm.
    first_failure: Option<(String, String, Option<RegisterValue>)>,
}

/// Walk a list of tasks on one host, sequentially. Used by the block
/// driver to execute `block.tasks`, `block.rescue`, and `block.always`.
///
/// Stops at the first non-recoverable failure (i.e. one that wasn't
/// converted to `Ok` by per-task `ignore_errors:`); subsequent tasks
/// in the list are not run. The caller — `run_block_on_one_host` —
/// decides whether to recover via the rescue arm.
///
/// Meta tasks (`flush_handlers`) inside a block are not supported in
/// v1: they're silently skipped here. The handler queue is play-level
/// concern, not block-local. Note in CLAUDE.md.
async fn run_task_list_on_host(
    tasks: &[Task],
    own_pool: PoolHandle,
    pools: Arc<BTreeMap<String, PoolHandle>>,
    mut ctx: HostCtx,
    next_seq: Arc<AtomicU32>,
    env: Arc<Environment<'static>>,
    world: Arc<WorldVars>,
    coord: RunOnceCoord,
    slot_counter: &mut u32,
    is_runner: bool,
) -> TaskListResult {
    let mut conn_alive = true;
    let mut first_failure: Option<(String, String, Option<RegisterValue>)> = None;
    let mut broken_at: Option<usize> = None;

    for (idx, task) in tasks.iter().enumerate() {
        // Meta tasks inside a block aren't dispatched. Tag filtering
        // is also play-level (block-inner tasks inherit the block's
        // tags via the load-time pass; the play-level filter has
        // already decided whether the whole block runs).
        if matches!(&task.body, TaskBody::Meta(_)) {
            // Still advance the slot counter — every Task in the tree
            // owns a coord slot, including Meta. (Meta tasks can't be
            // run_once and can't carry a block subtree, so this is
            // always a +1, but compensate via subtree_size to stay
            // correct if that ever changes.)
            let slot = *slot_counter;
            let size = coord.subtree_size(slot);
            *slot_counter = slot + size;
            continue;
        }

        let r = dispatch_one_task(
            task,
            own_pool.clone(),
            pools.clone(),
            ctx,
            next_seq.clone(),
            env.clone(),
            world.clone(),
            coord.clone(),
            slot_counter,
            is_runner,
        )
        .await;
        ctx = r.ctx;
        if !r.conn_alive {
            conn_alive = false;
        }
        match r.outcome {
            HostTaskOutcome::Ok { .. } | HostTaskOutcome::Skipped => {
                // Continue to next task. ignore_errors was already
                // applied inside run_task_on_one_host, so a failed
                // task with ignore_errors=true shows up here as Ok.
            }
            HostTaskOutcome::Failed { reason, register } => {
                first_failure = Some((task.name.clone(), reason, register));
                broken_at = Some(idx + 1);
                break;
            }
        }
        if !conn_alive {
            // Conn died — no point continuing the list.
            broken_at = Some(idx + 1);
            break;
        }
    }

    // If we broke early, advance slot_counter past every task we
    // didn't visit — keeps this host's counter aligned with hosts
    // that walked the full list (e.g. the runner that succeeded
    // while this host failed earlier).
    if let Some(from) = broken_at {
        for task in &tasks[from..] {
            let slot = *slot_counter;
            let size = coord.subtree_size(slot);
            *slot_counter = slot + size;
            let _ = task;
        }
    }

    TaskListResult {
        ctx,
        conn_alive,
        first_failure,
    }
}

/// Drive a `block:` on one host: run `tasks`, fall to `rescue` on
/// failure (with `ansible_failed_*` in scope), then always run
/// `always`. Returns a `PerHostTaskResult` shaped the same way
/// `run_task_on_one_host` does for non-block bodies, so the calling
/// strategy code doesn't have to special-case blocks.
///
/// Loop semantics: the block-level `loop:` iterates the whole
/// block→rescue→always triple per item, with `item` (or
/// `loop_control.loop_var`) in scope for every child task. A failure
/// in iteration N doesn't stop iteration N+1 from running — each
/// iteration is independent.
async fn run_block_on_one_host(
    block_task: &Task,
    block: &BlockSpec,
    own_pool: PoolHandle,
    pools: Arc<BTreeMap<String, PoolHandle>>,
    mut ctx: HostCtx,
    next_seq: Arc<AtomicU32>,
    env: Arc<Environment<'static>>,
    world: Arc<WorldVars>,
    coord: RunOnceCoord,
    slot_counter: &mut u32,
    is_runner: bool,
) -> PerHostTaskResult {
    let name = ctx.host_name.clone();

    // Resolve loop items (None → single iteration with no iter_item).
    let single_shot = block_task.loop_spec.is_none();
    let items: Vec<JsonValue> = if single_shot {
        Vec::new()
    } else {
        match resolve_loop_items(&env, block_task.loop_spec.as_ref(), &ctx, &world) {
            Ok(items) => items,
            Err(e) => {
                return PerHostTaskResult {
                    name,
                    ctx,
                    outcome: HostTaskOutcome::Failed {
                        reason: format!("loop: {e:#}"),
                        register: None,
                    },
                    conn_alive: true,
                };
            }
        }
    };
    let loop_var = block_task
        .loop_control
        .as_ref()
        .and_then(|lc| lc.loop_var.clone())
        .unwrap_or_else(|| "item".to_string());

    let mut overall_failure: Option<(String, String, Option<RegisterValue>)> = None;
    let mut conn_alive = true;

    // Build the iteration set: one None for single-shot, or one
    // Some(item) per loop item. Keeps the per-iteration body
    // uniform between the two cases.
    let iter_set: Vec<Option<JsonValue>> = if single_shot {
        vec![None]
    } else {
        items.into_iter().map(Some).collect()
    };

    // For single-shot blocks (the common case, and the only shape
    // drill-failover uses today), inherit the outer coord so that
    // `run_once:` on inner tasks is honored. For LOOPED blocks, every
    // iteration would re-traverse the same coord slots — the
    // OnceCells set on iteration 1 would deadlock iteration 2's
    // non-runner hosts. Fall back to an empty coord (no run_once
    // coordination — each host runs each inner task per iteration);
    // counter advancement is compensated by the outer
    // `dispatch_one_task`'s `subtree_size` push. This matches
    // pre-fix behavior for looped blocks; a future commit can wire
    // per-iteration fresh OnceCells if a real playbook needs it.
    let inner_coord = if single_shot {
        coord.clone()
    } else {
        RunOnceCoord::empty()
    };
    let inner_start = *slot_counter;

    for maybe_item in iter_set {
        // Each iteration replays the same inner slot range. For
        // single-shot this is a no-op (the for loop only runs once);
        // for looped blocks the empty coord means the slot identities
        // don't matter, but we still reset to keep the counter
        // intelligible.
        *slot_counter = inner_start;

        if let Some(item) = maybe_item {
            ctx.iter_item = Some((loop_var.clone(), item));
        }

        // 1. Run block.tasks
        let body_r = run_task_list_on_host(
            &block.tasks,
            own_pool.clone(),
            pools.clone(),
            ctx,
            next_seq.clone(),
            env.clone(),
            world.clone(),
            inner_coord.clone(),
            slot_counter,
            is_runner,
        )
        .await;
        ctx = body_r.ctx;
        if !body_r.conn_alive {
            conn_alive = false;
        }

        let recovered;
        if let Some((failed_name, _failed_reason, failed_register)) = &body_r.first_failure {
            // 2. On failure with non-empty rescue, set
            // ansible_failed_* and run rescue. Save/restore in case
            // we're inside a nested block's rescue.
            if block.rescue.is_empty() {
                recovered = false;
            } else {
                let saved_task = ctx.ansible_failed_task.take();
                let saved_result = ctx.ansible_failed_result.take();
                ctx.ansible_failed_task = Some(failed_name.clone());
                ctx.ansible_failed_result = failed_register.clone();

                let rescue_r = run_task_list_on_host(
                    &block.rescue,
                    own_pool.clone(),
                    pools.clone(),
                    ctx,
                    next_seq.clone(),
                    env.clone(),
                    world.clone(),
                    inner_coord.clone(),
                    slot_counter,
                    is_runner,
                )
                .await;
                ctx = rescue_r.ctx;
                if !rescue_r.conn_alive {
                    conn_alive = false;
                }

                ctx.ansible_failed_task = saved_task;
                ctx.ansible_failed_result = saved_result;

                recovered = rescue_r.first_failure.is_none();
                // If rescue itself failed, surface that as the overall
                // failure for this iteration (rescue's failure wins
                // over the original block failure — same as Ansible).
                if let Some(rf) = rescue_r.first_failure {
                    if overall_failure.is_none() {
                        overall_failure = Some(rf);
                    }
                }
            }
        } else {
            recovered = true;
        }

        // 3. always: runs regardless of recovery state.
        if !block.always.is_empty() {
            let always_r = run_task_list_on_host(
                &block.always,
                own_pool.clone(),
                pools.clone(),
                ctx,
                next_seq.clone(),
                env.clone(),
                world.clone(),
                inner_coord.clone(),
                slot_counter,
                is_runner,
            )
            .await;
            ctx = always_r.ctx;
            if !always_r.conn_alive {
                conn_alive = false;
            }
            if let Some(af) = always_r.first_failure {
                if overall_failure.is_none() {
                    overall_failure = Some(af);
                }
            }
        }

        // 4. If the original block.tasks failed and rescue didn't
        // recover, surface that as the overall failure.
        if !recovered {
            if let Some(bf) = body_r.first_failure {
                if overall_failure.is_none() {
                    overall_failure = Some(bf);
                }
            }
        }

        ctx.iter_item = None;

        // Stop iterating if conn is gone — there's no point.
        if !conn_alive {
            break;
        }
    }

    let outcome = match overall_failure {
        None => HostTaskOutcome::Ok {
            // We intentionally don't track block-aggregate `changed`
            // for now. `register:`/`notify:` on a block are rejected
            // at parse time, so the changed flag isn't observable —
            // and a per-iteration aggregate would be misleading once
            // looped blocks land. Revisit if/when notify-on-block is
            // implemented.
            changed: false,
            skipped: false,
        },
        Some((_, reason, register)) => {
            ctx.failed = true;
            HostTaskOutcome::Failed { reason, register }
        }
    };
    let outcome = maybe_ignore_failure(block_task, outcome, &name);
    PerHostTaskResult {
        name,
        ctx,
        outcome,
        conn_alive,
    }
}

/// Apply `ignore_errors: true` semantics by converting a Failed outcome
/// to Ok at the per-host result boundary. The register (recorded
/// earlier with `.failed=true`) is untouched, and `enqueue_notifies`
/// was already skipped on the Failed arm — so handlers don't fire for
/// an ignored failure. Effect on the surrounding orchestrator: the
/// host's `HostOutcome` stays `Ok`, the connection is not dropped, and
/// `on_failure: stop` is not tripped. Matches Ansible's behavior:
/// task-level opt-out from play-halting, register still reflects the
/// truth so a downstream `when: prev.failed` can react to it.
fn maybe_ignore_failure(
    task: &Task,
    outcome: HostTaskOutcome,
    host: &str,
) -> HostTaskOutcome {
    match (&task.ignore_errors, &outcome) {
        (Some(true), HostTaskOutcome::Failed { reason, .. }) => {
            info!(
                host = %host,
                task = %task.name,
                reason = %reason,
                "task failed but ignored (ignore_errors: true)"
            );
            HostTaskOutcome::Ok { changed: false, skipped: false }
        }
        _ => outcome,
    }
}

/// Render every entry in `task.notify` against the host's current view and
/// insert the result into `ctx.pending_handlers`. Only called on successful
/// (non-skipped) task completion where `changed` is true.
fn enqueue_notifies(
    task: &Task,
    changed: bool,
    skipped: bool,
    ctx: &mut HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) {
    if skipped || !changed || task.notify.is_empty() {
        return;
    }
    let view = build_template_ctx(ctx, world);
    for n in &task.notify {
        let rendered = match render_str(env, n, &view) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    host = %ctx.host_name,
                    task = %task.name,
                    notify = %n,
                    "notify render failed: {e:#}; using literal name"
                );
                n.clone()
            }
        };
        ctx.pending_handlers.insert(rendered);
    }
}

/// Render `task.retries` (a templated int-or-string) against the current
/// host view. Returns the parsed retry-count, or an error string suitable
/// for surfacing as a BodyResult::Failed reason.
///
/// Plain integer literals short-circuit the template render (gothab has
/// many `retries: 5`-style sites; we don't want to spin up a jinja
/// template for those). Negative values are not rejected here — the
/// retry-policy code clamps to 0.
fn render_int_field(
    env: &Environment<'static>,
    src: &str,
    ctx: &HostCtx,
    world: &WorldVars,
) -> Result<i64> {
    if let Ok(n) = src.trim().parse::<i64>() {
        return Ok(n);
    }
    let view = build_template_ctx(ctx, world);
    let rendered = render_str(env, src, &view)?;
    rendered
        .trim()
        .parse::<i64>()
        .map_err(|e| anyhow!("expected integer after rendering, got {rendered:?}: {e}"))
}

/// Same as `render_int_field` but for float-valued fields (currently
/// just `delay:`). Accepts `5`, `5.0`, `"5"`, `"{{ poll_interval }}"`.
fn render_float_field(
    env: &Environment<'static>,
    src: &str,
    ctx: &HostCtx,
    world: &WorldVars,
) -> Result<f64> {
    if let Ok(n) = src.trim().parse::<f64>() {
        return Ok(n);
    }
    let view = build_template_ctx(ctx, world);
    let rendered = render_str(env, src, &view)?;
    rendered
        .trim()
        .parse::<f64>()
        .map_err(|e| anyhow!("expected number after rendering, got {rendered:?}: {e}"))
}

/// One execution of a task body (no loop expansion here). Updates `ctx`
/// for controller-side bodies (set_fact); returns the register value for
/// the caller to record under `task.register` if appropriate.
enum BodyResult {
    Ok {
        register: RegisterValue,
        /// Whether the task actually changed state. Used to gate `notify`.
        changed: bool,
        /// True iff the agent (or controller composite path) declined to
        /// mutate state under `--check`. Distinct from `changed=false`
        /// (which is "ran and was idempotent"): `skipped` means "did not
        /// run at all" or "would have mutated but didn't, because dry-run."
        skipped: bool,
    },
    Failed {
        reason: String,
        register: Option<RegisterValue>,
        conn_alive: bool,
    },
}

async fn run_body_once(
    task: &Task,
    target_conn: &ConnHandle,
    ctx: &mut HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
    next_seq: &Arc<AtomicU32>,
) -> BodyResult {
    match &task.body {
        TaskBody::Op(op) => run_op_body(task, op, target_conn, ctx, env, world, next_seq).await,
        TaskBody::Assert(a) => run_assert_body(a, ctx, env, world),
        TaskBody::Fail(f) => run_fail_body(f, ctx, env, world),
        TaskBody::Debug(d) => run_debug_body(d, task, ctx, env, world),
        TaskBody::Pause(p) => run_pause_body(p, ctx, env, world).await,
        TaskBody::SetFact(m) => run_set_fact_body(m, ctx, env, world),
        TaskBody::ImportTasks(p) => BodyResult::Failed {
            reason: format!(
                "internal: import_tasks({}) reached the orchestrator; \
                 flattening pass should have removed it",
                p.display()
            ),
            register: None,
            conn_alive: true,
        },
        TaskBody::IncludeRole(ir) => BodyResult::Failed {
            reason: format!(
                "internal: include_role({:?}, tasks_from={:?}) reached the orchestrator; \
                 expansion pass should have removed it",
                ir.name, ir.tasks_from
            ),
            register: None,
            conn_alive: true,
        },
        TaskBody::Meta(_) => {
            // Meta bodies are handled at the loop level, not per-host body
            // dispatch. Reaching here means a bug in the orchestrator.
            BodyResult::Failed {
                reason: "internal: meta task dispatched to body-runner".into(),
                register: None,
                conn_alive: true,
            }
        }
        TaskBody::Block(_) => {
            // Block bodies are handled at the loop level by the block
            // driver, not by run_body_once. Reaching here means a bug
            // in the orchestrator's block dispatch (the per-host driver
            // should have intercepted and called into run_block_on_one_host).
            // Until the block executor lands (step 5), the load-time
            // pipeline accepts `block:` tasks but the executor will
            // surface this error if it tries to dispatch one.
            BodyResult::Failed {
                reason: "internal: block task dispatched to body-runner \
                         (block executor not yet wired up)"
                    .into(),
                register: None,
                conn_alive: true,
            }
        }
    }
}

/// Drive `run_body_once` under `retries:` / `until:` / `delay:` semantics.
///
/// Decision table (matches Ansible's `task_executor.py` exactly):
///
/// | task.retries | task.until | total attempts | exit condition       |
/// |--------------|------------|----------------|----------------------|
/// | None         | None       | 1              | n/a (no retry loop)  |
/// | None         | Some(_)    | 4 (3 retries)  | `until` truthy       |
/// | Some(n)      | None       | 1 + max(0, n)  | body returned Ok     |
/// | Some(n)      | Some(_)    | 1 + max(0, n)  | `until` truthy       |
///
/// Per-attempt details:
/// - On each attempt, if `task.register` is set, the resulting register
///   is stashed on `ctx` so the `until` expression can see it as
///   `{{ register_name.* }}`. It's overwritten on every attempt.
/// - `delay:` (default 5s, clamped to >= 1s if negative) is awaited
///   between attempts via `tokio::time::sleep`. No sleep after the
///   final attempt.
/// - When retry semantics were active (total attempts > 1), the final
///   register's `attempts` field is set to the number of attempts
///   actually made. With only one attempt (no retry semantics) the
///   field stays at 0 — single-attempt tasks don't surface
///   `register.attempts` at all (see `RegisterValue::to_json`).
///
/// Note: `until` and `failed_when` (when we ship the latter) are
/// independent. `failed_when` would post-process the body's Ok/Failed
/// outcome BEFORE this function decides whether to break — the
/// integration point is to apply `failed_when` to `result` right after
/// each `run_body_once` call returns. Not in scope here.
async fn run_body_with_retries(
    task: &Task,
    target_conn: &ConnHandle,
    ctx: &mut HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
    next_seq: &Arc<AtomicU32>,
) -> BodyResult {
    // Compute total_attempts. Render `task.retries` against the host
    // view; a render or parse failure is fatal for the task and shows
    // up before any body is dispatched.
    let parsed_retries: Option<u32> = match task.retries.as_deref() {
        None => None,
        Some(src) => match render_int_field(env, src, ctx, world) {
            Ok(n) => Some(n.max(0) as u32),
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("retries: {e:#}"),
                    register: None,
                    conn_alive: true,
                };
            }
        },
    };
    let total_attempts: u32 = match parsed_retries {
        Some(n) => 1 + n,
        None if task.until.is_some() => 4, // Ansible default: 3 retries
        None => 1,
    };
    let retry_active = total_attempts > 1;

    // Single-attempt fast path — no delay parsing, no extra logic. This
    // is the hot path for every task that doesn't use retries.
    if !retry_active {
        return run_body_once(task, target_conn, ctx, env, world, next_seq).await;
    }

    // Delay (only consulted when retries are active).
    let delay_secs: f64 = match task.delay.as_deref() {
        None => 5.0,
        Some(src) => match render_float_field(env, src, ctx, world) {
            Ok(d) => {
                if d < 0.0 {
                    1.0
                } else {
                    d
                }
            }
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("delay: {e:#}"),
                    register: None,
                    conn_alive: true,
                };
            }
        },
    };

    let host_name = ctx.host_name.clone();
    let mut last_result: BodyResult;
    let mut attempts_made: u32 = 0;
    let mut exhausted_without_exit = false;
    loop {
        attempts_made += 1;
        let result = run_body_once(task, target_conn, ctx, env, world, next_seq).await;

        // Stash register on ctx so `until` can see it. Even on a Failed
        // attempt we record under the user's register name when there's
        // a register-shape payload — the final attempt's value ends up
        // there too, matching the natural single-shot flow.
        if let Some(reg_name) = &task.register {
            let rv_for_ctx = match &result {
                BodyResult::Ok { register, .. } => Some(register.clone()),
                BodyResult::Failed { register, .. } => register.clone(),
            };
            if let Some(rv) = rv_for_ctx {
                ctx.record_register(reg_name, rv);
            }
        }

        // Exit condition: `until` if set (evaluated after register is
        // recorded), otherwise "body returned Ok". Note: a truthy
        // `until` exits even on a Failed attempt — `until` controls
        // when to stop retrying, NOT whether to flag the task failed.
        let should_break = if let Some(until_expr) = task.until.as_deref() {
            match eval_when(env, Some(until_expr), ctx, world) {
                Ok(b) => b,
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("until: {e:#}"),
                        register: None,
                        conn_alive: true,
                    };
                }
            }
        } else {
            matches!(&result, BodyResult::Ok { .. })
        };

        if should_break {
            last_result = result;
            break;
        }
        if attempts_made >= total_attempts {
            last_result = result;
            exhausted_without_exit = true;
            break;
        }

        info!(
            host = %host_name,
            task = %task.name,
            attempt = attempts_made,
            total_attempts,
            delay_secs,
            "retry condition not met; sleeping before next attempt"
        );
        tokio::time::sleep(std::time::Duration::from_secs_f64(delay_secs)).await;
    }

    // Ansible parity: when retries exhaust without the exit condition
    // ever being satisfied, the task is flagged failed even if the
    // last attempt's body succeeded. This only changes the outcome
    // when `until:` was set and never became truthy (without `until`,
    // the exit condition IS "body succeeded", so an exhausted loop
    // already ends on a Failed body).
    if exhausted_without_exit {
        if let BodyResult::Ok { register, .. } = last_result {
            last_result = BodyResult::Failed {
                reason: format!(
                    "task did not satisfy `until:` after {attempts_made} attempts"
                ),
                register: Some(register),
                conn_alive: true,
            };
        }
    }

    // Annotate `attempts` on the register so templates can read
    // `{{ result.attempts }}`.
    match &mut last_result {
        BodyResult::Ok { register, .. } => {
            register.attempts = attempts_made;
        }
        BodyResult::Failed { register, .. } => {
            if let Some(rv) = register.as_mut() {
                rv.attempts = attempts_made;
            }
        }
    }
    last_result
}

// ---------- body kinds ----------

async fn run_op_body(
    task: &Task,
    op: &TaskOp,
    target_conn: &ConnHandle,
    ctx: &mut HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
    next_seq: &Arc<AtomicU32>,
) -> BodyResult {
    let mut rendered = match render_op(op, ctx, env, world) {
        Ok(r) => r,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("template render: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };

    // `command:` / `shell:` idempotency probes — `creates:` / `removes:`.
    // If either marker is set, stat the path on the agent first and
    // short-circuit when the marker says "already in the right state":
    //   - creates="/path" + path exists → skip (changed=false)
    //   - removes="/path" + path missing → skip (changed=false)
    // Otherwise we drop the markers from `rendered` and fall through to
    // the normal dispatch path, which now sees a plain `command:` and
    // ships an OpExec.
    if let TaskOp::Command(c) = &rendered {
        if !c.creates.is_empty() || !c.removes.is_empty() {
            let probe_path = if !c.creates.is_empty() {
                c.creates.clone()
            } else {
                c.removes.clone()
            };
            let probe_is_creates = !c.creates.is_empty();
            let stat_seq = next_seq.fetch_add(1, Ordering::Relaxed);
            let stat_op = rsansible_wire::msg::op_stat(probe_path.clone(), false);
            let stat_outcome = {
                let mut guard = target_conn.lock().await;
                let conn = match guard.as_mut() {
                    Some(conn) => conn,
                    None => {
                        return BodyResult::Failed {
                            reason: "agent conn is dead (host marked failed)".into(),
                            register: None,
                            conn_alive: false,
                        };
                    }
                };
                let clock_offset_ns = conn.clock_offset_ns;
                let check_mode = task.check_mode.unwrap_or(ctx.check_mode);
                run_one_task_op(
                    conn,
                    stat_seq,
                    stat_op,
                    true,
                    clock_offset_ns,
                    check_mode,
                    &ctx.run_metrics,
                )
                .await
            };
            let exists = match stat_outcome {
                Ok(exec) => {
                    if exec.done.exit_code != 0 {
                        return BodyResult::Failed {
                            reason: format!(
                                "command creates/removes probe (OpStat) non-zero exit {} for {probe_path:?}",
                                exec.done.exit_code
                            ),
                            register: None,
                            conn_alive: true,
                        };
                    }
                    let stdout = String::from_utf8_lossy(&exec.stdout);
                    serde_json::from_str::<JsonValue>(stdout.trim())
                        .ok()
                        .and_then(|j| j.get("exists").and_then(|v| v.as_bool()))
                        .unwrap_or(false)
                }
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("command creates/removes probe: {e:#}"),
                        register: None,
                        conn_alive: false,
                    };
                }
            };
            let should_skip = if probe_is_creates {
                // `creates`: skip when the marker is already there.
                exists
            } else {
                // `removes`: skip when the marker is already gone.
                !exists
            };
            if should_skip {
                let mut rv = RegisterValue::default();
                rv.took_ms = 0;
                rv.changed = false;
                rv.skipped = true;
                return BodyResult::Ok {
                    register: rv,
                    changed: false,
                    skipped: true,
                };
            }
            // Marker says "go ahead". Drop the creates/removes so the
            // normal `to_wire_op` path doesn't reject the task.
            if let TaskOp::Command(c) = &mut rendered {
                c.creates.clear();
                c.removes.clear();
            }
        }
    }

    // Controller-side --check skip for mutating `postgresql_query:`.
    // The SQL classifier (re-)ran during render so the read_only flag
    // reflects the post-Jinja statement. We DON'T dispatch a mutating
    // SQL statement under check_mode — there's no agent-side probe that
    // could tell "would this DELETE delete anything" without actually
    // running it. The escape hatch is per-task `check_mode: false`.
    {
        let effective_check_mode = task.check_mode.unwrap_or(ctx.check_mode);
        if effective_check_mode {
            if let TaskOp::PostgresqlQuery(p) = &rendered {
                if !p.read_only {
                    let mut rv = RegisterValue::default();
                    rv.took_ms = 0;
                    rv.skipped = true;
                    rv.changed = false;
                    return BodyResult::Ok {
                        register: rv,
                        changed: false,
                        skipped: true,
                    };
                }
            }
            // postgresql_ext under check_mode: keep dispatching — the
            // agent probes pg_extension and emits skipped=true itself
            // if DDL would be needed. That probe is read-only.
        }
    }

    // Composite-dispatch intercepts. These three ops break the
    // single-op-per-task invariant of the normal path:
    //
    // - `OpenSslPrivkey` may emit OpStat + OpWriteFile (probe branch),
    //   just OpWriteFile w/ only_if_missing=1 (ship-blind branch), or
    //   neither (probe found the file already there).
    // - `OpenSslCsrPipe` and `X509CertificatePipe` synthesize content
    //   purely on the controller and never touch the wire — they bind
    //   `register.content` to the generated PEM.
    //
    // We intercept BEFORE `become_::apply` (no argv to wrap) and
    // BEFORE `to_wire_op` (which deliberately errors for these
    // variants — see task_op.rs's to_wire_op match arms).
    match &rendered {
        TaskOp::OpenSslPrivkey(p) => {
            return run_privkey_composite(task, p, target_conn, ctx, next_seq).await;
        }
        TaskOp::OpenSslCsrPipe(c) => {
            return synth_csr_pipe(c, ctx, target_conn, next_seq, task).await;
        }
        TaskOp::X509CertificatePipe(c) => {
            return synth_cert_pipe(c);
        }
        TaskOp::Tempfile(t) => {
            return synth_tempfile(t);
        }
        TaskOp::PostgresqlUser(u) => {
            return run_postgresql_user_composite(task, u, target_conn, ctx, next_seq).await;
        }
        TaskOp::PostgresqlDb(d) => {
            return run_postgresql_db_composite(task, d, target_conn, ctx, next_seq).await;
        }
        TaskOp::PostgresqlMembership(m) => {
            return run_postgresql_membership_composite(task, m, target_conn, ctx, next_seq).await;
        }
        _ => {}
    }
    // `become:` is honored at the transport layer now — the task's
    // wire op is dispatched against the pool slot keyed by its
    // effective BecomeKey. See the per-host `AgentPool` and the
    // routing logic at the four task-dispatch sites that call this
    // function. Argv wrapping (the old `sudo -n -u <user> --` prefix
    // on shell/exec/command) is gone; the agent for that BecomeKey
    // already runs with the right EUID. No mutation needed here.
    let mut inner_wire_op = match rendered.to_wire_op() {
        Ok(w) => w,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("to wire op: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };

    // `environment:` overlay — render each value through Jinja against
    // the host's current view, then splice the rendered (key, value)
    // pairs into the wire op's env_keys/env_values. Today only OpExec
    // and OpShell carry env on the wire; future ops that grow env
    // slots can extend this match without touching task parsing or
    // inheritance. If a task sets `environment:` on a body that has
    // nowhere to put it, we treat that as a soft no-op rather than a
    // hard error — matches Ansible (which lets `environment:` set on
    // e.g. a `file:` task pass silently).
    if !task.environment.is_empty() {
        let view = build_template_ctx(ctx, world);
        let mut rendered_env: Vec<(String, String)> =
            Vec::with_capacity(task.environment.len());
        for (k, v) in &task.environment {
            let rendered_val = match render_str(env, v, &view) {
                Ok(s) => s,
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("render environment[{k:?}]: {e:#}"),
                        register: None,
                        conn_alive: true,
                    };
                }
            };
            rendered_env.push((k.clone(), rendered_val));
        }
        match &mut inner_wire_op {
            rsansible_wire::Op::OpExec(e) => {
                for (k, v) in rendered_env {
                    // Child task `environment:` wins on collision with
                    // anything baked into the body (e.g. an `exec:`
                    // task that also declares `env:` inline). This
                    // mirrors how Ansible merges its own `environment:`
                    // on top of module-internal env handling.
                    if let Some(idx) = e.env_keys.iter().position(|x| x == &k) {
                        e.env_values[idx] = v;
                    } else {
                        e.env_keys.push(k);
                        e.env_values.push(v);
                    }
                }
            }
            rsansible_wire::Op::OpShell(s) => {
                for (k, v) in rendered_env {
                    if let Some(idx) = s.env_keys.iter().position(|x| x == &k) {
                        s.env_values[idx] = v;
                    } else {
                        s.env_keys.push(k);
                        s.env_values.push(v);
                    }
                }
            }
            _ => {
                // Soft no-op for ops without env slots. Could be made
                // strict if it surprises users; today gothab only uses
                // environment: on command/shell which DO carry env.
            }
        }
    }

    // `async: N` (with N>0) wraps the inner op in OpAsyncStart so the
    // agent runs it as a background job. `async: 0` (or absent) is
    // synchronous — same as Ansible. `async:` is stored as a string
    // (int|jinja) so it accepts templated values like
    // `async: "{{ writer_duration_s | int + 30 }}"`.
    let async_wrap = match task.async_seconds.as_deref() {
        None => None,
        Some(src) => match render_int_field(env, src, ctx, world) {
            Ok(n) if n > 0 => Some(n as u32),
            Ok(_) => None, // async: 0 → synchronous
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("rendering `async:`: {e:#}"),
                    register: None,
                    conn_alive: true,
                };
            }
        },
    };
    let wire_op = match async_wrap {
        Some(seconds) => rsansible_wire::msg::op_async_start(
            seconds.saturating_mul(1000),
            inner_wire_op,
        ),
        None => inner_wire_op,
    };

    let seq = next_seq.fetch_add(1, Ordering::Relaxed);
    let capture = task.register.is_some();
    let started = Instant::now();

    // Lock the target conn for the duration of the op. If the inner is
    // None (host marked failed previously), bail immediately.
    let mut guard = target_conn.lock().await;
    let conn = match guard.as_mut() {
        Some(c) => c,
        None => {
            return BodyResult::Failed {
                reason: "agent conn is dead (host marked failed)".into(),
                register: None,
                conn_alive: false,
            };
        }
    };
    let clock_offset_ns = conn.clock_offset_ns;
    // Effective per-task check_mode: task field wins both directions,
    // otherwise inherit the run-level flag.
    let check_mode = task.check_mode.unwrap_or(ctx.check_mode);
    let mut result = run_one_task_op(
        conn,
        seq,
        wire_op,
        capture,
        clock_offset_ns,
        check_mode,
        &ctx.run_metrics,
    )
    .await;

    // Async poll loop: when `async: N, poll: M (M>0)`, the orchestrator
    // blocks on the same connection, dispatching OpAsyncStatus every M
    // seconds until the job reports `finished:1` or the async deadline
    // elapses. The register receives the FINAL status envelope (inner
    // module fields lifted via the agent), making the wrapped task feel
    // like a synchronous run from the caller's perspective.
    if let (Some(async_n), Ok(exec)) = (async_wrap, result.as_ref()) {
        // `poll:` is stored as a templated string (int|jinja). Render
        // it now; default to 10 when unset (matches Ansible). A render
        // failure surfaces as a clean task failure rather than silently
        // falling back.
        let poll = match task.poll_seconds.as_deref() {
            None => 10u32,
            Some(src) => match render_int_field(env, src, ctx, world) {
                Ok(n) if n >= 0 => n as u32,
                Ok(n) => {
                    return BodyResult::Failed {
                        reason: format!("rendering `poll:`: got negative value {n}"),
                        register: None,
                        conn_alive: true,
                    };
                }
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("rendering `poll:`: {e:#}"),
                        register: None,
                        conn_alive: true,
                    };
                }
            },
        };
        if poll > 0 && exec.done.exit_code == 0 {
            let deadline = Instant::now() + std::time::Duration::from_secs(async_n as u64);
            let job_id = seq;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(poll as u64)).await;
                if Instant::now() > deadline {
                    // Treat as timeout: dispatch a final status (to harvest
                    // any partial output) but don't loop further. The
                    // envelope's `finished` flag will say if the agent has
                    // actually finished by then.
                }
                let poll_seq = next_seq.fetch_add(1, Ordering::Relaxed);
                let status_op = rsansible_wire::msg::op_async_status(job_id);
                let r = run_one_task_op(
                    conn,
                    poll_seq,
                    status_op,
                    /*capture=*/ true,
                    clock_offset_ns,
                    /*check_mode=*/ false,
                    &ctx.run_metrics,
                )
                .await;
                let exec_now = match r {
                    Ok(e) => e,
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                };
                let finished = serde_json::from_slice::<JsonValue>(&exec_now.stdout)
                    .ok()
                    .and_then(|v| {
                        v.get("finished")
                            .and_then(|n| n.as_u64().map(|u| u != 0))
                    })
                    .unwrap_or(false);
                let past_deadline = Instant::now() > deadline;
                result = Ok(exec_now);
                if finished || past_deadline {
                    break;
                }
            }
        }
    }
    let label = conn.label.clone();
    drop(guard); // release the lock before doing CPU work / waiting on ctx
    let _ = ctx; // ctx isn't mutated here; silence unused-mut

    match result {
        Ok(exec) => {
            let agent_elapsed_ns =
                exec.done.finished_unix_ns.saturating_sub(exec.done.started_unix_ns);
            let took_ms = (agent_elapsed_ns / 1_000_000).min(u64::MAX);
            let mut rv = RegisterValue::from_exec_with_skipped(
                exec.done.exit_code,
                exec.done.changed != 0,
                exec.done.skipped != 0,
                took_ms,
                &exec.stdout,
                &exec.stderr,
            );
            // Module-specific result lifting. `stat:` ships its result as a
            // JSON object on stdout; we expose it as `register.stat.<field>`
            // to match Ansible's contract. Failure to parse here is silent —
            // the user can still see the raw stdout and `register.json`.
            if let TaskOp::Stat(_) = op {
                if let Some(JsonValue::Object(_)) = rv.json.as_ref() {
                    let parsed = rv.json.clone().unwrap();
                    rv.extra.insert("stat".into(), parsed);
                }
            }
            // `uri:` ships a JSON envelope on stdout. Unlike stat, Ansible's
            // contract exposes the envelope keys at the **top level** of the
            // register (`register.status`, `register.content`, …), not under
            // `register.uri.*`. Lift each key into `rv.extra`, and swap the
            // envelope's parsed `json` body into `rv.json` so
            // `register.json.<body-field>` resolves to the response body
            // rather than the envelope itself.
            if let TaskOp::Uri(_) = op {
                lift_uri_envelope(&mut rv);
            }
            // `postgresql_query:` / `postgresql_ext:` ship JSON
            // envelopes whose top-level keys (query_result/rowcount/
            // statusmessage; extension/state/prior_version/version)
            // belong directly under `register.*` so existing Ansible
            // playbook accessors like `{{ result.query_result[0].col }}`
            // work unchanged.
            if matches!(op, TaskOp::PostgresqlQuery(_) | TaskOp::PostgresqlExt(_)) {
                lift_postgresql_envelope(&mut rv);
            }
            // get_url envelope: url/dest/checksum_src/checksum_dest/size/
            // status_code/msg all live at the top level of the register
            // so vendored playbooks can do `register.checksum_dest ==
            // expected` directly, matching ansible.builtin.get_url.
            if matches!(op, TaskOp::GetUrl(_)) {
                lift_get_url_envelope(&mut rv);
            }
            // slurp envelope: `content` (base64), `source` (path),
            // `encoding` ("base64") — Ansible's slurp contract lifts
            // these to the top level so playbooks can do
            // `register.content | b64decode`.
            if matches!(op, TaskOp::Slurp(_)) {
                lift_slurp_envelope(&mut rv);
            }
            // unarchive envelope: dest/src/handler/extract_results/files —
            // Ansible's unarchive return shape. Top-level lift so
            // playbooks can do `register.files | length > 0` etc.
            if matches!(op, TaskOp::Unarchive(_)) {
                lift_unarchive_envelope(&mut rv);
            }
            // async start/status envelope: `ansible_job_id`, `started`,
            // `finished`, `results_file` — Ansible's contract is to put
            // these at the top of the register so playbooks can do
            // `register.ansible_job_id` and pass it to a follow-up
            // `async_status: jid:`. Applies both when async_wrap fires
            // (the wire op was OpAsyncStart) and when the user wrote
            // an explicit `async_status:` task (inner op is AsyncStatus).
            if async_wrap.is_some() || matches!(op, TaskOp::AsyncStatus(_)) {
                lift_async_envelope(&mut rv);
            }
            // getent envelope: agent emits {database, <key>: [...]}.
            // Ansible's contract is `register.getent_<database>` (a map
            // from key → list-of-fields) AND `ansible_facts.getent_<db>`
            // for cross-task lookup. Lift to the register-side
            // `getent_<database>: {<key>: [...]}` and (separately)
            // set the fact when `register:` isn't used.
            if matches!(op, TaskOp::Getent(_)) {
                lift_getent_envelope(&mut rv);
            }
            emit_timing_trace(&label, &task.name, seq, &exec);
            if exec.done.exit_code == 0 {
                let changed = exec.done.changed != 0;
                let skipped = exec.done.skipped != 0;
                info!(
                    host = %label,
                    task = %task.name,
                    seq,
                    exit = exec.done.exit_code,
                    changed,
                    skipped,
                    took_ms,
                    "ok",
                );
                // Surface per-task check-mode markers on stderr so the
                // operator can see at a glance what happened. Real runs
                // stay quiet — the existing summary line carries the count.
                if check_mode {
                    let marker = if skipped {
                        "[CHECK]"
                    } else if changed {
                        "[WOULD CHANGE]"
                    } else {
                        "[CHECK OK]"
                    };
                    eprintln!("  {marker} {label}: {task_name}", task_name = task.name);
                }
                BodyResult::Ok {
                    register: rv,
                    changed,
                    skipped,
                }
            } else {
                warn!(
                    host = %label,
                    task = %task.name,
                    seq,
                    exit = exec.done.exit_code,
                    took_ms,
                    "task non-zero exit",
                );
                BodyResult::Failed {
                    reason: format!("exit {}", exec.done.exit_code),
                    register: Some(rv),
                    conn_alive: true,
                }
            }
        }
        Err(e) => {
            let elapsed = started.elapsed();
            warn!(
                host = %label,
                task = %task.name,
                seq,
                took_ms = elapsed.as_millis() as u64,
                "task errored: {e:#}",
            );
            BodyResult::Failed {
                reason: format!("{e:#}"),
                register: None,
                conn_alive: false,
            }
        }
    }
}

// ---------- x509 composite dispatch (controller-side ops) ----------

/// `openssl_privatekey:` — generate a private key on the controller and
/// ship it to the remote.
///
/// Idempotency model:
/// - The key on disk is sacred — re-generating means existing certs
///   become invalid. We never overwrite.
/// - Two paths, picked by `WireStrategy.decide(...)`:
///   * **Ship-blind** (small payload / high-RTT link): dispatch one
///     `OpWriteFile { only_if_missing: 1 }`. The agent writes iff the
///     file is absent and reports `changed` accordingly. Zero round
///     trips on the no-op case beyond the write itself.
///   * **Probe-first** (large payload / low-RTT link): dispatch an
///     `OpStat`; if the file exists, synthesize `changed: false` with
///     no further wire traffic. If absent, dispatch `OpWriteFile`
///     with `only_if_missing: 0` (we already know it's absent — no
///     reason for the agent to re-check).
/// - `force_probe: true` on the task wins regardless.
///
/// On generation, the PEM bytes are stashed in
/// `HostCtx.privkey_pem_cache` so a subsequent `openssl_csr_pipe`
/// task in the same play can sign with the matching key without
/// fetching it back from the remote.
async fn run_privkey_composite(
    task: &Task,
    p: &OpenSslPrivkeyOp,
    target_conn: &ConnHandle,
    ctx: &mut HostCtx,
    next_seq: &Arc<AtomicU32>,
) -> BodyResult {
    let pem = match crate::x509::generate_privkey(&crate::x509::PrivkeyParams {
        kind: p.kind,
        size: p.size,
    }) {
        Ok(b) => b,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("openssl_privatekey: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };
    // Cache for the csr_pipe step that may follow. Done before we
    // dispatch anything — even on a probe-hit-exists no-op, callers
    // in the same play can still sign with this newly-generated PEM
    // if they want a deterministic chain. (If they don't, they
    // shouldn't have asked us to generate a key.)
    ctx.privkey_pem_cache.insert(p.path.clone(), pem.clone());

    // Effective check_mode for this task (per-task field wins, else inherit).
    let effective_check_mode = task.check_mode.unwrap_or(ctx.check_mode);

    // Decide which branch to take. force_probe wins over both auto and
    // CLI overrides — operator opt-in to exact Ansible-flavored
    // idempotency reporting. Under --check we force probing
    // unconditionally: the dry-run path *must* see whether the key
    // exists so we can report a meaningful `changed`/`skipped` pair
    // without writing bytes.
    let probe =
        effective_check_mode || p.force_probe || ctx.wire_strategy.decide(&ctx.wire_cost, pem.len());

    if probe {
        // Step 1: OpStat. Short, cheap, returns JSON on stdout.
        let stat_seq = next_seq.fetch_add(1, Ordering::Relaxed);
        let stat_op = rsansible_wire::msg::op_stat(p.path.clone(), false);
        let stat_result = {
            let mut guard = target_conn.lock().await;
            let conn = match guard.as_mut() {
                Some(c) => c,
                None => {
                    return BodyResult::Failed {
                        reason: "agent conn is dead (host marked failed)".into(),
                        register: None,
                        conn_alive: false,
                    };
                }
            };
            let clock_offset_ns = conn.clock_offset_ns;
            // OpStat is read-only; pass effective check_mode through
            // for consistency (the agent's stat module ignores it).
            let check_mode = task.check_mode.unwrap_or(ctx.check_mode);
            let r = run_one_task_op(
                conn,
                stat_seq,
                stat_op,
                true,
                clock_offset_ns,
                check_mode,
                &ctx.run_metrics,
            )
            .await;
            let _label = conn.label.clone();
            r
        };
        let exists = match stat_result {
            Ok(exec) => {
                if exec.done.exit_code != 0 {
                    return BodyResult::Failed {
                        reason: format!(
                            "openssl_privatekey probe (OpStat) non-zero exit {}",
                            exec.done.exit_code
                        ),
                        register: None,
                        conn_alive: true,
                    };
                }
                let stdout = String::from_utf8_lossy(&exec.stdout);
                serde_json::from_str::<JsonValue>(stdout.trim())
                    .ok()
                    .and_then(|j| j.get("exists").and_then(|v| v.as_bool()))
                    .unwrap_or(false)
            }
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("openssl_privatekey probe: {e:#}"),
                    register: None,
                    conn_alive: false,
                };
            }
        };
        if exists {
            // No-op path: the key is already on the remote. Don't ship
            // a single byte. Surfaces as `changed: false`.
            //
            // We still expose the *just-generated* PEM via
            // `register.content` so a downstream `openssl_csr_pipe` /
            // `x509_certificate_pipe` in the same play can chain. The
            // privkey_pem_cache also still holds it (set earlier),
            // matching the same in-play contract.
            //
            // A play that wants to sign against the *on-disk* key
            // (e.g. a follow-up run that already provisioned the key)
            // can skip the privkey task entirely and call
            // `openssl_csr_pipe:` directly; the synth path now
            // fetches the PEM via OpReadFile on cache miss.
            let pem_str = String::from_utf8_lossy(&pem).into_owned();
            let mut rv = RegisterValue::default();
            rv.took_ms = 0;
            rv.extra
                .insert("content".into(), JsonValue::String(pem_str));
            return BodyResult::Ok {
                register: rv,
                changed: false,
                skipped: false,
            };
        }
        // File is absent.
        //
        // Under --check we stop here: synthesize a `changed=true,
        // skipped=true` result and keep the freshly-generated PEM in
        // the cache so a chained csr_pipe / cert_pipe can still produce
        // a meaningful register during the dry-run. We never dispatch
        // OpWriteFile in this branch — that's the whole point.
        if effective_check_mode {
            let pem_str = String::from_utf8_lossy(&pem).into_owned();
            let mut rv = RegisterValue::default();
            rv.took_ms = 0;
            rv.skipped = true;
            rv.changed = true;
            rv.extra
                .insert("content".into(), JsonValue::String(pem_str));
            return BodyResult::Ok {
                register: rv,
                changed: true,
                skipped: true,
            };
        }
        // Real run: fall through to ship the bytes. only_if_missing=0
        // because we already know it's gone; the agent shouldn't re-stat.
        let _ = task; // satisfy unused warning when this branch returns early
    }

    // Ship-blind branch (or probe-said-absent fallthrough). only_if_missing
    // toggles based on which path we're on: on the blind path we want
    // the agent to make the idempotency decision; on the post-probe
    // path we already made it.
    let only_if_missing = !probe;
    let write_seq = next_seq.fetch_add(1, Ordering::Relaxed);
    let mode_bits = match p.mode.expect_resolved("openssl_privkey.mode") {
        Ok(m) => m,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("openssl_privatekey: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };
    let write_op = rsansible_wire::msg::op_write_file(
        p.path.clone(),
        mode_bits,
        only_if_missing,
        pem.clone(),
        // openssl_privatekey doesn't expose `validate:` — PEM keys
        // aren't a file format where ad-hoc validators make sense.
        String::new(),
        // openssl_privatekey doesn't yet expose owner/group; the
        // module typically runs with become so the PEM lands as the
        // post-become user (usually root). If we add the fields,
        // plumb them here.
        String::new(),
        String::new(),
    );
    let started = Instant::now();
    let write_result = {
        let mut guard = target_conn.lock().await;
        let conn = match guard.as_mut() {
            Some(c) => c,
            None => {
                return BodyResult::Failed {
                    reason: "agent conn is dead (host marked failed)".into(),
                    register: None,
                    conn_alive: false,
                };
            }
        };
        let clock_offset_ns = conn.clock_offset_ns;
        let check_mode = task.check_mode.unwrap_or(ctx.check_mode);
        run_one_task_op(
            conn,
            write_seq,
            write_op,
            task.register.is_some(),
            clock_offset_ns,
            check_mode,
            &ctx.run_metrics,
        )
        .await
    };
    match write_result {
        Ok(exec) => {
            let agent_elapsed_ns =
                exec.done.finished_unix_ns.saturating_sub(exec.done.started_unix_ns);
            let took_ms = (agent_elapsed_ns / 1_000_000).min(u64::MAX);
            let mut rv = RegisterValue::from_exec_with_skipped(
                exec.done.exit_code,
                exec.done.changed != 0,
                exec.done.skipped != 0,
                took_ms,
                &exec.stdout,
                &exec.stderr,
            );
            // Lift the generated PEM into `register.content` so a
            // downstream csr_pipe / cert_pipe can chain via Jinja.
            // Mirrors the no-op branch above for a consistent contract.
            let pem_str = String::from_utf8_lossy(&pem).into_owned();
            rv.extra
                .insert("content".into(), JsonValue::String(pem_str));
            if exec.done.exit_code == 0 {
                BodyResult::Ok {
                    register: rv,
                    changed: exec.done.changed != 0,
                    skipped: exec.done.skipped != 0,
                }
            } else {
                BodyResult::Failed {
                    reason: format!("openssl_privatekey write exit {}", exec.done.exit_code),
                    register: Some(rv),
                    conn_alive: true,
                }
            }
        }
        Err(e) => {
            let _ = started;
            BodyResult::Failed {
                reason: format!("openssl_privatekey write: {e:#}"),
                register: None,
                conn_alive: false,
            }
        }
    }
}

/// Per-host upper bound on the PEM blob we'll pull back via OpReadFile.
/// Even fat RSA-4096 PEMs are only ~3 KiB; 1 MiB is comfortably above
/// anything legitimate and below "you misconfigured `privatekey_path` to
/// a tarball." The cap is sent to the agent, which rejects oversized
/// files before reading.
const CSR_PIPE_PRIVKEY_MAX_BYTES: u32 = 1024 * 1024;

/// `openssl_csr_pipe:` — synthesize a CSR PEM on the controller using
/// the privkey for `privatekey_path`. The PEM lands on
/// `register.content` so the next task (`x509_certificate_pipe`) can
/// sign it via Jinja.
///
/// Cache hit (privkey was generated earlier in this play): zero round
/// trips, pure controller-side. Cache miss: dispatch an `OpReadFile`
/// against the agent to fetch the on-disk PEM, then proceed. The
/// fetched PEM is cached so a subsequent csr/cert chain doesn't pay
/// twice.
///
/// `changed: false` always, matching Ansible's `_pipe` semantics (the
/// task computes a value, doesn't mutate state). Even the cache-miss
/// dispatch is read-only on the agent.
async fn synth_csr_pipe(
    c: &OpenSslCsrPipeOp,
    ctx: &mut HostCtx,
    target_conn: &ConnHandle,
    next_seq: &Arc<AtomicU32>,
    task: &Task,
) -> BodyResult {
    let pem = match ctx.privkey_pem_cache.get(&c.privatekey_path) {
        Some(b) => b.clone(),
        None => match fetch_privkey_via_read_file(
            &c.privatekey_path,
            target_conn,
            next_seq,
            task,
            ctx,
        )
        .await
        {
            Ok(b) => {
                // Cache for any follow-up _pipe step in this play.
                ctx.privkey_pem_cache.insert(c.privatekey_path.clone(), b.clone());
                b
            }
            Err(e) => return e,
        },
    };
    synth_csr_pipe_from_pem(c, pem)
}

/// Pure-controller-side CSR synthesis. Split out from `synth_csr_pipe`
/// so the synthesis path can be unit-tested without an agent
/// connection. The wire fetch (when the privkey isn't cached) is the
/// async wrapper above.
fn synth_csr_pipe_from_pem(c: &OpenSslCsrPipeOp, pem: Vec<u8>) -> BodyResult {
    let csr_pem = match crate::x509::generate_csr(&crate::x509::CsrParams {
        privkey_pem: pem,
        common_name: c.common_name.clone(),
        country_name: c.country_name.clone(),
        organization_name: c.organization_name.clone(),
        organizational_unit_name: c.organizational_unit_name.clone(),
        subject_alt_name: c.subject_alt_name.clone(),
        key_usage: c.key_usage.clone(),
        extended_key_usage: c.extended_key_usage.clone(),
        basic_constraints: c.basic_constraints.clone(),
    }) {
        Ok(b) => b,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("openssl_csr_pipe: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };
    let csr_str = String::from_utf8_lossy(&csr_pem).into_owned();
    let mut rv = RegisterValue::default();
    // Ansible's `community.crypto.openssl_csr_pipe` returns the PEM
    // under `.csr` (canonical Ansible spelling) and also under
    // `.content` (for symmetry with other `_pipe` modules). We emit
    // both so chained playbooks work regardless of which key they
    // reference downstream.
    rv.extra
        .insert("content".into(), JsonValue::String(csr_str.clone()));
    rv.extra.insert("csr".into(), JsonValue::String(csr_str));
    BodyResult::Ok {
        register: rv,
        changed: false,
        skipped: false,
    }
}

/// Fetch a private-key PEM from the agent host via OpReadFile and
/// decode the slurp-style base64 envelope. Used by `synth_csr_pipe` on
/// cache miss to enable cross-run signing of an existing on-disk key.
///
/// Errors come back as a fully-formed `BodyResult::Failed` so the
/// caller can early-return; all other reachable paths produce the
/// raw PEM bytes.
async fn fetch_privkey_via_read_file(
    path: &str,
    target_conn: &ConnHandle,
    next_seq: &Arc<AtomicU32>,
    task: &Task,
    ctx: &HostCtx,
) -> std::result::Result<Vec<u8>, BodyResult> {
    use base64::Engine as _;

    let read_seq = next_seq.fetch_add(1, Ordering::Relaxed);
    let read_op =
        rsansible_wire::msg::op_read_file(path.to_string(), CSR_PIPE_PRIVKEY_MAX_BYTES);
    let exec = {
        let mut guard = target_conn.lock().await;
        let conn = match guard.as_mut() {
            Some(c) => c,
            None => {
                return Err(BodyResult::Failed {
                    reason: "openssl_csr_pipe: agent conn is dead (host marked failed)"
                        .into(),
                    register: None,
                    conn_alive: false,
                });
            }
        };
        let clock_offset_ns = conn.clock_offset_ns;
        // OpReadFile is read-only; pass effective check_mode through
        // for plumbing consistency. The agent ignores it.
        let check_mode = task.check_mode.unwrap_or(ctx.check_mode);
        match run_one_task_op(
            conn,
            read_seq,
            read_op,
            true,
            clock_offset_ns,
            check_mode,
            &ctx.run_metrics,
        )
        .await
        {
            Ok(o) => o,
            Err(e) => {
                return Err(BodyResult::Failed {
                    reason: format!("openssl_csr_pipe: OpReadFile dispatch: {e:#}"),
                    register: None,
                    conn_alive: false,
                });
            }
        }
    };
    if exec.done.exit_code != 0 {
        return Err(BodyResult::Failed {
            reason: format!(
                "openssl_csr_pipe: OpReadFile({path:?}) returned exit_code={}",
                exec.done.exit_code
            ),
            register: None,
            conn_alive: true,
        });
    }
    let envelope: JsonValue = match serde_json::from_slice(&exec.stdout) {
        Ok(v) => v,
        Err(e) => {
            return Err(BodyResult::Failed {
                reason: format!(
                    "openssl_csr_pipe: malformed slurp envelope from OpReadFile({path:?}): {e}"
                ),
                register: None,
                conn_alive: true,
            });
        }
    };
    let b64 = envelope
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BodyResult::Failed {
            reason: format!(
                "openssl_csr_pipe: slurp envelope missing `content` field for {path:?}"
            ),
            register: None,
            conn_alive: true,
        })?;
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(BodyResult::Failed {
            reason: format!(
                "openssl_csr_pipe: base64-decoding slurp content from {path:?}: {e}"
            ),
            register: None,
            conn_alive: true,
        }),
    }
}

/// `x509_certificate_pipe:` — sign a CSR and return the resulting cert
/// PEM via `register.content`. Pure controller-side; no wire dispatch.
///
/// Two provider modes:
///   - `selfsigned`: the CSR is signed by the SAME private key that
///     produced it. `privatekey_content:` / `privatekey_path:`.
///   - `ownca`: the CSR is signed by a separate CA cert + CA private
///     key. `ownca_content:` (CA cert PEM), `ownca_privatekey_content:`
///     / `ownca_privatekey_path:` (CA key).
///
/// All PEM-carrying fields are pre-rendered by `render_op`, so playbooks
/// typically pass them as `{{ csr_result.content }}` / `{{ ca_var }}`
/// chained through registers and inventory vars.
fn synth_cert_pipe(c: &X509CertificatePipeOp) -> BodyResult {
    let cert_pem_result = match c.provider.as_str() {
        "selfsigned" => {
            // Resolve the privkey PEM from either `privatekey_content`
            // (inline PEM, typically chained from a register) or
            // `privatekey_path` (controller-side file read). The parser
            // already enforced exactly-one-of, and render_op rendered
            // both.
            let privkey_pem: Vec<u8> = if !c.privatekey_path.is_empty() {
                match std::fs::read(&c.privatekey_path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return BodyResult::Failed {
                            reason: format!(
                                "x509_certificate_pipe: reading privatekey_path {:?} failed: {e}",
                                c.privatekey_path
                            ),
                            register: None,
                            conn_alive: true,
                        };
                    }
                }
            } else {
                c.privatekey_content.as_bytes().to_vec()
            };
            crate::x509::generate_selfsigned_cert(&crate::x509::SelfSignedCertParams {
                csr_pem: c.csr_content.as_bytes().to_vec(),
                privkey_pem,
                valid_for_days: c.valid_for_days,
            })
        }
        "ownca" => {
            let ca_key_pem: Vec<u8> = if !c.ownca_privatekey_path.is_empty() {
                match std::fs::read(&c.ownca_privatekey_path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return BodyResult::Failed {
                            reason: format!(
                                "x509_certificate_pipe: reading ownca_privatekey_path {:?} failed: {e}",
                                c.ownca_privatekey_path
                            ),
                            register: None,
                            conn_alive: true,
                        };
                    }
                }
            } else {
                c.ownca_privatekey_content.as_bytes().to_vec()
            };
            crate::x509::generate_ownca_signed_cert(&crate::x509::OwnCaSignedCertParams {
                csr_pem: c.csr_content.as_bytes().to_vec(),
                ca_cert_pem: c.ownca_content.as_bytes().to_vec(),
                ca_privkey_pem: ca_key_pem,
                valid_for_days: c.valid_for_days,
            })
        }
        other => {
            return BodyResult::Failed {
                reason: format!(
                    "x509_certificate_pipe.provider: unknown provider {other:?}; \
                     expected \"selfsigned\" or \"ownca\""
                ),
                register: None,
                conn_alive: true,
            };
        }
    };
    let cert_pem = match cert_pem_result {
        Ok(b) => b,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("x509_certificate_pipe: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };
    let cert_str = String::from_utf8_lossy(&cert_pem).into_owned();
    let mut rv = RegisterValue::default();
    // Ansible's `community.crypto.x509_certificate_pipe` returns both
    // `.content` and `.certificate` keyed to the same PEM. Emit both
    // so playbooks referencing either spelling work.
    rv.extra
        .insert("content".into(), JsonValue::String(cert_str.clone()));
    rv.extra
        .insert("certificate".into(), JsonValue::String(cert_str));
    BodyResult::Ok {
        register: rv,
        changed: false,
        skipped: false,
    }
}

/// `tempfile:` — create a temp file or directory on the **controller**
/// filesystem and bind `register.path` to the absolute path. v1 is
/// controller-side only; see ANSIBLE_COMPAT.md for the divergence (real
/// Ansible runs this on the target host).
///
/// Random suffix uses 12 chars from a URL-safe alphabet — wide enough
/// to avoid collisions in practice without bloating the path. Failure
/// to create (parent dir absent, permission denied, etc.) is reported
/// as a normal task failure with a useful reason; the register on
/// success contains both `path` and `state` for Ansible parity.
fn synth_tempfile(t: &TempfileOp) -> BodyResult {
    use std::path::PathBuf;

    let parent: PathBuf = match &t.path {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => std::env::temp_dir(),
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix(&t.prefix).suffix(&t.suffix);
    // 12 hex chars (~48 bits of entropy) — plenty for uniqueness while
    // keeping the filename short.
    builder.rand_bytes(12);

    let (full_path, state_str) = match t.state {
        TempfileKind::File => {
            let f = match builder.tempfile_in(&parent) {
                Ok(f) => f,
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!(
                            "tempfile: creating file under {parent:?} failed: {e}"
                        ),
                        register: None,
                        conn_alive: true,
                    };
                }
            };
            // `keep()` detaches the NamedTempFile so the file survives
            // drop — matches Ansible's contract that the path remains
            // valid for downstream tasks to consume.
            match f.keep() {
                Ok((_file, path)) => (path, "file"),
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("tempfile: persisting temp file failed: {e}"),
                        register: None,
                        conn_alive: true,
                    };
                }
            }
        }
        TempfileKind::Directory => {
            let d = match builder.tempdir_in(&parent) {
                Ok(d) => d,
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!(
                            "tempfile: creating directory under {parent:?} failed: {e}"
                        ),
                        register: None,
                        conn_alive: true,
                    };
                }
            };
            // Same rationale as the file branch: detach so the dir
            // outlives this scope.
            (d.keep(), "directory")
        }
    };

    let mut rv = RegisterValue::default();
    rv.extra.insert(
        "path".into(),
        JsonValue::String(full_path.to_string_lossy().into_owned()),
    );
    rv.extra
        .insert("state".into(), JsonValue::String(state_str.to_string()));
    BodyResult::Ok {
        register: rv,
        changed: true,
        skipped: false,
    }
}

fn run_assert_body(
    a: &AssertTask,
    ctx: &HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> BodyResult {
    let view = build_template_ctx(ctx, world);
    for (i, expr) in a.that.iter().enumerate() {
        let prepared = crate::template::prepare_jinja_source(expr);
        match env.compile_expression(&prepared) {
            Ok(compiled) => match compiled.eval(&view) {
                Ok(v) if v.is_true() => continue,
                Ok(_) => {
                    let reason = a
                        .fail_msg
                        .as_ref()
                        .map(|m| render_str(env, m, &view).unwrap_or_else(|_| m.clone()))
                        .unwrap_or_else(|| format!("assertion failed: {expr}"));
                    let mut rv = RegisterValue::default();
                    rv.failed = true;
                    rv.stderr = reason.clone();
                    rv.rc = 1;
                    return BodyResult::Failed {
                        reason,
                        register: Some(rv),
                        conn_alive: true,
                    };
                }
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("assert.that[{i}] eval: {e}"),
                        register: None,
                        conn_alive: true,
                    };
                }
            },
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("assert.that[{i}] compile: {e}"),
                    register: None,
                    conn_alive: true,
                };
            }
        }
    }
    // assert that passed: no state change.
    BodyResult::Ok {
        register: RegisterValue {
            changed: false,
            ..RegisterValue::default()
        },
        changed: false,
        skipped: false,
    }
}

fn run_fail_body(
    f: &FailTask,
    ctx: &HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> BodyResult {
    let view = build_template_ctx(ctx, world);
    let msg = match render_str(env, &f.msg, &view) {
        Ok(s) => s,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("fail.msg render: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };
    let mut rv = RegisterValue::default();
    rv.failed = true;
    rv.rc = 1;
    rv.stderr = msg.clone();
    BodyResult::Failed {
        reason: msg,
        register: Some(rv),
        conn_alive: true,
    }
}

/// `pause:` — controller-side sleep. Mirrors Ansible's
/// `ansible.builtin.pause` for the non-interactive subset
/// (`seconds:` / `minutes:`); interactive `prompt:` is rejected at
/// parse time, see ANSIBLE_COMPAT.md §8.
///
/// One of `seconds` / `minutes` is guaranteed Some by PauseTask's
/// deserializer (both-Some / neither-Some / null are parse-time errors).
/// Negative durations are rejected at render time with a clean task
/// failure rather than panicking or being treated as zero.
async fn run_pause_body(
    p: &PauseTask,
    ctx: &HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> BodyResult {
    // Render whichever knob is set. PauseTask::deserialize guarantees
    // exactly one is Some; multiplication picks the right unit factor.
    let (src, unit_secs, field_name) = match (&p.seconds, &p.minutes) {
        (Some(s), None) => (s.as_str(), 1u64, "seconds"),
        (None, Some(m)) => (m.as_str(), 60u64, "minutes"),
        _ => unreachable!("PauseTask::deserialize guarantees exactly one of seconds/minutes"),
    };
    let n = match render_int_field(env, src, ctx, world) {
        Ok(n) => n,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("pause.{field_name} render: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };
    if n < 0 {
        return BodyResult::Failed {
            reason: format!("pause.{field_name}: negative duration {n} is not allowed"),
            register: None,
            conn_alive: true,
        };
    }
    let duration = std::time::Duration::from_secs((n as u64).saturating_mul(unit_secs));
    info!(
        host = %ctx.host_name,
        secs = duration.as_secs(),
        "pause",
    );
    tokio::time::sleep(duration).await;
    let mut rv = RegisterValue::default();
    rv.changed = false;
    BodyResult::Ok {
        register: rv,
        changed: false,
        skipped: false,
    }
}

fn run_debug_body(
    d: &DebugTask,
    task: &Task,
    ctx: &HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> BodyResult {
    let view = build_template_ctx(ctx, world);
    // Render msg (Jinja-templated) or look up var by dotted path.
    let (label, payload) = match (&d.msg, &d.var) {
        (Some(crate::playbook::DebugMsg::One(msg)), _) => match render_str(env, msg, &view) {
            Ok(rendered) => ("msg".to_string(), JsonValue::String(rendered)),
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("debug.msg render: {e:#}"),
                    register: None,
                    conn_alive: true,
                };
            }
        },
        (Some(crate::playbook::DebugMsg::Many(lines)), _) => {
            // Render each line independently — keeps embedded Jinja
            // string literals from getting YAML-escape-mangled.
            let mut rendered_lines = Vec::with_capacity(lines.len());
            for (i, line) in lines.iter().enumerate() {
                match render_str(env, line, &view) {
                    Ok(r) => rendered_lines.push(JsonValue::String(r)),
                    Err(e) => {
                        return BodyResult::Failed {
                            reason: format!("debug.msg[{i}] render: {e:#}"),
                            register: None,
                            conn_alive: true,
                        };
                    }
                }
            }
            ("msg".to_string(), JsonValue::Array(rendered_lines))
        }
        (None, Some(var_name)) => {
            // First render the var-name string itself (Ansible allows
            // `var: "{{ dyn_name }}"`), then dotted-path-lookup.
            let resolved_name = match render_str(env, var_name, &view) {
                Ok(s) => s,
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("debug.var render: {e:#}"),
                        register: None,
                        conn_alive: true,
                    };
                }
            };
            let value = resolve_dotted_path(&view, &resolved_name).unwrap_or(JsonValue::String(
                format!("VARIABLE IS NOT DEFINED!: {resolved_name}"),
            ));
            (resolved_name, value)
        }
        (None, None) => unreachable!("DebugTask::deserialize forbids this"),
    };
    // Emit one info line so the operator sees it. Matches Ansible's
    // playbook output format: "TASK [<name>] => { "<label>": <value> }".
    let value_str = match &payload {
        JsonValue::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    };
    info!(task = %task.name, label = %label, value = %value_str, "debug");
    let mut rv = RegisterValue::default();
    rv.changed = false;
    rv.extra.insert(label, payload);
    BodyResult::Ok {
        register: rv,
        changed: false,
        skipped: false,
    }
}

/// Resolve a dotted path like `groups.postgres[0].ansible_host` against
/// the template view. Returns None if any segment is missing. Brackets
/// are not parsed — `foo.bar.0` works for lists, `foo[0]` does not.
fn resolve_dotted_path(view: &BTreeMap<String, JsonValue>, path: &str) -> Option<JsonValue> {
    let mut parts = path.split('.');
    let head = parts.next()?;
    let mut cur = view.get(head)?.clone();
    for seg in parts {
        cur = match cur {
            JsonValue::Object(mut o) => o.remove(seg)?,
            JsonValue::Array(arr) => {
                let idx = seg.parse::<usize>().ok()?;
                arr.into_iter().nth(idx)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

fn run_set_fact_body(
    m: &SetFactMap,
    ctx: &mut HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> BodyResult {
    let view = build_template_ctx(ctx, world);
    let mut to_set: Vec<(String, JsonValue)> = Vec::with_capacity(m.0.len());
    for (k, v) in &m.0 {
        let val = match v {
            serde_yaml::Value::String(s) => {
                // Render the string. If it parses cleanly as JSON afterward
                // (lets `set_fact: count: "{{ x + 1 }}"` produce a number),
                // expose it as that. Otherwise keep it as a string.
                match render_str(env, s, &view) {
                    Ok(rendered) => {
                        // Heuristic: only auto-parse when the rendered
                        // output looks like JSON (starts with `{`, `[`,
                        // a digit, or the keywords true/false/null). This
                        // avoids surprises like `"y2k"` getting parsed.
                        let trimmed = rendered.trim();
                        let auto = looks_jsonish(trimmed);
                        if auto {
                            serde_json::from_str::<JsonValue>(trimmed)
                                .unwrap_or(JsonValue::String(rendered))
                        } else {
                            JsonValue::String(rendered)
                        }
                    }
                    Err(e) => {
                        return BodyResult::Failed {
                            reason: format!("set_fact.{k}: {e:#}"),
                            register: None,
                            conn_alive: true,
                        };
                    }
                }
            }
            other => match yaml_to_json(other.clone()) {
                Ok(j) => j,
                Err(e) => {
                    return BodyResult::Failed {
                        reason: format!("set_fact.{k}: {e:#}"),
                        register: None,
                        conn_alive: true,
                    };
                }
            },
        };
        to_set.push((k.clone(), val));
    }
    for (k, v) in to_set {
        ctx.set_facts.insert(k, v);
    }
    // set_fact synthesizes a changed=true register so notify-on-set_fact
    // fires (matches Ansible).
    BodyResult::Ok {
        register: RegisterValue::synthetic_ok(),
        changed: true,
        skipped: false,
    }
}

fn looks_jsonish(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    first == '{'
        || first == '['
        || first.is_ascii_digit()
        || first == '-'
        || s == "true"
        || s == "false"
        || s == "null"
}

// ---------- postgres composite dispatch (controller-side ops) ----------

/// Quote a string as a PostgreSQL identifier: surround with double
/// quotes, double any internal double quotes. Rejects names that
/// contain a NUL byte (postgres can't store those) by returning Err.
fn quote_pg_ident(name: &str) -> Result<String> {
    if name.contains('\0') {
        return Err(anyhow!(
            "identifier {name:?} contains a NUL byte — postgres can't store these"
        ));
    }
    let mut s = String::with_capacity(name.len() + 2);
    s.push('"');
    for c in name.chars() {
        if c == '"' {
            s.push('"');
            s.push('"');
        } else {
            s.push(c);
        }
    }
    s.push('"');
    Ok(s)
}

/// Quote a string as a PostgreSQL string literal: surround with single
/// quotes, double any internal single quotes. We don't use `E'...'`
/// escape form — backslashes are passed through literally, which
/// matches standard_conforming_strings=on (the default for ~all
/// supported postgres versions).
fn quote_pg_string_literal(val: &str) -> String {
    let mut s = String::with_capacity(val.len() + 2);
    s.push('\'');
    for c in val.chars() {
        if c == '\'' {
            s.push('\'');
            s.push('\'');
        } else {
            s.push(c);
        }
    }
    s.push('\'');
    s
}

/// Dispatch one `OpPostgresqlQuery` and return its raw exec outcome.
/// All postgres composite helpers funnel through here so error wiring
/// stays uniform.
async fn dispatch_one_pg_query(
    task: &Task,
    ctx: &HostCtx,
    target_conn: &ConnHandle,
    next_seq: &Arc<AtomicU32>,
    op: Op,
    capture: bool,
) -> std::result::Result<OpExecOutcome, BodyResult> {
    let seq = next_seq.fetch_add(1, Ordering::Relaxed);
    let mut guard = target_conn.lock().await;
    let conn = match guard.as_mut() {
        Some(c) => c,
        None => {
            return Err(BodyResult::Failed {
                reason: "agent conn is dead (host marked failed)".into(),
                register: None,
                conn_alive: false,
            });
        }
    };
    let clock_offset_ns = conn.clock_offset_ns;
    // Composite SQL dispatches inherit the task's effective check_mode;
    // the read-only probe always runs even under --check (matches the
    // agent-side postgresql_ext probe shape), and the mutating arm
    // suppresses itself under check_mode at the composite level.
    let check_mode = task.check_mode.unwrap_or(ctx.check_mode);
    run_one_task_op(
        conn,
        seq,
        op,
        capture,
        clock_offset_ns,
        check_mode,
        &ctx.run_metrics,
    )
    .await
    .map_err(|e| BodyResult::Failed {
        reason: format!("postgresql composite dispatch: {e:#}"),
        register: None,
        conn_alive: false,
    })
}

/// Parse the JSON envelope an `OpPostgresqlQuery` agent emits on
/// stdout. The envelope shape is `{ query_result: [...], rowcount,
/// statusmessage }` — see `crates/agent/src/modules/postgresql.rs`.
fn parse_pg_query_envelope(
    exec: &OpExecOutcome,
    label: &str,
) -> std::result::Result<JsonValue, BodyResult> {
    if exec.done.exit_code != 0 {
        // The agent emits a structured error envelope on stderr when
        // it fails; surface its message when available, fall back to
        // the exit code.
        let stderr = String::from_utf8_lossy(&exec.stderr);
        let reason = if stderr.trim().is_empty() {
            format!("{label}: agent returned exit_code={}", exec.done.exit_code)
        } else {
            format!(
                "{label}: agent returned exit_code={}: {}",
                exec.done.exit_code,
                stderr.trim()
            )
        };
        return Err(BodyResult::Failed {
            reason,
            register: None,
            conn_alive: true,
        });
    }
    let stdout = String::from_utf8_lossy(&exec.stdout);
    serde_json::from_str::<JsonValue>(stdout.trim()).map_err(|e| BodyResult::Failed {
        reason: format!("{label}: malformed agent envelope: {e}; stdout={stdout:?}"),
        register: None,
        conn_alive: true,
    })
}

/// Mask known-secret SQL substrings (currently: `PASSWORD '<…>'`)
/// from a stringified SQL statement for inclusion in
/// `register.queries`. Case-insensitive on the `PASSWORD` keyword.
fn mask_password_in_sql(sql: &str) -> String {
    // Greedy replace: walk the string, when we hit "PASSWORD '<...>'"
    // replace the quoted literal with '<masked>'. We don't try to
    // handle E'...' or dollar-quoted strings — the composite never
    // emits those.
    let lower = sql.to_ascii_lowercase();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;
    let bytes = sql.as_bytes();
    while i < bytes.len() {
        // Look for "password '" (case-insensitive) — preceded by
        // whitespace/keyword separator boundary at i, then a literal '.
        if lower[i..].starts_with("password") {
            // Find the next single quote.
            let kw_end = i + "password".len();
            // Skip whitespace.
            let mut j = kw_end;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\'' {
                // Find the closing single quote, respecting '' escape.
                let mut k = j + 1;
                while k < bytes.len() {
                    if bytes[k] == b'\'' {
                        if k + 1 < bytes.len() && bytes[k + 1] == b'\'' {
                            k += 2;
                            continue;
                        }
                        break;
                    }
                    k += 1;
                }
                if k < bytes.len() {
                    out.push_str(&sql[i..j]);
                    out.push_str("'<masked>'");
                    i = k + 1;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Resolved boolean attrs requested by `role_attr_flags`. Each Option
/// is `Some(true)` for set / `Some(false)` for cleared / `None` if
/// the user didn't mention this attr at all.
#[derive(Debug, Default, Clone, Copy)]
struct ResolvedRoleAttrs {
    canlogin: Option<bool>,
    super_: Option<bool>,
    createdb: Option<bool>,
    createrole: Option<bool>,
    inherit: Option<bool>,
    replication: Option<bool>,
    bypassrls: Option<bool>,
}

impl ResolvedRoleAttrs {
    fn from_flags_str(flags: &str) -> Result<Self> {
        let mut out = Self::default();
        for raw in flags.split(',') {
            let tok = raw.trim();
            if tok.is_empty() {
                continue;
            }
            let (canonical, want) =
                crate::playbook::task_op::postgresql::normalize_role_attr_token(tok)
                    .ok_or_else(|| {
                        anyhow!(
                            "postgresql_user.role_attr_flags: unknown attr {tok:?} \
                             (post-render); supported: LOGIN, SUPERUSER, CREATEDB, \
                             CREATEROLE, INHERIT, REPLICATION, BYPASSRLS (each with \
                             NO… counterpart)"
                        )
                    })?;
            match canonical {
                "canlogin" => out.canlogin = Some(want),
                "super" => out.super_ = Some(want),
                "createdb" => out.createdb = Some(want),
                "createrole" => out.createrole = Some(want),
                "inherit" => out.inherit = Some(want),
                "replication" => out.replication = Some(want),
                "bypassrls" => out.bypassrls = Some(want),
                _ => unreachable!("normalize_role_attr_token returned unknown {canonical:?}"),
            }
        }
        Ok(out)
    }

    /// Emit the CREATE ROLE option clause for this set. Skipped attrs
    /// don't appear — postgres uses LOGIN/NOLOGIN-style defaults.
    fn render_create_clause(&self) -> String {
        let mut parts: Vec<&'static str> = Vec::new();
        if let Some(v) = self.canlogin {
            parts.push(if v { "LOGIN" } else { "NOLOGIN" });
        }
        if let Some(v) = self.super_ {
            parts.push(if v { "SUPERUSER" } else { "NOSUPERUSER" });
        }
        if let Some(v) = self.createdb {
            parts.push(if v { "CREATEDB" } else { "NOCREATEDB" });
        }
        if let Some(v) = self.createrole {
            parts.push(if v { "CREATEROLE" } else { "NOCREATEROLE" });
        }
        if let Some(v) = self.inherit {
            parts.push(if v { "INHERIT" } else { "NOINHERIT" });
        }
        if let Some(v) = self.replication {
            parts.push(if v { "REPLICATION" } else { "NOREPLICATION" });
        }
        if let Some(v) = self.bypassrls {
            parts.push(if v { "BYPASSRLS" } else { "NOBYPASSRLS" });
        }
        parts.join(" ")
    }

    /// Diff the requested attrs against current server-side values
    /// (each column from `pg_authid`). Returns the diff as an ALTER
    /// ROLE option clause covering only the attrs that need to flip.
    /// Empty string means "no attr diff."
    fn diff_against_probe(&self, probe: &PgAuthidRow) -> String {
        let mut parts: Vec<&'static str> = Vec::new();
        macro_rules! diff_one {
            ($req:expr, $cur:expr, $true_kw:literal, $false_kw:literal) => {
                if let Some(want) = $req {
                    if want != $cur {
                        parts.push(if want { $true_kw } else { $false_kw });
                    }
                }
            };
        }
        diff_one!(self.canlogin, probe.canlogin, "LOGIN", "NOLOGIN");
        diff_one!(self.super_, probe.super_, "SUPERUSER", "NOSUPERUSER");
        diff_one!(self.createdb, probe.createdb, "CREATEDB", "NOCREATEDB");
        diff_one!(self.createrole, probe.createrole, "CREATEROLE", "NOCREATEROLE");
        diff_one!(self.inherit, probe.inherit, "INHERIT", "NOINHERIT");
        diff_one!(self.replication, probe.replication, "REPLICATION", "NOREPLICATION");
        diff_one!(self.bypassrls, probe.bypassrls, "BYPASSRLS", "NOBYPASSRLS");
        parts.join(" ")
    }
}

/// Decoded one-row result from the `pg_authid` probe SELECT.
#[derive(Debug, Clone)]
struct PgAuthidRow {
    super_: bool,
    createrole: bool,
    createdb: bool,
    canlogin: bool,
    inherit: bool,
    replication: bool,
    bypassrls: bool,
    connlimit: i32,
    /// `rolpassword` (NULL → None). Tokio-postgres `simple_query`
    /// surfaces every value as a text string; `NULL` shows as None.
    rolpassword: Option<String>,
}

fn parse_pg_authid_row(env: &JsonValue) -> Result<Option<PgAuthidRow>> {
    let rows = env
        .get("query_result")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("pg_authid probe: missing/non-array query_result"))?;
    if rows.is_empty() {
        return Ok(None);
    }
    let row = rows[0]
        .as_object()
        .ok_or_else(|| anyhow!("pg_authid probe: row is not an object"))?;
    let parse_bool = |k: &str| -> Result<bool> {
        let v = row
            .get(k)
            .ok_or_else(|| anyhow!("pg_authid probe: missing column {k:?}"))?;
        match v {
            JsonValue::Bool(b) => Ok(*b),
            JsonValue::String(s) => match s.as_str() {
                "t" | "true" | "1" => Ok(true),
                "f" | "false" | "0" => Ok(false),
                other => Err(anyhow!(
                    "pg_authid probe: column {k:?} unparseable as bool: {other:?}"
                )),
            },
            other => Err(anyhow!(
                "pg_authid probe: column {k:?} not a bool/string, got: {other:?}"
            )),
        }
    };
    let parse_i32 = |k: &str| -> Result<i32> {
        let v = row
            .get(k)
            .ok_or_else(|| anyhow!("pg_authid probe: missing column {k:?}"))?;
        match v {
            JsonValue::Number(n) => n
                .as_i64()
                .and_then(|x| i32::try_from(x).ok())
                .ok_or_else(|| anyhow!("pg_authid probe: column {k:?} out of i32 range: {n}")),
            JsonValue::String(s) => s
                .parse::<i32>()
                .map_err(|e| anyhow!("pg_authid probe: column {k:?} not an int: {s:?}: {e}")),
            other => Err(anyhow!(
                "pg_authid probe: column {k:?} not a number/string, got: {other:?}"
            )),
        }
    };
    let parse_str_opt = |k: &str| -> Option<String> {
        match row.get(k) {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::String(s)) => Some(s.clone()),
            // tokio-postgres simple_query returns every column as a
            // text string, so we shouldn't hit other variants. Coerce
            // anyway for robustness.
            Some(other) => Some(other.to_string()),
        }
    };
    Ok(Some(PgAuthidRow {
        super_: parse_bool("rolsuper")?,
        createrole: parse_bool("rolcreaterole")?,
        createdb: parse_bool("rolcreatedb")?,
        canlogin: parse_bool("rolcanlogin")?,
        inherit: parse_bool("rolinherit")?,
        replication: parse_bool("rolreplication")?,
        bypassrls: parse_bool("rolbypassrls")?,
        connlimit: parse_i32("rolconnlimit")?,
        rolpassword: parse_str_opt("rolpassword"),
    }))
}

/// Decide whether the requested plaintext `password` should trigger
/// an ALTER ROLE PASSWORD given the role's current `rolpassword`
/// value.
///
/// v1 strategy: if password is set, **always emit ALTER** (returns
/// true). This matches Ansible's behaviour on SCRAM-SHA-256 hashed
/// roles (the default in PG 14+), where the stored hash includes a
/// random salt and there's no way to tell client-side whether the
/// plaintext matches without doing the SCRAM PBKDF2 dance.
/// Consequence: `changed=true` is reported on every run that has
/// `password:` set. Operators who want strict idempotency set
/// `no_password_changes: true` after the role is provisioned.
///
/// Documented as a follow-up in TODO.md: we could implement the
/// SCRAM-SHA-256 client-side comparison (extract salt + iter count
/// from the stored `SCRAM-SHA-256$<iters>:<salt>$<storedkey>:<serverkey>`
/// envelope, PBKDF2 the plaintext, compare keys) but the dependency
/// footprint (pbkdf2 + hmac + base64) and complexity isn't worth it
/// for v1. Also md5-hashed roles still hit this path and over-report;
/// adding md5 client-side comparison is a smaller follow-up.
fn decide_password_alter(
    password: &str,
    _username: &str,
    _cur_rolpassword: Option<&str>,
) -> bool {
    // v1: always re-set when password is provided. See doc comment
    // above for the SCRAM-vs-md5 hash-comparison follow-up.
    !password.is_empty()
}

/// `postgresql_user:` composite. See the doc comment on
/// `PostgresqlUserOp` for the high-level shape; this function owns
/// the actual dispatch sequence.
async fn run_postgresql_user_composite(
    task: &Task,
    op: &PostgresqlUserOp,
    target_conn: &ConnHandle,
    ctx: &mut HostCtx,
    next_seq: &Arc<AtomicU32>,
) -> BodyResult {
    let effective_check_mode = task.check_mode.unwrap_or(ctx.check_mode);

    // Validate identifier early — quote_pg_ident errors on NUL bytes.
    let name_quoted = match quote_pg_ident(&op.name) {
        Ok(s) => s,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("postgresql_user: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };

    // Step 1: probe pg_authid.
    let probe_sql = "SELECT rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, \
                     rolinherit, rolreplication, rolbypassrls, rolconnlimit, \
                     rolpassword \
                     FROM pg_authid WHERE rolname = $1"
        .to_string();
    let probe_op = rsansible_wire::msg::op_postgresql_query(
        probe_sql.clone(),
        op.db.clone(),
        op.login_user.clone(),
        op.login_password.clone(),
        op.login_unix_socket.clone(),
        op.login_host.clone(),
        op.login_port,
        false, // autocommit
        vec![op.name.clone()],
        true, // read_only
    );
    let probe_exec = match dispatch_one_pg_query(task, ctx, target_conn, next_seq, probe_op, true)
        .await
    {
        Ok(e) => e,
        Err(br) => return br,
    };
    let probe_env = match parse_pg_query_envelope(&probe_exec, "postgresql_user.probe") {
        Ok(v) => v,
        Err(br) => return br,
    };
    let current = match parse_pg_authid_row(&probe_env) {
        Ok(c) => c,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("postgresql_user.probe: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };

    // Resolve requested attrs.
    let requested_attrs = match ResolvedRoleAttrs::from_flags_str(&op.role_attr_flags) {
        Ok(a) => a,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("{e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };

    // Decide what to do.
    let want_present = op.state == 0;
    let mut queries: Vec<String> = Vec::new();
    let mut changed = false;

    match (want_present, current.as_ref()) {
        (true, None) => {
            // CREATE ROLE.
            let mut clauses = requested_attrs.render_create_clause();
            if op.conn_limit != crate::playbook::task_op::postgresql::CONN_LIMIT_UNSET {
                if !clauses.is_empty() {
                    clauses.push(' ');
                }
                clauses.push_str(&format!("CONNECTION LIMIT {}", op.conn_limit));
            }
            let mut sql = format!("CREATE ROLE {name_quoted}");
            if !clauses.is_empty() {
                sql.push_str(" WITH ");
                sql.push_str(&clauses);
            }
            if !op.password.is_empty() {
                sql.push_str(" PASSWORD ");
                sql.push_str(&quote_pg_string_literal(&op.password));
            }
            queries.push(mask_password_in_sql(&sql));
            changed = true;
            if !effective_check_mode {
                let mut_op = rsansible_wire::msg::op_postgresql_query(
                    sql,
                    op.db.clone(),
                    op.login_user.clone(),
                    op.login_password.clone(),
                    op.login_unix_socket.clone(),
                    op.login_host.clone(),
                    op.login_port,
                    false,
                    vec![],
                    false,
                );
                let exec = match dispatch_one_pg_query(
                    task, ctx, target_conn, next_seq, mut_op, true,
                )
                .await
                {
                    Ok(e) => e,
                    Err(br) => return br,
                };
                if let Err(br) = parse_pg_query_envelope(&exec, "postgresql_user.create") {
                    return br;
                }
            }
        }
        (true, Some(cur)) => {
            // ALTER ROLE if anything diverges.
            let attr_clause = requested_attrs.diff_against_probe(cur);
            let conn_limit_diff =
                op.conn_limit != crate::playbook::task_op::postgresql::CONN_LIMIT_UNSET
                    && op.conn_limit != cur.connlimit;
            let want_password_alter = !op.password.is_empty()
                && !op.no_password_changes
                && decide_password_alter(
                    &op.password,
                    &op.name,
                    cur.rolpassword.as_deref(),
                );
            if !attr_clause.is_empty() || conn_limit_diff || want_password_alter {
                let mut sql = format!("ALTER ROLE {name_quoted}");
                let mut wrote_with = false;
                if !attr_clause.is_empty() {
                    sql.push_str(" WITH ");
                    sql.push_str(&attr_clause);
                    wrote_with = true;
                }
                if conn_limit_diff {
                    if !wrote_with {
                        sql.push_str(" WITH");
                        wrote_with = true;
                    }
                    sql.push_str(&format!(" CONNECTION LIMIT {}", op.conn_limit));
                }
                if want_password_alter {
                    if !wrote_with {
                        sql.push_str(" WITH");
                    }
                    sql.push_str(" PASSWORD ");
                    sql.push_str(&quote_pg_string_literal(&op.password));
                }
                queries.push(mask_password_in_sql(&sql));
                changed = true;
                if !effective_check_mode {
                    let mut_op = rsansible_wire::msg::op_postgresql_query(
                        sql,
                        op.db.clone(),
                        op.login_user.clone(),
                        op.login_password.clone(),
                        op.login_unix_socket.clone(),
                        op.login_host.clone(),
                        op.login_port,
                        false,
                        vec![],
                        false,
                    );
                    let exec = match dispatch_one_pg_query(
                        task, ctx, target_conn, next_seq, mut_op, true,
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(br) => return br,
                    };
                    if let Err(br) = parse_pg_query_envelope(&exec, "postgresql_user.alter")
                    {
                        return br;
                    }
                }
            }
        }
        (false, Some(_)) => {
            // DROP ROLE.
            let sql = format!("DROP ROLE {name_quoted}");
            queries.push(sql.clone());
            changed = true;
            if !effective_check_mode {
                let mut_op = rsansible_wire::msg::op_postgresql_query(
                    sql,
                    op.db.clone(),
                    op.login_user.clone(),
                    op.login_password.clone(),
                    op.login_unix_socket.clone(),
                    op.login_host.clone(),
                    op.login_port,
                    false,
                    vec![],
                    false,
                );
                let exec = match dispatch_one_pg_query(
                    task, ctx, target_conn, next_seq, mut_op, true,
                )
                .await
                {
                    Ok(e) => e,
                    Err(br) => return br,
                };
                if let Err(br) = parse_pg_query_envelope(&exec, "postgresql_user.drop") {
                    return br;
                }
            }
        }
        (false, None) => {
            // No-op: role already absent.
        }
    }

    // Assemble register.
    let mut rv = RegisterValue::default();
    rv.took_ms = 0;
    rv.changed = changed;
    rv.skipped = effective_check_mode && changed;
    rv.extra
        .insert("user".into(), JsonValue::String(op.name.clone()));
    rv.extra.insert(
        "queries".into(),
        JsonValue::Array(queries.into_iter().map(JsonValue::String).collect()),
    );
    BodyResult::Ok {
        register: rv,
        changed,
        skipped: effective_check_mode && changed,
    }
}

/// `postgresql_membership:` composite. Probes `pg_auth_members` per
/// (group, target_role) pair via a one-row EXISTS query and emits at
/// most one GRANT or REVOKE per divergent pair. Idempotent: a run
/// where every pair already matches the requested `state` emits zero
/// mutating statements and reports `changed=false`. Cost: one probe
/// roundtrip per pair plus one mutation roundtrip per divergent pair.
/// See `PostgresqlMembershipOp` doc comment for the high-level shape.
async fn run_postgresql_membership_composite(
    task: &Task,
    op: &PostgresqlMembershipOp,
    target_conn: &ConnHandle,
    ctx: &mut HostCtx,
    next_seq: &Arc<AtomicU32>,
) -> BodyResult {
    let effective_check_mode = task.check_mode.unwrap_or(ctx.check_mode);
    let want_present = op.state == 0;

    // Validate identifiers up front so a typo in any list element
    // surfaces before we touch the network.
    let mut group_idents: Vec<(String, String)> = Vec::with_capacity(op.groups.len());
    for g in &op.groups {
        match quote_pg_ident(g) {
            Ok(q) => group_idents.push((g.clone(), q)),
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("postgresql_membership.groups: {e:#}"),
                    register: None,
                    conn_alive: true,
                };
            }
        }
    }
    let mut target_idents: Vec<(String, String)> = Vec::with_capacity(op.target_roles.len());
    for t in &op.target_roles {
        match quote_pg_ident(t) {
            Ok(q) => target_idents.push((t.clone(), q)),
            Err(e) => {
                return BodyResult::Failed {
                    reason: format!("postgresql_membership.target_roles: {e:#}"),
                    register: None,
                    conn_alive: true,
                };
            }
        }
    }

    let mut queries: Vec<String> = Vec::new();
    let mut granted: Vec<JsonValue> = Vec::new();
    let mut revoked: Vec<JsonValue> = Vec::new();
    let mut changed = false;

    // Pair-loop. Each iteration: probe → maybe mutate.
    for (group_name, group_quoted) in &group_idents {
        for (target_name, target_quoted) in &target_idents {
            // Probe pg_auth_members. We also check existence of both
            // roles in the same SELECT so `fail_on_role` can be
            // honored — three columns: group_exists, target_exists,
            // is_member.
            let probe_sql = "SELECT \
                              EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1) AS group_exists, \
                              EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $2) AS target_exists, \
                              EXISTS (SELECT 1 FROM pg_auth_members am \
                                      JOIN pg_roles g ON g.oid = am.roleid \
                                      JOIN pg_roles t ON t.oid = am.member \
                                      WHERE g.rolname = $1 AND t.rolname = $2) AS is_member"
                .to_string();
            let probe_op = rsansible_wire::msg::op_postgresql_query(
                probe_sql,
                op.db.clone(),
                op.login_user.clone(),
                op.login_password.clone(),
                op.login_unix_socket.clone(),
                op.login_host.clone(),
                op.login_port,
                false,
                vec![group_name.clone(), target_name.clone()],
                true,
            );
            let probe_exec = match dispatch_one_pg_query(
                task, ctx, target_conn, next_seq, probe_op, true,
            )
            .await
            {
                Ok(e) => e,
                Err(br) => return br,
            };
            let probe_env =
                match parse_pg_query_envelope(&probe_exec, "postgresql_membership.probe") {
                    Ok(v) => v,
                    Err(br) => return br,
                };
            let rows = match probe_env.get("query_result").and_then(|v| v.as_array()) {
                Some(r) => r,
                None => {
                    return BodyResult::Failed {
                        reason: "postgresql_membership.probe: missing/non-array query_result"
                            .into(),
                        register: None,
                        conn_alive: true,
                    };
                }
            };
            if rows.is_empty() {
                return BodyResult::Failed {
                    reason: "postgresql_membership.probe: empty result set".into(),
                    register: None,
                    conn_alive: true,
                };
            }
            let row = match rows[0].as_object() {
                Some(r) => r,
                None => {
                    return BodyResult::Failed {
                        reason: "postgresql_membership.probe: row is not an object".into(),
                        register: None,
                        conn_alive: true,
                    };
                }
            };
            let parse_bool_col = |k: &str| -> std::result::Result<bool, BodyResult> {
                match row.get(k) {
                    Some(JsonValue::Bool(b)) => Ok(*b),
                    Some(JsonValue::String(s)) => match s.as_str() {
                        "t" | "true" | "1" => Ok(true),
                        "f" | "false" | "0" => Ok(false),
                        other => Err(BodyResult::Failed {
                            reason: format!(
                                "postgresql_membership.probe: column {k:?} unparseable as bool: {other:?}"
                            ),
                            register: None,
                            conn_alive: true,
                        }),
                    },
                    other => Err(BodyResult::Failed {
                        reason: format!(
                            "postgresql_membership.probe: column {k:?} missing or wrong type: {other:?}"
                        ),
                        register: None,
                        conn_alive: true,
                    }),
                }
            };
            let group_exists = match parse_bool_col("group_exists") {
                Ok(b) => b,
                Err(br) => return br,
            };
            let target_exists = match parse_bool_col("target_exists") {
                Ok(b) => b,
                Err(br) => return br,
            };
            let is_member = match parse_bool_col("is_member") {
                Ok(b) => b,
                Err(br) => return br,
            };

            if !group_exists || !target_exists {
                if op.fail_on_role {
                    let missing = if !group_exists {
                        format!("group role {group_name:?} does not exist")
                    } else {
                        format!("target role {target_name:?} does not exist")
                    };
                    return BodyResult::Failed {
                        reason: format!("postgresql_membership: {missing}"),
                        register: None,
                        conn_alive: true,
                    };
                } else {
                    // Skip this pair silently — matches Ansible.
                    continue;
                }
            }

            if want_present && !is_member {
                let sql = format!("GRANT {group_quoted} TO {target_quoted}");
                queries.push(sql.clone());
                granted.push(JsonValue::Array(vec![
                    JsonValue::String(group_name.clone()),
                    JsonValue::String(target_name.clone()),
                ]));
                changed = true;
                if !effective_check_mode {
                    let mut_op = rsansible_wire::msg::op_postgresql_query(
                        sql,
                        op.db.clone(),
                        op.login_user.clone(),
                        op.login_password.clone(),
                        op.login_unix_socket.clone(),
                        op.login_host.clone(),
                        op.login_port,
                        false,
                        vec![],
                        false,
                    );
                    let exec = match dispatch_one_pg_query(
                        task, ctx, target_conn, next_seq, mut_op, true,
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(br) => return br,
                    };
                    if let Err(br) =
                        parse_pg_query_envelope(&exec, "postgresql_membership.grant")
                    {
                        return br;
                    }
                }
            } else if !want_present && is_member {
                let sql = format!("REVOKE {group_quoted} FROM {target_quoted}");
                queries.push(sql.clone());
                revoked.push(JsonValue::Array(vec![
                    JsonValue::String(group_name.clone()),
                    JsonValue::String(target_name.clone()),
                ]));
                changed = true;
                if !effective_check_mode {
                    let mut_op = rsansible_wire::msg::op_postgresql_query(
                        sql,
                        op.db.clone(),
                        op.login_user.clone(),
                        op.login_password.clone(),
                        op.login_unix_socket.clone(),
                        op.login_host.clone(),
                        op.login_port,
                        false,
                        vec![],
                        false,
                    );
                    let exec = match dispatch_one_pg_query(
                        task, ctx, target_conn, next_seq, mut_op, true,
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(br) => return br,
                    };
                    if let Err(br) =
                        parse_pg_query_envelope(&exec, "postgresql_membership.revoke")
                    {
                        return br;
                    }
                }
            }
        }
    }

    let mut rv = RegisterValue::default();
    rv.took_ms = 0;
    rv.changed = changed;
    rv.skipped = effective_check_mode && changed;
    rv.extra.insert("granted".into(), JsonValue::Array(granted));
    rv.extra.insert("revoked".into(), JsonValue::Array(revoked));
    rv.extra.insert(
        "queries".into(),
        JsonValue::Array(queries.into_iter().map(JsonValue::String).collect()),
    );
    BodyResult::Ok {
        register: rv,
        changed,
        skipped: effective_check_mode && changed,
    }
}

/// `postgresql_db:` composite. Probes `pg_database` for the database
/// row, then issues CREATE/ALTER/DROP DATABASE on divergence. Like
/// `postgresql_user`, idempotent steady state costs one probe
/// roundtrip; first-time creation costs one extra mutation
/// roundtrip.
///
/// CREATE DATABASE cannot run inside a transaction block — the
/// agent's autocommit=false default would refuse it; we pass
/// `autocommit=true` on every mutation here. The probe stays
/// autocommit=false (read-only).
async fn run_postgresql_db_composite(
    task: &Task,
    op: &PostgresqlDbOp,
    target_conn: &ConnHandle,
    ctx: &mut HostCtx,
    next_seq: &Arc<AtomicU32>,
) -> BodyResult {
    let effective_check_mode = task.check_mode.unwrap_or(ctx.check_mode);

    let name_quoted = match quote_pg_ident(&op.name) {
        Ok(s) => s,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("postgresql_db: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
    };

    // Probe pg_database joined with pg_roles for the owner name.
    // `db: ""` defers to the agent's default — connecting to the DB
    // you're about to create/drop is a chicken-and-egg problem, and
    // the agent picks a reasonable default ("postgres") when the
    // login is a unix socket. Callers who want a different bootstrap
    // DB set `login_user` / `login_unix_socket` to point there.
    let probe_op = rsansible_wire::msg::op_postgresql_query(
        "SELECT d.datname, r.rolname AS owner, \
         pg_encoding_to_char(d.encoding) AS encoding, \
         d.datcollate AS lc_collate, d.datctype AS lc_ctype \
         FROM pg_database d \
         JOIN pg_roles r ON r.oid = d.datdba \
         WHERE d.datname = $1"
            .to_string(),
        String::new(),
        op.login_user.clone(),
        op.login_password.clone(),
        op.login_unix_socket.clone(),
        op.login_host.clone(),
        op.login_port,
        false,
        vec![op.name.clone()],
        true,
    );
    let probe_exec = match dispatch_one_pg_query(task, ctx, target_conn, next_seq, probe_op, true)
        .await
    {
        Ok(e) => e,
        Err(br) => return br,
    };
    let probe_env = match parse_pg_query_envelope(&probe_exec, "postgresql_db.probe") {
        Ok(v) => v,
        Err(br) => return br,
    };
    let rows = match probe_env.get("query_result").and_then(|v| v.as_array()) {
        Some(r) => r,
        None => {
            return BodyResult::Failed {
                reason: "postgresql_db.probe: missing/non-array query_result".into(),
                register: None,
                conn_alive: true,
            };
        }
    };
    let current: Option<(String, String, String, String)> = if rows.is_empty() {
        None
    } else {
        let row = match rows[0].as_object() {
            Some(r) => r,
            None => {
                return BodyResult::Failed {
                    reason: "postgresql_db.probe: row not an object".into(),
                    register: None,
                    conn_alive: true,
                };
            }
        };
        let get_str = |k: &str| -> String {
            match row.get(k) {
                Some(JsonValue::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            }
        };
        Some((
            get_str("owner"),
            get_str("encoding"),
            get_str("lc_collate"),
            get_str("lc_ctype"),
        ))
    };

    let want_present = op.state == 0;
    let mut queries: Vec<String> = Vec::new();
    let mut changed = false;

    match (want_present, current.as_ref()) {
        (true, None) => {
            // CREATE DATABASE.
            let mut sql = format!("CREATE DATABASE {name_quoted}");
            let mut parts: Vec<String> = Vec::new();
            if !op.owner.is_empty() {
                parts.push(format!("OWNER {}", quote_pg_ident(&op.owner).unwrap_or_else(|_| op.owner.clone())));
            }
            if !op.template.is_empty() {
                parts.push(format!(
                    "TEMPLATE {}",
                    quote_pg_ident(&op.template).unwrap_or_else(|_| op.template.clone())
                ));
            }
            if !op.encoding.is_empty() {
                parts.push(format!("ENCODING {}", quote_pg_string_literal(&op.encoding)));
            }
            if !op.lc_collate.is_empty() {
                parts.push(format!(
                    "LC_COLLATE {}",
                    quote_pg_string_literal(&op.lc_collate)
                ));
            }
            if !op.lc_ctype.is_empty() {
                parts.push(format!(
                    "LC_CTYPE {}",
                    quote_pg_string_literal(&op.lc_ctype)
                ));
            }
            if !parts.is_empty() {
                sql.push_str(" WITH ");
                sql.push_str(&parts.join(" "));
            }
            queries.push(sql.clone());
            changed = true;
            if !effective_check_mode {
                let mut_op = rsansible_wire::msg::op_postgresql_query(
                    sql,
                    String::new(),
                    op.login_user.clone(),
                    op.login_password.clone(),
                    op.login_unix_socket.clone(),
                    op.login_host.clone(),
                    op.login_port,
                    true, // autocommit — CREATE DATABASE forbids txn block
                    vec![],
                    false,
                );
                let exec =
                    match dispatch_one_pg_query(task, ctx, target_conn, next_seq, mut_op, true)
                        .await
                    {
                        Ok(e) => e,
                        Err(br) => return br,
                    };
                if let Err(br) = parse_pg_query_envelope(&exec, "postgresql_db.create") {
                    return br;
                }
            }
        }
        (true, Some((owner, _encoding, _lc_collate, _lc_ctype))) => {
            // Only OWNER can be ALTERed cheaply in-place — encoding,
            // lc_collate, lc_ctype are baked at CREATE DATABASE and
            // changing them requires DROP + CREATE which would
            // destroy data. Match Ansible: warn-silently — emit no
            // mutation for those, only adjust OWNER on divergence.
            if !op.owner.is_empty() && owner != &op.owner {
                let owner_quoted =
                    quote_pg_ident(&op.owner).unwrap_or_else(|_| op.owner.clone());
                let sql = format!("ALTER DATABASE {name_quoted} OWNER TO {owner_quoted}");
                queries.push(sql.clone());
                changed = true;
                if !effective_check_mode {
                    let mut_op = rsansible_wire::msg::op_postgresql_query(
                        sql,
                        String::new(),
                        op.login_user.clone(),
                        op.login_password.clone(),
                        op.login_unix_socket.clone(),
                        op.login_host.clone(),
                        op.login_port,
                        true,
                        vec![],
                        false,
                    );
                    let exec = match dispatch_one_pg_query(
                        task, ctx, target_conn, next_seq, mut_op, true,
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(br) => return br,
                    };
                    if let Err(br) =
                        parse_pg_query_envelope(&exec, "postgresql_db.alter_owner")
                    {
                        return br;
                    }
                }
            }
        }
        (false, Some(_)) => {
            let sql = format!("DROP DATABASE {name_quoted}");
            queries.push(sql.clone());
            changed = true;
            if !effective_check_mode {
                let mut_op = rsansible_wire::msg::op_postgresql_query(
                    sql,
                    String::new(),
                    op.login_user.clone(),
                    op.login_password.clone(),
                    op.login_unix_socket.clone(),
                    op.login_host.clone(),
                    op.login_port,
                    true,
                    vec![],
                    false,
                );
                let exec =
                    match dispatch_one_pg_query(task, ctx, target_conn, next_seq, mut_op, true)
                        .await
                    {
                        Ok(e) => e,
                        Err(br) => return br,
                    };
                if let Err(br) = parse_pg_query_envelope(&exec, "postgresql_db.drop") {
                    return br;
                }
            }
        }
        (false, None) => {}
    }

    let mut rv = RegisterValue::default();
    rv.took_ms = 0;
    rv.changed = changed;
    rv.skipped = effective_check_mode && changed;
    rv.extra
        .insert("db".into(), JsonValue::String(op.name.clone()));
    rv.extra.insert(
        "queries".into(),
        JsonValue::Array(queries.into_iter().map(JsonValue::String).collect()),
    );
    BodyResult::Ok {
        register: rv,
        changed,
        skipped: effective_check_mode && changed,
    }
}

// ---------- module result lifting ----------

/// Lift the `uri:` envelope JSON object into the canonical RegisterValue
/// shape Ansible exposes: top-level keys (`register.status`,
/// `register.content`, `register.url`, …) instead of nested
/// `register.uri.<field>`, with the response body's parsed JSON swapped
/// into `rv.json` so `register.json.<field>` resolves to the body.
///
/// No-op when `rv.json` isn't a JSON object (the agent failed to ship a
/// well-formed envelope, e.g. on a TaskError path — but in that case the
/// orchestrator runs the error branch, not this one). The set of
/// shadow-protected keys is the public RegisterValue field set so a
/// pathological response body can't override `changed`, `rc`, etc.
/// Lift a `postgresql_query:` / `postgresql_ext:` JSON envelope into
/// the register's top-level keys, matching Ansible's
/// `community.postgresql.postgresql_query` contract:
///
/// * `register.query_result[0].col_name` — list of row dicts
/// * `register.rowcount` — affected/returned row count
/// * `register.statusmessage` — the PostgreSQL command tag
///
/// For `postgresql_ext:` the envelope keys are `extension`, `state`,
/// `prior_version`, `version`; same lift mechanism, just different
/// keys. Shadow-protection list matches `lift_uri_envelope`.
fn lift_postgresql_envelope(rv: &mut RegisterValue) {
    let Some(JsonValue::Object(obj)) = rv.json.as_ref() else {
        return;
    };
    let envelope = obj.clone();
    for (k, v) in envelope {
        if matches!(
            k.as_str(),
            "changed"
                | "rc"
                | "stdout"
                | "stderr"
                | "stdout_lines"
                | "stderr_lines"
                | "took_ms"
                | "skipped"
                | "failed"
                | "results"
                | "json"
        ) {
            continue;
        }
        rv.extra.insert(k, v);
    }
}

fn lift_get_url_envelope(rv: &mut RegisterValue) {
    // The agent's envelope is a single JSON object on stdout; the
    // orchestrator parses it into `rv.json`. Move the well-known keys
    // out to the top level so vendored playbooks see
    // `register.checksum_dest`, `register.dest`, etc. — matching
    // ansible.builtin.get_url's contract — without needing to dig
    // into `register.json`.
    let Some(JsonValue::Object(obj)) = rv.json.as_ref() else {
        return;
    };
    let envelope = obj.clone();
    rv.json = None;
    for (k, v) in envelope {
        if matches!(
            k.as_str(),
            "changed" | "rc" | "stdout" | "stderr" | "stdout_lines" | "stderr_lines" | "took_ms" | "skipped"
                | "failed"
        ) {
            continue;
        }
        rv.extra.insert(k, v);
    }
}

fn lift_slurp_envelope(rv: &mut RegisterValue) {
    // Identical shape to get_url's lifter: top-level keys move out of
    // `rv.json` into `rv.extra` so accessors like `register.content` /
    // `register.source` / `register.encoding` resolve as Ansible does.
    let Some(JsonValue::Object(obj)) = rv.json.as_ref() else {
        return;
    };
    let envelope = obj.clone();
    rv.json = None;
    for (k, v) in envelope {
        if matches!(
            k.as_str(),
            "changed" | "rc" | "stdout" | "stderr" | "stdout_lines" | "stderr_lines" | "took_ms" | "skipped"
                | "failed"
        ) {
            continue;
        }
        rv.extra.insert(k, v);
    }
}

/// Lift the async-job envelope from `rv.json` to top-level register
/// keys. Used both for OpAsyncStart-wrapped tasks (where the agent
/// emits `{ansible_job_id, started, finished, results_file}` on stdout)
/// and for explicit OpAsyncStatus polls (where the agent emits the
/// same envelope shape plus the inner module's keys merged in).
///
/// Ansible's contract is `register.ansible_job_id`,
/// `register.finished`, `register.started`, etc. — direct top-level
/// access, not nested under `register.json`. Matches how
/// ansible.builtin.async / async_status return shape work.
/// Lift the getent envelope to Ansible's register shape. The agent
/// emits `{database, <key>: [...]}`. Ansible's contract is
/// `register.getent_<database>` (a map keyed by `<key>` whose value
/// is the field list). Build that map and place it at the top level.
fn lift_getent_envelope(rv: &mut RegisterValue) {
    let Some(JsonValue::Object(obj)) = rv.json.as_ref() else {
        return;
    };
    let envelope = obj.clone();
    rv.json = None;
    // Pull the database name out so we know the lift target.
    let database = match envelope.get("database").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return,
    };
    // Build {<key>: [...fields...]} from the rest of the envelope.
    let mut map = serde_json::Map::new();
    for (k, v) in envelope {
        if k == "database" {
            continue;
        }
        map.insert(k, v);
    }
    rv.extra.insert(
        format!("getent_{database}"),
        JsonValue::Object(map),
    );
}

fn lift_async_envelope(rv: &mut RegisterValue) {
    let Some(JsonValue::Object(obj)) = rv.json.as_ref() else {
        return;
    };
    let envelope = obj.clone();
    rv.json = None;
    for (k, v) in envelope {
        if matches!(
            k.as_str(),
            "changed" | "rc" | "stdout" | "stderr" | "stdout_lines" | "stderr_lines" | "took_ms" | "skipped"
                | "failed"
        ) {
            continue;
        }
        rv.extra.insert(k, v);
    }
}

fn lift_unarchive_envelope(rv: &mut RegisterValue) {
    // Same shape as get_url / slurp: hoist top-level envelope keys into
    // `rv.extra` so vendored playbooks can `register.files`,
    // `register.handler`, etc.
    let Some(JsonValue::Object(obj)) = rv.json.as_ref() else {
        return;
    };
    let envelope = obj.clone();
    rv.json = None;
    for (k, v) in envelope {
        if matches!(
            k.as_str(),
            "changed" | "rc" | "stdout" | "stderr" | "stdout_lines" | "stderr_lines" | "took_ms" | "skipped"
                | "failed"
        ) {
            continue;
        }
        rv.extra.insert(k, v);
    }
}

fn lift_uri_envelope(rv: &mut RegisterValue) {
    let Some(JsonValue::Object(obj)) = rv.json.as_ref() else {
        return;
    };
    let mut envelope = obj.clone();
    rv.json = envelope.remove("json");
    for (k, v) in envelope {
        if matches!(
            k.as_str(),
            "changed"
                | "rc"
                | "stdout"
                | "stderr"
                | "stdout_lines"
                | "stderr_lines"
                | "took_ms"
                | "skipped"
                | "failed"
                | "results"
        ) {
            continue;
        }
        rv.extra.insert(k, v);
    }
}

// ---------- template rendering ----------

fn render_op(
    op: &TaskOp,
    ctx: &HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> Result<TaskOp> {
    let view = build_template_ctx(ctx, world);
    Ok(match op {
        TaskOp::Shell(s) => {
            let cmd = render_str(env, s.command(), &view)?;
            TaskOp::Shell(match s {
                ShellOp::Simple(_) => ShellOp::Simple(cmd),
                ShellOp::Detailed { timeout_ms, .. } => ShellOp::Detailed {
                    command: cmd,
                    timeout_ms: *timeout_ms,
                },
            })
        }
        TaskOp::Exec(e) => {
            let argv = e
                .argv
                .iter()
                .map(|a| render_str(env, a, &view))
                .collect::<Result<Vec<_>>>()?;
            let mut env_out = std::collections::BTreeMap::new();
            for (k, v) in &e.env {
                env_out.insert(k.clone(), render_str(env, v, &view)?);
            }
            let cwd = match &e.cwd {
                Some(c) => Some(render_str(env, c, &view)?),
                None => None,
            };
            let stdin = render_str(env, &e.stdin, &view)?;
            TaskOp::Exec(ExecOp {
                argv,
                env: env_out,
                cwd,
                stdin,
                timeout_ms: e.timeout_ms,
            })
        }
        TaskOp::Command(c) => {
            // If `cmd:` / shorthand was used, render the whole string
            // *first*, then shlex-split — so `{{ var }}` arguments end
            // up as one argv element, not three (`{{`, var, `}}`). The
            // argv-list form keeps per-element rendering since the user
            // explicitly told us how to slice it.
            let argv = if let Some(raw) = c.raw_cmd.as_deref() {
                let rendered = render_str(env, raw, &view)?;
                let v = shlex::split(&rendered).ok_or_else(|| {
                    anyhow!(
                        "command.cmd: shlex parse failed on rendered command \
                         {rendered:?} (unterminated quote?)"
                    )
                })?;
                if v.is_empty() {
                    return Err(anyhow!(
                        "command.cmd: empty after rendering+shlex-split"
                    ));
                }
                v
            } else {
                c.argv
                    .iter()
                    .map(|a| render_str(env, a, &view))
                    .collect::<Result<Vec<_>>>()?
            };
            let chdir = render_str(env, &c.chdir, &view)?;
            let creates = render_str(env, &c.creates, &view)?;
            let removes = render_str(env, &c.removes, &view)?;
            let stdin = render_str(env, &c.stdin, &view)?;
            TaskOp::Command(crate::playbook::CommandOp {
                argv,
                // raw_cmd was the *source* for the rendered argv above;
                // downstream wire-conversion only reads argv.
                raw_cmd: None,
                chdir,
                creates,
                removes,
                stdin,
                timeout_ms: c.timeout_ms,
            })
        }
        TaskOp::WriteFile(w) => {
            let path = render_str(env, &w.path, &view)?;
            let content = render_str(env, &w.content, &view)?;
            let validate = match &w.validate {
                Some(v) => Some(render_str(env, v, &view)?),
                None => None,
            };
            let owner = match &w.owner {
                Some(s) => Some(render_str(env, s, &view)?),
                None => None,
            };
            let group = match &w.group {
                Some(s) => Some(render_str(env, s, &view)?),
                None => None,
            };
            TaskOp::WriteFile(WriteFileOp {
                path,
                mode: resolve_mode(env, &w.mode, &view)?,
                content,
                validate,
                owner,
                group,
            })
        }
        TaskOp::Template(t) => {
            // Desugar `template:` into `OpWriteFile`. The body is either
            // (a) loaded at parse time when `src:` was a literal path, or
            // (b) located lazily here when `src:` was Jinja-templated —
            // we render src against the per-host view and probe the
            // search_dirs captured at load time.
            let body_string: String;
            let body_ref: &str = if let Some(b) = t.body.as_deref() {
                b
            } else {
                let rendered_src = render_str(env, &t.src, &view)?;
                let p = std::path::PathBuf::from(&rendered_src);
                let mut located: Option<std::path::PathBuf> = None;
                if p.is_absolute() {
                    if p.is_file() {
                        located = Some(p.clone());
                    }
                } else {
                    for base in &t.search_dirs {
                        let cand = base.join(&p);
                        if cand.is_file() {
                            located = Some(cand);
                            break;
                        }
                    }
                }
                let path = match located {
                    Some(path) => path,
                    None => {
                        let tried = if p.is_absolute() {
                            format!("  {}", p.display())
                        } else {
                            t.search_dirs
                                .iter()
                                .map(|b| format!("  {}", b.join(&p).display()))
                                .collect::<Vec<_>>()
                                .join("\n")
                        };
                        return Err(anyhow!(
                            "template src {rendered_src:?} (rendered from {:?}) not found; tried:\n{tried}",
                            t.src
                        ));
                    }
                };
                let bytes = std::fs::read(&path)
                    .map_err(|e| anyhow!("reading template {}: {e}", path.display()))?;
                body_string = String::from_utf8(bytes).map_err(|e| {
                    anyhow!("template {} contains non-UTF-8 bytes: {e}", path.display())
                })?;
                &body_string
            };
            let dest = render_str(env, &t.dest, &view)?;
            // The body render needs to resolve `{% include "name" %}`
            // statements against the role's templates dirs captured at
            // load time. We can't mutate the shared env, so build a
            // per-task one with a path loader. Other renders here
            // (dest, validate, mode) keep using the shared env — they
            // are scalar strings unlikely to carry includes.
            let content = if t.search_dirs.is_empty() {
                render_str(env, body_ref, &view)?
            } else {
                let mut local_env: minijinja::Environment<'static> =
                    crate::template::make_env();
                crate::template::install_include_loader(
                    &mut local_env,
                    t.search_dirs.clone(),
                );
                render_str(&local_env, body_ref, &view)?
            };
            let validate = match &t.validate {
                Some(v) => Some(render_str(env, v, &view)?),
                None => None,
            };
            let owner = match &t.owner {
                Some(s) => Some(render_str(env, s, &view)?),
                None => None,
            };
            let group = match &t.group {
                Some(s) => Some(render_str(env, s, &view)?),
                None => None,
            };
            TaskOp::WriteFile(WriteFileOp {
                path: dest,
                mode: resolve_mode(env, &t.mode, &view)?,
                content,
                validate,
                owner,
                group,
            })
        }
        TaskOp::Copy(c) => {
            // Three forms:
            //   - `src:` form with remote_src=false — bytes were loaded
            //     at parse time into `c.body`; we just clone them
            //     through. Variant stays `TaskOp::Copy` rather than
            //     desugaring to WriteFile so binary content survives
            //     (WriteFileOp.content is String).
            //   - `content:` form — Jinja-render the inline content
            //     against the per-host view and populate `body` here.
            //   - `remote_src: true` — `src:` is a path on the target
            //     host. Render src+dest+validate through Jinja, leave
            //     body=None; `to_wire_op` emits `OpCopyTarget` and the
            //     agent reads the bytes itself.
            let dest = render_str(env, &c.dest, &view)?;
            let validate = match &c.validate {
                Some(v) => Some(render_str(env, v, &view)?),
                None => None,
            };
            // Render owner/group up front — both Copy branches need
            // them. Before this fix a `copy: ... owner: "{{ user }}"`
            // task shipped the literal Jinja string to the agent,
            // which then rejected it as `unknown owner "{{ user }}"`.
            // The TaskOp::WriteFile / TaskOp::Template arms already
            // do this; Copy was the one that was forgotten.
            let owner = match &c.owner {
                Some(s) => Some(render_str(env, s, &view)?),
                None => None,
            };
            let group = match &c.group {
                Some(s) => Some(render_str(env, s, &view)?),
                None => None,
            };
            if c.remote_src {
                let src = match &c.src {
                    Some(s) => Some(render_str(env, s, &view)?),
                    None => {
                        return Err(anyhow!(
                            "internal: copy task dest {:?} has remote_src=true but no src (should have been caught at parse)",
                            c.dest
                        ))
                    }
                };
                return Ok(TaskOp::Copy(CopyOp {
                    src,
                    content: None,
                    dest,
                    mode: resolve_mode(env, &c.mode, &view)?,
                    owner,
                    group,
                    body: None,
                    validate,
                    remote_src: true,
                    search_dirs: Vec::new(),
                }));
            }
            let body = match (&c.src, &c.content) {
                (Some(src), _) => {
                    if let Some(b) = c.body.as_ref() {
                        b.clone()
                    } else {
                        // Deferred load: src was Jinja, render and probe
                        // the search_dirs captured at load time.
                        let rendered_src = render_str(env, src, &view)?;
                        let p = std::path::PathBuf::from(&rendered_src);
                        let mut located: Option<std::path::PathBuf> = None;
                        if p.is_absolute() {
                            if p.is_file() {
                                located = Some(p.clone());
                            }
                        } else {
                            for base in &c.search_dirs {
                                let cand = base.join(&p);
                                if cand.is_file() {
                                    located = Some(cand);
                                    break;
                                }
                            }
                        }
                        let path = match located {
                            Some(p) => p,
                            None => {
                                let tried = if p.is_absolute() {
                                    format!("  {}", p.display())
                                } else {
                                    c.search_dirs
                                        .iter()
                                        .map(|b| format!("  {}", b.join(&p).display()))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                };
                                return Err(anyhow!(
                                    "copy src {rendered_src:?} (rendered from {src:?}) not found; tried:\n{tried}"
                                ));
                            }
                        };
                        std::fs::read(&path)
                            .map_err(|e| anyhow!("reading copy src {}: {e}", path.display()))?
                    }
                }
                (None, Some(template)) => {
                    let rendered = render_str(env, template, &view)?;
                    rendered.into_bytes()
                }
                (None, None) => {
                    return Err(anyhow!(
                        "internal: copy task dest {:?} has neither src nor content (should have been caught at parse)",
                        c.dest
                    ));
                }
            };
            TaskOp::Copy(CopyOp {
                src: c.src.clone(),
                content: c.content.clone(),
                dest,
                mode: resolve_mode(env, &c.mode, &view)?,
                owner,
                group,
                body: Some(body),
                validate,
                remote_src: false,
                search_dirs: Vec::new(),
            })
        }
        TaskOp::GatherFacts => TaskOp::GatherFacts,
        TaskOp::Stat(s) => {
            let path = render_str(env, &s.path, &view)?;
            TaskOp::Stat(StatOp {
                path,
                follow: s.follow,
            })
        }
        TaskOp::WaitFor(w) => {
            let host = match &w.host {
                Some(h) => Some(render_str(env, h, &view)?),
                None => None,
            };
            let path = match &w.path {
                Some(p) => Some(render_str(env, p, &view)?),
                None => None,
            };
            // If `port:` was a Jinja template, render+parse it now.
            let port = if !w.port_template.is_empty() {
                let rendered = render_str(env, &w.port_template, &view)?;
                let n: u32 = rendered.trim().parse().map_err(|e| {
                    anyhow::anyhow!(
                        "wait_for.port: rendered {rendered:?} (from template \
                         {tpl:?}) is not a non-negative integer: {e}",
                        tpl = w.port_template
                    )
                })?;
                if n == 0 {
                    return Err(anyhow::anyhow!(
                        "wait_for.port: rendered to 0 (from template {:?}); must be non-zero",
                        w.port_template
                    ));
                }
                Some(n)
            } else {
                w.port
            };
            TaskOp::WaitFor(WaitForOp {
                host,
                port,
                path,
                state: w.state,
                timeout_ms: w.timeout_ms,
                delay_ms: w.delay_ms,
                sleep_ms: w.sleep_ms,
                port_template: String::new(),
            })
        }
        TaskOp::File(f) => {
            let path = render_str(env, &f.path, &view)?;
            let owner = match &f.owner {
                Some(o) => Some(render_str(env, o, &view)?),
                None => None,
            };
            let group = match &f.group {
                Some(g) => Some(render_str(env, g, &view)?),
                None => None,
            };
            TaskOp::File(FileOp {
                path,
                state: f.state,
                mode: resolve_mode_opt(env, &f.mode, &view)?,
                owner,
                group,
                recurse: f.recurse,
            })
        }
        TaskOp::LineInFile(l) => {
            let path = render_str(env, &l.path, &view)?;
            let line = render_str(env, &l.line, &view)?;
            let validate = match &l.validate {
                Some(v) => Some(render_str(env, v, &view)?),
                None => None,
            };
            TaskOp::LineInFile(LineInFileOp {
                path,
                regexp: l.regexp.clone(),
                line,
                state: l.state,
                mode: resolve_mode_opt(env, &l.mode, &view)?,
                create: l.create,
                insertbefore: l.insertbefore.clone(),
                insertafter: l.insertafter.clone(),
                backrefs: l.backrefs,
                validate,
            })
        }
        TaskOp::BlockInFile(b) => {
            let path = render_str(env, &b.path, &view)?;
            let block = render_str(env, &b.block, &view)?;
            let validate = match &b.validate {
                Some(v) => Some(render_str(env, v, &view)?),
                None => None,
            };
            TaskOp::BlockInFile(BlockInFileOp {
                path,
                block,
                marker: b.marker.clone(),
                marker_begin: b.marker_begin.clone(),
                marker_end: b.marker_end.clone(),
                state: b.state,
                mode: resolve_mode_opt(env, &b.mode, &view)?,
                create: b.create,
                insertbefore: b.insertbefore.clone(),
                insertafter: b.insertafter.clone(),
                validate,
            })
        }
        TaskOp::Systemd(s) => {
            let name = render_str(env, &s.name, &view)?;
            TaskOp::Systemd(SystemdOp {
                name,
                state: s.state,
                enabled: s.enabled,
                masked: s.masked,
                daemon_reload: s.daemon_reload,
                no_block: s.no_block,
            })
        }
        TaskOp::Package(p) => {
            // `name: "{{ pkg_list }}"` must splat the list into N
            // package names. See `render_string_or_list_sources`.
            let names = render_string_or_list_sources(env, &p.names, &view)?;
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            TaskOp::Package(PackageOp {
                manager: p.manager,
                names,
                state: p.state,
                update_cache: p.update_cache,
                cache_valid_time: p.cache_valid_time,
                purge: p.purge,
                autoremove: p.autoremove,
                default_release: render_if(&p.default_release)?,
                allow_unauthenticated: p.allow_unauthenticated,
                virtualenv: render_if(&p.virtualenv)?,
                virtualenv_command: render_if(&p.virtualenv_command)?,
            })
        }
        TaskOp::Repository(r) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            TaskOp::Repository(RepositoryOp {
                manager: r.manager,
                repo: render_str(env, &r.repo, &view)?,
                state: r.state,
                filename: render_if(&r.filename)?,
                mode: resolve_mode_opt(env, &r.mode, &view)?,
                update_cache: r.update_cache,
            })
        }
        TaskOp::Group(g) => TaskOp::Group(GroupOp {
            name: render_str(env, &g.name, &view)?,
            state: g.state,
            system: g.system,
        }),
        TaskOp::User(u) => {
            let render_opt = |o: &Option<String>| -> Result<Option<String>> {
                match o {
                    None => Ok(None),
                    Some(s) => Ok(Some(render_str(env, s, &view)?)),
                }
            };
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            let mut groups = Vec::with_capacity(u.groups.len());
            for g in &u.groups {
                groups.push(render_str(env, g, &view)?);
            }
            TaskOp::User(UserOp {
                name: render_str(env, &u.name, &view)?,
                state: u.state,
                system: u.system,
                shell: render_opt(&u.shell)?,
                home: render_opt(&u.home)?,
                create_home: u.create_home,
                primary_group: render_if(&u.primary_group)?,
                groups,
                append: u.append,
            })
        }
        TaskOp::AuthorizedKey(a) => TaskOp::AuthorizedKey(AuthorizedKeyOp {
            user: render_str(env, &a.user, &view)?,
            key: render_str(env, &a.key, &view)?,
            state: a.state,
            exclusive: a.exclusive,
        }),
        TaskOp::Getent(g) => TaskOp::Getent(GetentOp {
            database: render_str(env, &g.database, &view)?,
            key: render_str(env, &g.key, &view)?,
            fail_key: g.fail_key,
            split: if g.split.is_empty() {
                String::new()
            } else {
                render_str(env, &g.split, &view)?
            },
        }),
        TaskOp::Hostname(h) => TaskOp::Hostname(HostnameOp {
            name: render_str(env, &h.name, &view)?,
        }),
        TaskOp::Timezone(z) => TaskOp::Timezone(crate::playbook::task_op::TimezoneOp {
            name: render_str(env, &z.name, &view)?,
        }),
        TaskOp::Ufw(u) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            TaskOp::Ufw(UfwOp {
                op: u.op,
                rule: render_if(&u.rule)?,
                direction: render_if(&u.direction)?,
                proto: render_if(&u.proto)?,
                from_ip: render_if(&u.from_ip)?,
                from_port: render_if(&u.from_port)?,
                to_ip: render_if(&u.to_ip)?,
                to_port: render_if(&u.to_port)?,
                interface: render_if(&u.interface)?,
                comment: render_if(&u.comment)?,
                delete: u.delete,
                insert: u.insert,
            })
        }
        TaskOp::AsyncStatus(a) => {
            let jid = render_str(env, &a.jid, &view)?;
            TaskOp::AsyncStatus(AsyncStatusOp { jid })
        }
        TaskOp::Iptables(i) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            TaskOp::Iptables(IptablesOp {
                table: render_if(&i.table)?,
                chain: render_if(&i.chain)?,
                protocol: render_if(&i.protocol)?,
                source: render_if(&i.source)?,
                destination: render_if(&i.destination)?,
                source_port: render_if(&i.source_port)?,
                destination_port: render_if(&i.destination_port)?,
                in_interface: render_if(&i.in_interface)?,
                out_interface: render_if(&i.out_interface)?,
                jump: render_if(&i.jump)?,
                ctstate: render_if(&i.ctstate)?,
                comment: render_if(&i.comment)?,
                ip_version: i.ip_version,
                action: i.action,
                rule_state: i.rule_state,
            })
        }
        TaskOp::Uri(u) => {
            // url, header values, and body all support Jinja. Header
            // keys are not rendered (header names aren't useful Jinja
            // targets and `:` would be ambiguous with regex syntax).
            let url = render_str(env, &u.url, &view)?;
            let mut headers = BTreeMap::new();
            for (k, v) in &u.headers {
                headers.insert(k.clone(), render_str(env, v, &view)?);
            }
            let body = if u.body.is_empty() {
                String::new()
            } else {
                render_str(env, &u.body, &view)?
            };
            // mTLS / CA paths are Jinja-templatable so a per-host
            // path (e.g. `/etc/pki/{{ inventory_hostname }}.crt`)
            // works. Bytes are read at to_wire_op time, not here.
            let client_cert = render_str(env, &u.client_cert, &view)?;
            let client_key = render_str(env, &u.client_key, &view)?;
            let ca_path = render_str(env, &u.ca_path, &view)?;
            TaskOp::Uri(UriOp {
                url,
                method: u.method,
                headers,
                body,
                body_format: u.body_format,
                status_codes: u.status_codes.clone(),
                timeout_ms: u.timeout_ms,
                return_content: u.return_content,
                validate_certs: u.validate_certs,
                follow_redirects: u.follow_redirects,
                client_cert,
                client_key,
                ca_path,
            })
        }
        TaskOp::OpenSslPrivkey(p) => {
            // `path:` is Jinja-templatable so a per-host destination
            // works. Everything else (kind/size/mode/force_probe) is
            // a scalar — no rendering needed.
            let path = render_str(env, &p.path, &view)?;
            TaskOp::OpenSslPrivkey(OpenSslPrivkeyOp { path, ..p.clone() })
        }
        TaskOp::OpenSslCsrPipe(c) => {
            // All string fields are templatable; SAN entries individually
            // so a Jinja-loop over `groups['etcd']` produces fresh SANs
            // per host.
            let privatekey_path = render_str(env, &c.privatekey_path, &view)?;
            let common_name = render_str(env, &c.common_name, &view)?;
            let subject_alt_name = c
                .subject_alt_name
                .iter()
                .map(|s| render_str(env, s, &view))
                .collect::<Result<Vec<_>>>()?;
            let key_usage = c
                .key_usage
                .iter()
                .map(|s| render_str(env, s, &view))
                .collect::<Result<Vec<_>>>()?;
            let extended_key_usage = c
                .extended_key_usage
                .iter()
                .map(|s| render_str(env, s, &view))
                .collect::<Result<Vec<_>>>()?;
            // DN fields are typically literal but accept Jinja so things
            // like `organization_name: "{{ org }}"` work without ceremony.
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            let country_name = render_if(&c.country_name)?;
            let organization_name = render_if(&c.organization_name)?;
            let organizational_unit_name = render_if(&c.organizational_unit_name)?;
            // basic_constraints: the per-entry strings (`CA:TRUE`,
            // `pathlen:0`) are typically literal but render them in
            // case someone parameterizes (e.g.
            // `pathlen:{{ chain_depth }}`).
            let basic_constraints = c
                .basic_constraints
                .iter()
                .map(|s| render_str(env, s, &view))
                .collect::<Result<Vec<_>>>()?;
            TaskOp::OpenSslCsrPipe(OpenSslCsrPipeOp {
                privatekey_path,
                common_name,
                country_name,
                organization_name,
                organizational_unit_name,
                subject_alt_name,
                key_usage,
                extended_key_usage,
                basic_constraints,
                basic_constraints_critical: c.basic_constraints_critical,
                key_usage_critical: c.key_usage_critical,
                digest: c.digest.clone(),
            })
        }
        TaskOp::X509CertificatePipe(c) => {
            // CSR + key PEMs / paths almost always come from
            // previous-task registers via Jinja, so they MUST be
            // rendered before we hand them to rcgen / the filesystem.
            let csr_content = render_str(env, &c.csr_content, &view)?;
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            let privatekey_content = render_if(&c.privatekey_content)?;
            let privatekey_path = render_if(&c.privatekey_path)?;
            let ownca_content = render_if(&c.ownca_content)?;
            let ownca_privatekey_content = render_if(&c.ownca_privatekey_content)?;
            let ownca_privatekey_path = render_if(&c.ownca_privatekey_path)?;
            // Late-bound `selfsigned_not_after:` / `ownca_not_after:`
            // duration: deferred at parse time when it contained Jinja.
            // Render then parse now, override valid_for_days.
            let valid_for_days = if !c.not_after_template.is_empty() {
                let rendered = render_str(env, &c.not_after_template, &view)?;
                crate::playbook::task_op::openssl::parse_relative_duration_days(&rendered)
                    .map_err(|e| anyhow::anyhow!(e))?
            } else {
                c.valid_for_days
            };
            TaskOp::X509CertificatePipe(X509CertificatePipeOp {
                csr_content,
                privatekey_content,
                privatekey_path,
                provider: c.provider.clone(),
                valid_for_days,
                selfsigned_digest: c.selfsigned_digest.clone(),
                ownca_content,
                ownca_privatekey_content,
                ownca_privatekey_path,
                ownca_digest: c.ownca_digest.clone(),
                not_after_template: String::new(),
            })
        }
        TaskOp::PostgresqlQuery(p) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            let query = render_str(env, &p.query, &view)?;
            // SQL classification was done at parse time on the literal
            // query text. After Jinja renders, the resulting SQL might
            // differ — e.g. a Jinja-templated query that produces
            // `SELECT ...` vs `INSERT ...`. Re-classify on the rendered
            // string to be safe.
            let read_only = crate::playbook::classify_sql_readonly(&query);
            let positional_args = p
                .positional_args
                .iter()
                .map(|a| render_str(env, a, &view))
                .collect::<Result<Vec<_>>>()?;
            TaskOp::PostgresqlQuery(PostgresqlQueryOp {
                query,
                db: render_if(&p.db)?,
                login_user: render_if(&p.login_user)?,
                login_password: render_if(&p.login_password)?,
                login_unix_socket: render_if(&p.login_unix_socket)?,
                login_host: render_if(&p.login_host)?,
                login_port: p.login_port,
                autocommit: p.autocommit,
                positional_args,
                read_only,
            })
        }
        TaskOp::PostgresqlExt(p) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            TaskOp::PostgresqlExt(PostgresqlExtOp {
                name: render_str(env, &p.name, &view)?,
                state: p.state,
                version: render_if(&p.version)?,
                ext_schema: render_if(&p.ext_schema)?,
                cascade: p.cascade,
                db: render_if(&p.db)?,
                login_user: render_if(&p.login_user)?,
                login_password: render_if(&p.login_password)?,
                login_unix_socket: render_if(&p.login_unix_socket)?,
                login_host: render_if(&p.login_host)?,
                login_port: p.login_port,
            })
        }
        TaskOp::PostgresqlUser(u) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            TaskOp::PostgresqlUser(PostgresqlUserOp {
                name: render_str(env, &u.name, &view)?,
                password: render_if(&u.password)?,
                role_attr_flags: render_if(&u.role_attr_flags)?,
                state: u.state,
                no_password_changes: u.no_password_changes,
                conn_limit: u.conn_limit,
                db: render_if(&u.db)?,
                login_user: render_if(&u.login_user)?,
                login_password: render_if(&u.login_password)?,
                login_unix_socket: render_if(&u.login_unix_socket)?,
                login_host: render_if(&u.login_host)?,
                login_port: u.login_port,
            })
        }
        TaskOp::PostgresqlDb(d) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            TaskOp::PostgresqlDb(PostgresqlDbOp {
                name: render_str(env, &d.name, &view)?,
                owner: render_if(&d.owner)?,
                encoding: render_if(&d.encoding)?,
                lc_collate: render_if(&d.lc_collate)?,
                lc_ctype: render_if(&d.lc_ctype)?,
                template: render_if(&d.template)?,
                state: d.state,
                login_user: render_if(&d.login_user)?,
                login_password: render_if(&d.login_password)?,
                login_unix_socket: render_if(&d.login_unix_socket)?,
                login_host: render_if(&d.login_host)?,
                login_port: d.login_port,
            })
        }
        TaskOp::PostgresqlMembership(m) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            let mut groups = Vec::with_capacity(m.groups.len());
            for g in &m.groups {
                groups.push(render_str(env, g, &view)?);
            }
            let mut target_roles = Vec::with_capacity(m.target_roles.len());
            for t in &m.target_roles {
                target_roles.push(render_str(env, t, &view)?);
            }
            TaskOp::PostgresqlMembership(PostgresqlMembershipOp {
                groups,
                target_roles,
                state: m.state,
                fail_on_role: m.fail_on_role,
                db: render_if(&m.db)?,
                login_user: render_if(&m.login_user)?,
                login_password: render_if(&m.login_password)?,
                login_unix_socket: render_if(&m.login_unix_socket)?,
                login_host: render_if(&m.login_host)?,
                login_port: m.login_port,
            })
        }
        TaskOp::GetUrl(g) => {
            let render_if = |s: &str| -> Result<String> {
                if s.is_empty() {
                    Ok(String::new())
                } else {
                    render_str(env, s, &view)
                }
            };
            let mut rendered_headers = BTreeMap::new();
            for (k, v) in &g.headers {
                rendered_headers.insert(k.clone(), render_str(env, v, &view)?);
            }
            TaskOp::GetUrl(GetUrlOp {
                url: render_str(env, &g.url, &view)?,
                dest: render_str(env, &g.dest, &view)?,
                checksum: render_if(&g.checksum)?,
                mode: resolve_mode_opt(env, &g.mode, &view)?,
                owner: render_if(&g.owner)?,
                group: render_if(&g.group)?,
                headers: rendered_headers,
                timeout_ms: g.timeout_ms,
                force: g.force,
                validate_certs: g.validate_certs,
                follow_redirects: g.follow_redirects,
                client_cert: render_if(&g.client_cert)?,
                client_key: render_if(&g.client_key)?,
                ca_path: render_if(&g.ca_path)?,
            })
        }
        TaskOp::Slurp(s) => TaskOp::Slurp(SlurpOp {
            src: render_str(env, &s.src, &view)?,
            max_bytes: s.max_bytes,
        }),
        TaskOp::Unarchive(u) => {
            let include = u
                .include
                .iter()
                .map(|p| render_str(env, p, &view))
                .collect::<Result<Vec<_>>>()?;
            let exclude = u
                .exclude
                .iter()
                .map(|p| render_str(env, p, &view))
                .collect::<Result<Vec<_>>>()?;
            TaskOp::Unarchive(UnarchiveOp {
                src: render_str(env, &u.src, &view)?,
                dest: render_str(env, &u.dest, &view)?,
                format: u.format,
                creates: render_str(env, &u.creates, &view)?,
                mode: resolve_mode_opt(env, &u.mode, &view)?,
                owner: render_str(env, &u.owner, &view)?,
                group: render_str(env, &u.group, &view)?,
                keep_newer: u.keep_newer,
                list_files: u.list_files,
                include,
                exclude,
            })
        }
        TaskOp::Tempfile(t) => {
            // Every string field is Jinja-templatable; the typical use
            // is `suffix: "_{{ inventory_hostname }}"` or a Jinja-rendered
            // parent `path:`.
            let path = match &t.path {
                Some(p) => Some(render_str(env, p, &view)?),
                None => None,
            };
            TaskOp::Tempfile(TempfileOp {
                state: t.state,
                suffix: render_str(env, &t.suffix, &view)?,
                prefix: render_str(env, &t.prefix, &view)?,
                path,
            })
        }
    })
}

/// Resolve a [`ModeField`] for dispatch: render any embedded Jinja
/// template against the per-host view and parse the result as an octal
/// permission. `Literal` values pass through unchanged. This is the
/// single place the orchestrator turns parse-time mode forms (literal
/// or template) into post-render literals before they hit
/// `to_wire_op`. Used by every op variant carrying a `mode:` field.
fn resolve_mode(
    env: &Environment<'static>,
    m: &crate::playbook::ModeField,
    view: &BTreeMap<String, JsonValue>,
) -> Result<crate::playbook::ModeField> {
    use crate::playbook::ModeField;
    match m {
        ModeField::Literal(_) => Ok(m.clone()),
        ModeField::Template(t) => {
            let rendered = render_str(env, t, view)?;
            let trimmed = rendered.trim();
            let n = crate::playbook::parse_rendered_mode(trimmed).map_err(|e| {
                anyhow!("mode template {t:?} rendered to {rendered:?}: {e}")
            })?;
            Ok(ModeField::Literal(n))
        }
    }
}

fn resolve_mode_opt(
    env: &Environment<'static>,
    m: &Option<crate::playbook::ModeField>,
    view: &BTreeMap<String, JsonValue>,
) -> Result<Option<crate::playbook::ModeField>> {
    match m {
        Some(m) => Ok(Some(resolve_mode(env, m, view)?)),
        None => Ok(None),
    }
}

fn render_str(
    env: &Environment<'static>,
    src: &str,
    view: &BTreeMap<String, JsonValue>,
) -> Result<String> {
    // Pre-resolve vars-of-vars in the view so the body render below
    // can stay single-pass. Ansible's Templar evaluates variable
    // values lazily as templates whenever they're accessed; we get
    // the same observable result by walking the view up front and
    // expanding any string-valued var that contains Jinja markers.
    //
    // The body render itself MUST run exactly once — alert-rule
    // templates (Prometheus / vmalert) commonly emit literal
    // `{{ $labels.x }}` via `{{ '{{' }} $labels.x {{ '}}' }}`, and
    // re-rendering that output would treat `$labels.x` as a Jinja
    // expression and explode. So the recursion is confined to the
    // var-resolution helper; the body render is one pass exactly.
    //
    // Caught in the gothab live drill: vmalert's defaults say
    // `monitoring_vmalert_version: "{{ monitoring_vm_version }}"`,
    // and a get_url task referencing `{{ monitoring_vmalert_version }}`
    // was producing a URL with the literal `{{ monitoring_vm_version }}`
    // still in it. The fix is var-side, not render-side.
    let resolved = resolve_view_var_templates(env, view)?;
    let prepared = crate::template::prepare_jinja_source(src);
    let tmpl = env
        .template_from_str(&prepared)
        .map_err(|e| anyhow!("template parse: {e}"))?;
    let out = tmpl
        .render(&resolved)
        .map_err(|e| anyhow!("template render: {e}"))?;
    // Ansible-style `default(omit)` support: if the entire rendered
    // result is exactly the omit sentinel, collapse to empty string.
    // Most task-op fields treat empty as "absent" — see
    // template::OMIT_SENTINEL for rationale.
    if out == crate::template::OMIT_SENTINEL {
        return Ok(String::new());
    }
    Ok(out)
}

/// Walk `view` and rewrite any string-valued variable whose contents
/// contain Jinja markers into its rendered form, recursively into
/// arrays and objects. Iterates until the view is stable (no string
/// changed during the pass) or `MAX_PASSES` is hit. The body of
/// `render_str` calls this once before rendering its own template,
/// so a body template that references `{{ a }}` where `a = "{{ b }}"`
/// and `b = "literal"` sees `a` as `"literal"` directly.
///
/// Bug 18 motivation: pre-fix this function stopped at the top level
/// of the map, so role defaults like
/// `patroni_pg_hba: ["host all all {{ vswitch_cidr }} scram-sha-256"]`
/// passed into minijinja with the inner template still literal. The
/// template-iteration body then emitted the literal Jinja text — and
/// in gothab's case that text was a `pg_hba.conf` entry stored in
/// Patroni's DCS, which postmaster then rejected as an "invalid
/// authentication method 'vswitch_cidr'". Ansible's own Templar
/// renders lazily on every variable access regardless of depth; this
/// matches that.
///
/// Each pass renders against a snapshot of the view taken at the
/// start of the pass, so the rendered output is independent of map
/// traversal order. Strings whose render produces the same text as
/// the source (a constant-Jinja literal in a var, or a cycle that
/// hits its fixed point) are left as-is and don't trigger another
/// pass — `MAX_PASSES` exhaustion only fires on true non-convergence.
fn resolve_view_var_templates(
    env: &Environment<'static>,
    view: &BTreeMap<String, JsonValue>,
) -> Result<BTreeMap<String, JsonValue>> {
    const MAX_PASSES: u32 = 8;
    let mut current: BTreeMap<String, JsonValue> = view.clone();
    for _ in 0..MAX_PASSES {
        let snapshot = current.clone();
        let mut changed = false;
        for (k, v) in current.iter_mut() {
            resolve_strings_in_value(env, k, v, &snapshot, &mut changed)?;
        }
        if !changed {
            return Ok(current);
        }
    }
    Err(anyhow!(
        "var-template resolution did not stabilize after {MAX_PASSES} passes \
         (likely a circular variable reference)"
    ))
}

/// Walk a JSON value in place, rendering every string scalar that
/// contains Jinja markers against `view`. Sibling of
/// `render_json_strings` (used for loop items), but goes through
/// minijinja directly rather than through `render_str` so it does
/// not re-enter `resolve_view_var_templates` — that would explode
/// the cost into something like O(view_size × MAX_PASSES²) and the
/// extra passes add no information beyond what the outer fixpoint
/// loop already does.
///
/// `path` is the dotted/indexed key path of the value being walked,
/// surfaced only in error messages
/// (`var "patroni_pg_hba[0]" template parse: …`) — gives the
/// playbook author a starting point when an inner template is
/// malformed.
fn resolve_strings_in_value(
    env: &Environment<'static>,
    path: &str,
    val: &mut JsonValue,
    view: &BTreeMap<String, JsonValue>,
    changed: &mut bool,
) -> Result<()> {
    match val {
        JsonValue::String(s) if s.contains("{{") || s.contains("{%") => {
            let prepared = crate::template::prepare_jinja_source(s);
            let tmpl = env
                .template_from_str(&prepared)
                .map_err(|e| anyhow!("var {path:?} template parse: {e}"))?;
            let rendered = tmpl
                .render(view)
                .map_err(|e| anyhow!("var {path:?} template render: {e}"))?;
            if &rendered != s {
                *s = rendered;
                *changed = true;
            }
        }
        JsonValue::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let child_path = format!("{path}[{i}]");
                resolve_strings_in_value(env, &child_path, item, view, changed)?;
            }
        }
        JsonValue::Object(map) => {
            for (k, v) in map.iter_mut() {
                let child_path = format!("{path}.{k}");
                resolve_strings_in_value(env, &child_path, v, view, changed)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn eval_when(
    env: &Environment<'static>,
    expr: Option<&str>,
    ctx: &HostCtx,
    world: &WorldVars,
) -> Result<bool> {
    let Some(expr) = expr else { return Ok(true) };
    let prepared = crate::template::prepare_jinja_source(expr);
    let compiled = env
        .compile_expression(&prepared)
        .map_err(|e| anyhow!("compile: {e}"))?;
    let view = build_template_ctx(ctx, world);
    let val = compiled
        .eval(&view)
        .map_err(|e| anyhow!("eval: {e}"))?;
    Ok(val.is_true())
}

fn resolve_loop_items(
    env: &Environment<'static>,
    spec: Option<&LoopSpec>,
    ctx: &HostCtx,
    world: &WorldVars,
) -> Result<Vec<JsonValue>> {
    let Some(spec) = spec else { return Ok(Vec::new()) };
    match spec {
        LoopSpec::Items(items) => {
            // Each item is a raw YAML value from the playbook source. Render
            // any Jinja inside string scalars (recursively into sequences and
            // mappings) against the per-host template context — Ansible loop
            // items get one render pass per evaluation, so `loop: ["{{ x }}",
            // "{{ y }}"]` resolves before `src: "{{ item }}"` substitutes.
            let view = build_template_ctx(ctx, world);
            items
                .iter()
                .cloned()
                .map(|item| {
                    let mut json = yaml_to_json(item)?;
                    render_json_strings(env, &mut json, &view)?;
                    Ok(json)
                })
                .collect::<Result<Vec<_>>>()
        }
        LoopSpec::Expr(s) => {
            let view = build_template_ctx(ctx, world);
            // Render as a template, then re-parse the resulting string
            // as JSON-ish. This handles `{{ list }}`, where minijinja
            // renders a Python-style repr; safer is to compile as an
            // expression and convert the resulting Value.
            // We use compile_expression to keep types intact.
            let prepared = crate::template::prepare_jinja_source(s);
            let trimmed_prepared = crate::template::prepare_jinja_source(
                s.trim_start_matches("{{").trim_end_matches("}}").trim(),
            );
            let compiled = env
                .compile_expression(&trimmed_prepared)
                .or_else(|_| env.compile_expression(&prepared))
                .map_err(|e| anyhow!("loop expr compile: {e}"))?;
            let val = compiled
                .eval(&view)
                .map_err(|e| anyhow!("loop expr eval: {e}"))?;
            let json = mjvalue_to_json(&val)?;
            match json {
                JsonValue::Array(items) => Ok(items),
                other => bail!("loop expression did not yield a list, got: {other:?}"),
            }
        }
    }
}

/// Walk a JSON value, rendering every string scalar through the template
/// engine in place. Used for loop items: `loop: ["{{ vars_file }}", ...]`
/// must resolve to real paths *before* the per-iteration body renders
/// `src: "{{ item }}"`. Without this, the body sees `item = "{{ vars_file }}"`
/// and emits the literal template string downstream.
fn render_json_strings(
    env: &Environment<'static>,
    value: &mut JsonValue,
    view: &BTreeMap<String, JsonValue>,
) -> Result<()> {
    match value {
        JsonValue::String(s) => {
            if s.contains("{{") || s.contains("{%") {
                let rendered = render_str(env, s, view)?;
                *s = rendered;
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                render_json_strings(env, item, view)?;
            }
        }
        JsonValue::Object(map) => {
            for (_k, v) in map.iter_mut() {
                render_json_strings(env, v, view)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn mjvalue_to_json(v: &minijinja::Value) -> Result<JsonValue> {
    let s = serde_json::to_string(v).map_err(|e| anyhow!("serialize loop value: {e}"))?;
    serde_json::from_str::<JsonValue>(&s).map_err(|e| anyhow!("re-parse loop value: {e}"))
}

/// Render a list of string sources that may individually be Jinja
/// expressions resolving to either a string or a sequence of strings.
/// When a source is a *pure* Jinja expression (the whole string is
/// `{{ ... }}` with no surrounding text), we evaluate it as an
/// expression rather than as a template so the underlying Value's
/// type is preserved. If the result is a sequence, we splat it into
/// the output. Otherwise we coerce to string.
///
/// Why: Ansible's `apt:`/`package:`/`pip:` etc. accept
/// `name: "{{ pkg_list }}"` where `pkg_list` is a list var, and the
/// op then iterates over the list. minijinja's `template_from_str`
/// always returns a string, so `render_str` on the same input would
/// produce `'["curl", "git", ...]'` — a single literal string that
/// then gets shipped as one bogus package name. Caught in the gothab
/// drill: `apt-get install -y '["curl", "git", ...]'` → "Unable to
/// correct problems, you have held broken packages."
fn render_string_or_list_sources(
    env: &Environment<'static>,
    sources: &[String],
    view: &BTreeMap<String, JsonValue>,
) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(sources.len());
    for src in sources {
        let trimmed = src.trim();
        let is_pure_expr = trimmed.starts_with("{{")
            && trimmed.ends_with("}}")
            // Reject mixed templates like `"{{ a }}-{{ b }}"` — the
            // inner closing/opening pair means the source is not a
            // single expression.
            && !trimmed[2..trimmed.len() - 2].contains("}}");
        if is_pure_expr {
            let inner = trimmed[2..trimmed.len() - 2].trim();
            let prepared = crate::template::prepare_jinja_source(inner);
            match env.compile_expression(&prepared) {
                Ok(compiled) => {
                    let val = compiled
                        .eval(view)
                        .map_err(|e| anyhow!("expression eval for {src:?}: {e}"))?;
                    let json = mjvalue_to_json(&val)?;
                    match json {
                        JsonValue::Array(items) => {
                            for item in items {
                                match item {
                                    JsonValue::String(s) => out.push(s),
                                    other => out.push(
                                        serde_json::to_string(&other)
                                            .unwrap_or_else(|_| String::new()),
                                    ),
                                }
                            }
                        }
                        JsonValue::String(s) => out.push(s),
                        JsonValue::Null => {}
                        other => out.push(
                            serde_json::to_string(&other).unwrap_or_else(|_| String::new()),
                        ),
                    }
                    continue;
                }
                Err(_) => {
                    // Not a clean expression — fall back to template
                    // rendering. e.g. `{{ items | join(',') }}` is
                    // technically an expression but a template render
                    // also produces a usable string, so either path
                    // works; we let the template path handle the
                    // edge cases.
                }
            }
        }
        out.push(render_str(env, src, view)?);
    }
    Ok(out)
}

// ---------- wire-level task dispatch ----------

/// Tracing target gating the per-task timing line. Always populated on the
/// wire (the agent always sends start/finish nanos in TaskDone); displayed
/// only when this target is enabled, e.g.
/// `RUST_LOG=rsansible::timing=debug`. Fields:
///
/// - `host`, `task`, `seq` — identity.
/// - `agent_started_unix_ns`, `agent_finished_unix_ns` — agent's wall-clock
///   bracket of the module's work.
/// - `ctl_dispatched_unix_ns`, `ctl_received_unix_ns` — controller's
///   wall-clock observations of the wire boundary.
/// - `agent_offset_us` — controller-minus-agent clock offset measured by a
///   single Ping/Pong exchange right after Hello. Subtracted from
///   `agent_started_unix_ns` / `agent_finished_unix_ns` before computing
///   `outbound_us` / `inbound_us`, so those numbers reflect wire-time, not
///   clock skew.
/// - `agent_us`, `wall_us` — derived microseconds: agent-local work (skew-
///   immune) and controller-observed end-to-end. `outbound_us` and
///   `inbound_us` are signed (i64) because the single-sample offset still
///   has some residual error; a slightly negative value is normal and just
///   means the probe under-estimated skew by less than the wire delay.
pub const TIMING_TARGET: &str = "rsansible::timing";

fn emit_timing_trace(host: &str, task_name: &str, seq: u32, exec: &OpExecOutcome) {
    let agent_ns = exec
        .done
        .finished_unix_ns
        .saturating_sub(exec.done.started_unix_ns);
    let wall_ns = exec
        .received_unix_ns
        .saturating_sub(exec.dispatched_unix_ns);
    // Translate the agent's wall-clock instants into the controller's
    // reference frame using the offset measured by the startup Ping/Pong
    // probe (`agent_clock ≈ ctl_clock + offset`). Without correction the
    // outbound/inbound deltas are dominated by skew on any pair of hosts
    // whose clocks haven't been NTP-tightened recently.
    let offset = exec.clock_offset_ns as i128;
    let agent_started_corrected =
        (exec.done.started_unix_ns as i128) - offset;
    let agent_finished_corrected =
        (exec.done.finished_unix_ns as i128) - offset;
    // Signed: small RTTs plus a sloppy single-sample offset can still leave
    // these mildly negative; the magnitude is the useful number.
    let outbound_ns = agent_started_corrected - (exec.dispatched_unix_ns as i128);
    let inbound_ns = (exec.received_unix_ns as i128) - agent_finished_corrected;
    tracing::debug!(
        target: TIMING_TARGET,
        host = %host,
        task = %task_name,
        seq,
        agent_started_unix_ns = exec.done.started_unix_ns,
        agent_finished_unix_ns = exec.done.finished_unix_ns,
        ctl_dispatched_unix_ns = exec.dispatched_unix_ns,
        ctl_received_unix_ns = exec.received_unix_ns,
        agent_offset_us = (exec.clock_offset_ns / 1_000),
        agent_us = (agent_ns / 1_000) as u64,
        wall_us = (wall_ns / 1_000) as u64,
        outbound_us = (outbound_ns / 1_000) as i64,
        inbound_us = (inbound_ns / 1_000) as i64,
        "task timing"
    );
}

struct OpExecOutcome {
    done: TaskDoneOutput,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Controller-observed wall-clock nanos (since UNIX epoch) when the
    /// `TaskDispatch` frame finished writing. Paired with `done.started_unix_ns`
    /// (the agent's wall clock when it began work), this lets observers see
    /// outbound wire delta — modulo host/controller clock skew.
    dispatched_unix_ns: u64,
    /// Controller-observed wall-clock nanos when the matching `TaskDone`
    /// frame finished reading. Paired with `done.finished_unix_ns` for the
    /// inbound delta.
    received_unix_ns: u64,
    /// Clock offset of the agent's wall clock vs the controller's, as
    /// measured by the startup Ping/Pong probe (positive iff the agent
    /// is ahead of the controller). Subtracted from the agent's two
    /// timestamps in the timing trace to produce skew-corrected outbound
    /// and inbound deltas.
    clock_offset_ns: i64,
}

/// Drive one TaskDispatch / TaskDone pair on one host. When `capture` is
/// true, accumulates stdout/stderr chunks (capped at MAX_CAPTURED_BYTES).
/// Otherwise streams them to `tracing::debug` only.
///
/// `metrics` is the run-shared timing accumulator: every successful
/// round-trip contributes its agent / wall / outbound / inbound
/// deltas. This is the single source of truth for the end-of-run
/// timing summary, so probes (stat-before-write, idempotency checks,
/// async-status polls) — which all funnel through this function but
/// are NOT individual user-visible tasks — are still counted as the
/// real dispatch cost the operator paid.
async fn run_one_task_op(
    conn: &mut AgentConn,
    seq: u32,
    op: Op,
    capture: bool,
    clock_offset_ns: i64,
    check_mode: bool,
    metrics: &crate::run_metrics::RunMetrics,
) -> Result<OpExecOutcome> {
    let dispatch = task_dispatch(seq, check_mode, op);
    write_frame(&mut conn.stream, &dispatch)
        .await
        .with_context(|| format!("writing TaskDispatch to {}", conn.label))?;
    let dispatched_unix_ns = now_unix_ns();

    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut truncated = false;

    loop {
        let frame = read_frame(&mut conn.stream)
            .await
            .with_context(|| format!("reading from {}", conn.label))?
            .ok_or_else(|| anyhow!("agent {} closed stdout mid-task", conn.label))?;
        match frame {
            Message::TaskProgress(p) => {
                if p.seq != seq {
                    return Err(anyhow!(
                        "{}: progress seq mismatch: expected {seq}, got {}",
                        conn.label,
                        p.seq
                    ));
                }
                if capture {
                    let used = stdout.len() + stderr.len();
                    let budget = MAX_CAPTURED_BYTES.saturating_sub(used);
                    if budget == 0 {
                        if !truncated {
                            truncated = true;
                            stderr.extend_from_slice(b"\n[output truncated at 1 MiB]\n");
                        }
                    } else {
                        let take = p.chunk.len().min(budget);
                        let target: &mut Vec<u8> = match p.stream {
                            rsansible_wire::msg::stream::STDERR => &mut stderr,
                            _ => &mut stdout,
                        };
                        target.extend_from_slice(&p.chunk[..take]);
                        if take < p.chunk.len() && !truncated {
                            truncated = true;
                            stderr.extend_from_slice(b"\n[output truncated at 1 MiB]\n");
                        }
                    }
                }
                let label = match p.stream {
                    rsansible_wire::msg::stream::STDERR => "stderr",
                    _ => "stdout",
                };
                let s = String::from_utf8_lossy(&p.chunk);
                debug!(host = %conn.label, seq, stream = label, "{}", s.trim_end_matches('\n'));
            }
            Message::TaskDone(d) => {
                let received_unix_ns = now_unix_ns();
                if d.seq != seq {
                    return Err(anyhow!(
                        "{}: done seq mismatch: expected {seq}, got {}",
                        conn.label,
                        d.seq
                    ));
                }
                metrics.record(
                    d.started_unix_ns,
                    d.finished_unix_ns,
                    dispatched_unix_ns,
                    received_unix_ns,
                    clock_offset_ns,
                );
                return Ok(OpExecOutcome {
                    done: d,
                    stdout,
                    stderr,
                    dispatched_unix_ns,
                    received_unix_ns,
                    clock_offset_ns,
                });
            }
            Message::TaskError(e) => {
                return Err(anyhow!(
                    "{}: agent reported TaskError (code {}): {}",
                    conn.label,
                    e.code,
                    e.message
                ));
            }
            Message::Hello(_)
            | Message::TaskDispatch(_)
            | Message::Bye(_)
            | Message::Ping(_)
            | Message::Pong(_) => {
                return Err(anyhow!(
                    "{}: unexpected frame from agent during task {seq}",
                    conn.label
                ));
            }
        }
    }
}

// ---------- result plumbing ----------

/// Update report + state for one host's result of one task. Returns true
/// if this host counted as "failed for the on_failure policy".
async fn apply_per_host_result(
    play: &Play,
    task: &Task,
    r: PerHostTaskResult,
    pools: &Arc<BTreeMap<String, PoolHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
) -> bool {
    let PerHostTaskResult {
        name,
        ctx,
        outcome,
        conn_alive,
    } = r;
    let failed = matches!(outcome, HostTaskOutcome::Failed { .. });
    match &outcome {
        HostTaskOutcome::Ok { changed, skipped } => {
            report.tasks_ok += 1;
            if *changed {
                report.tasks_changed += 1;
            }
            if *skipped {
                report.tasks_skipped += 1;
            }
        }
        HostTaskOutcome::Failed { reason, .. } => {
            report.host_outcomes.insert(
                name.clone(),
                HostOutcome::Failed {
                    task: task.name.clone(),
                    reason: reason.clone(),
                },
            );
        }
        HostTaskOutcome::Skipped => {}
    }
    // Always reinsert ctx — set_facts/registers should persist even from failed hosts.
    ctxs.insert(name.clone(), ctx);
    // Decide whether to kill every conn in this host's pool. We
    // kill the whole pool rather than the just-died slot because
    // (a) under SSH the slots share one session — when one channel
    // dies it's almost always the session dying; (b) under local
    // each slot is independent but the host is still "failed" from
    // the orchestrator's perspective, so leaving stale slots in
    // place would just confuse the next task.
    let drop_conns = !conn_alive
        || (failed
            && matches!(
                play.on_failure,
                OnFailure::MarkHostFailed | OnFailure::Stop
            ));
    if drop_conns {
        if let Some(pool_handle) = pools.get(&name) {
            let pool = pool_handle.lock().await;
            debug!(host = %name, "dropping pool conns (conn_alive={conn_alive}, on_failure={:?})", play.on_failure);
            pool.kill_all().await;
        }
    }
    failed
}

// ---------- handlers ----------

/// End-of-play (or `meta: flush_handlers`) handler drain for the
/// per_task strategy. Iterates handlers in declaration order; for each,
/// finds hosts whose pending set contains the handler's name, dispatches
/// the handler against just those hosts, then clears the entry. Returns
/// true if a handler failure under `OnFailure::Stop` should halt the play.
async fn flush_handlers(
    play: &Play,
    targets: &[String],
    pools: &Arc<BTreeMap<String, PoolHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
) -> Result<bool> {
    if play.handlers.is_empty() {
        return Ok(false);
    }
    for handler in &play.handlers {
        // Snapshot interested hosts (lock-free: read pending sets).
        let interested: Vec<String> = targets
            .iter()
            .filter(|n| matches!(report.host_outcomes.get(*n), Some(HostOutcome::Ok)))
            .filter(|n| {
                ctxs.get(*n)
                    .map(|c| c.pending_handlers.contains(&handler.name))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if interested.is_empty() {
            continue;
        }
        info!(
            play = %play.name,
            handler = %handler.name,
            hosts = interested.len(),
            "flushing handler",
        );

        let any_failed = run_task_fanout(
            handler, &interested, pools, ctxs, report, next_seq, env, world, play,
        )
        .await?;

        // Clear the pending entry from every host we tried to flush,
        // regardless of success (Ansible: a handler runs at most once per
        // play per host).
        for h in &interested {
            if let Some(c) = ctxs.get_mut(h) {
                c.pending_handlers.remove(&handler.name);
            }
        }

        if any_failed && play.on_failure == OnFailure::Stop {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Per-host handler drain used by the per_play strategy. Runs each
/// pending handler inline against this host's conn, returning the first
/// (handler-name, reason) pair that failed (None on success).
async fn run_handlers_one_host(
    handlers: &[Task],
    own_pool: PoolHandle,
    pools: Arc<BTreeMap<String, PoolHandle>>,
    ctx: &mut HostCtx,
    next_seq: Arc<AtomicU32>,
    env: Arc<Environment<'static>>,
    world: Arc<WorldVars>,
    play_name: &str,
) -> Option<(String, String)> {
    let mut first_failure: Option<(String, String)> = None;
    // Iterate in declaration order; skip handlers not pending on this host.
    for handler in handlers {
        if !ctx.pending_handlers.contains(&handler.name) {
            continue;
        }
        info!(
            play = %play_name,
            host = %ctx.host_name,
            handler = %handler.name,
            "running handler",
        );
        let placeholder = HostCtx::new(ctx.host_name.clone());
        let taken = std::mem::replace(ctx, placeholder);
        // ctx temporarily replaced; restore from the per-host result.
        // Handlers are dispatched once per host (run_once on handlers
        // is not honored — same as Ansible). No cross-host coord.
        let handler_coord = RunOnceCoord::empty();
        let mut handler_slot: u32 = 0;
        let r = run_task_on_one_host(
            handler,
            own_pool.clone(),
            pools.clone(),
            taken,
            next_seq.clone(),
            env.clone(),
            world.clone(),
            handler_coord,
            &mut handler_slot,
            /*is_runner=*/ true,
        )
        .await;
        *ctx = r.ctx;
        ctx.pending_handlers.remove(&handler.name);
        if let HostTaskOutcome::Failed { reason, .. } = &r.outcome {
            if first_failure.is_none() {
                first_failure = Some((handler.name.clone(), reason.clone()));
            }
        }
        if !r.conn_alive {
            break;
        }
    }
    first_failure
}

// ---------- helpers ----------

/// Per-host transport choice for the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnMode {
    /// Default: push agent over SSH using the host's inventory coords.
    Ssh,
    /// Run agent as a local subprocess on the controller. Picked when
    /// any play targeting this host declares `connection: local`. The
    /// host's `ansible_host`/`ansible_user` fields are ignored on this
    /// path — we exec the agent binary in-process.
    Local,
}

/// Resolve each targeted host's transport choice by scanning the
/// playbook. A host is `Local` iff at least one play with
/// `connection: local` targets it. Mixing `connection: local` and
/// `connection: ssh` (or default) for the same host across plays is
/// rejected at startup — that's a footgun where one play would
/// silently shell out while another SSH'd, with no diagnostic in the
/// middle.
fn resolve_host_connection_modes(
    playbook: &Playbook,
    inv: &Inventory,
    world: &WorldVars,
    targets: &BTreeSet<String>,
) -> Result<BTreeMap<String, ConnMode>> {
    use crate::playbook::Connection;
    let mut out: BTreeMap<String, ConnMode> = targets
        .iter()
        .map(|h| (h.clone(), ConnMode::Ssh))
        .collect();
    // Host-var pin first. A host with inventory-level
    // `ansible_connection: local` (most prominently the implicit
    // `localhost` — Ansible auto-seeds it that way) is forced to
    // Local regardless of what plays declare. Host-var wins over
    // play-level connection in Ansible, so we do the same.
    let mut pinned_local: BTreeSet<String> = BTreeSet::new();
    for h in targets {
        if let Some(hv) = world.hostvars.get(h) {
            if let Some(JsonValue::String(s)) = hv.get("ansible_connection") {
                if s == "local" {
                    out.insert(h.clone(), ConnMode::Local);
                    pinned_local.insert(h.clone());
                }
            }
        }
    }
    // Track whether we've ever seen an explicit non-local for each
    // host so we can detect the conflict cleanly.
    let mut seen_ssh: BTreeSet<String> = BTreeSet::new();
    for play in &playbook.plays {
        let play_mode = match play.connection {
            Some(Connection::Local) => ConnMode::Local,
            // `Some(Ssh)` and `None` both mean SSH for our purposes;
            // we only need to flag the conflict when local was set
            // elsewhere on the same host.
            _ => ConnMode::Ssh,
        };
        let hosts = resolve_play_targets(&play.hosts, inv);
        for h in hosts {
            if !targets.contains(&h) {
                continue;
            }
            // Hosts pinned Local via inventory `ansible_connection`
            // skip the play-level conflict check — host-var wins.
            if pinned_local.contains(&h) {
                continue;
            }
            match play_mode {
                ConnMode::Local => {
                    if seen_ssh.contains(&h) {
                        anyhow::bail!(
                            "host {h:?}: targeted by both `connection: local` \
                             and `connection: ssh` plays in the same run; \
                             pick one — mixed transport per host is not supported"
                        );
                    }
                    out.insert(h, ConnMode::Local);
                }
                ConnMode::Ssh => {
                    if out.get(&h) == Some(&ConnMode::Local) {
                        anyhow::bail!(
                            "host {h:?}: targeted by both `connection: local` \
                             and `connection: ssh` plays in the same run; \
                             pick one — mixed transport per host is not supported"
                        );
                    }
                    seen_ssh.insert(h);
                }
            }
        }
    }
    Ok(out)
}

fn compute_all_targeted_hosts(playbook: &Playbook, inv: &Inventory) -> BTreeSet<String> {
    let mut acc = BTreeSet::new();
    for play in &playbook.plays {
        for name in resolve_play_targets(&play.hosts, inv) {
            acc.insert(name);
        }
    }
    acc
}

fn resolve_play_targets(sel: &HostSelector, inv: &Inventory) -> Vec<String> {
    // The pattern engine accepts the same grammar Ansible does — globs,
    // regex, intersection, exclusion, index/slice. The current schema's
    // `Names(Vec<String>)` form is joined with `,` so each list entry
    // becomes a union term. `All` short-circuits.
    let raw = match sel {
        HostSelector::All(_) => {
            // `hosts: all` resolves to the `all` group's members,
            // NOT every key in inv.hosts. Matches Ansible: the
            // implicit localhost is auto-added to `inv.hosts` but
            // deliberately excluded from `all`, so plays with
            // `hosts: all` don't accidentally include it. Fall
            // back to every host only when no `all` group was
            // declared (hand-built test inventories).
            return inv
                .groups
                .get("all")
                .cloned()
                .unwrap_or_else(|| inv.hosts.keys().cloned().collect());
        }
        HostSelector::Name(n) => n.clone(),
        HostSelector::Names(names) => names.join(","),
    };
    match crate::host_pattern::HostPattern::parse(&raw) {
        Ok(p) => p.resolve(inv),
        // Validate catches parse errors earlier; if one slips through
        // (e.g. a programmatic caller skipping validate) we silently
        // resolve to nothing rather than panicking mid-run.
        Err(_) => Vec::new(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Host;
    use crate::playbook;

    fn make_inv(names: &[&str]) -> Inventory {
        let mut hosts = BTreeMap::new();
        let mut all_members: Vec<String> = Vec::new();
        for n in names {
            hosts.insert(
                n.to_string(),
                Host {
                    host: format!("{n}.local"),
                    port: 22,
                    user: "u".into(),
                    key_path: None,
                    inline_vars: BTreeMap::new(),
                    member_of: vec!["all".to_string()],
                },
            );
            all_members.push(n.to_string());
        }
        let mut groups = BTreeMap::new();
        groups.insert("all".to_string(), all_members);
        Inventory {
            hosts,
            groups,
            all_vars: BTreeMap::new(),
            group_inline_vars: BTreeMap::new(),
        }
    }

    /// Regression: a host with inventory-level
    /// `ansible_connection: local` (e.g. the implicit localhost
    /// auto-injected by `inventory::parse`) must be resolved to
    /// `ConnMode::Local` even when no play declares
    /// `connection: local` — host-var wins, matching Ansible.
    ///
    /// Caught during the gothab live drill: site.yml's first play
    /// (`hosts: all`) targeted localhost, rsansible SSH'd to
    /// bart@127.0.0.1, then died trying to spawn the as=root agent
    /// over a sudo that wasn't NOPASSWD on the controller laptop.
    #[test]
    fn ansible_connection_local_host_var_pins_conn_mode_local() {
        let mut inv = make_inv(&["a", "b"]);
        inv.hosts.get_mut("a").unwrap().inline_vars.insert(
            "ansible_connection".into(),
            serde_json::Value::String("local".into()),
        );
        let pb = playbook::parse(
            r#"
- name: p
  hosts: all
  tasks:
    - name: t
      shell: echo
"#,
        )
        .unwrap();
        let mut world = WorldVars::default();
        for (n, h) in &inv.hosts {
            world
                .hostvars
                .insert(n.clone(), h.inline_vars.clone());
        }
        let targets: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let modes = resolve_host_connection_modes(&pb, &inv, &world, &targets).unwrap();
        assert_eq!(modes.get("a"), Some(&ConnMode::Local));
        assert_eq!(modes.get("b"), Some(&ConnMode::Ssh));
    }

    /// Host-var `ansible_connection: local` must override a play's
    /// `connection: ssh`. Ansible's precedence is host-var > play-level,
    /// and we mirror that — the would-be conflict ("local-pinned host
    /// targeted by an ssh play") is NOT an error.
    #[test]
    fn host_var_local_overrides_play_level_ssh() {
        let mut inv = make_inv(&["a"]);
        inv.hosts.get_mut("a").unwrap().inline_vars.insert(
            "ansible_connection".into(),
            serde_json::Value::String("local".into()),
        );
        let pb = playbook::parse(
            r#"
- name: p
  hosts: all
  connection: ssh
  tasks:
    - name: t
      shell: echo
"#,
        )
        .unwrap();
        let mut world = WorldVars::default();
        world
            .hostvars
            .insert("a".to_string(), inv.hosts["a"].inline_vars.clone());
        let targets: BTreeSet<String> = ["a"].iter().map(|s| s.to_string()).collect();
        let modes = resolve_host_connection_modes(&pb, &inv, &world, &targets).unwrap();
        assert_eq!(modes.get("a"), Some(&ConnMode::Local));
    }

    #[test]
    fn all_keyword_resolves_to_all_inventory_hosts() {
        let inv = make_inv(&["a", "b", "c"]);
        let pb = playbook::parse(
            r#"
- name: p
  hosts: all
  tasks:
    - name: t
      shell: echo
"#,
        )
        .unwrap();
        let resolved = resolve_play_targets(&pb.plays[0].hosts, &inv);
        assert_eq!(resolved, vec!["a", "b", "c"]);
    }

    #[test]
    fn compute_targeted_hosts_unions_across_plays() {
        let inv = make_inv(&["a", "b", "c", "d"]);
        let pb = playbook::parse(
            r#"
- name: one
  hosts: [a, b]
  tasks:
    - name: t
      shell: echo
- name: two
  hosts: [b, c]
  tasks:
    - name: t
      shell: echo
"#,
        )
        .unwrap();
        let targets = compute_all_targeted_hosts(&pb, &inv);
        assert_eq!(
            targets.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert!(!targets.contains("d"));
    }

    /// Build a minimal `WorldVars` carrying a static hostvars map —
    /// matches what `build_world_vars` would produce for the same
    /// inventory shape (inventory_vars baked into each peer's view).
    fn static_world_for(peers: &[(&str, &[(&str, JsonValue)])]) -> WorldVars {
        let mut hostvars: BTreeMap<String, BTreeMap<String, JsonValue>> =
            BTreeMap::new();
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut all_members = Vec::new();
        for (name, inv_vars) in peers {
            let mut view = BTreeMap::new();
            for (k, v) in *inv_vars {
                view.insert(k.to_string(), v.clone());
            }
            hostvars.insert(name.to_string(), view);
            all_members.push(name.to_string());
        }
        groups.insert("all".into(), all_members);
        WorldVars {
            groups,
            hostvars,
            playbook_dir: None,
            inventory_dir: None,
        }
    }

    #[test]
    fn merge_dynamic_hostvars_overlays_facts_and_set_facts_and_registers() {
        let base = static_world_for(&[
            ("a", &[("vswitch_ip", serde_json::json!("10.0.0.1"))]),
            ("b", &[("vswitch_ip", serde_json::json!("10.0.0.2"))]),
        ]);
        let mut ctx_a = HostCtx::new("a".into());
        ctx_a.facts.insert(
            "ansible_distribution".into(),
            serde_json::json!("Ubuntu"),
        );
        ctx_a
            .set_facts
            .insert("patroni_ready".into(), serde_json::json!(true));
        ctx_a.record_register(
            "pubkey_blob",
            RegisterValue::from_exec(0, false, 0, b"ssh-ed25519 AAA...", b""),
        );
        let ctx_b = HostCtx::new("b".into());
        // b is plain; should still get its `inventory_hostname` added.
        let mut ctxs = BTreeMap::new();
        ctxs.insert("a".to_string(), ctx_a);
        ctxs.insert("b".to_string(), ctx_b);

        let merged = merge_dynamic_hostvars(&base, &ctxs);

        // Static layer survives (inventory_vars).
        assert_eq!(
            merged.hostvars["a"].get("vswitch_ip"),
            Some(&serde_json::json!("10.0.0.1"))
        );

        // Facts → set_facts → registers all visible cross-host.
        assert_eq!(
            merged.hostvars["a"].get("ansible_distribution"),
            Some(&serde_json::json!("Ubuntu"))
        );
        assert_eq!(
            merged.hostvars["a"].get("patroni_ready"),
            Some(&serde_json::json!(true))
        );
        let reg = merged.hostvars["a"].get("pubkey_blob").expect("pubkey");
        assert_eq!(
            reg.get("stdout").and_then(|v| v.as_str()),
            Some("ssh-ed25519 AAA...")
        );

        // inventory_hostname stamped into every peer's view — even the
        // one with no dynamic state of its own.
        assert_eq!(
            merged.hostvars["a"].get("inventory_hostname"),
            Some(&serde_json::json!("a"))
        );
        assert_eq!(
            merged.hostvars["b"].get("inventory_hostname"),
            Some(&serde_json::json!("b"))
        );

    }

    #[test]
    fn merge_dynamic_hostvars_precedence_registers_beat_facts_beat_inventory() {
        let base = static_world_for(&[("a", &[("v", serde_json::json!("inv"))])]);
        let mut ctx = HostCtx::new("a".into());
        ctx.facts.insert("v".into(), serde_json::json!("fact"));
        ctx.set_facts.insert("v".into(), serde_json::json!("set"));
        ctx.record_register(
            "v",
            RegisterValue::from_exec(0, false, 0, b"reg", b""),
        );
        let mut ctxs = BTreeMap::new();
        ctxs.insert("a".to_string(), ctx);

        let merged = merge_dynamic_hostvars(&base, &ctxs);
        // Register wins (highest of the three layers we overlay).
        let reg = merged.hostvars["a"].get("v").expect("v");
        assert_eq!(
            reg.get("stdout").and_then(|v| v.as_str()),
            Some("reg"),
            "register should beat set_fact / fact / inventory"
        );
    }

    /// End-to-end integration: drive `run_play_per_task` against two
    /// mock-pool hosts. Host A sets a fact in task 1 that's keyed off
    /// its `inventory_hostname`; host B's task 2 asserts the value is
    /// visible via `hostvars['a']`. If the dynamic-hostvars refresh
    /// between tasks is removed, this assertion fails at render time
    /// (B sees only A's inventory layer, not its set_facts).
    #[tokio::test(flavor = "current_thread")]
    async fn run_play_per_task_makes_cross_host_set_facts_visible_via_hostvars() {
        use crate::pool::{AgentPool, PoolTransport};
        use tokio::sync::Mutex as TokioMutex;

        let pb = playbook::parse(
            r#"
- name: dyn-hostvars
  hosts: all
  gather_facts: false
  tasks:
    - name: stamp role per host
      set_fact:
        my_role: "{{ inventory_hostname }}"
    - name: cross-host assertion
      assert:
        that: "hostvars['a'].my_role == 'a'"
"#,
        )
        .expect("playbook parses");
        let play = &pb.plays[0];

        let targets: Vec<String> = vec!["a".into(), "b".into()];
        // Static world has both hosts with empty inventory views; the
        // refresh between tasks is what surfaces `a`'s set_fact to `b`.
        let base_world = static_world_for(&[("a", &[]), ("b", &[])]);

        // One mock pool per host.
        let mut pools_map: BTreeMap<String, PoolHandle> = BTreeMap::new();
        for name in &targets {
            let p = AgentPool::new(name.clone(), PoolTransport::Mock);
            pools_map.insert(name.clone(), Arc::new(TokioMutex::new(p)));
        }
        let pools = Arc::new(pools_map);

        let mut ctxs: BTreeMap<String, HostCtx> = BTreeMap::new();
        for name in &targets {
            ctxs.insert(name.clone(), HostCtx::new(name.clone()));
        }

        let mut report = RunReport {
            host_outcomes: targets
                .iter()
                .map(|n| (n.clone(), HostOutcome::Ok))
                .collect(),
            stopped_early: false,
            check_mode: false,
            tasks_changed: 0,
            tasks_skipped: 0,
            tasks_ok: 0,
            timing: crate::run_metrics::RunMetricsSnapshot::default(),
        };
        let next_seq = Arc::new(AtomicU32::new(1));
        let env = Arc::new(template::make_env());
        let world = Arc::new(base_world);
        let tag_filter = Arc::new(crate::tags::TagFilter::from_cli(&[], &[]).unwrap());

        let stopped = run_play_per_task(
            play,
            &targets,
            &pools,
            &mut ctxs,
            &mut report,
            &next_seq,
            &env,
            &world,
            &tag_filter,
        )
        .await
        .expect("per_task runs");

        assert!(!stopped, "play should not have stopped early");
        for n in &targets {
            assert_eq!(
                report.host_outcomes.get(n),
                Some(&HostOutcome::Ok),
                "host {n} should be Ok; report = {report:?}"
            );
        }
    }

    /// Same shape as the per_task cross-host test, but under
    /// `strategy: per_play`. Verifies the published-snapshot path in
    /// `run_play_per_play`: host `a`'s `set_fact` on task 1 must be
    /// visible to host `b`'s `assert` on task 2 via
    /// `hostvars['a'].my_role`.
    #[tokio::test(flavor = "current_thread")]
    async fn run_play_per_play_makes_cross_host_set_facts_visible_via_hostvars() {
        use crate::pool::{AgentPool, PoolTransport};
        use tokio::sync::Mutex as TokioMutex;

        let pb = playbook::parse(
            r#"
- name: dyn-hostvars-per-play
  hosts: all
  gather_facts: false
  strategy: per_play
  tasks:
    - name: stamp role per host
      set_fact:
        my_role: "{{ inventory_hostname }}"
    - name: cross-host assertion
      assert:
        that: "hostvars['a'].my_role == 'a'"
"#,
        )
        .expect("playbook parses");
        let play = &pb.plays[0];

        let targets: Vec<String> = vec!["a".into(), "b".into()];
        let base_world = static_world_for(&[("a", &[]), ("b", &[])]);

        let mut pools_map: BTreeMap<String, PoolHandle> = BTreeMap::new();
        for name in &targets {
            let p = AgentPool::new(name.clone(), PoolTransport::Mock);
            pools_map.insert(name.clone(), Arc::new(TokioMutex::new(p)));
        }
        let pools = Arc::new(pools_map);

        let mut ctxs: BTreeMap<String, HostCtx> = BTreeMap::new();
        for name in &targets {
            ctxs.insert(name.clone(), HostCtx::new(name.clone()));
        }

        let mut report = RunReport {
            host_outcomes: targets
                .iter()
                .map(|n| (n.clone(), HostOutcome::Ok))
                .collect(),
            stopped_early: false,
            check_mode: false,
            tasks_changed: 0,
            tasks_skipped: 0,
            tasks_ok: 0,
            timing: crate::run_metrics::RunMetricsSnapshot::default(),
        };
        let next_seq = Arc::new(AtomicU32::new(1));
        let env = Arc::new(template::make_env());
        let world = Arc::new(base_world);
        let tag_filter = Arc::new(crate::tags::TagFilter::from_cli(&[], &[]).unwrap());

        // Bound the test so a regression (peer-publish skipped → host
        // `b`'s assert hangs waiting on a value that never appears, or
        // simply fails) surfaces as a clear failure instead of a
        // mysterious hang.
        let stopped = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_play_per_play(
                play,
                &targets,
                &pools,
                &mut ctxs,
                &mut report,
                &next_seq,
                &env,
                &world,
                &tag_filter,
            ),
        )
        .await
        .expect("per_play did not deadlock")
        .expect("per_play runs");

        assert!(!stopped, "play should not have stopped early");
        for n in &targets {
            assert_eq!(
                report.host_outcomes.get(n),
                Some(&HostOutcome::Ok),
                "host {n} should be Ok under per_play; report = {report:?}"
            );
        }
    }

    #[test]
    fn merge_dynamic_hostvars_does_not_leak_task_local_or_loop_state() {
        // task_vars + iter_item are transient (set per-task / per-iteration
        // on the OWNING host) and must NOT bleed into peer views — a host
        // doing `hostvars[a].x` should not see `a`'s in-flight loop item.
        let base = static_world_for(&[("a", &[])]);
        let mut ctx = HostCtx::new("a".into());
        ctx.task_vars
            .insert("transient".into(), serde_json::json!("nope"));
        ctx.iter_item = Some(("item".into(), serde_json::json!("nope")));
        let mut ctxs = BTreeMap::new();
        ctxs.insert("a".to_string(), ctx);

        let merged = merge_dynamic_hostvars(&base, &ctxs);
        assert!(
            !merged.hostvars["a"].contains_key("transient"),
            "task_vars must not leak into hostvars[peer]"
        );
        assert!(
            !merged.hostvars["a"].contains_key("item"),
            "iter_item must not leak into hostvars[peer]"
        );
    }

    #[test]
    fn eval_when_uses_register_values() {
        let env = Arc::new(template::make_env());
        let world = WorldVars::default();
        let mut ctx = HostCtx::new("h".into());
        let rv = RegisterValue::from_exec(0, true, 5, b"hi", b"");
        ctx.record_register("greet", rv);
        assert!(eval_when(&env, Some("greet.rc == 0"), &ctx, &world).unwrap());
        assert!(!eval_when(&env, Some("greet.rc != 0"), &ctx, &world).unwrap());
    }

    #[test]
    fn eval_when_undefined_is_falsy() {
        let env = Arc::new(template::make_env());
        let ctx = HostCtx::new("h".into());
        // Lenient undefined → `x` is falsy; the expression is `false`.
        assert!(!eval_when(&env, Some("x"), &ctx, &WorldVars::default()).unwrap());
    }

    #[test]
    fn lift_uri_envelope_pulls_keys_to_top_level() {
        // Build a register value with the agent's envelope sitting in
        // rv.json (simulating from_exec parsing of `{...}` on stdout).
        let envelope = serde_json::json!({
            "status": 200,
            "url": "https://api/x",
            "headers": {"content-type": "application/json"},
            "content_length": 9,
            "content_type": "application/json",
            "elapsed_ms": 12,
            "redirected": false,
            "json": {"a": 1, "b": "two"},
            // Shadow-protection: must NOT clobber rv.rc/rv.changed.
            "rc": 999,
            "changed": true
        });
        let stdout = serde_json::to_vec(&envelope).unwrap();
        let mut rv = RegisterValue::from_exec(0, false, 5, &stdout, b"");
        // Sanity: from_exec parses stdout as JSON into rv.json when it
        // looks like a JSON object.
        assert!(matches!(rv.json, Some(JsonValue::Object(_))));
        lift_uri_envelope(&mut rv);
        // Top-level lifts.
        assert_eq!(rv.extra.get("status").unwrap(), &serde_json::json!(200));
        assert_eq!(
            rv.extra.get("url").unwrap(),
            &serde_json::json!("https://api/x")
        );
        assert_eq!(
            rv.extra.get("content_type").unwrap(),
            &serde_json::json!("application/json")
        );
        assert_eq!(rv.extra.get("elapsed_ms").unwrap(), &serde_json::json!(12));
        assert_eq!(
            rv.extra.get("redirected").unwrap(),
            &serde_json::json!(false)
        );
        // rv.json now holds the response body, not the envelope.
        assert_eq!(rv.json, Some(serde_json::json!({"a": 1, "b": "two"})));
        // Canonical fields were NOT shadowed by the envelope.
        assert_eq!(rv.rc, 0);
        assert!(!rv.changed);
        assert!(!rv.extra.contains_key("rc"));
        assert!(!rv.extra.contains_key("changed"));
    }

    /// Regression: `register:` on an `async: N` task previously dropped
    /// the start envelope's `ansible_job_id` / `started` / `finished` /
    /// `results_file` into `rv.json` instead of lifting them to the top
    /// level. Result: a follow-up `async_status: jid: "{{
    /// async_register.ansible_job_id }}"` rendered to `""` and failed
    /// the play. `lift_async_envelope` mirrors the existing per-module
    /// lift pattern (postgresql, slurp, …) — verify it pulls each
    /// envelope key into `rv.extra`, drops `rv.json`, and skips the
    /// reserved register fields.
    #[test]
    fn lift_async_envelope_pulls_job_id_to_top_level() {
        let envelope = serde_json::json!({
            "ansible_job_id": 7,
            "started": 1,
            "finished": 0,
            "results_file": "",
            // Reserved keys — should NOT be lifted into extra.
            "changed": true,
            "rc": 999
        });
        let stdout = serde_json::to_vec(&envelope).unwrap();
        let mut rv = RegisterValue::from_exec(0, false, 0, &stdout, b"");
        lift_async_envelope(&mut rv);
        // Envelope keys ended up at the top level.
        assert_eq!(
            rv.extra.get("ansible_job_id").unwrap(),
            &serde_json::json!(7)
        );
        assert_eq!(rv.extra.get("started").unwrap(), &serde_json::json!(1));
        assert_eq!(rv.extra.get("finished").unwrap(), &serde_json::json!(0));
        assert_eq!(
            rv.extra.get("results_file").unwrap(),
            &serde_json::json!("")
        );
        // Reserved fields are NOT shadowed via extra.
        assert!(!rv.extra.contains_key("rc"));
        assert!(!rv.extra.contains_key("changed"));
        assert_eq!(rv.rc, 0);
        assert!(!rv.changed);
        // rv.json drained — the lifted shape replaces the nested one,
        // same as get_url / slurp / unarchive.
        assert!(rv.json.is_none());
    }

    /// Regression: when the non-runner host hits a `run_once:` task
    /// before the runner has published, it MUST be woken by an
    /// external `publish()` call. The previous implementation used
    /// `OnceCell::get_or_init(|| pending().await)` for the non-runner,
    /// which locked the cell's init slot — the runner's later
    /// `cell.set(...)` returned `Err` (silently swallowed by `let _ =
    /// ...`) and the waiter never woke, deadlocking the play.
    ///
    /// The fix wraps the OnceCell with a `Notify`: `publish` calls
    /// `set` then `notify_waiters`; `wait` registers on the Notify
    /// BEFORE checking the cell so it can't miss the wake. This test
    /// drives the actual sequence (wait first, publish later) to catch
    /// any future regression where the wake mechanism gets cut out.
    #[tokio::test(flavor = "current_thread")]
    async fn run_once_slot_external_publish_wakes_pending_waiter() {
        let slot = Arc::new(RunOnceSlot::new());
        let waiter_slot = slot.clone();
        // Spawn the waiter first. With the buggy `get_or_init` shape,
        // this call would acquire the init permit; the later `publish`
        // would silently fail and the waiter would hang forever — the
        // test would time out instead of completing.
        let waiter = tokio::spawn(async move { waiter_slot.wait().await });
        // Yield enough times for the waiter to register on the Notify
        // before we publish. Both `yield_now()` and a short sleep work
        // on current-thread; sleep is more forgiving across scheduler
        // versions.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        slot.publish(RunOnceResult {
            register: None,
            set_facts: BTreeMap::new(),
            success: true,
            outcome: HostTaskOutcome::Ok {
                changed: true,
                skipped: false,
            },
        });
        // The waiter unblocks with the published value. Wrap in a tight
        // timeout so a re-introduced deadlock fails fast instead of
        // hanging the test process.
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("waiter must unblock after publish — deadlock regressed?")
            .expect("waiter task didn't panic");
        assert!(r.success);
        assert!(matches!(
            r.outcome,
            HostTaskOutcome::Ok {
                changed: true,
                skipped: false
            }
        ));
    }

    /// Companion to the wake-test above: when the cell is already
    /// published BEFORE the waiter calls `wait`, the waiter must
    /// return immediately rather than blocking on a new Notify
    /// registration that nobody will ever fire. The `wait` impl checks
    /// the cell after registering interest, which covers this case —
    /// guard against a future "optimize by skipping the initial check"
    /// regression.
    #[tokio::test(flavor = "current_thread")]
    async fn run_once_slot_wait_returns_immediately_when_already_published() {
        let slot = RunOnceSlot::new();
        slot.publish(RunOnceResult {
            register: None,
            set_facts: BTreeMap::new(),
            success: true,
            outcome: HostTaskOutcome::Skipped,
        });
        let r = tokio::time::timeout(std::time::Duration::from_millis(100), slot.wait())
            .await
            .expect("wait must return immediately when value already present");
        assert!(matches!(r.outcome, HostTaskOutcome::Skipped));
    }

    #[test]
    fn lift_postgresql_envelope_pulls_query_result_to_top_level() {
        let envelope = serde_json::json!({
            "query_result": [
                {"id": "1", "name": "alice"},
                {"id": "2", "name": "bob"}
            ],
            "rowcount": 2,
            "statusmessage": "SELECT 2",
            // Shadow protection.
            "changed": true,
            "rc": 999
        });
        let stdout = serde_json::to_vec(&envelope).unwrap();
        let mut rv = RegisterValue::from_exec(0, false, 3, &stdout, b"");
        lift_postgresql_envelope(&mut rv);
        let qr = rv.extra.get("query_result").unwrap();
        assert!(qr.is_array());
        assert_eq!(qr.as_array().unwrap().len(), 2);
        assert_eq!(rv.extra.get("rowcount").unwrap(), &serde_json::json!(2));
        assert_eq!(
            rv.extra.get("statusmessage").unwrap(),
            &serde_json::json!("SELECT 2")
        );
        // Reserved fields untouched.
        assert_eq!(rv.rc, 0);
        assert!(!rv.changed);
        assert!(!rv.extra.contains_key("rc"));
        assert!(!rv.extra.contains_key("changed"));
    }

    #[test]
    fn lift_postgresql_envelope_pulls_ext_fields_to_top_level() {
        let envelope = serde_json::json!({
            "extension": "pg_stat_statements",
            "state": "present",
            "prior_version": null,
            "version": "1.10"
        });
        let stdout = serde_json::to_vec(&envelope).unwrap();
        let mut rv = RegisterValue::from_exec(0, true, 7, &stdout, b"");
        lift_postgresql_envelope(&mut rv);
        assert_eq!(
            rv.extra.get("extension").unwrap(),
            &serde_json::json!("pg_stat_statements")
        );
        assert_eq!(
            rv.extra.get("state").unwrap(),
            &serde_json::json!("present")
        );
        assert_eq!(
            rv.extra.get("version").unwrap(),
            &serde_json::json!("1.10")
        );
    }

    #[test]
    fn lift_get_url_envelope_pulls_dest_and_checksum_to_top_level() {
        let envelope = serde_json::json!({
            "url": "https://example.com/x",
            "dest": "/tmp/x",
            "checksum_src": "sha256:abc",
            "checksum_dest": "deadbeef",
            "size": 12345,
            "status_code": 200,
            "msg": "OK"
        });
        let stdout = serde_json::to_vec(&envelope).unwrap();
        let mut rv = RegisterValue::from_exec(0, true, 7, &stdout, b"");
        lift_get_url_envelope(&mut rv);
        assert_eq!(rv.extra.get("dest").unwrap(), &serde_json::json!("/tmp/x"));
        assert_eq!(
            rv.extra.get("checksum_dest").unwrap(),
            &serde_json::json!("deadbeef")
        );
        assert_eq!(rv.extra.get("size").unwrap(), &serde_json::json!(12345));
        assert_eq!(
            rv.extra.get("status_code").unwrap(),
            &serde_json::json!(200)
        );
    }

    #[test]
    fn lift_uri_envelope_noop_when_no_json() {
        let mut rv = RegisterValue::from_exec(0, false, 5, b"not json", b"");
        // rv.json is None — should pass through with no panics.
        lift_uri_envelope(&mut rv);
        assert!(rv.extra.is_empty());
    }

    #[test]
    fn resolve_loop_items_literal_list() {
        let env = template::make_env();
        let ctx = HostCtx::new("h".into());
        let spec = LoopSpec::Items(vec![
            serde_yaml::Value::String("a".into()),
            serde_yaml::Value::String("b".into()),
        ]);
        let items = resolve_loop_items(&env, Some(&spec), &ctx, &WorldVars::default()).unwrap();
        assert_eq!(items, vec![JsonValue::String("a".into()), JsonValue::String("b".into())]);
    }

    #[test]
    fn resolve_loop_items_expression() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert(
            "names".into(),
            serde_json::json!(["alice", "bob"]),
        );
        let spec = LoopSpec::Expr("names".into());
        let items = resolve_loop_items(&env, Some(&spec), &ctx, &WorldVars::default()).unwrap();
        assert_eq!(
            items,
            vec![JsonValue::String("alice".into()), JsonValue::String("bob".into())]
        );
    }

    #[test]
    fn resolve_loop_items_expression_with_braces() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("xs".into(), serde_json::json!([1, 2, 3]));
        let spec = LoopSpec::Expr("{{ xs }}".into());
        let items = resolve_loop_items(&env, Some(&spec), &ctx, &WorldVars::default()).unwrap();
        assert_eq!(items, vec![JsonValue::from(1), JsonValue::from(2), JsonValue::from(3)]);
    }

    /// Regression: `apt: { name: "{{ pkg_list }}" }` where
    /// `pkg_list` is a list var must splat into separate package
    /// names, not get rendered as the literal string `'["curl",
    /// "git", ...]'`. Caught during the gothab drill — apt failed
    /// with "Unable to correct problems, you have held broken
    /// packages" because the entire stringified list was being
    /// sent as a single argv element.
    #[test]
    fn render_string_or_list_sources_splats_list_var() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert(
            "pkg_list".into(),
            serde_json::json!(["curl", "git", "vim"]),
        );
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_string_or_list_sources(
            &env,
            &["{{ pkg_list }}".to_string()],
            &view,
        )
        .unwrap();
        assert_eq!(
            out,
            vec!["curl".to_string(), "git".to_string(), "vim".to_string()],
            "pure-expression list var must splat into separate names",
        );
    }

    /// A plain string source still resolves to a single name —
    /// the splat path only triggers when the source is a pure
    /// `{{ ... }}` expression resolving to a sequence.
    #[test]
    fn render_string_or_list_sources_keeps_literal_strings_as_single_name() {
        let env = template::make_env();
        let ctx = HostCtx::new("h".into());
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_string_or_list_sources(
            &env,
            &["curl".to_string(), "git".to_string()],
            &view,
        )
        .unwrap();
        assert_eq!(out, vec!["curl".to_string(), "git".to_string()]);
    }

    /// A pure-expression source resolving to a scalar string is
    /// added as a single name — no splat for non-sequence values.
    #[test]
    fn render_string_or_list_sources_scalar_expression_stays_single() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts
            .insert("pkg".into(), serde_json::json!("nginx"));
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_string_or_list_sources(
            &env,
            &["{{ pkg }}".to_string()],
            &view,
        )
        .unwrap();
        assert_eq!(out, vec!["nginx".to_string()]);
    }

    /// Regression: `render_str` must follow vars-referencing-vars
    /// until the output stabilizes. Caught in the gothab live drill —
    /// monitoring-host's defaults say
    /// `monitoring_vmalert_version: "{{ monitoring_vm_version }}"`,
    /// and a get_url task's URL referenced
    /// `{{ monitoring_vmalert_version }}`. A single-pass render
    /// returned the URL with the literal `{{ monitoring_vm_version }}`
    /// still in it, which then 404'd against GitHub. Real Ansible
    /// follows the indirection via lazy Templar templates; we get the
    /// same result by re-rendering whenever the output still contains
    /// template markers.
    #[test]
    fn render_str_follows_vars_referencing_vars() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.role_defaults
            .insert("inner".into(), serde_json::json!("v1.143.0"));
        // `outer` references `inner` — classic defaults indirection.
        ctx.role_defaults
            .insert("outer".into(), serde_json::json!("{{ inner }}"));
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_str(&env, "version={{ outer }}", &view).unwrap();
        assert_eq!(
            out, "version=v1.143.0",
            "render_str must chase vars-of-vars to a stable value, \
             not stop after one pass with a literal `{{{{ inner }}}}` \
             in the output"
        );
    }

    /// Pathological case: a var graph that cycles (`a = "{{ b }}"`,
    /// `b = "{{ a }}"`) must terminate. The var-resolution pass
    /// stabilizes at the cycle's fixed point (both vars resolve to a
    /// literal template-looking string), and the body render then
    /// renders that fixed point literally. The non-hang property is
    /// what matters; the visible output is the cycled literal, which
    /// makes the bug obvious to the playbook author.
    #[test]
    fn render_str_terminates_on_circular_var_references() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.role_defaults
            .insert("a".into(), serde_json::json!("{{ b }}"));
        ctx.role_defaults
            .insert("b".into(), serde_json::json!("{{ a }}"));
        let view = build_template_ctx(&ctx, &WorldVars::default());
        // Must not hang and must not error — the resolver stabilizes
        // and the body render emits the literal stuck value.
        let out = render_str(&env, "{{ a }}", &view).unwrap();
        // The exact fixed-point string is implementation-dependent
        // (either `{{ a }}` or `{{ b }}` depending on iteration
        // order), but it MUST still look like an unresolved template
        // — that's the signal to the playbook author that they have
        // a cycle.
        assert!(
            out.contains("{{") && out.contains("}}"),
            "circular var should leave template-looking literal in output, got: {out:?}"
        );
    }

    /// Body templates that intentionally emit Jinja-looking literals
    /// (Prometheus / vmalert alert rules say
    /// `summary: "down on {{{{ '{{{{' }}}} $labels.instance {{{{ '}}}}' }}}}"`,
    /// expecting the rendered file to literally contain `{{ $labels.instance }}`)
    /// must NOT be re-rendered — that would treat `$labels.instance`
    /// as a Jinja expression and error on parse. Caught in the gothab
    /// live drill: the first render-until-stable fix broke vmalert's
    /// `gothab.yml.j2` rule file with `template parse: syntax error`.
    #[test]
    fn render_str_does_not_re_render_jinja_looking_body_output() {
        let env = template::make_env();
        let ctx = HostCtx::new("h".into());
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let body = "summary: \"gothab-server down on {{ '{{' }} $labels.instance {{ '}}' }}\"";
        let out = render_str(&env, body, &view).unwrap();
        assert_eq!(
            out, "summary: \"gothab-server down on {{ $labels.instance }}\"",
            "body render must run exactly once — Prometheus-style \
             escapes that resolve to `{{{{ ... }}}}` text must not \
             be re-fed to minijinja"
        );
    }

    /// Bug 18: `resolve_view_var_templates` historically only walked
    /// the top level of the vars map. A role default like
    /// `patroni_pg_hba: ["host all all {{ vswitch_cidr }} scram-sha-256"]`
    /// passed straight into minijinja with the inner `{{ vswitch_cidr }}`
    /// unrendered, so iterating it in a template emitted literal
    /// Jinja text. That broke gothab's Postgres cluster in production
    /// (literal `{{ vswitch_cidr }}` ended up in Patroni's DCS, then
    /// in `pg_hba.conf`, and postmaster refused to start with
    /// "invalid authentication method 'vswitch_cidr'"). Recovery
    /// playbook: `gothab/ansible/playbooks/recover-patroni-pg-hba.yml`.
    #[test]
    fn render_str_renders_jinja_in_list_elements() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.role_defaults
            .insert("vswitch_cidr".into(), serde_json::json!("10.10.0.0/16"));
        ctx.role_defaults.insert(
            "patroni_pg_hba".into(),
            serde_json::json!(["host all all {{ vswitch_cidr }} scram-sha-256"]),
        );
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_str(
            &env,
            "{% for e in patroni_pg_hba %}{{ e }}{% endfor %}",
            &view,
        )
        .unwrap();
        assert_eq!(
            out, "host all all 10.10.0.0/16 scram-sha-256",
            "list elements containing `{{{{ … }}}}` must be expanded \
             before the body render reads them — Ansible's Templar \
             does this lazily on every access regardless of depth"
        );
    }

    /// Symmetric Bug 18 case: the same recursion must apply to dict
    /// values. Without it, `{{ wrapper.key }}` emits literal
    /// `{{ inner }}` instead of `value`.
    #[test]
    fn render_str_renders_jinja_in_dict_values() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.role_defaults
            .insert("inner".into(), serde_json::json!("value"));
        ctx.role_defaults.insert(
            "wrapper".into(),
            serde_json::json!({"key": "x-{{ inner }}-y"}),
        );
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_str(&env, "{{ wrapper.key }}", &view).unwrap();
        assert_eq!(out, "x-value-y");
    }

    /// Bug 18, multi-pass convergence: a list element references a
    /// top-level var which itself references another top-level var.
    /// First pass resolves the top-level chain, second pass picks up
    /// the now-resolved value inside the list. Pre-fix the list
    /// element was simply never visited.
    #[test]
    fn render_str_renders_jinja_through_layered_container_indirection() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.role_defaults
            .insert("base".into(), serde_json::json!("10.10.0.0/16"));
        ctx.role_defaults
            .insert("cidr".into(), serde_json::json!("{{ base }}"));
        ctx.role_defaults
            .insert("rules".into(), serde_json::json!(["allow {{ cidr }}"]));
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_str(
            &env,
            "{% for r in rules %}{{ r }}{% endfor %}",
            &view,
        )
        .unwrap();
        assert_eq!(out, "allow 10.10.0.0/16");
    }

    #[test]
    fn render_op_omit_collapses_to_empty_string() {
        // `default(omit)` on an undefined var should erase the field.
        // For string-carrier fields ("" = absent), that means we render
        // to an empty string.
        let env = template::make_env();
        let ctx = HostCtx::new("h".into()); // no `who` fact
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_str(&env, "{{ who | default(omit) }}", &view).unwrap();
        assert_eq!(out, "", "expected omit to collapse to empty, got {out:?}");
    }

    #[test]
    fn render_op_omit_does_not_collapse_partial_strings() {
        // If the sentinel is embedded mid-string (rare but possible),
        // we deliberately do NOT strip it — only an exact-match
        // collapses. This matches Ansible's behavior: `omit` is meant
        // for whole-field substitution, not interpolation.
        let env = template::make_env();
        let ctx = HostCtx::new("h".into());
        let view = build_template_ctx(&ctx, &WorldVars::default());
        let out = render_str(&env, "before {{ omit }} after", &view).unwrap();
        assert!(out.contains("rsansible_omit_placeholder"));
        assert!(out.starts_with("before "));
        assert!(out.ends_with(" after"));
    }

    #[test]
    fn render_op_shell_expands_template() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("who".into(), serde_json::json!("alice"));
        let op = TaskOp::Shell(ShellOp::Simple("echo {{ who }}".into()));
        let rendered = render_op(&op, &ctx, &env, &WorldVars::default()).unwrap();
        match rendered {
            TaskOp::Shell(s) => assert_eq!(s.command(), "echo alice"),
            _ => panic!(),
        }
    }

    /// `copy: content:` Jinja-renders at dispatch time. The rendered
    /// string becomes the on-wire body; the resulting CopyOp must have
    /// `body: Some(rendered_bytes)`. Regression-guards the "render
    /// inline content" branch of `render_op`'s `TaskOp::Copy` arm.
    #[test]
    fn render_op_copy_content_form_renders_jinja_into_body() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("name".into(), serde_json::json!("world"));
        let op = TaskOp::Copy(CopyOp {
            src: None,
            content: Some("hello {{ name }}\n".into()),
            dest: "/etc/greeting".into(),
            mode: crate::playbook::ModeField::Literal(0o644),
            owner: None,
            group: None,
            body: None,
            validate: None,
            remote_src: false,
            search_dirs: Vec::new(),
        });
        let rendered = render_op(&op, &ctx, &env, &WorldVars::default()).unwrap();
        match rendered {
            TaskOp::Copy(c) => {
                assert_eq!(c.body.as_deref(), Some(b"hello world\n".as_ref()));
                assert_eq!(c.dest, "/etc/greeting");
            }
            _ => panic!(),
        }
    }

    /// Regression: `mode: "{{ item.mode }}"` must Jinja-render at
    /// dispatch and end up as a `ModeField::Literal(parsed)` on the
    /// rendered op. Guards the entire ModeField-template plumbing —
    /// parse-side detection of Jinja in mode strings, orchestrator-side
    /// resolve_mode/resolve_mode_opt rendering, and post-render parsing
    /// of the octal value.
    #[test]
    fn render_op_resolves_mode_template_to_literal() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert(
            "item".into(),
            serde_json::json!({"mode": "0750"}),
        );
        let op = TaskOp::Copy(CopyOp {
            src: None,
            content: Some("body\n".into()),
            dest: "/etc/x".into(),
            mode: crate::playbook::ModeField::Template("{{ item.mode }}".into()),
            owner: None,
            group: None,
            body: None,
            validate: None,
            remote_src: false,
            search_dirs: Vec::new(),
        });
        let rendered = render_op(&op, &ctx, &env, &WorldVars::default()).unwrap();
        match rendered {
            TaskOp::Copy(c) => {
                assert_eq!(c.mode, crate::playbook::ModeField::Literal(0o750));
            }
            _ => panic!(),
        }
    }

    /// Regression for the `Deploy vmagent bearer-token file` failure:
    /// `copy: ... owner: "{{ vmagent_user }}"` was shipping the literal
    /// Jinja string to the agent, which then rejected the wire op with
    /// `unknown owner "{{ vmagent_user }}"`. The Copy arm of
    /// `render_op` was carrying `c.owner.clone()` through unchanged —
    /// every other arm that takes owner/group renders it (WriteFile,
    /// Template). This test pins the fix: a Jinja-bearing owner/group
    /// on a copy task must end up rendered on the wire-bound op.
    #[test]
    fn render_op_copy_renders_owner_and_group_templates() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("vmagent_user".into(), serde_json::json!("vmagent"));
        // Content form (remote_src=false).
        let op = TaskOp::Copy(CopyOp {
            src: None,
            content: Some("token\n".into()),
            dest: "/etc/vmagent/secrets/remote-write-token".into(),
            mode: crate::playbook::ModeField::Literal(0o600),
            owner: Some("{{ vmagent_user }}".into()),
            group: Some("{{ vmagent_user }}".into()),
            body: None,
            validate: None,
            remote_src: false,
            search_dirs: Vec::new(),
        });
        let rendered = render_op(&op, &ctx, &env, &WorldVars::default()).unwrap();
        match rendered {
            TaskOp::Copy(c) => {
                assert_eq!(c.owner.as_deref(), Some("vmagent"),
                    "owner Jinja must be rendered before wire dispatch");
                assert_eq!(c.group.as_deref(), Some("vmagent"),
                    "group Jinja must be rendered before wire dispatch");
            }
            _ => panic!(),
        }

        // remote_src form takes a separate branch — guard it too.
        let op = TaskOp::Copy(CopyOp {
            src: Some("/etc/src".into()),
            content: None,
            dest: "/etc/dst".into(),
            mode: crate::playbook::ModeField::Literal(0o600),
            owner: Some("{{ vmagent_user }}".into()),
            group: Some("{{ vmagent_user }}".into()),
            body: None,
            validate: None,
            remote_src: true,
            search_dirs: Vec::new(),
        });
        let rendered = render_op(&op, &ctx, &env, &WorldVars::default()).unwrap();
        match rendered {
            TaskOp::Copy(c) => {
                assert!(c.remote_src);
                assert_eq!(c.owner.as_deref(), Some("vmagent"));
                assert_eq!(c.group.as_deref(), Some("vmagent"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn render_op_exec_expands_argv_and_env() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("target".into(), serde_json::json!("/etc/foo"));
        ctx.set_facts.insert("level".into(), serde_json::json!("debug"));
        let op = TaskOp::Exec(ExecOp {
            argv: vec!["/bin/cat".into(), "{{ target }}".into()],
            env: [("LEVEL".to_string(), "{{ level }}".to_string())].into(),
            cwd: None,
            stdin: String::new(),
            timeout_ms: 0,
        });
        let rendered = render_op(&op, &ctx, &env, &WorldVars::default()).unwrap();
        match rendered {
            TaskOp::Exec(e) => {
                assert_eq!(e.argv, vec!["/bin/cat", "/etc/foo"]);
                assert_eq!(e.env.get("LEVEL").map(String::as_str), Some("debug"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn assert_passes_when_truthy() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("x".into(), serde_json::json!(5));
        let a = AssertTask {
            that: vec!["x > 0".into(), "x < 10".into()],
            fail_msg: None,
        };
        let r = run_assert_body(&a, &ctx, &env, &WorldVars::default());
        assert!(matches!(r, BodyResult::Ok { .. }));
    }

    #[test]
    fn assert_fails_with_custom_msg() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("x".into(), serde_json::json!(0));
        let a = AssertTask {
            that: vec!["x > 0".into()],
            fail_msg: Some("x must be positive".into()),
        };
        let r = run_assert_body(&a, &ctx, &env, &WorldVars::default());
        match r {
            BodyResult::Failed { reason, .. } => assert_eq!(reason, "x must be positive"),
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn pause_body_sleeps_rendered_seconds() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts
            .insert("wait_s".into(), serde_json::json!(1));
        let p = PauseTask {
            seconds: Some("{{ wait_s }}".into()),
            minutes: None,
        };
        let started = std::time::Instant::now();
        let r = run_pause_body(&p, &ctx, &env, &WorldVars::default()).await;
        let elapsed = started.elapsed();
        match r {
            BodyResult::Ok { .. } => {}
            _ => panic!("expected Ok"),
        }
        // We asked for 1s; allow some slack on the slow side and reject
        // anything that suspiciously short-circuited.
        assert!(
            elapsed >= std::time::Duration::from_millis(950),
            "pause too short: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "pause too long: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn pause_body_minutes_unit_factor() {
        // Using a tiny rendered value (0) so the test stays fast — the
        // point is that minutes is accepted and routed correctly.
        let env = template::make_env();
        let ctx = HostCtx::new("h".into());
        let p = PauseTask {
            seconds: None,
            minutes: Some("0".into()),
        };
        let r = run_pause_body(&p, &ctx, &env, &WorldVars::default()).await;
        assert!(matches!(r, BodyResult::Ok { .. }));
    }

    #[tokio::test]
    async fn pause_body_negative_value_fails_cleanly() {
        let env = template::make_env();
        let ctx = HostCtx::new("h".into());
        let p = PauseTask {
            seconds: Some("-5".into()),
            minutes: None,
        };
        let r = run_pause_body(&p, &ctx, &env, &WorldVars::default()).await;
        match r {
            BodyResult::Failed { reason, .. } => {
                assert!(reason.contains("negative"), "unexpected reason: {reason}");
            }
            _ => panic!("expected Failed"),
        }
    }

    #[tokio::test]
    async fn pause_body_render_failure_propagates() {
        let env = template::make_env();
        let ctx = HostCtx::new("h".into());
        let p = PauseTask {
            seconds: Some("not_a_number".into()),
            minutes: None,
        };
        let r = run_pause_body(&p, &ctx, &env, &WorldVars::default()).await;
        match r {
            BodyResult::Failed { reason, .. } => {
                assert!(reason.contains("pause.seconds"), "unexpected reason: {reason}");
            }
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn apply_task_vars_renders_in_order_and_chains() {
        // BTreeMap key order (alphabetical) means `all_attempts` lands
        // first, then `writer_aggregate_data` can reference it. This is
        // the exact pattern the gothab drill-failover playbook uses.
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("n".into(), serde_json::json!(3));
        let mut vars: BTreeMap<String, serde_yaml::Value> = BTreeMap::new();
        vars.insert(
            "all_attempts".into(),
            serde_yaml::Value::String("{{ n }}".into()),
        );
        vars.insert(
            "writer_aggregate_data".into(),
            serde_yaml::Value::String("count={{ all_attempts }}".into()),
        );
        apply_task_vars(&vars, &mut ctx, &env, &WorldVars::default()).unwrap();
        // Numeric-looking rendered output is coerced (looks_jsonish path);
        // the non-numeric chained reference stays a string but with the
        // chained value substituted in.
        assert_eq!(ctx.task_vars["all_attempts"], serde_json::json!(3));
        assert_eq!(ctx.task_vars["writer_aggregate_data"], serde_json::json!("count=3"));
    }

    #[test]
    fn apply_task_vars_render_failure_propagates() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        let mut vars: BTreeMap<String, serde_yaml::Value> = BTreeMap::new();
        vars.insert(
            "bad".into(),
            serde_yaml::Value::String("{{ undefined_filter | nope }}".into()),
        );
        let err = apply_task_vars(&vars, &mut ctx, &env, &WorldVars::default()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bad"), "got: {msg}");
    }

    #[test]
    fn apply_task_vars_extra_vars_still_wins() {
        // CLI -e overrides per-task vars (matches Ansible precedence).
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.extra_vars.insert("v".into(), serde_json::json!("from_cli"));
        let mut vars: BTreeMap<String, serde_yaml::Value> = BTreeMap::new();
        vars.insert(
            "v".into(),
            serde_yaml::Value::String("from_task".into()),
        );
        apply_task_vars(&vars, &mut ctx, &env, &WorldVars::default()).unwrap();
        // The slot is set...
        assert_eq!(ctx.task_vars["v"], serde_json::json!("from_task"));
        // ...but the merged view shows extra_vars winning.
        let view = build_template_ctx(&ctx, &WorldVars::default());
        assert_eq!(view.get("v"), Some(&serde_json::json!("from_cli")));
    }

    #[test]
    fn fail_body_renders_msg() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("why".into(), serde_json::json!("nope"));
        let f = FailTask {
            msg: "stop: {{ why }}".into(),
        };
        let r = run_fail_body(&f, &ctx, &env, &WorldVars::default());
        match r {
            BodyResult::Failed { reason, .. } => assert_eq!(reason, "stop: nope"),
            _ => panic!(),
        }
    }

    #[test]
    fn set_fact_string_renders_and_stores() {
        let env = template::make_env();
        let mut ctx = HostCtx::new("h".into());
        ctx.set_facts.insert("name".into(), serde_json::json!("ed"));
        let mut m: BTreeMap<String, serde_yaml::Value> = BTreeMap::new();
        m.insert(
            "greeting".into(),
            serde_yaml::Value::String("hello {{ name }}".into()),
        );
        m.insert("count".into(), serde_yaml::from_str("3").unwrap());
        let r = run_set_fact_body(&SetFactMap(m), &mut ctx, &env, &WorldVars::default());
        assert!(matches!(r, BodyResult::Ok { .. }));
        assert_eq!(
            ctx.set_facts.get("greeting"),
            Some(&serde_json::json!("hello ed"))
        );
        assert_eq!(ctx.set_facts.get("count"), Some(&serde_json::json!(3)));
    }

    #[test]
    fn host_outcome_helpers() {
        assert!(HostOutcome::Ok.is_ok());
        assert!(!HostOutcome::Ok.failed());
        let f = HostOutcome::Failed {
            task: "t".into(),
            reason: "boom".into(),
        };
        assert!(!f.is_ok());
        assert!(f.failed());
        assert!(HostOutcome::Unreachable {
            reason: "tcp".into()
        }
        .failed());
        assert!(!HostOutcome::NotTargeted.is_ok());
        assert!(!HostOutcome::NotTargeted.failed());
    }

    #[test]
    fn make_initial_ctx_seeds_ansible_vars() {
        let h = Host {
            host: "1.2.3.4".into(),
            port: 22,
            user: "deploy".into(),
            key_path: None,
            inline_vars: BTreeMap::new(),
            member_of: vec!["all".to_string()],
        };
        let c = make_initial_ctx("web1", &h, &WorldVars::default(), &BTreeMap::new());
        assert_eq!(
            c.inventory_vars.get("ansible_host"),
            Some(&serde_json::json!("1.2.3.4"))
        );
        assert_eq!(
            c.inventory_vars.get("ansible_user"),
            Some(&serde_json::json!("deploy"))
        );
    }

    #[test]
    fn resolve_play_targets_expands_group_names() {
        let inv = crate::inventory::parse(
            r#"
all:
  vars:
    ansible_user: u
  children:
    web:
      hosts:
        w1: { ansible_host: 1.1.1.1 }
        w2: { ansible_host: 1.1.1.2 }
    db:
      hosts:
        d1: { ansible_host: 1.1.1.3 }
"#,
        )
        .unwrap();
        let sel = HostSelector::Names(vec!["web".into()]);
        let got = resolve_play_targets(&sel, &inv);
        assert_eq!(got, vec!["w1".to_string(), "w2".to_string()]);
    }

    #[test]
    fn resolve_play_targets_mixes_groups_and_hosts() {
        let inv = crate::inventory::parse(
            r#"
all:
  vars:
    ansible_user: u
  children:
    web:
      hosts:
        w1: { ansible_host: 1.1.1.1 }
    db:
      hosts:
        d1: { ansible_host: 1.1.1.3 }
"#,
        )
        .unwrap();
        let sel = HostSelector::Names(vec!["web".into(), "d1".into()]);
        let got = resolve_play_targets(&sel, &inv);
        assert!(got.contains(&"w1".to_string()));
        assert!(got.contains(&"d1".to_string()));
    }

    // ---- ignore_errors gate ----

    fn shell_task_with_ignore(ignore: Option<bool>) -> Task {
        Task {
            name: "t".into(),
            body: TaskBody::Op(TaskOp::Shell(ShellOp::Simple("false".into()))),
            when: None,
            register: None,
            loop_spec: None,
            loop_control: None,
            tags: Vec::new(),
            delegate_to: None,
            delegate_facts: false,
            run_once: false,
            notify: Vec::new(),
            role_dir: None,
            become_: None,
            become_user: None,
            ignore_errors: ignore,
            check_mode: None,
            async_seconds: None,
            poll_seconds: None,
            retries: None,
            delay: None,
            until: None,
            changed_when: None,
            failed_when: None,
            no_log: None,
            vars: std::collections::BTreeMap::new(),
            environment: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn maybe_ignore_failure_converts_failed_to_ok_when_set() {
        let task = shell_task_with_ignore(Some(true));
        let outcome = HostTaskOutcome::Failed {
            reason: "exit 1".into(),
            register: None,
        };
        let got = maybe_ignore_failure(&task, outcome, "h1");
        assert!(matches!(got, HostTaskOutcome::Ok { .. }));
    }

    #[test]
    fn maybe_ignore_failure_passes_through_failed_when_unset() {
        // None → don't ignore.
        let task = shell_task_with_ignore(None);
        let outcome = HostTaskOutcome::Failed {
            reason: "exit 1".into(),
            register: None,
        };
        let got = maybe_ignore_failure(&task, outcome, "h1");
        assert!(matches!(got, HostTaskOutcome::Failed { .. }));
    }

    #[test]
    fn maybe_ignore_failure_passes_through_failed_when_false() {
        // Explicit `ignore_errors: false` also doesn't ignore.
        let task = shell_task_with_ignore(Some(false));
        let outcome = HostTaskOutcome::Failed {
            reason: "exit 1".into(),
            register: None,
        };
        let got = maybe_ignore_failure(&task, outcome, "h1");
        assert!(matches!(got, HostTaskOutcome::Failed { .. }));
    }

    #[test]
    fn maybe_ignore_failure_leaves_ok_alone() {
        let task = shell_task_with_ignore(Some(true));
        let got = maybe_ignore_failure(&task, HostTaskOutcome::Ok { changed: false, skipped: false }, "h1");
        assert!(matches!(got, HostTaskOutcome::Ok { .. }));
    }

    #[test]
    fn maybe_ignore_failure_leaves_skipped_alone() {
        // Skipped tasks shouldn't be affected — ignore_errors only
        // covers actual failures.
        let task = shell_task_with_ignore(Some(true));
        let got = maybe_ignore_failure(&task, HostTaskOutcome::Skipped, "h1");
        assert!(matches!(got, HostTaskOutcome::Skipped));
    }

    // ---------- x509 composite dispatch (controller-side path) ----------
    //
    // These exercise the actual controller-side helpers used by the
    // `openssl_csr_pipe` / `x509_certificate_pipe` ops. The privkey op
    // is excluded here because it does wire I/O — covered separately
    // by the docker-based e2e in `crates/ctl/tests/x509_e2e.rs`.

    #[test]
    fn synth_csr_pipe_round_trips_via_pem_helper() {
        // Generate a key controller-side and pump it directly through
        // the synthesis helper. The output PEM must parse as a CSR.
        // The cache-hit path of `synth_csr_pipe` is a thin wrapper
        // around this helper; the cache-miss path dispatches OpReadFile
        // and is covered by the wire-level x509 e2e instead.
        let key_pem = crate::x509::generate_privkey(&crate::x509::PrivkeyParams {
            kind: crate::x509::PrivkeyType::Ed25519,
            size: 0,
        })
        .expect("ed25519 key");

        let op = OpenSslCsrPipeOp {
            privatekey_path: "/etc/x/key.pem".into(),
            common_name: "test-cn".into(),
            country_name: String::new(),
            organization_name: String::new(),
            organizational_unit_name: String::new(),
            subject_alt_name: vec!["DNS:test.example".into()],
            key_usage: vec![],
            extended_key_usage: vec![],
            basic_constraints: vec![],
            basic_constraints_critical: false,
            key_usage_critical: false,
            digest: String::new(),
        };
        let result = synth_csr_pipe_from_pem(&op, key_pem);
        let rv = match result {
            BodyResult::Ok { register, changed, .. } => {
                assert!(!changed, "_pipe always changed=false");
                register
            }
            BodyResult::Failed { reason, .. } => panic!("expected Ok, got: {reason}"),
        };
        let content = rv
            .extra
            .get("content")
            .and_then(|v| v.as_str())
            .expect("register.content present");
        assert!(content.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        rcgen::CertificateSigningRequestParams::from_pem(content)
            .expect("CSR PEM parses");
    }

    #[test]
    fn synth_csr_pipe_from_pem_surfaces_garbage_key() {
        // Garbage PEM input → Failed with a meaningful reason. The
        // synthesis helper has to deal with whatever the on-wire fetch
        // delivers, including operator misconfiguration pointing
        // privatekey_path at a non-PEM file.
        let op = OpenSslCsrPipeOp {
            privatekey_path: "/etc/missing.pem".into(),
            common_name: "x".into(),
            country_name: String::new(),
            organization_name: String::new(),
            organizational_unit_name: String::new(),
            subject_alt_name: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            basic_constraints: vec![],
            basic_constraints_critical: false,
            key_usage_critical: false,
            digest: String::new(),
        };
        match synth_csr_pipe_from_pem(&op, b"not a pem file".to_vec()) {
            BodyResult::Failed { reason, .. } => {
                assert!(reason.contains("openssl_csr_pipe"), "got: {reason}");
            }
            BodyResult::Ok { .. } => panic!("expected failure on garbage PEM"),
        }
    }

    #[test]
    fn synth_cert_pipe_signs_csr_with_provided_key() {
        // End-to-end: generate key, generate CSR off that key, then
        // synth_cert_pipe should produce a parseable self-signed cert
        // whose public key matches the CSR's.
        let key_pem = crate::x509::generate_privkey(&crate::x509::PrivkeyParams {
            kind: crate::x509::PrivkeyType::Ed25519,
            size: 0,
        })
        .expect("ed25519 key");
        let csr_pem = crate::x509::generate_csr(&crate::x509::CsrParams {
            privkey_pem: key_pem.clone(),
            common_name: "etcd-server".into(),
            country_name: String::new(),
            organization_name: String::new(),
            organizational_unit_name: String::new(),
            subject_alt_name: vec!["DNS:etcd.local".into()],
            key_usage: vec![],
            extended_key_usage: vec![],
            basic_constraints: vec![],
        })
        .expect("csr");

        let op = X509CertificatePipeOp {
            csr_content: String::from_utf8(csr_pem).unwrap(),
            privatekey_content: String::from_utf8(key_pem).unwrap(),
            privatekey_path: String::new(),
            provider: "selfsigned".into(),
            valid_for_days: 30,
            selfsigned_digest: String::new(),
            ownca_content: String::new(),
            ownca_privatekey_content: String::new(),
            ownca_privatekey_path: String::new(),
            ownca_digest: String::new(),
            not_after_template: String::new(),
        };
        let rv = match synth_cert_pipe(&op) {
            BodyResult::Ok { register, .. } => register,
            BodyResult::Failed { reason, .. } => panic!("got: {reason}"),
        };
        let cert = rv
            .extra
            .get("content")
            .and_then(|v| v.as_str())
            .expect("register.content present");
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.trim_end().ends_with("-----END CERTIFICATE-----"));
        // Sanity: the cert body should reference our common_name. PEM is
        // base64'd DER so the CN string itself isn't searchable, but the
        // length/structure check above plus the absence of a panic in
        // generate_selfsigned_cert is enough — full parse coverage lives
        // in x509::tests::selfsigned_cert_validity_window which probes
        // the X.509 fields directly.
    }

    #[test]
    fn synth_cert_pipe_signs_csr_via_ownca_provider() {
        // End-to-end ownca path: build a CA (key + self-signed cert),
        // then a separate leaf key + CSR, then synth_cert_pipe with
        // provider="ownca" should hand back a parseable cert.
        let ca_key = crate::x509::generate_privkey(&crate::x509::PrivkeyParams {
            kind: crate::x509::PrivkeyType::Ed25519,
            size: 0,
        })
        .unwrap();
        let ca_csr = crate::x509::generate_csr(&crate::x509::CsrParams {
            privkey_pem: ca_key.clone(),
            common_name: "Test CA".into(),
            country_name: String::new(),
            organization_name: String::new(),
            organizational_unit_name: String::new(),
            subject_alt_name: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            basic_constraints: vec![],
        })
        .unwrap();
        let ca_cert = crate::x509::generate_selfsigned_cert(
            &crate::x509::SelfSignedCertParams {
                privkey_pem: ca_key.clone(),
                csr_pem: ca_csr,
                valid_for_days: 365,
            },
        )
        .expect("CA self-signed cert");

        let leaf_key = crate::x509::generate_privkey(&crate::x509::PrivkeyParams {
            kind: crate::x509::PrivkeyType::Ed25519,
            size: 0,
        })
        .unwrap();
        let leaf_csr = crate::x509::generate_csr(&crate::x509::CsrParams {
            privkey_pem: leaf_key,
            common_name: "etcd-peer-0".into(),
            country_name: String::new(),
            organization_name: String::new(),
            organizational_unit_name: String::new(),
            subject_alt_name: vec!["DNS:etcd0.example".into()],
            key_usage: vec![],
            extended_key_usage: vec![],
            basic_constraints: vec![],
        })
        .unwrap();

        let op = X509CertificatePipeOp {
            csr_content: String::from_utf8(leaf_csr).unwrap(),
            // ownca path doesn't need the leaf's privkey, but the
            // parser still requires one to be set. Use the leaf key
            // we just generated (the synth fn ignores it for ownca).
            privatekey_content: String::new(),
            privatekey_path: String::new(),
            provider: "ownca".into(),
            valid_for_days: 30,
            selfsigned_digest: String::new(),
            ownca_content: String::from_utf8(ca_cert).unwrap(),
            ownca_privatekey_content: String::from_utf8(ca_key).unwrap(),
            ownca_privatekey_path: String::new(),
            ownca_digest: String::new(),
            not_after_template: String::new(),
        };
        let rv = match synth_cert_pipe(&op) {
            BodyResult::Ok { register, .. } => register,
            BodyResult::Failed { reason, .. } => panic!("got: {reason}"),
        };
        let cert = rv
            .extra
            .get("content")
            .and_then(|v| v.as_str())
            .expect("register.content present");
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.trim_end().ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn synth_cert_pipe_rejects_unknown_provider() {
        // Provider validity is checked at parse time, but the synth
        // helper is also defensive: an unknown provider that
        // somehow made it through must fail with a clear reason.
        let op = X509CertificatePipeOp {
            csr_content: "x".into(),
            privatekey_content: "y".into(),
            privatekey_path: String::new(),
            provider: "acme".into(),
            valid_for_days: 1,
            selfsigned_digest: String::new(),
            ownca_content: String::new(),
            ownca_privatekey_content: String::new(),
            ownca_privatekey_path: String::new(),
            ownca_digest: String::new(),
            not_after_template: String::new(),
        };
        match synth_cert_pipe(&op) {
            BodyResult::Failed { reason, .. } => {
                assert!(
                    reason.contains("provider") || reason.contains("acme"),
                    "got: {reason}"
                );
            }
            BodyResult::Ok { .. } => panic!("expected provider rejection"),
        }
    }

    // ---------- postgres composite helpers ----------

    #[test]
    fn quote_pg_ident_doubles_internal_double_quotes() {
        assert_eq!(quote_pg_ident("gothab").unwrap(), "\"gothab\"");
        // Mixed-case preserved.
        assert_eq!(quote_pg_ident("MyRole").unwrap(), "\"MyRole\"");
        // Internal " is doubled.
        assert_eq!(quote_pg_ident(r#"weird"name"#).unwrap(), r#""weird""name""#);
        // NUL is rejected (postgres can't store it).
        assert!(quote_pg_ident("nul\0byte").is_err());
    }

    #[test]
    fn quote_pg_string_literal_doubles_internal_single_quotes() {
        assert_eq!(quote_pg_string_literal("hello"), "'hello'");
        // Internal ' is doubled.
        assert_eq!(quote_pg_string_literal("it's"), "'it''s'");
        // Backslash is passed through literally — standard_conforming_strings=on.
        assert_eq!(quote_pg_string_literal(r"a\b"), r"'a\b'");
    }

    #[test]
    fn mask_password_in_sql_redacts_password_clause() {
        let sql = "CREATE ROLE \"gothab\" WITH LOGIN PASSWORD 'super-secret-123'";
        let masked = mask_password_in_sql(sql);
        assert!(!masked.contains("super-secret"), "got: {masked}");
        assert!(masked.contains("'<masked>'"), "got: {masked}");
        assert!(masked.contains("\"gothab\""), "got: {masked}");
    }

    #[test]
    fn mask_password_in_sql_handles_doubled_single_quote() {
        // Password is `pa''ss` — the doubled single-quote is the SQL
        // escape for one literal '. Masking must consume the whole
        // literal (not stop at the inner '').
        let sql = "ALTER ROLE \"x\" WITH PASSWORD 'pa''ss'";
        let masked = mask_password_in_sql(sql);
        assert!(!masked.contains("pa''ss"), "got: {masked}");
        assert!(masked.contains("'<masked>'"), "got: {masked}");
    }

    #[test]
    fn resolved_role_attrs_renders_create_clause() {
        let attrs = ResolvedRoleAttrs::from_flags_str(
            "LOGIN,NOSUPERUSER,NOCREATEROLE,NOCREATEDB",
        )
        .unwrap();
        let clause = attrs.render_create_clause();
        // Order is fixed by the rendering function; just check
        // membership rather than spelling.
        for kw in ["LOGIN", "NOSUPERUSER", "NOCREATEROLE", "NOCREATEDB"] {
            assert!(clause.contains(kw), "got: {clause}");
        }
    }

    #[test]
    fn resolved_role_attrs_diff_only_emits_divergent_attrs() {
        let attrs = ResolvedRoleAttrs::from_flags_str(
            "LOGIN,NOSUPERUSER,NOCREATEROLE,NOCREATEDB",
        )
        .unwrap();
        // Probe says the role is in the requested state already for
        // 3 of 4 attrs; only LOGIN differs.
        let probe = PgAuthidRow {
            super_: false,
            createrole: false,
            createdb: false,
            canlogin: false, // ← request was LOGIN, this differs
            inherit: true,
            replication: false,
            bypassrls: false,
            connlimit: -1,
            rolpassword: None,
        };
        let diff = attrs.diff_against_probe(&probe);
        assert!(diff.contains("LOGIN"));
        assert!(!diff.contains("SUPERUSER"));
        assert!(!diff.contains("CREATEROLE"));
        assert!(!diff.contains("CREATEDB"));
    }

    #[test]
    fn resolved_role_attrs_diff_empty_when_role_matches() {
        let attrs = ResolvedRoleAttrs::from_flags_str(
            "LOGIN,NOSUPERUSER,NOCREATEROLE,NOCREATEDB",
        )
        .unwrap();
        let probe = PgAuthidRow {
            super_: false,
            createrole: false,
            createdb: false,
            canlogin: true,
            inherit: true,
            replication: false,
            bypassrls: false,
            connlimit: -1,
            rolpassword: None,
        };
        assert!(attrs.diff_against_probe(&probe).is_empty());
    }

    #[test]
    fn decide_password_alter_skips_when_password_empty() {
        assert!(!decide_password_alter("", "user", Some("md5abc")));
        assert!(!decide_password_alter("", "user", None));
    }

    #[test]
    fn decide_password_alter_emits_when_password_set() {
        // v1: always re-set when password is provided (SCRAM-faithful).
        assert!(decide_password_alter("pw", "user", None));
        assert!(decide_password_alter("pw", "user", Some("md5deadbeef")));
        assert!(decide_password_alter(
            "pw",
            "user",
            Some("SCRAM-SHA-256$4096:salt$storedkey:serverkey")
        ));
    }

    #[test]
    fn parse_pg_authid_row_decodes_text_columns() {
        // tokio-postgres simple_query returns every column as a text
        // string; the agent's envelope reflects that. The parser must
        // accept both string form (the real shape) and bool form
        // (defensive).
        let env: JsonValue = serde_json::from_str(
            r#"{
                "query_result": [{
                    "rolsuper": "f",
                    "rolcreaterole": "f",
                    "rolcreatedb": "f",
                    "rolcanlogin": "t",
                    "rolinherit": "t",
                    "rolreplication": "f",
                    "rolbypassrls": "f",
                    "rolconnlimit": "-1",
                    "rolpassword": null
                }],
                "rowcount": 1,
                "statusmessage": "SELECT 1"
            }"#,
        )
        .unwrap();
        let row = parse_pg_authid_row(&env).unwrap().expect("one row");
        assert!(!row.super_);
        assert!(!row.createrole);
        assert!(!row.createdb);
        assert!(row.canlogin);
        assert!(row.inherit);
        assert_eq!(row.connlimit, -1);
        assert!(row.rolpassword.is_none());
    }

    #[test]
    fn parse_pg_authid_row_returns_none_for_empty_result() {
        let env: JsonValue =
            serde_json::from_str(r#"{"query_result":[],"rowcount":0,"statusmessage":"SELECT 0"}"#)
                .unwrap();
        assert!(parse_pg_authid_row(&env).unwrap().is_none());
    }

    // ---------- block / rescue / always executor matrix ----------
    //
    // These tests exercise the block driver end-to-end (parser → load
    // inheritance pass → `run_task_on_one_host` → `run_block_on_one_host`
    // → `run_task_list_on_host` → controller-side bodies). They use
    // only controller-side body kinds (`assert`, `fail`, `debug`,
    // `set_fact`) so the dummy `ConnHandle` is never touched — no
    // mocking required.

    fn plain_task(name: &str, body: TaskBody) -> Task {
        Task {
            name: name.into(),
            body,
            when: None,
            register: None,
            loop_spec: None,
            loop_control: None,
            tags: Vec::new(),
            delegate_to: None,
            delegate_facts: false,
            run_once: false,
            notify: Vec::new(),
            role_dir: None,
            become_: None,
            become_user: None,
            ignore_errors: None,
            check_mode: None,
            async_seconds: None,
            poll_seconds: None,
            retries: None,
            delay: None,
            until: None,
            changed_when: None,
            failed_when: None,
            no_log: None,
            vars: std::collections::BTreeMap::new(),
            environment: std::collections::BTreeMap::new(),
        }
    }

    fn assert_true(name: &str) -> Task {
        plain_task(
            name,
            TaskBody::Assert(AssertTask {
                that: vec!["1 == 1".into()],
                fail_msg: None,
            }),
        )
    }

    fn assert_false(name: &str) -> Task {
        plain_task(
            name,
            TaskBody::Assert(AssertTask {
                that: vec!["1 == 2".into()],
                fail_msg: None,
            }),
        )
    }

    fn set_fact(name: &str, key: &str, val_yaml: &str) -> Task {
        let mut m = BTreeMap::new();
        m.insert(
            key.to_string(),
            serde_yaml::from_str::<serde_yaml::Value>(val_yaml).unwrap(),
        );
        plain_task(name, TaskBody::SetFact(SetFactMap(m)))
    }

    fn block_node(name: &str, tasks: Vec<Task>, rescue: Vec<Task>, always: Vec<Task>) -> Task {
        plain_task(
            name,
            TaskBody::Block(BlockSpec {
                tasks,
                rescue,
                always,
            }),
        )
    }

    /// Pool with the `Mock` transport: `get_or_spawn` vends a dead
    /// handle (inner `Option=None`) for every requested key. Tests
    /// for controller-only tasks (set_fact, fail, assert, debug,
    /// block dispatch, …) use this — those bodies never call
    /// `run_op_body` against the conn, so the dead handle is never
    /// touched. A controller-only test that ever does dispatch a
    /// wire op surfaces a clean "agent conn is dead" failure, which
    /// is the right signal.
    fn dead_pool() -> PoolHandle {
        let p = AgentPool::new("test".to_string(), crate::pool::PoolTransport::Mock);
        Arc::new(TokioMutex::new(p))
    }

    async fn drive(task: &Task) -> PerHostTaskResult {
        let pool = dead_pool();
        let pools_map: Arc<BTreeMap<String, PoolHandle>> = Arc::new(BTreeMap::new());
        let ctx = HostCtx::new("h1".into());
        let env = Arc::new(template::make_env());
        let world = WorldVars::empty();
        let seq = Arc::new(AtomicU32::new(1));
        let coord = RunOnceCoord::allocate(std::slice::from_ref(task));
        let mut slot_counter: u32 = 0;
        // Go through dispatch_one_task so the counter is properly
        // incremented past this task's own slot before recursing into
        // a block body — same invariant the production dispatchers
        // (per_play / per_task fanout) rely on.
        dispatch_one_task(
            task,
            pool,
            pools_map,
            ctx,
            seq,
            env,
            world,
            coord,
            &mut slot_counter,
            /*is_runner=*/ true,
        )
        .await
    }

    fn assert_ok(r: &PerHostTaskResult) {
        match &r.outcome {
            HostTaskOutcome::Ok { .. } => {}
            other => panic!("expected Ok, got: {other:?}"),
        }
    }
    fn assert_failed(r: &PerHostTaskResult, contains: &str) {
        match &r.outcome {
            HostTaskOutcome::Failed { reason, .. } => assert!(
                reason.contains(contains),
                "reason {reason:?} does not contain {contains:?}"
            ),
            other => panic!("expected Failed, got: {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_succeeds_when_all_inner_tasks_succeed() {
        let block = block_node(
            "outer",
            vec![assert_true("t1"), set_fact("t2", "x", "1")],
            vec![],
            vec![],
        );
        let r = drive(&block).await;
        assert_ok(&r);
        // set_fact in t2 should have left a side effect on ctx.
        assert_eq!(
            r.ctx.set_facts.get("x"),
            Some(&serde_json::json!(1))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_without_rescue_propagates_failure() {
        let block = block_node(
            "outer",
            vec![assert_true("t1"), assert_false("t2")],
            vec![],
            vec![],
        );
        let r = drive(&block).await;
        assert_failed(&r, "assertion failed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_with_recovering_rescue_returns_ok() {
        let block = block_node(
            "outer",
            vec![assert_true("t1"), assert_false("t2"), assert_true("t3")],
            vec![set_fact("recover", "recovered", "true")],
            vec![],
        );
        let r = drive(&block).await;
        // Rescue recovered the failure — overall Ok.
        assert_ok(&r);
        // Rescue ran (side effect visible).
        assert_eq!(
            r.ctx.set_facts.get("recovered"),
            Some(&serde_json::json!(true))
        );
        // t3 (after the failed t2) did NOT run — block list stops at
        // first failure (Ansible behavior).
        // No direct side effect to test, but the recovery semantic
        // confirms the rescue path took over after t2.
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_with_failing_rescue_returns_failed_and_runs_always() {
        let block = block_node(
            "outer",
            vec![assert_false("t1")],
            vec![assert_false("r1")],
            vec![set_fact("a1", "always_ran", "true")],
        );
        let r = drive(&block).await;
        assert_failed(&r, "assertion failed");
        // Always still ran despite both block and rescue failing.
        assert_eq!(
            r.ctx.set_facts.get("always_ran"),
            Some(&serde_json::json!(true))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn always_runs_on_success() {
        let block = block_node(
            "outer",
            vec![assert_true("t1")],
            vec![],
            vec![set_fact("a1", "always_ran", "true")],
        );
        let r = drive(&block).await;
        assert_ok(&r);
        assert_eq!(
            r.ctx.set_facts.get("always_ran"),
            Some(&serde_json::json!(true))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn always_runs_on_failure_without_rescue() {
        let block = block_node(
            "outer",
            vec![assert_false("t1")],
            vec![],
            vec![set_fact("a1", "always_ran", "true")],
        );
        let r = drive(&block).await;
        assert_failed(&r, "assertion failed");
        assert_eq!(
            r.ctx.set_facts.get("always_ran"),
            Some(&serde_json::json!(true))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nested_block_inner_rescue_isolates_failure() {
        // outer.tasks = [ inner-block (with rescue), set_fact ]
        // inner block fails, inner rescue recovers → outer block
        // continues to set_fact.
        let inner = block_node(
            "inner",
            vec![assert_false("inner-fail")],
            vec![set_fact("inner-recover", "inner_rec", "true")],
            vec![],
        );
        let outer = block_node(
            "outer",
            vec![inner, set_fact("after-inner", "outer_continued", "true")],
            vec![],
            vec![],
        );
        let r = drive(&outer).await;
        assert_ok(&r);
        assert_eq!(
            r.ctx.set_facts.get("inner_rec"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            r.ctx.set_facts.get("outer_continued"),
            Some(&serde_json::json!(true))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nested_block_inner_failure_bubbles_when_no_rescue() {
        let inner = block_node("inner", vec![assert_false("inner-fail")], vec![], vec![]);
        let outer = block_node(
            "outer",
            vec![inner, set_fact("after-inner", "outer_continued", "true")],
            vec![],
            vec![],
        );
        let r = drive(&outer).await;
        // Inner fail bubbles through to outer, which has no rescue.
        assert_failed(&r, "assertion failed");
        // The outer's next task (after the failing inner block)
        // should NOT have run.
        assert!(!r.ctx.set_facts.contains_key("outer_continued"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rescue_sees_ansible_failed_task_var() {
        // Rescue uses an `assert: { that: ['ansible_failed_task ==
        // "inner-fail"'] }` to verify the var is exposed during
        // rescue. If the var weren't set, the assert would fail and
        // the overall outcome would be Failed.
        let block = block_node(
            "outer",
            vec![assert_false("inner-fail")],
            vec![plain_task(
                "verify-failed-task",
                TaskBody::Assert(AssertTask {
                    that: vec!["ansible_failed_task == \"inner-fail\"".into()],
                    fail_msg: Some("rescue did not see the right failed task name".into()),
                }),
            )],
            vec![],
        );
        let r = drive(&block).await;
        assert_ok(&r);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rescue_sees_ansible_failed_result_register() {
        // The failing assert task leaves a register-shape result
        // with failed=true and rc=1. Rescue should see it.
        let block = block_node(
            "outer",
            vec![assert_false("inner-fail")],
            vec![plain_task(
                "check-result",
                TaskBody::Assert(AssertTask {
                    that: vec![
                        "ansible_failed_result.failed == true".into(),
                        "ansible_failed_result.rc == 1".into(),
                    ],
                    fail_msg: None,
                }),
            )],
            vec![],
        );
        let r = drive(&block).await;
        assert_ok(&r);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ansible_failed_vars_cleared_after_rescue_ends() {
        // After rescue completes and we move into `always`, the
        // ansible_failed_* vars should be back to their pre-rescue
        // state (None at top level — should be Undefined in templates).
        let block = block_node(
            "outer",
            vec![assert_false("inner-fail")],
            vec![assert_true("recover")],
            vec![plain_task(
                "after-rescue",
                TaskBody::Assert(AssertTask {
                    // minijinja: `is undefined` checks for undefined.
                    that: vec!["ansible_failed_task is undefined".into()],
                    fail_msg: Some("ansible_failed_task leaked past rescue".into()),
                }),
            )],
        );
        let r = drive(&block).await;
        assert_ok(&r);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_ignore_errors_inherited_to_children_skips_rescue() {
        // With ignore_errors:true on the block, the cascade pushes
        // ignore_errors=true into the inner failing task. Its failure
        // is converted to Ok inside run_task_on_one_host, so the
        // block driver never sees a failure → rescue is not invoked.
        // (This matches Ansible's behavior.)
        //
        // We bypass the load() pass here because plain_task() doesn't
        // go through the inheritance pipeline; instead we set
        // ignore_errors directly on the inner child to simulate the
        // post-cascade state.
        let mut inner = assert_false("inner-fail");
        inner.ignore_errors = Some(true);
        let block = block_node(
            "outer",
            vec![inner],
            vec![set_fact("rescue-not-run", "rescue_fired", "true")],
            vec![],
        );
        let r = drive(&block).await;
        assert_ok(&r);
        // Rescue should NOT have fired — the inner failure was
        // ignored at child level.
        assert!(!r.ctx.set_facts.contains_key("rescue_fired"));
    }

    // ---------- run_once inside block ----------

    /// Drive a single task on one host with an explicit coord +
    /// is_runner. Used by tests that exercise run_once-in-block
    /// coordination — the runner test pre-allocates the coord, runs
    /// the task with is_runner=true, then a separate test simulates
    /// the non-runner by pre-filling the same coord's cell.
    async fn drive_with_coord(
        task: &Task,
        ctx: HostCtx,
        coord: RunOnceCoord,
        is_runner: bool,
    ) -> PerHostTaskResult {
        let pool = dead_pool();
        let pools_map: Arc<BTreeMap<String, PoolHandle>> = Arc::new(BTreeMap::new());
        let env = Arc::new(template::make_env());
        let world = WorldVars::empty();
        let seq = Arc::new(AtomicU32::new(1));
        let mut slot_counter: u32 = 0;
        dispatch_one_task(
            task,
            pool,
            pools_map,
            ctx,
            seq,
            env,
            world,
            coord,
            &mut slot_counter,
            is_runner,
        )
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_once_coord_assigns_one_slot_per_task_in_tree() {
        // Block holding 2 tasks + 1 rescue + 1 always. Plus the block
        // task itself. Plus a sibling top-level task. Pre-order DFS
        // total: 1 (block) + 2 (tasks) + 1 (rescue) + 1 (always) + 1
        // (sibling) = 6.
        let block = block_node(
            "outer",
            vec![assert_true("inner1"), assert_true("inner2")],
            vec![assert_true("rescue1")],
            vec![assert_true("always1")],
        );
        let sibling = assert_true("sibling");
        let tasks = vec![block, sibling];
        let coord = RunOnceCoord::allocate(&tasks);
        assert_eq!(coord.cells.len(), 6);
        assert_eq!(coord.subtree_sizes.len(), 6);
        // The block at slot 0 has subtree size 5 (self + 4 inner).
        assert_eq!(coord.subtree_size(0), 5);
        // Inner tasks are leaves: subtree size 1.
        assert_eq!(coord.subtree_size(1), 1);
        assert_eq!(coord.subtree_size(2), 1);
        assert_eq!(coord.subtree_size(3), 1);
        assert_eq!(coord.subtree_size(4), 1);
        // Sibling at slot 5: leaf.
        assert_eq!(coord.subtree_size(5), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_once_inside_block_runner_publishes_to_cell() {
        // A run_once SetFact task inside a block. Running as the
        // designated runner should populate the cell's RunOnceResult
        // with the set_facts the task produced.
        let mut inner = set_fact("inner-runonce", "marker", "true");
        inner.run_once = true;
        let block = block_node("outer", vec![inner], vec![], vec![]);
        let coord = RunOnceCoord::allocate(std::slice::from_ref(&block));
        // The inner run_once task is at slot 1 (block at 0, inner at 1).
        let cell = coord.cell(1).expect("inner slot exists");
        let r = drive_with_coord(
            &block,
            HostCtx::new("runner".into()),
            coord,
            /*is_runner=*/ true,
        )
        .await;
        assert_ok(&r);
        // Cell got populated with the runner's set_facts.
        let published = cell.cell.get().expect("cell published");
        assert!(published.success);
        assert_eq!(
            published.set_facts.get("marker"),
            Some(&JsonValue::Bool(true))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_once_inside_block_non_runner_inherits_set_facts() {
        // Pre-populate the cell with a "runner-published" result, then
        // run the same block on a non-runner host. The non-runner
        // should NOT execute the inner body (set_fact would otherwise
        // run regardless of is_runner), but should pick up the set_fact
        // from the broadcast.
        let mut inner = set_fact("inner-runonce", "from_runner", "\"runner-value\"");
        inner.run_once = true;
        let block = block_node("outer", vec![inner.clone()], vec![], vec![]);
        let coord = RunOnceCoord::allocate(std::slice::from_ref(&block));
        // Pre-fill slot 1 with a synthetic runner result that carries
        // a different value — proving the non-runner used the cell's
        // value rather than re-executing the body.
        let mut synthetic_set_facts = BTreeMap::new();
        synthetic_set_facts.insert(
            "from_runner".into(),
            JsonValue::String("from-cell".into()),
        );
        let cell = coord.cell(1).expect("inner slot");
        cell.publish(RunOnceResult {
            register: None,
            set_facts: synthetic_set_facts,
            success: true,
            outcome: HostTaskOutcome::Ok {
                changed: true,
                skipped: false,
            },
        });

        let r = drive_with_coord(
            &block,
            HostCtx::new("nonrunner".into()),
            coord,
            /*is_runner=*/ false,
        )
        .await;
        assert_ok(&r);
        // The non-runner picked up the cell's value, NOT what the
        // body would have set ("runner-value").
        assert_eq!(
            r.ctx.set_facts.get("from_runner"),
            Some(&JsonValue::String("from-cell".into()))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_once_inside_block_non_runner_propagates_failure_to_rescue() {
        // The runner's body failed. A non-runner host should see
        // Failed via the cell broadcast and the block's rescue arm
        // should fire — same as if the non-runner had executed and
        // failed locally.
        let mut inner = assert_false("inner-runonce");
        inner.run_once = true;
        let block = block_node(
            "outer",
            vec![inner.clone()],
            vec![set_fact("rescue-ran", "rescue_fired", "true")],
            vec![],
        );
        let coord = RunOnceCoord::allocate(std::slice::from_ref(&block));
        // Pre-fill slot 1 with a Failed runner result.
        let cell = coord.cell(1).expect("inner slot");
        cell.publish(RunOnceResult {
            register: None,
            set_facts: BTreeMap::new(),
            success: false,
            outcome: HostTaskOutcome::Failed {
                reason: "synthetic runner failure".into(),
                register: None,
            },
        });

        let r = drive_with_coord(
            &block,
            HostCtx::new("nonrunner".into()),
            coord,
            /*is_runner=*/ false,
        )
        .await;
        // The block recovered via the rescue arm, so the overall
        // outcome is Ok.
        assert_ok(&r);
        // Rescue task fired, set_fact landed in ctx.
        assert_eq!(
            r.ctx.set_facts.get("rescue_fired"),
            Some(&JsonValue::Bool(true))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_once_slot_counter_advances_past_skipped_block() {
        // A block with `when: false` should not be entered, but its
        // subtree slots must still be consumed so a sibling task on
        // the same host lands on the same slot index as on a host
        // that walked the full subtree. We check this by reading the
        // counter after dispatching a block-then-sibling pair.
        let mut block = block_node(
            "outer-skipped",
            vec![assert_true("inner1"), assert_true("inner2")],
            vec![],
            vec![],
        );
        block.when = Some("false".into());
        let sibling = assert_true("sibling");
        let tasks = vec![block, sibling];
        let coord = RunOnceCoord::allocate(&tasks);
        // Block subtree (slot 0 + 2 inners) = 3 slots; sibling at slot 3.
        assert_eq!(coord.subtree_size(0), 3);

        let mut slot_counter: u32 = 0;
        let pool = dead_pool();
        let pools_map: Arc<BTreeMap<String, PoolHandle>> = Arc::new(BTreeMap::new());
        let env = Arc::new(template::make_env());
        let world = WorldVars::empty();
        let seq = Arc::new(AtomicU32::new(1));

        // Dispatch the block via dispatch_one_task; the counter must
        // jump from 0 to 3 even though `when: false` short-circuited
        // before recursing into block.tasks.
        let _ = dispatch_one_task(
            &tasks[0],
            pool,
            pools_map,
            HostCtx::new("h".into()),
            seq,
            env,
            world,
            coord.clone(),
            &mut slot_counter,
            /*is_runner=*/ true,
        )
        .await;
        assert_eq!(slot_counter, 3, "skipped block must consume its subtree");
    }

    // ---------- retries: / until: / delay: matrix ----------

    fn fail_task(name: &str, msg: &str) -> Task {
        plain_task(
            name,
            TaskBody::Fail(FailTask { msg: msg.into() }),
        )
    }

    /// Drive a task with a pre-built `HostCtx` so tests can preload
    /// host vars (used by the templating tests for retries/delay).
    async fn drive_with_ctx(task: &Task, ctx: HostCtx) -> PerHostTaskResult {
        let pool = dead_pool();
        let pools_map: Arc<BTreeMap<String, PoolHandle>> = Arc::new(BTreeMap::new());
        let env = Arc::new(template::make_env());
        let world = WorldVars::empty();
        let seq = Arc::new(AtomicU32::new(1));
        let coord = RunOnceCoord::allocate(std::slice::from_ref(task));
        let mut slot_counter: u32 = 0;
        dispatch_one_task(
            task,
            pool,
            pools_map,
            ctx,
            seq,
            env,
            world,
            coord,
            &mut slot_counter,
            /*is_runner=*/ true,
        )
        .await
    }

    /// Pull the register a task wrote to its `register:` slot.
    fn registered<'a>(r: &'a PerHostTaskResult, name: &str) -> &'a RegisterValue {
        r.ctx
            .registers
            .get(name)
            .unwrap_or_else(|| panic!("no register named {name:?} on host"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_retry_metadata_runs_once_and_attempts_field_absent() {
        // assert_true succeeds; with no retries metadata it should run
        // exactly once and the register's `attempts` should be 0
        // (i.e. hidden from to_json).
        let mut t = assert_true("once");
        t.register = Some("r".into());
        let r = drive(&t).await;
        assert_ok(&r);
        assert_eq!(registered(&r, "r").attempts, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retries_three_means_four_attempts_total() {
        // Ansible semantics: `retries: 3` = 1 + 3 = 4 total attempts.
        // We use `fail:` which always fails and no `until:`, so the
        // loop runs to exhaustion.
        let mut t = fail_task("always-fail", "boom");
        t.retries = Some("3".into());
        t.delay = Some("0".into());
        let r = drive(&t).await;
        assert_failed(&r, "boom");
        // The Failed outcome carries the failing register; assert its
        // attempts == 4.
        match &r.outcome {
            HostTaskOutcome::Failed { register, .. } => {
                let rv = register.as_ref().expect("fail body provides a register");
                assert_eq!(rv.attempts, 4);
            }
            _ => panic!("expected Failed"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn until_set_but_retries_unset_defaults_to_three_retries() {
        // No `retries:` but `until:` set → Ansible default of 3 retries
        // (4 total attempts). `until: "false"` is never truthy, so the
        // loop exhausts.
        let mut t = fail_task("flaky", "oops");
        t.register = Some("r".into());
        t.until = Some("false".into());
        t.delay = Some("0".into());
        let r = drive(&t).await;
        assert_failed(&r, "oops");
        assert_eq!(registered(&r, "r").attempts, 4);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retry_stops_on_first_success_without_until() {
        // First attempt succeeds → break immediately, no retries
        // consumed. `retries: 5` is the budget but only attempt 1 ran.
        let mut t = assert_true("succeed");
        t.register = Some("r".into());
        t.retries = Some("5".into());
        t.delay = Some("0".into());
        let r = drive(&t).await;
        assert_ok(&r);
        assert_eq!(registered(&r, "r").attempts, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn until_truthy_breaks_loop_even_on_failed_attempt() {
        // `until: "true"` exits immediately after attempt 1, regardless
        // of whether the body succeeded. The task's outcome is the
        // body's outcome (Failed here) — `until` controls retry
        // termination, NOT success/failure classification.
        let mut t = fail_task("fails-but-until-truthy", "nope");
        t.register = Some("r".into());
        t.until = Some("true".into());
        t.retries = Some("5".into());
        t.delay = Some("0".into());
        let r = drive(&t).await;
        assert_failed(&r, "nope");
        match &r.outcome {
            HostTaskOutcome::Failed { register, .. } => {
                assert_eq!(register.as_ref().unwrap().attempts, 1);
            }
            _ => unreachable!(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn until_falsey_with_succeeded_attempt_keeps_retrying_then_fails() {
        // set_fact (always succeeds) + impossible `until` → exhausts the
        // full retry budget. Final outcome is Failed (Ansible parity:
        // retries exhausted without `until:` ever truthy flags the
        // task failed even when the body succeeded each time).
        // `attempts == 1 + retries`.
        let mut t = set_fact("incr", "v", "1");
        t.register = Some("r".into());
        t.until = Some("false".into());
        t.retries = Some("2".into());
        t.delay = Some("0".into());
        let r = drive(&t).await;
        assert_failed(&r, "did not satisfy `until:`");
        assert_eq!(registered(&r, "r").attempts, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ignore_errors_applies_after_retries_exhaust() {
        // Retries should run to exhaustion BEFORE ignore_errors flips
        // the outcome — so we get the full retry budget AND an Ok
        // outcome.
        let mut t = fail_task("ignored-after-retries", "ignored");
        t.register = Some("r".into());
        t.retries = Some("2".into());
        t.delay = Some("0".into());
        t.ignore_errors = Some(true);
        let r = drive(&t).await;
        assert_ok(&r);
        assert_eq!(registered(&r, "r").attempts, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retries_template_renders_from_host_vars() {
        // `retries: "{{ count }}"` resolves to 2 against a host fact,
        // yielding 3 total attempts (1 + 2).
        let mut t = fail_task("templated", "kaboom");
        t.register = Some("r".into());
        t.retries = Some("{{ count }}".into());
        t.delay = Some("0".into());

        let mut ctx = HostCtx::new("h1".into());
        ctx.set_facts.insert("count".into(), serde_json::json!(2));
        let r = drive_with_ctx(&t, ctx).await;
        assert_failed(&r, "kaboom");
        assert_eq!(registered(&r, "r").attempts, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delay_template_renders_from_host_vars() {
        // `delay: "{{ d }}"` rendering — combined with tokio pause, we
        // verify the elapsed virtual time matches the rendered delay.
        // 2 retries × 0.1s = 0.2s of sleep before the third (final)
        // attempt completes.
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let mut t = fail_task("timed", "tick");
        t.retries = Some("2".into());
        t.delay = Some("{{ d }}".into());
        let mut ctx = HostCtx::new("h1".into());
        ctx.set_facts.insert("d".into(), serde_json::json!(0.1));

        let driver = drive_with_ctx(&t, ctx);
        tokio::pin!(driver);
        // Loop: poll the driver; whenever it parks on a sleep,
        // advance virtual time. This is the standard tokio::time::pause
        // pattern for measuring sleep-based delays without wall-clock
        // dependence.
        let outcome = loop {
            tokio::select! {
                biased;
                r = &mut driver => break r,
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    tokio::time::advance(std::time::Duration::from_millis(50)).await;
                }
            }
        };
        assert_failed(&outcome, "tick");
        let elapsed = started.elapsed();
        // 2 sleeps × 100ms each = 200ms minimum.
        assert!(
            elapsed >= std::time::Duration::from_millis(200),
            "expected >= 200ms virtual elapsed, got {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retries_render_failure_bubbles_as_body_failure() {
        // `retries:` that fails to render (or parse to an int) →
        // surfaces as a single Failed for the task with the render
        // error as the reason. No body dispatch happens.
        let mut t = assert_true("would-have-succeeded");
        t.retries = Some("not a number".into());
        let r = drive(&t).await;
        assert_failed(&r, "retries:");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delay_template_render_failure_bubbles_as_body_failure() {
        let mut t = fail_task("dummy", "x");
        t.retries = Some("2".into());
        t.delay = Some("nan-cake".into());
        let r = drive(&t).await;
        assert_failed(&r, "delay:");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn until_render_failure_bubbles_as_body_failure() {
        // A bogus `until:` Jinja expression surfaces with the until:
        // prefix so users can grep the error back to the task field.
        let mut t = fail_task("u", "x");
        t.register = Some("r".into());
        t.until = Some("this is { not valid jinja".into());
        t.retries = Some("1".into());
        t.delay = Some("0".into());
        let r = drive(&t).await;
        assert_failed(&r, "until:");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn negative_delay_clamps_to_one_second() {
        // delay: -3 → clamped to 1.0s. Use pause+advance to verify
        // we awaited ~1s (between attempts 1 and 2 — only one sleep
        // happens for retries: 1).
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let mut t = fail_task("neg-delay", "x");
        t.retries = Some("1".into());
        t.delay = Some("-3".into());
        let driver = drive(&t);
        tokio::pin!(driver);
        let outcome = loop {
            tokio::select! {
                biased;
                r = &mut driver => break r,
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    tokio::time::advance(std::time::Duration::from_millis(100)).await;
                }
            }
        };
        assert_failed(&outcome, "x");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(1000),
            "expected >= 1000ms virtual elapsed (clamp), got {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn looped_task_gets_per_iteration_retry_budget() {
        // 3 loop items × (1 + retries:1) = 6 total body invocations.
        // The aggregate register's `results` array should have 3
        // entries, each with attempts == 2.
        let mut t = fail_task("loop-with-retry", "boom on item {{ item }}");
        t.register = Some("agg".into());
        t.retries = Some("1".into());
        t.delay = Some("0".into());
        t.loop_spec = Some(LoopSpec::Items(vec![
            serde_yaml::Value::String("a".into()),
            serde_yaml::Value::String("b".into()),
            serde_yaml::Value::String("c".into()),
        ]));
        let r = drive(&t).await;
        // Outcome is Failed (every iteration failed); the looped path
        // surfaces an aggregate register on the Failed outcome.
        match &r.outcome {
            HostTaskOutcome::Failed { register, .. } => {
                let agg = register.as_ref().expect("loop failure carries aggregate register");
                let results = agg.results.as_ref().expect("loop produces results array");
                assert_eq!(results.len(), 3, "one register per loop item");
                for (i, item_rv) in results.iter().enumerate() {
                    assert_eq!(
                        item_rv.attempts, 2,
                        "iter {i} should have run 2 attempts, got {}",
                        item_rv.attempts
                    );
                }
            }
            _ => panic!("expected Failed"),
        }
    }
}
