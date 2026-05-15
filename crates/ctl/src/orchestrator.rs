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
use tokio::sync::{Mutex as TokioMutex, OnceCell, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::become_;
use crate::exec_ctx::{build_template_ctx, yaml_to_json, HostCtx, RegisterValue, WorldVars};
use crate::inventory::{Host, Inventory, InventoryVars};
use crate::playbook::{
    AptOp, AssertTask, BlockInFileOp, CopyOp, ExecOp, FailTask, FileOp, HostSelector,
    LineInFileOp, LoopSpec, MetaAction, OnFailure, Play, Playbook, SetFactMap, ShellOp, StatOp,
    Strategy, SystemdOp, Task, TaskBody, TaskOp, WaitForOp, WriteFileOp,
};
use crate::ssh::{self, AgentConn, ConnectOptions};
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
        }
    }
}

/// The final outcome of a run.
#[derive(Debug)]
pub struct RunReport {
    pub host_outcomes: BTreeMap<String, HostOutcome>,
    pub stopped_early: bool,
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
    } = spec;

    // Build the per-host inventory_vars views + the shared WorldVars
    // once at startup. Both are stable for the run.
    let world = Arc::new(build_world_vars(&inventory, &inventory_vars));

    let target_hosts = compute_all_targeted_hosts(&playbook, &inventory);

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

    // Connect phase — parallel-bounded.
    let mut conns_raw: BTreeMap<String, AgentConn> = BTreeMap::new();
    let semaphore = Arc::new(Semaphore::new(max_concurrent_hosts.max(1)));
    let mut set: JoinSet<(String, Result<AgentConn>)> = JoinSet::new();
    for name in &target_hosts {
        let host = inventory
            .hosts
            .get(name)
            .cloned()
            .expect("target host was resolved from inventory");
        let bin = agent_binary.clone();
        let sem = semaphore.clone();
        let name_owned = name.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");
            let opts = ConnectOptions::from_host(&host);
            let r = ssh::connect_and_push(&opts, &bin)
                .await
                .with_context(|| format!("connecting to {name_owned}"));
            (name_owned, r)
        });
    }
    while let Some(joined) = set.join_next().await {
        let (name, r) = joined.context("connect task panicked")?;
        match r {
            Ok(c) => {
                info!(host = %name, "connected");
                conns_raw.insert(name, c);
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

    // Wrap each AgentConn in Arc<Mutex<Option<…>>> so any task future can
    // borrow any host's conn for `delegate_to`. The map itself never
    // mutates after this point; liveness lives in the inner Option.
    let conns: Arc<BTreeMap<String, ConnHandle>> = Arc::new(
        conns_raw
            .into_iter()
            .map(|(n, c)| (n, Arc::new(TokioMutex::new(Some(c)))))
            .collect(),
    );

    // Build per-host execution contexts. Lives across the whole run so
    // set_facts and registers persist across plays (Ansible-faithful).
    let mut ctxs: BTreeMap<String, HostCtx> = BTreeMap::new();
    for name in conns.keys() {
        let host = inventory.hosts.get(name).expect("conn host in inventory");
        ctxs.insert(
            name.clone(),
            make_initial_ctx(name, host, &world, &extra_vars),
        );
    }

    let mut report = RunReport {
        host_outcomes: outcomes,
        stopped_early: false,
    };

    let next_seq = Arc::new(AtomicU32::new(1));
    let env = Arc::new(template::make_env());

    'plays: for play in &playbook.plays {
        // Live-host filter: hosts that connected AND haven't been marked
        // failed under a prior play's mark_host_failed/stop policy.
        let play_targets: Vec<String> = resolve_play_targets(&play.hosts, &inventory)
            .into_iter()
            .filter(|n| {
                conns.contains_key(n)
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
            &conns,
            &mut ctxs,
            &mut report,
            &next_seq,
            &env,
            &world_for_play,
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
                    &conns,
                    &mut ctxs,
                    &mut report,
                    &next_seq,
                    &env,
                    &world_for_play,
                )
                .await?
            }
            Strategy::PerPlay => {
                run_play_per_play(
                    play,
                    &play_targets,
                    &conns,
                    &mut ctxs,
                    &mut report,
                    &next_seq,
                    &env,
                    &world_for_play,
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

    // Best-effort Bye. Iterate the map; lock each handle, take the conn
    // out, send Bye, drop. Hosts whose conn was dropped earlier (failed
    // under mark_host_failed) have inner = None and are skipped.
    for (name, handle) in conns.iter() {
        let mut guard = handle.lock().await;
        if let Some(mut conn) = guard.take() {
            if let Err(e) = write_frame(&mut conn.stream, &bye()).await {
                warn!(host = %name, "Bye send failed: {e:#}");
            } else {
                debug!(host = %name, "Bye sent");
            }
        }
    }

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
        tags: Vec::new(),
        delegate_to: None,
        run_once: false,
        notify: Vec::new(),
        role_dir: None,
        // Fact-gathering must always run as whoever the agent was
        // launched as — never sudo-wrapped (the agent runs the helper
        // in-process). Explicit `Some(false)` so a play-level
        // `become: true` doesn't accidentally wrap it.
        become_: Some(false),
        become_user: None,
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
    conns: &Arc<BTreeMap<String, ConnHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
) -> Result<()> {
    if !play.gather_facts {
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
    let task = make_gather_facts_task();
    let mut set: JoinSet<PerHostTaskResult> = JoinSet::new();
    for name in &live {
        let own_conn = conns.get(name).expect("live host has handle").clone();
        let ctx = ctxs
            .remove(name)
            .unwrap_or_else(|| HostCtx::new(name.clone()));
        let task = task.clone();
        let seq_src = next_seq.clone();
        let env = env.clone();
        let world = world.clone();
        let conns_for = conns.clone();
        set.spawn(async move {
            run_task_on_one_host(&task, own_conn, conns_for, ctx, seq_src, env, world).await
        });
    }
    while let Some(joined) = set.join_next().await {
        let mut r = joined.context("gather_facts task panicked")?;
        // Drain the transient register; user code never sees it.
        let reg = r.ctx.registers.remove(GATHER_FACTS_REGISTER);
        match &r.outcome {
            HostTaskOutcome::Ok => {
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
            HostTaskOutcome::Failed { reason } => {
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
    conns: &Arc<BTreeMap<String, ConnHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
) -> Result<bool> {
    for task in &play.tasks {
        // `meta: flush_handlers` is not dispatched to hosts — it's a
        // control-flow marker that drains the per-host pending queue.
        if let TaskBody::Meta(MetaAction::FlushHandlers) = &task.body {
            let stop =
                flush_handlers(play, targets, conns, ctxs, report, next_seq, env, world).await?;
            if stop {
                return Ok(true);
            }
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
            run_task_once_per_task(task, &live, conns, ctxs, report, next_seq, env, world, play)
                .await?
        } else {
            run_task_fanout(task, &live, conns, ctxs, report, next_seq, env, world, play).await?
        };

        if any_failed && play.on_failure == OnFailure::Stop {
            return Ok(true);
        }
    }
    // Implicit end-of-play flush.
    let stop = flush_handlers(play, targets, conns, ctxs, report, next_seq, env, world).await?;
    Ok(stop)
}

/// Fan a task out across every live host, in parallel.
async fn run_task_fanout(
    task: &Task,
    live: &[String],
    conns: &Arc<BTreeMap<String, ConnHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
    play: &Play,
) -> Result<bool> {
    let mut set: JoinSet<PerHostTaskResult> = JoinSet::new();
    for name in live {
        let own_conn = conns.get(name).expect("live host has handle").clone();
        let ctx = ctxs
            .remove(name)
            .unwrap_or_else(|| HostCtx::new(name.clone()));
        let task = task.clone();
        let seq_src = next_seq.clone();
        let env = env.clone();
        let world = world.clone();
        let conns_for = conns.clone();
        set.spawn(async move {
            run_task_on_one_host(&task, own_conn, conns_for, ctx, seq_src, env, world).await
        });
    }
    let mut any_failed = false;
    while let Some(joined) = set.join_next().await {
        let r = joined.context("per-host task panicked")?;
        let host_failed = apply_per_host_result(play, task, r, conns, ctxs, report).await;
        any_failed = any_failed || host_failed;
    }
    Ok(any_failed)
}

/// run_once under per_task: pick one runner, execute, broadcast result to
/// every other live host's ctx.
async fn run_task_once_per_task(
    task: &Task,
    live: &[String],
    conns: &Arc<BTreeMap<String, ConnHandle>>,
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

    let own_conn = conns.get(&runner).expect("runner has handle").clone();
    let ctx = ctxs
        .remove(&runner)
        .unwrap_or_else(|| HostCtx::new(runner.clone()));
    let result = run_task_on_one_host(
        task,
        own_conn,
        conns.clone(),
        ctx,
        next_seq.clone(),
        env.clone(),
        world.clone(),
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
    let notify_fired = matches!(result.outcome, HostTaskOutcome::Ok)
        && !task.notify.is_empty()
        && register_for_broadcast
            .as_ref()
            .map(|r| r.changed)
            .unwrap_or(true);

    let runner_failed = apply_per_host_result(play, task, result, conns, ctxs, report).await;
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
    conns: &Arc<BTreeMap<String, ConnHandle>>,
    ctxs: &mut BTreeMap<String, HostCtx>,
    report: &mut RunReport,
    next_seq: &Arc<AtomicU32>,
    env: &Arc<Environment<'static>>,
    world: &Arc<WorldVars>,
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

    // One OnceCell per task in the play, shared across all per-host
    // futures. run_once-flagged tasks use these to coordinate: the first
    // arrival fills the cell with the runner's RegisterValue (and a
    // changed flag); the others await it and write the value into their
    // own ctx without re-running the body.
    let oncecells: Arc<Vec<Arc<OnceCell<RunOnceResult>>>> = Arc::new(
        play.tasks
            .iter()
            .map(|_| Arc::new(OnceCell::new()))
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
        let world = world.clone();
        let conns_for = conns.clone();
        let own_conn = conns.get(name).expect("live host has handle").clone();
        let ctx = ctxs
            .remove(name)
            .unwrap_or_else(|| HostCtx::new(name.clone()));
        let oncecells = oncecells.clone();
        let name_owned = name.clone();
        let handlers = handlers.clone();
        let live_names = live.clone();
        set.spawn(async move {
            let mut ctx = ctx;
            let mut first_failure: Option<(String, String)> = None;
            for (i, task) in tasks.iter().enumerate() {
                // Meta tasks: flush handlers inline.
                if let TaskBody::Meta(MetaAction::FlushHandlers) = &task.body {
                    let stop_handler_failure = run_handlers_one_host(
                        &handlers,
                        own_conn.clone(),
                        conns_for.clone(),
                        &mut ctx,
                        seq_src.clone(),
                        env.clone(),
                        world.clone(),
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

                let r: PerHostTaskResult;
                if task.run_once {
                    // The first live host (inventory order) is the runner;
                    // every other host waits for the runner's result.
                    let cell = oncecells[i].clone();
                    let is_runner = name_owned == live_names[0];
                    if is_runner {
                        let ran = run_task_on_one_host(
                            task,
                            own_conn.clone(),
                            conns_for.clone(),
                            ctx,
                            seq_src.clone(),
                            env.clone(),
                            world.clone(),
                        )
                        .await;
                        let register_val = task
                            .register
                            .as_ref()
                            .and_then(|n| ran.ctx.registers.get(n).cloned());
                        let set_facts_snap: BTreeMap<String, JsonValue> = match &task.body {
                            TaskBody::SetFact(_) => ran.ctx.set_facts.clone(),
                            _ => BTreeMap::new(),
                        };
                        let success = matches!(ran.outcome, HostTaskOutcome::Ok);
                        let _ = cell.set(RunOnceResult {
                            register: register_val,
                            set_facts: set_facts_snap,
                            success,
                            outcome: clone_outcome(&ran.outcome),
                        });
                        r = ran;
                    } else {
                        // Wait until the runner publishes its result.
                        let waited = cell
                            .get_or_init(|| async {
                                // We're not the runner; just wait forever
                                // for the runner to set the cell.
                                std::future::pending::<RunOnceResult>().await
                            })
                            .await;
                        // Apply broadcast effects.
                        if let (Some(name), Some(rv)) =
                            (task.register.as_ref(), waited.register.as_ref())
                        {
                            ctx.registers.insert(name.clone(), rv.clone());
                        }
                        if matches!(&task.body, TaskBody::SetFact(_)) && waited.success {
                            for (k, v) in &waited.set_facts {
                                ctx.set_facts.insert(k.clone(), v.clone());
                            }
                        }
                        if waited.success
                            && !task.notify.is_empty()
                            && waited.register.as_ref().map(|r| r.changed).unwrap_or(true)
                        {
                            for n in &task.notify {
                                let rendered =
                                    match render_str(&env, n, &build_template_ctx(&ctx, &world)) {
                                        Ok(s) => s,
                                        Err(_) => n.clone(),
                                    };
                                ctx.pending_handlers.insert(rendered);
                            }
                        }
                        // Build a synthetic per-host result so the
                        // per-play loop's bookkeeping stays uniform.
                        r = PerHostTaskResult {
                            name: name_owned.clone(),
                            ctx,
                            outcome: clone_outcome(&waited.outcome),
                            conn_alive: true,
                        };
                        ctx = r.ctx;
                        match &r.outcome {
                            HostTaskOutcome::Ok | HostTaskOutcome::Skipped => {}
                            HostTaskOutcome::Failed { reason } => {
                                if first_failure.is_none() {
                                    first_failure = Some((task.name.clone(), reason.clone()));
                                }
                                if matches!(on_failure, OnFailure::Stop | OnFailure::MarkHostFailed)
                                {
                                    break;
                                }
                            }
                        }
                        info!(host = %name_owned, play = %play_name, task = %task.name, "task done (inherited from run_once runner)");
                        continue;
                    }
                } else {
                    r = run_task_on_one_host(
                        task,
                        own_conn.clone(),
                        conns_for.clone(),
                        ctx,
                        seq_src.clone(),
                        env.clone(),
                        world.clone(),
                    )
                    .await;
                }
                ctx = r.ctx;
                match &r.outcome {
                    HostTaskOutcome::Ok | HostTaskOutcome::Skipped => {}
                    HostTaskOutcome::Failed { reason } => {
                        if first_failure.is_none() {
                            first_failure = Some((task.name.clone(), reason.clone()));
                        }
                        if matches!(on_failure, OnFailure::Stop | OnFailure::MarkHostFailed) {
                            break;
                        }
                    }
                }
                if !r.conn_alive {
                    // Conn died; mark inner None and stop this host's loop.
                    let mut guard = own_conn.lock().await;
                    *guard = None;
                    drop(guard);
                    break;
                }
                info!(host = %name_owned, play = %play_name, task = %task.name, "task done");
            }
            // End-of-play implicit flush for this host (only if not already
            // bailed under a fatal on_failure).
            if first_failure.is_none()
                || matches!(on_failure, OnFailure::Continue)
            {
                if let Some((hn, reason)) = run_handlers_one_host(
                    &handlers,
                    own_conn.clone(),
                    conns_for.clone(),
                    &mut ctx,
                    seq_src.clone(),
                    env.clone(),
                    world.clone(),
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
            // Drop the conn under mark_host_failed / stop policies so it
            // doesn't carry into the next play.
            if matches!(on_failure, OnFailure::MarkHostFailed | OnFailure::Stop) {
                if let Some(handle) = conns.get(&r.name) {
                    let mut guard = handle.lock().await;
                    *guard = None;
                    debug!(host = %r.name, "dropping conn (on_failure={:?})", on_failure);
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
        HostTaskOutcome::Ok => HostTaskOutcome::Ok,
        HostTaskOutcome::Skipped => HostTaskOutcome::Skipped,
        HostTaskOutcome::Failed { reason } => HostTaskOutcome::Failed {
            reason: reason.clone(),
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
    Ok,
    Skipped,
    Failed { reason: String },
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
/// `own_conn` is this host's connection handle; if `task.delegate_to` is
/// set and resolves to another host, the body runs against *that* host's
/// handle. Register/set_fact/notify side effects still land on this
/// host's ctx (Ansible semantics).
async fn run_task_on_one_host(
    task: &Task,
    own_conn: ConnHandle,
    conns_map: Arc<BTreeMap<String, ConnHandle>>,
    mut ctx: HostCtx,
    next_seq: Arc<AtomicU32>,
    env: Arc<Environment<'static>>,
    world: Arc<WorldVars>,
) -> PerHostTaskResult {
    let name = ctx.host_name.clone();

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
                outcome: HostTaskOutcome::Failed { reason },
                conn_alive: true,
            };
        }
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

    // Helper to resolve which conn handle the body should run against.
    let resolve_target = |ctx: &HostCtx| -> Result<ConnHandle, String> {
        match &task.delegate_to {
            None => Ok(own_conn.clone()),
            Some(expr) => {
                let view = build_template_ctx(ctx, &world);
                let rendered = render_str(&env, expr, &view)
                    .map_err(|e| format!("delegate_to render: {e:#}"))?;
                conns_map
                    .get(&rendered)
                    .cloned()
                    .ok_or_else(|| format!("delegate_to references unknown host {rendered:?}"))
            }
        }
    };

    let mut own_conn_alive = true;

    if task.loop_spec.is_none() {
        // Single execution.
        let target = match resolve_target(&ctx) {
            Ok(t) => t,
            Err(reason) => {
                return PerHostTaskResult {
                    name,
                    ctx,
                    outcome: HostTaskOutcome::Failed { reason },
                    conn_alive: true,
                };
            }
        };
        let exec = run_body_once(task, &target, &mut ctx, &env, &world, &next_seq).await;
        let outcome = match exec {
            BodyResult::Ok { register, changed } => {
                if let Some(reg_name) = &task.register {
                    ctx.record_register(reg_name, register);
                }
                enqueue_notifies(task, changed, false, &mut ctx, &env, &world);
                HostTaskOutcome::Ok
            }
            BodyResult::Failed { reason, register, conn_alive } => {
                if let Some(reg_name) = &task.register {
                    if let Some(rv) = register {
                        ctx.record_register(reg_name, rv);
                    }
                }
                ctx.failed = true;
                // Conn liveness only flips own_conn_alive when the dead
                // conn IS this host's. A failed delegate hop doesn't kill
                // the originator.
                if !conn_alive && task.delegate_to.is_none() {
                    own_conn_alive = false;
                }
                HostTaskOutcome::Failed { reason }
            }
        };
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
        let target = match resolve_target(&ctx) {
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
        let exec = run_body_once(task, &target, &mut ctx, &env, &world, &next_seq).await;
        match exec {
            BodyResult::Ok { register, changed: _ } => iter_registers.push(register),
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
    let any_iter_failed = iter_registers.iter().any(|r| r.failed);
    let aggregate = RegisterValue {
        changed: any_changed,
        failed: any_iter_failed,
        results: Some(iter_registers),
        ..Default::default()
    };
    if let Some(reg_name) = &task.register {
        ctx.record_register(reg_name, aggregate);
    }
    let outcome = match any_failed {
        None => {
            enqueue_notifies(task, any_changed, false, &mut ctx, &env, &world);
            HostTaskOutcome::Ok
        }
        Some(reason) => {
            ctx.failed = true;
            HostTaskOutcome::Failed { reason }
        }
    };
    PerHostTaskResult {
        name,
        ctx,
        outcome,
        conn_alive: own_conn_alive,
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

/// One execution of a task body (no loop expansion here). Updates `ctx`
/// for controller-side bodies (set_fact); returns the register value for
/// the caller to record under `task.register` if appropriate.
enum BodyResult {
    Ok {
        register: RegisterValue,
        /// Whether the task actually changed state. Used to gate `notify`.
        changed: bool,
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
    }
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
    // Apply `become:` argv wrapping after render (so the wrapping is
    // never templated) and before `to_wire_op` (so the wire op carries
    // the wrapped argv verbatim, with no further string surgery agent-
    // side).
    let eff = become_::effective(task, ctx);
    become_::apply(&mut rendered, &eff);
    let wire_op = match rendered.to_wire_op() {
        Ok(w) => w,
        Err(e) => {
            return BodyResult::Failed {
                reason: format!("to wire op: {e:#}"),
                register: None,
                conn_alive: true,
            };
        }
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
    let result = run_one_task_op(conn, seq, wire_op, capture, clock_offset_ns).await;
    let label = conn.label.clone();
    drop(guard); // release the lock before doing CPU work / waiting on ctx
    let _ = ctx; // ctx isn't mutated here; silence unused-mut

    match result {
        Ok(exec) => {
            let agent_elapsed_ns =
                exec.done.finished_unix_ns.saturating_sub(exec.done.started_unix_ns);
            let took_ms = (agent_elapsed_ns / 1_000_000).min(u64::MAX);
            let mut rv = RegisterValue::from_exec(
                exec.done.exit_code,
                exec.done.changed != 0,
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
            emit_timing_trace(&label, &task.name, seq, &exec);
            if exec.done.exit_code == 0 {
                info!(
                    host = %label,
                    task = %task.name,
                    seq,
                    exit = exec.done.exit_code,
                    changed = exec.done.changed != 0,
                    took_ms,
                    "ok",
                );
                let changed = exec.done.changed != 0;
                BodyResult::Ok {
                    register: rv,
                    changed,
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

fn run_assert_body(
    a: &AssertTask,
    ctx: &HostCtx,
    env: &Environment<'static>,
    world: &WorldVars,
) -> BodyResult {
    let view = build_template_ctx(ctx, world);
    for (i, expr) in a.that.iter().enumerate() {
        match env.compile_expression(expr) {
            Ok(compiled) => match compiled.eval(&view) {
                Ok(v) if v.is_true() => continue,
                Ok(_) => {
                    let reason = a
                        .msg
                        .clone()
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
        TaskOp::WriteFile(w) => {
            let path = render_str(env, &w.path, &view)?;
            let content = render_str(env, &w.content, &view)?;
            TaskOp::WriteFile(WriteFileOp {
                path,
                mode: w.mode,
                content,
            })
        }
        TaskOp::Template(t) => {
            // Desugar `template:` into `OpWriteFile`. The body was loaded
            // and stashed onto the TemplateOp during `playbook::load()`;
            // missing-body here means the template wasn't resolved at
            // load time, which validation should have caught.
            let body = t.body.as_deref().ok_or_else(|| {
                anyhow!(
                    "template src {:?} was not loaded — playbook::load() didn't resolve it (this is a bug; validate should have caught it)",
                    t.src
                )
            })?;
            let dest = render_str(env, &t.dest, &view)?;
            let content = render_str(env, body, &view)?;
            TaskOp::WriteFile(WriteFileOp {
                path: dest,
                mode: t.mode,
                content,
            })
        }
        TaskOp::Copy(c) => {
            // Resolved bytes live on `c.body`; we just render `dest`
            // and keep the variant intact through dispatch. `to_wire_op`
            // emits the actual `OpWriteFile` with the bytes shipped
            // verbatim — going through `TaskOp::WriteFile` here would
            // force a lossy String roundtrip for binary content.
            if c.body.is_none() {
                return Err(anyhow!(
                    "copy src {:?} was not loaded — playbook::load() didn't resolve it (validate should have caught this)",
                    c.src
                ));
            }
            let dest = render_str(env, &c.dest, &view)?;
            TaskOp::Copy(CopyOp {
                src: c.src.clone(),
                dest,
                mode: c.mode,
                body: c.body.clone(),
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
            TaskOp::WaitFor(WaitForOp {
                host,
                port: w.port,
                path,
                state: w.state,
                timeout_ms: w.timeout_ms,
                delay_ms: w.delay_ms,
                sleep_ms: w.sleep_ms,
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
                mode: f.mode,
                owner,
                group,
                recurse: f.recurse,
            })
        }
        TaskOp::LineInFile(l) => {
            let path = render_str(env, &l.path, &view)?;
            let line = render_str(env, &l.line, &view)?;
            TaskOp::LineInFile(LineInFileOp {
                path,
                regexp: l.regexp.clone(),
                line,
                state: l.state,
                mode: l.mode,
                create: l.create,
                insertbefore: l.insertbefore.clone(),
                insertafter: l.insertafter.clone(),
                backrefs: l.backrefs,
            })
        }
        TaskOp::BlockInFile(b) => {
            let path = render_str(env, &b.path, &view)?;
            let block = render_str(env, &b.block, &view)?;
            TaskOp::BlockInFile(BlockInFileOp {
                path,
                block,
                marker: b.marker.clone(),
                marker_begin: b.marker_begin.clone(),
                marker_end: b.marker_end.clone(),
                state: b.state,
                mode: b.mode,
                create: b.create,
                insertbefore: b.insertbefore.clone(),
                insertafter: b.insertafter.clone(),
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
        TaskOp::Apt(a) => {
            let mut names = Vec::with_capacity(a.names.len());
            for n in &a.names {
                names.push(render_str(env, n, &view)?);
            }
            let default_release = if a.default_release.is_empty() {
                String::new()
            } else {
                render_str(env, &a.default_release, &view)?
            };
            TaskOp::Apt(AptOp {
                names,
                state: a.state,
                update_cache: a.update_cache,
                cache_valid_time: a.cache_valid_time,
                purge: a.purge,
                autoremove: a.autoremove,
                default_release,
                allow_unauthenticated: a.allow_unauthenticated,
            })
        }
    })
}

fn render_str(
    env: &Environment<'static>,
    src: &str,
    view: &BTreeMap<String, JsonValue>,
) -> Result<String> {
    let tmpl = env
        .template_from_str(src)
        .map_err(|e| anyhow!("template parse: {e}"))?;
    let out = tmpl
        .render(view)
        .map_err(|e| anyhow!("template render: {e}"))?;
    Ok(out)
}

fn eval_when(
    env: &Environment<'static>,
    expr: Option<&str>,
    ctx: &HostCtx,
    world: &WorldVars,
) -> Result<bool> {
    let Some(expr) = expr else { return Ok(true) };
    let compiled = env
        .compile_expression(expr)
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
        LoopSpec::Items(items) => items
            .iter()
            .cloned()
            .map(yaml_to_json)
            .collect::<Result<Vec<_>>>(),
        LoopSpec::Expr(s) => {
            let view = build_template_ctx(ctx, world);
            // Render as a template, then re-parse the resulting string
            // as JSON-ish. This handles `{{ list }}`, where minijinja
            // renders a Python-style repr; safer is to compile as an
            // expression and convert the resulting Value.
            // We use compile_expression to keep types intact.
            let compiled = env
                .compile_expression(s.trim_start_matches("{{").trim_end_matches("}}").trim())
                .or_else(|_| env.compile_expression(s))
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

fn mjvalue_to_json(v: &minijinja::Value) -> Result<JsonValue> {
    let s = serde_json::to_string(v).map_err(|e| anyhow!("serialize loop value: {e}"))?;
    serde_json::from_str::<JsonValue>(&s).map_err(|e| anyhow!("re-parse loop value: {e}"))
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
async fn run_one_task_op(
    conn: &mut AgentConn,
    seq: u32,
    op: Op,
    capture: bool,
    clock_offset_ns: i64,
) -> Result<OpExecOutcome> {
    let dispatch = task_dispatch(seq, op);
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
    conns: &Arc<BTreeMap<String, ConnHandle>>,
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
    if let HostTaskOutcome::Failed { reason } = &outcome {
        report.host_outcomes.insert(
            name.clone(),
            HostOutcome::Failed {
                task: task.name.clone(),
                reason: reason.clone(),
            },
        );
    }
    // Always reinsert ctx — set_facts/registers should persist even from failed hosts.
    ctxs.insert(name.clone(), ctx);
    // Decide whether to kill this host's conn handle.
    let drop_conn = !conn_alive
        || (failed
            && matches!(
                play.on_failure,
                OnFailure::MarkHostFailed | OnFailure::Stop
            ));
    if drop_conn {
        if let Some(handle) = conns.get(&name) {
            let mut guard = handle.lock().await;
            if guard.is_some() {
                debug!(host = %name, "dropping conn (conn_alive={conn_alive}, on_failure={:?})", play.on_failure);
                *guard = None;
            }
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
    conns: &Arc<BTreeMap<String, ConnHandle>>,
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
            handler, &interested, conns, ctxs, report, next_seq, env, world, play,
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
    own_conn: ConnHandle,
    conns: Arc<BTreeMap<String, ConnHandle>>,
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
        let r = run_task_on_one_host(
            handler,
            own_conn.clone(),
            conns.clone(),
            taken,
            next_seq.clone(),
            env.clone(),
            world.clone(),
        )
        .await;
        *ctx = r.ctx;
        ctx.pending_handlers.remove(&handler.name);
        if let HostTaskOutcome::Failed { reason } = &r.outcome {
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
    // Normalize the bare-string shorthand into a slice we can iterate.
    let single: [String; 1];
    let names: &[String] = match sel {
        HostSelector::All(_) => return inv.hosts.keys().cloned().collect(),
        HostSelector::Names(names) => names.as_slice(),
        HostSelector::Name(n) => {
            single = [n.clone()];
            &single
        }
    };
    let mut out: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    for n in names {
        // Group wins if both names overlap (Ansible's behavior).
        if let Some(members) = inv.groups.get(n) {
            for m in members {
                if seen.insert(m.clone()) {
                    out.push(m.clone());
                }
            }
        } else if inv.hosts.contains_key(n) {
            if seen.insert(n.clone()) {
                out.push(n.clone());
            }
        }
        // Unknown names are caught at validate time. If they slip
        // through, we silently drop them (no panic).
    }
    out
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
            msg: None,
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
            msg: Some("x must be positive".into()),
        };
        let r = run_assert_body(&a, &ctx, &env, &WorldVars::default());
        match r {
            BodyResult::Failed { reason, .. } => assert_eq!(reason, "x must be positive"),
            _ => panic!(),
        }
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
}
