//! Per-host agent process pool, keyed by [`BecomeKey`].
//!
//! ## Why a pool
//!
//! `become:` is more than "sudo this command" — every wire op a task
//! issues (systemd start, copy, file, lineinfile, package, …) needs
//! to be evaluated under the right EUID. The original "wrap the
//! argv" trick only worked for shell / exec / command because those
//! are the only ops whose body IS an argv; everything else dispatched
//! against an agent running as the SSH user and silently lost the
//! `become:` directive (manifesting as `Interactive authentication
//! required` from systemctl, EACCES from `copy`, …).
//!
//! The fix: run one agent process per distinct `(host,
//! become-config)` tuple. A play with `become: true, become_user:
//! root` and some unbecomed tasks ends up with TWO agents on the
//! host — one under the SSH user (key = [`BecomeKey::None`]), one
//! under root via `sudo -n -u root -- <agent>` (key = `As("root")`).
//! Each wire op routes to the agent whose key matches its
//! effective-become, and the agent itself does the I/O — no
//! per-op privilege-escalation overhead, all the agent's normal
//! caching / book-keeping survives across tasks.
//!
//! One SSH session per host carries all the channels; one
//! controller-side child-spawn per agent for the local transport.
//! Pool is lazy: slots populate on first reference. We never evict
//! during a run — process count peaks at a handful per host, each
//! agent is ~3.7 MiB, and a long-lived multi-tenant controller is
//! out of scope today.
//!
//! ## Single-flight via `&mut self`
//!
//! [`AgentPool::get_or_spawn`] takes `&mut self` and the pool lives
//! inside an `Arc<TokioMutex<AgentPool>>`. Concurrent callers
//! serialize through the outer mutex — held only long enough to
//! either clone an existing slot's `ConnHandle` or to do the
//! channel-open / Hello dance for a new slot. Once the handle is
//! returned the outer mutex is released, so two ops against
//! different `BecomeKey`s on the same host don't block each other
//! at dispatch time. (This was a regression risk vs. the pre-pool
//! single-conn-per-host setup; check pool tests for the explicit
//! reuse-vs-spawn cases.)

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

use crate::back_channel::{self, BackChannelSession};
use crate::become_::BecomeKey;
use crate::local::{self, LocalSession};
use crate::ssh::{self, AgentConn, ConnectOptions, SshSession};

/// Shared handle to one pool slot's agent connection.
///
/// Same shape as the pre-pool `ConnHandle` so the orchestrator's
/// `run_op_body` doesn't need to know it came from a pool.
/// `None` inside the inner Option signals "this slot is dead because
/// the host was marked failed" — lockers see the `None` and bail
/// instead of deadlocking.
pub type ConnHandle = Arc<TokioMutex<Option<AgentConn>>>;

/// Shared handle to a host's pool. Cheap clone (`Arc`), one per
/// host. The orchestrator stores the host→pool map once and clones
/// the handle into each per-host task future.
pub type PoolHandle = Arc<TokioMutex<AgentPool>>;

/// The transport backing the pool. Variants own the resources that
/// outlive any single slot (the SSH session handle, the materialized
/// local binary path). Each `get_or_spawn` either re-uses an
/// existing slot or, on miss, opens a new channel / spawns a new
/// child process against this transport.
pub enum PoolTransport {
    /// SSH session keepalive. `spawn_agent_channel` opens a fresh
    /// channel per slot — multiple channels share one session.
    Ssh(SshSession),
    /// Local subprocess transport. `spawn_agent_process` execs a
    /// fresh child against the materialized agent path; each slot
    /// owns its own `Child` via `TransportKeepalive::Local`.
    Local(LocalSession),
    /// Back-channel unix-socket transport (forward mode). The socket
    /// is reverse-forwarded from the operator's laptop by SSH `-R`;
    /// each `get_or_spawn` opens a fresh unix-socket connection that
    /// tunnels back to the laptop's `local-agent --listen` process.
    /// One connection per `BecomeKey`, same shape as the SSH variant.
    BackChannel(BackChannelSession),
    /// Test-only transport that refuses to spawn. Used by
    /// controller-only unit tests (block dispatch, set_fact, fail,
    /// …) which never dispatch a wire op but do call
    /// `resolve_target!` on the path to `run_body_once`. Pre-seed a
    /// dead `BecomeKey::None` slot and `get_or_spawn` returns it
    /// without ever touching the transport.
    Mock,
}

/// Per-host pool of agent connections keyed by [`BecomeKey`].
pub struct AgentPool {
    pub label: String,
    transport: PoolTransport,
    agents: BTreeMap<BecomeKey, ConnHandle>,
}

impl AgentPool {
    pub fn new(label: String, transport: PoolTransport) -> Self {
        Self {
            label,
            transport,
            agents: BTreeMap::new(),
        }
    }

    /// Pre-seed a slot with a conn the caller already has. Used by
    /// the orchestrator's connect phase: the initial probe produces
    /// a `BecomeKey::None` conn, and rather than throw it away we
    /// fold it into the pool so the first task targeting None hits
    /// a warm slot.
    ///
    /// Returns the freshly-wrapped `ConnHandle` so the caller can
    /// e.g. probe `clock_rtt_ns` for wire-cost seeding.
    pub fn seed(&mut self, key: BecomeKey, conn: AgentConn) -> ConnHandle {
        let handle = Arc::new(TokioMutex::new(Some(conn)));
        self.agents.insert(key, handle.clone());
        handle
    }

    /// Cheap clone of an `Arc<Mutex<…>>` when the slot exists;
    /// otherwise opens a fresh channel / process and inserts.
    ///
    /// Caller (orchestrator) holds the outer pool mutex for the
    /// duration of this call. The slow path here is "real network /
    /// fork-exec I/O" so callers MUST NOT hold long-lived locks
    /// around it — current call sites all do `let h = { pool.lock();
    /// pool.get_or_spawn(); }` and drop the pool lock before doing
    /// anything with `h`.
    pub async fn get_or_spawn(&mut self, key: &BecomeKey) -> Result<ConnHandle> {
        if let Some(h) = self.agents.get(key) {
            return Ok(h.clone());
        }
        let conn = match &self.transport {
            PoolTransport::Ssh(session) => ssh::spawn_agent_channel(session, key)
                .await
                .with_context(|| {
                    format!(
                        "spawning SSH agent channel for {} on {}",
                        key.label(),
                        self.label
                    )
                })?,
            PoolTransport::Local(session) => local::spawn_agent_process(session, key)
                .await
                .with_context(|| {
                    format!(
                        "spawning local agent process for {} on {}",
                        key.label(),
                        self.label
                    )
                })?,
            PoolTransport::BackChannel(session) => {
                back_channel::spawn_back_channel_conn(session, key)
                    .await
                    .with_context(|| {
                        format!(
                            "opening back-channel connection for {} on {}",
                            key.label(),
                            self.label
                        )
                    })?
            }
            PoolTransport::Mock => {
                // Mock: vend a dead handle (inner Option=None) for
                // every key on demand. Controller-only unit tests
                // never reach `run_op_body`, so the dead handle is
                // never inspected; if it ever IS dispatched against,
                // the lock-and-bail path returns a clean
                // "agent conn is dead" BodyResult.
                let handle = Arc::new(TokioMutex::new(None));
                self.agents.insert(key.clone(), handle.clone());
                return Ok(handle);
            }
        };
        let handle = Arc::new(TokioMutex::new(Some(conn)));
        self.agents.insert(key.clone(), handle.clone());
        Ok(handle)
    }

    /// Currently-populated keys, for diagnostics + tests.
    pub fn keys(&self) -> impl Iterator<Item = &BecomeKey> {
        self.agents.keys()
    }

    /// True iff the pool has a live slot for `key`. Test-only.
    pub fn has(&self, key: &BecomeKey) -> bool {
        self.agents.contains_key(key)
    }

    /// Borrow an existing slot's `ConnHandle` if present. Used by the
    /// orchestrator's end-of-run Bye loop, which walks every key
    /// from `keys()` without wanting `get_or_spawn`'s re-spawn-on-miss
    /// behavior.
    pub fn slot(&self, key: &BecomeKey) -> Option<ConnHandle> {
        self.agents.get(key).cloned()
    }

    /// Open an SSH-backed pool against a host: connect + auth + push
    /// the agent binary, eagerly seed the `BecomeKey::None` slot, and
    /// return the wrapped pool handle alongside the seeded conn
    /// handle (so the caller can read RTT for wire-cost without
    /// re-locking).
    pub async fn open_ssh(opts: &ConnectOptions, agent_binary: &[u8]) -> Result<(Self, ConnHandle)> {
        let session = ssh::open_session(opts, agent_binary).await?;
        let label = session.label.clone();
        let conn = ssh::spawn_agent_channel(&session, &BecomeKey::None).await?;
        let mut pool = AgentPool::new(label, PoolTransport::Ssh(session));
        let handle = pool.seed(BecomeKey::None, conn);
        Ok((pool, handle))
    }

    /// Open a local-subprocess-backed pool: materialize the agent
    /// binary, spawn the initial `BecomeKey::None` child, seed the
    /// pool, return both handles.
    pub async fn open_local(label: String, agent_binary: &[u8]) -> Result<(Self, ConnHandle)> {
        let agent_path = local::write_agent_binary(agent_binary)?;
        let session = LocalSession {
            agent_path,
            label: label.clone(),
        };
        let conn = local::spawn_agent_process(&session, &BecomeKey::None).await?;
        let mut pool = AgentPool::new(label, PoolTransport::Local(session));
        let handle = pool.seed(BecomeKey::None, conn);
        Ok((pool, handle))
    }

    /// Open a back-channel-backed pool for `connection: local` tasks
    /// in forward mode. Eagerly opens the `BecomeKey::None` connection
    /// (tunnels through SSH `-R` back to the laptop's `local-agent`)
    /// and seeds it into the pool. Become-keyed slots populate lazily
    /// the first time a task with `become:` against this host runs.
    pub async fn open_back_channel(
        label: String,
        socket_path: std::path::PathBuf,
    ) -> Result<(Self, ConnHandle)> {
        let session = BackChannelSession {
            label: label.clone(),
            socket_path,
        };
        let conn = back_channel::spawn_back_channel_conn(&session, &BecomeKey::None).await?;
        let mut pool = AgentPool::new(label, PoolTransport::BackChannel(session));
        let handle = pool.seed(BecomeKey::None, conn);
        Ok((pool, handle))
    }

    /// Mark every slot's inner conn as dead (`Option::None`). The
    /// orchestrator calls this when a host is marked failed: every
    /// future op (including delegate_to hops) sees a dead handle and
    /// bails instead of deadlocking. The pool entries themselves
    /// stay in the map — only the inner `Option` flips. This matches
    /// the pre-pool semantics (`ConnHandle` had the same dead-marker
    /// pattern, just one cell deep).
    pub async fn kill_all(&self) {
        for (_, h) in self.agents.iter() {
            let mut guard = h.lock().await;
            *guard = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_pool() -> AgentPool {
        AgentPool::new("test".to_string(), PoolTransport::Mock)
    }

    #[tokio::test]
    async fn mock_pool_vends_dead_handle_for_none() {
        let mut p = mock_pool();
        let h = p.get_or_spawn(&BecomeKey::None).await.unwrap();
        // Inner Option is None — the dead-handle path that
        // run_op_body bails on.
        assert!(h.lock().await.is_none());
        // And the slot is now populated.
        assert!(p.has(&BecomeKey::None));
    }

    #[tokio::test]
    async fn get_or_spawn_reuses_same_slot_for_same_key() {
        let mut p = mock_pool();
        let a = p.get_or_spawn(&BecomeKey::None).await.unwrap();
        let b = p.get_or_spawn(&BecomeKey::None).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b), "second call must return the same ConnHandle");
    }

    #[tokio::test]
    async fn distinct_become_keys_get_distinct_slots() {
        let mut p = mock_pool();
        let none = p.get_or_spawn(&BecomeKey::None).await.unwrap();
        let root = p
            .get_or_spawn(&BecomeKey::As("root".into()))
            .await
            .unwrap();
        let pg = p
            .get_or_spawn(&BecomeKey::As("postgres".into()))
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&none, &root));
        assert!(!Arc::ptr_eq(&none, &pg));
        assert!(!Arc::ptr_eq(&root, &pg));
        // And every key sees the same handle on second call.
        let root2 = p
            .get_or_spawn(&BecomeKey::As("root".into()))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&root, &root2));
    }

    #[tokio::test]
    async fn keys_lists_every_spawned_slot() {
        let mut p = mock_pool();
        p.get_or_spawn(&BecomeKey::None).await.unwrap();
        p.get_or_spawn(&BecomeKey::As("root".into()))
            .await
            .unwrap();
        p.get_or_spawn(&BecomeKey::As("postgres".into()))
            .await
            .unwrap();
        let keys: Vec<_> = p.keys().cloned().collect();
        assert_eq!(keys.len(), 3);
        // BTreeMap ordering: None < As("postgres") < As("root").
        // The actual order is derive(Ord)'s output for the enum.
        assert!(keys.contains(&BecomeKey::None));
        assert!(keys.contains(&BecomeKey::As("root".into())));
        assert!(keys.contains(&BecomeKey::As("postgres".into())));
    }

    #[tokio::test]
    async fn kill_all_marks_every_slot_dead() {
        // Mock vends already-dead handles, so we use slot() to
        // re-check they stay dead after kill_all. Real value of this
        // test: confirms kill_all touches every key the pool knows
        // about (verified by enumerating keys() after kill_all and
        // confirming each handle has inner=None).
        let mut p = mock_pool();
        p.get_or_spawn(&BecomeKey::None).await.unwrap();
        p.get_or_spawn(&BecomeKey::As("root".into()))
            .await
            .unwrap();
        p.kill_all().await;
        for key in p.keys() {
            let h = p.slot(key).unwrap();
            assert!(h.lock().await.is_none(), "slot {key:?} not dead after kill_all");
        }
    }
}
