//! rsansible controller library.
//!
//! The CLI binary in `src/main.rs` is a thin wrapper over the modules here
//! so integration tests can drive them directly.

#[path = "become_.rs"]
pub mod become_;
pub mod back_channel;
pub mod exec_ctx;
pub mod extra_vars;
pub mod forward;
pub mod forward_bundle;
pub mod forward_push;
pub mod host_pattern;
pub mod inventory;
pub mod limit;
pub mod local;
pub mod local_agent;
pub mod orchestrator;
pub mod playbook;
pub mod pool;
pub mod run_metrics;
pub mod ssh;
pub mod tags;
pub mod template;
pub mod timing;
pub mod vault;
pub mod wire_cost;
pub mod x509;
