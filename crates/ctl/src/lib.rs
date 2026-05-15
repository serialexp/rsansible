//! rsansible controller library.
//!
//! The CLI binary in `src/main.rs` is a thin wrapper over the modules here
//! so integration tests can drive them directly.

#[path = "become_.rs"]
pub mod become_;
pub mod exec_ctx;
pub mod extra_vars;
pub mod host_pattern;
pub mod inventory;
pub mod limit;
pub mod orchestrator;
pub mod playbook;
pub mod ssh;
pub mod tags;
pub mod template;
pub mod vault;
pub mod wire_cost;
