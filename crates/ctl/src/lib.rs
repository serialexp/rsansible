//! rsansible controller library.
//!
//! The CLI binary in `src/main.rs` is a thin wrapper over the modules here
//! so integration tests can drive them directly.

pub mod exec_ctx;
pub mod inventory;
pub mod orchestrator;
pub mod playbook;
pub mod ssh;
pub mod template;
pub mod vault;
