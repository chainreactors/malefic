//! `malefic-runtime` — Cross-version, cross-target module runtime.
//!
//! This crate defines a pure C ABI protocol for hot-loading module DLLs
//! compiled with different Rust versions or targets. Data crosses the FFI
//! boundary as protobuf-encoded `Spite` messages; no Rust-internal types
//! ever cross the boundary.
//!
//! # Modules
//!
//! - [`abi`] / [`codec`] / [`module_sdk`]: Re-exported from `malefic-module`
//!   (canonical definitions live there). Used by module DLLs to implement
//!   the C ABI protocol via [`register_rt_modules!`].
//! - [`host`] (feature `host`): Host-side bridge that wraps C ABI modules
//!   into standard `Module` trait objects, transparent to the scheduler.
//!   Requires a runtime feature (`tokio` / `async-std` / `smol`).

// Re-export from malefic-module so existing `malefic_runtime::abi::*` paths still work.
pub use malefic_module::abi;
pub use malefic_module::codec;
pub use malefic_module::module_sdk;

// Re-export the registration macro for backward compatibility.
pub use malefic_module::register_rt_modules;

pub mod host;
