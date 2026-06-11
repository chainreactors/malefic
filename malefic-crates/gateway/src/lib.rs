// malefic-gateway: Unified public API for the malefic framework (Community Edition).
//
// All downstream crates should depend on this crate instead of malefic-macro directly.
// Community mode provides stub implementations for obfuscation APIs.

// --- Community mode: stub implementations ---
pub mod runtime;
pub mod traits;
pub mod secure {}

// Re-export nanorand for generated code paths (always available)
pub use nanorand;

/// Backward-compatible macro namespace:
/// `malefic_gateway::obfstr::obfstr!("...")`
pub mod obfstr {
    pub use malefic_macro::obfstr;
}

// Re-export all proc macros (directly from malefic-macro to avoid namespace conflicts)
pub use malefic_macro::flow;
pub use malefic_macro::include_encrypted;
pub use malefic_macro::junk;
pub use malefic_macro::lazy_static;
pub use malefic_macro::module_impl;
pub use malefic_macro::obf_bytes;
pub use malefic_macro::obf_int;
pub use malefic_macro::obf_stmts;
pub use malefic_macro::obf_string;
pub use malefic_macro::obfstr;
pub use malefic_macro::obfuscate;
pub use malefic_macro::ObfDebug;
pub use malefic_macro::Obfuscate;
pub use malefic_macro::ObfuscateBox;
