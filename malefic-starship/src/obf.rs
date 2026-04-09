//! Bridge macros for compile-time string obfuscation.
//!
//! The `obf_cstr!` macro is defined in `lib.rs` (via `#[macro_export]`) so
//! it is available in every module of the crate without import.
//!
//! When `obf_strings` feature is enabled, strings are AES-encrypted at compile
//! time and decrypted at runtime. When disabled, strings pass through as-is
//! with a `.to_vec()` allocation (negligible for a one-shot loader).
