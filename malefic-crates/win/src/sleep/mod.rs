#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod allocator;
pub mod config;
pub mod hypnus;
pub mod types;
pub mod winapis;

pub use allocator::HypnusHeap;
pub use hypnus::{ObfMode, Obfuscation};

/// Obfuscated sleep: encrypts `(base, size)` region during sleep, decrypts after.
///
/// # Arguments
/// - `base`: Pointer to the memory region to protect
/// - `size`: Size of the memory region in bytes
/// - `time`: Delay in seconds
/// - `obf`: Obfuscation strategy (Timer, Wait, or Foliage)
/// - `mode`: Obfuscation mode flags (Rwx, Heap, or both)
pub fn obf_sleep(
    base: *mut core::ffi::c_void,
    size: u64,
    time: u64,
    obf: Obfuscation,
    mode: ObfMode,
) {
    hypnus::__private::hypnus_entry(base, size, time, obf, mode)
}

/// Like [`obf_sleep`] but accepts the delay in **milliseconds** instead of seconds.
///
/// This avoids precision loss when the heartbeat interval has a sub-second component.
pub fn obf_sleep_ms(
    base: *mut core::ffi::c_void,
    size: u64,
    time_ms: u64,
    obf: Obfuscation,
    mode: ObfMode,
) {
    hypnus::__private::hypnus_entry_ms(base, size, time_ms, obf, mode)
}
