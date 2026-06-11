use anyhow::{anyhow, Result};
use detour::RawDetour;
use std::ffi::{c_void, CString};
use windows::{
    core::PCSTR,
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
};

pub struct RawHook {
    inner: RawDetour,
}

impl RawHook {
    pub unsafe fn new(target: *const c_void, replacement: *const c_void) -> Result<Self> {
        let inner = RawDetour::new(target as *const (), replacement as *const ())
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok(Self { inner })
    }

    pub fn trampoline(&self) -> *const c_void {
        self.inner.trampoline() as *const () as *const c_void
    }

    pub unsafe fn enable(&self) -> Result<()> {
        self.inner.enable().map_err(|e| anyhow!(e.to_string()))
    }

    pub unsafe fn disable(&self) -> Result<()> {
        self.inner.disable().map_err(|e| anyhow!(e.to_string()))
    }
}

pub fn resolve_proc_address(module_name: &str, proc_name: &str) -> Result<*const c_void> {
    let module = CString::new(module_name).map_err(|e| anyhow!(e.to_string()))?;
    let proc = CString::new(proc_name).map_err(|e| anyhow!(e.to_string()))?;

    let module_handle = unsafe { GetModuleHandleA(PCSTR(module.as_ptr() as _)) }
        .map_err(|_| anyhow!("module handle get failed"))?;
    let proc_address = unsafe { GetProcAddress(module_handle, PCSTR(proc.as_ptr() as _)) }
        .ok_or_else(|| anyhow!("func handle get failed"))?;

    Ok(proc_address as *const c_void)
}
