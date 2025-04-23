use core::{ffi::c_void, ptr::null};
use obfstr::obfstr;

use crate::{
    debug,
    CommonError::{self, ArgsError},
};


#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub unsafe fn get_function_address(module_base: *const c_void, function_name: &str) -> *const c_void {
    use crate::win::kit::MaleficGetFuncAddrWithModuleBaseDefault;

    MaleficGetFuncAddrWithModuleBaseDefault(
        module_base,
        function_name.as_ptr(),
        function_name.len(),
    )
}

#[cfg(target_os = "windows")]
#[cfg(feature = "source")]
pub unsafe fn get_function_address(module_base: *const c_void, function_name: &str) -> *const c_void {
    use malefic_win_kit::dynamic::DynamicLibraryUtils::GetFuncAddrWithModuleBaseDefault;

    GetFuncAddrWithModuleBaseDefault(module_base, function_name.as_bytes())
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub unsafe fn load_module(bins: Vec<u8>, bundle: String) -> Result<*const c_void, CommonError> {
    use crate::win::kit::{MaleficLoadLibrary, AUTO_RUN_DLL_MAIN, LOAD_MEMORY};

    if bins.is_empty() || bundle.is_empty() {
        return Err(ArgsError(obfstr!("bins or bundle is empty :)").to_string()));
    }
    debug!("[+] load module {}, len: {}", bundle, bins.len());
    
    let new_bundle = format!("{}{}", bundle, "\x00");

    let dark_module = MaleficLoadLibrary(
        AUTO_RUN_DLL_MAIN | LOAD_MEMORY as u32,
        null(),
        bins.as_ptr() as _,
        bins.len(),
        new_bundle.as_ptr() as _,
    ) as _;

    Ok(dark_module)
}

#[cfg(target_os = "windows")]
#[cfg(feature = "source")]
pub unsafe fn load_module(
    bins: Vec<u8>,
    bundle: String,
) -> Result<*const malefic_win_kit::dynamic::MaleficLoadLibrary::DarkModule, CommonError> {
    use malefic_win_kit::dynamic::MaleficLoadLibrary::{
        MaleficLoadLibrary, AUTO_RUN_DLL_MAIN, LOAD_MEMORY,
    };

    if bins.is_empty() || bundle.is_empty() {
        return Err(ArgsError(obfstr!("bins or bundle is empty :)").to_string()));
    }
    debug!("[+] in load module!");
    debug!("[+] bins len is {}", bins.len());
    let new_bundle = format!("{}{}", bundle, "\x00");
    let dark_module = MaleficLoadLibrary(
        AUTO_RUN_DLL_MAIN | LOAD_MEMORY as u32,
        null(),
        bins.as_ptr() as _,
        bins.len(),
        new_bundle.as_ptr() as _,
    );
    if dark_module.is_null() || !(*dark_module).is_successed {
        return Err(ArgsError("dark module load failed!".to_string()));
    }
    Ok(dark_module)
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub unsafe fn call_fresh_modules(module: *const c_void) -> Option<*const c_void> {
    use crate::win::kit::DarkModule;
    let module: *const DarkModule = module as _;
    if module.is_null() || !(*module).is_successed {
        return None;
    }

    Some(get_function_address((*module).module_base, "register_modules"))
}

#[cfg(target_os = "windows")]
#[cfg(feature = "source")]
pub unsafe fn call_fresh_modules(
    module: *const malefic_win_kit::dynamic::MaleficLoadLibrary::DarkModule,
) -> Option<*const c_void> {
    if module.is_null() || !(*module).is_successed {
        return None;
    }

    Some(get_function_address((*module).module_base, "register_modules"))
}

#[cfg(target_family = "unix")]
pub unsafe fn load_module(_bins: Vec<u8>, _bundle: String) -> Result<*const c_void, CommonError> {
    todo!()
}

#[cfg(target_family = "unix")]
pub unsafe fn call_fresh_modules(_module: *const c_void) -> Option<*const c_void> {
    todo!()
}
