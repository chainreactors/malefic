use crate::{IntPairResult, RemApi, RemDialResult, RemFunctions};
use std::os::raw::{c_char, c_int, c_void};

pub struct RemDynamic;

type RemDialFn = unsafe extern "C" fn(*const c_char) -> RemDialResult;
type MemoryDialFn = unsafe extern "C" fn(*const c_char, *const c_char) -> IntPairResult;
type MemoryReadFn = unsafe extern "C" fn(c_int, *mut c_void, c_int) -> IntPairResult;
type MemoryTryReadFn = unsafe extern "C" fn(c_int, *mut c_void, c_int) -> IntPairResult;
type MemoryWriteFn = unsafe extern "C" fn(c_int, *const c_void, c_int) -> IntPairResult;
type MemoryCloseFn = unsafe extern "C" fn(c_int) -> c_int;
type CleanupAgentFn = unsafe extern "C" fn();
type RemInitFn = unsafe extern "C" fn() -> c_int;

static mut REM_FUNCTIONS: RemFunctions = RemFunctions {
    rem_dial: None,
    memory_dial: None,
    memory_read: None,
    memory_try_read: None,
    memory_write: None,
    memory_close: None,
    cleanup_agent: None,
};

static mut LOADED: bool = false;

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::CString;
    use std::os::raw::c_char;

    type HMODULE = *mut std::ffi::c_void;
    type FARPROC = *mut std::ffi::c_void;

    extern "system" {
        fn LoadLibraryA(lpFileName: *const c_char) -> HMODULE;
        fn GetProcAddress(hModule: HMODULE, lpProcName: *const c_char) -> FARPROC;
        fn GetLastError() -> u32;
    }

    pub unsafe fn load_library(name: &str) -> Result<*mut std::ffi::c_void, String> {
        let c_name = CString::new(name).map_err(|e| e.to_string())?;
        let h = LoadLibraryA(c_name.as_ptr());
        if h.is_null() {
            Err(format!(
                "LoadLibraryA({}) failed, error={}",
                name,
                GetLastError()
            ))
        } else {
            Ok(h)
        }
    }

    pub unsafe fn get_proc(
        module: *mut std::ffi::c_void,
        name: &str,
    ) -> Result<*mut std::ffi::c_void, String> {
        let c_name = CString::new(name).map_err(|e| e.to_string())?;
        let p = GetProcAddress(module, c_name.as_ptr());
        if p.is_null() {
            Err(format!(
                "GetProcAddress({}) failed, error={}",
                name,
                GetLastError()
            ))
        } else {
            Ok(p)
        }
    }
}

unsafe fn load_dll() -> Result<(), String> {
    if LOADED {
        return Ok(());
    }

    let dll = platform::load_library("librem_tinygo.dll")?;

    // RemInit must be called first to initialize TinyGo runtime
    let rem_init: RemInitFn = std::mem::transmute(platform::get_proc(dll, "RemInit")?);
    let ret = rem_init();
    if ret != 0 {
        return Err(format!("RemInit() failed with code {}", ret));
    }

    REM_FUNCTIONS.rem_dial = Some(std::mem::transmute(platform::get_proc(dll, "RemDial")?));
    REM_FUNCTIONS.memory_dial = Some(std::mem::transmute(platform::get_proc(dll, "MemoryDial")?));
    REM_FUNCTIONS.memory_read = Some(std::mem::transmute(platform::get_proc(dll, "MemoryRead")?));
    REM_FUNCTIONS.memory_try_read = match platform::get_proc(dll, "MemoryTryRead") {
        Ok(proc) => Some(std::mem::transmute::<*mut std::ffi::c_void, MemoryTryReadFn>(proc)),
        Err(_) => None,
    };
    REM_FUNCTIONS.memory_write = Some(std::mem::transmute(platform::get_proc(dll, "MemoryWrite")?));
    REM_FUNCTIONS.memory_close = Some(std::mem::transmute(platform::get_proc(dll, "MemoryClose")?));
    REM_FUNCTIONS.cleanup_agent = Some(std::mem::transmute(platform::get_proc(
        dll,
        "CleanupAgent",
    )?));

    LOADED = true;
    Ok(())
}

impl RemApi for RemDynamic {
    unsafe fn get_functions(&self) -> Result<&RemFunctions, String> {
        load_dll()?;
        Ok(&REM_FUNCTIONS)
    }
}
