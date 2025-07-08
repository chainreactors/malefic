#[cfg(feature = "rem_static")]
mod rem_static;

#[cfg(feature = "rem_static")]
use rem_static::RemStatic as RemImpl;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// REM 统一错误码常量
const ERR_CMD_PARSE_FAILED: c_int = 1;  // Command line parsing error
const ERR_ARGS_PARSE_FAILED: c_int = 2; // Parameter parsing error
const ERR_PREPARE_FAILED: c_int = 3;    // Preparation failed
const ERR_NO_CONSOLE_URL: c_int = 4;    // No console URL
const ERR_CREATE_CONSOLE: c_int = 5;    // Failed to create console
const ERR_DIAL_FAILED: c_int = 6;       // Connection failed

/// 统一的rem错误处理函数
fn handle_rem_error(err_code: c_int) -> String {
    match err_code {
        ERR_CMD_PARSE_FAILED => "Command line parsing error".to_string(),
        ERR_ARGS_PARSE_FAILED => "Parameter parsing error".to_string(),
        ERR_PREPARE_FAILED => "Preparation failed".to_string(),
        ERR_NO_CONSOLE_URL => "No console URL".to_string(),
        ERR_CREATE_CONSOLE => "Failed to create console".to_string(),
        ERR_DIAL_FAILED => "Connection failed".to_string(),
        _ => format!("Unknown REM error: {}", err_code),
    }
}

// #[cfg(all(
//     target_os = "windows",
//     feature = "rem_reflection",
// ))]
// mod rem_reflection;
// #[cfg(all(
//     target_os = "windows",
//     feature = "rem_reflection"
// ))]
// use rem_reflection::RemReflection as RemImpl;
// 
// #[cfg(feature = "rem_reflection")]
// pub use rem_reflection::RemReflection;



extern "C" {
    fn RemDial(cmdline: *const c_char) -> (*mut c_char, c_int);
    fn MemoryDial(memhandle: *const c_char, dst: *const c_char) -> (c_int, c_int);
    fn MemoryRead(handle: c_int, buf: *mut c_void, size: c_int) -> (c_int, c_int);
    fn MemoryWrite(handle: c_int, buf: *const c_void, size: c_int) -> (c_int, c_int);
    fn MemoryClose(handle: c_int) -> c_int;
    fn CleanupAgent();
}

pub struct RemFunctions {
    pub rem_dial: Option<unsafe extern "C" fn(*const c_char) -> (*mut c_char, c_int)>,
    pub memory_dial: Option<unsafe extern "C" fn(*const c_char, *const c_char) -> (c_int, c_int)>,
    pub memory_read: Option<unsafe extern "C" fn(c_int, *mut c_void, c_int) -> (c_int, c_int)>,
    pub memory_write: Option<unsafe extern "C" fn(c_int, *const c_void, c_int) -> (c_int, c_int)>,
    pub memory_close: Option<unsafe extern "C" fn(c_int) -> c_int>,
    pub cleanup_agent: Option<unsafe extern "C" fn()>,
}

pub(crate) trait RemApi {
    unsafe fn get_functions(&self) -> Result<&RemFunctions, String>;
}

static mut REM_INSTANCE: Option<RemImpl> = None;

fn get_instance() -> &'static RemImpl {
    unsafe {
        if REM_INSTANCE.is_none() {
            REM_INSTANCE = Some(RemImpl);
        }
        REM_INSTANCE.as_ref().unwrap()
    }
}

fn get_functions() -> Result<&'static RemFunctions, String> {
    unsafe {
        let funcs = get_instance().get_functions()?;
        if funcs.rem_dial.is_none() {
            return Err("REM functions not initialized".to_string());
        }
        Ok(funcs)
    }
}

pub fn rem_dial(cmdline: &str) -> Result<String, String> {
    let funcs = get_functions()?;
    unsafe {
        let c_cmdline = CString::new(cmdline).map_err(|e| e.to_string())?;
        let (agent_id_ptr, err_code) = (funcs.rem_dial.unwrap())(c_cmdline.as_ptr());

        if err_code != 0 {
            Err(handle_rem_error(err_code))
        } else {
            if agent_id_ptr.is_null() {
                return Err("Invalid agent ID".to_string());
            }
            let agent_id = CStr::from_ptr(agent_id_ptr).to_string_lossy().into_owned();
            Ok(agent_id)
        }
    }
}

pub fn memory_dial(memhandle: &str, dst: &str) -> Result<i32, String> {
    let funcs = get_functions()?;
    unsafe {
        let c_memhandle = CString::new(memhandle).map_err(|e| e.to_string())?;
        let c_dst = CString::new(dst).map_err(|e| e.to_string())?;
        let (handle, err_code) = (funcs.memory_dial.unwrap())(c_memhandle.as_ptr(), c_dst.as_ptr());

        if err_code != 0 {
            Err(handle_rem_error(err_code))
        } else {
            Ok(handle)
        }
    }
}

pub fn memory_read(handle: i32, buf: &mut [u8]) -> Result<usize, String> {
    let funcs = get_functions()?;
    unsafe {
        let (n, err_code) = (funcs.memory_read.unwrap())(
            handle,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as c_int,
        );

        if err_code != 0 {
            Err(handle_rem_error(err_code))
        } else {
            Ok(n as usize)
        }
    }
}

pub fn memory_write(handle: i32, buf: &[u8]) -> Result<usize, String> {
    let funcs = get_functions()?;
    unsafe {
        let (n, err_code) = (funcs.memory_write.unwrap())(
            handle,
            buf.as_ptr() as *const c_void,
            buf.len() as c_int,
        );

        if err_code != 0 {
            Err(handle_rem_error(err_code))
        } else {
            Ok(n as usize)
        }
    }
}

pub fn memory_close(handle: i32) -> Result<(), String> {
    let funcs = get_functions()?;
    unsafe {
        let err_code = (funcs.memory_close.unwrap())(handle);
        if err_code != 0 {
            Err(handle_rem_error(err_code))
        } else {
            Ok(())
        }
    }
}

pub fn cleanup() {
    if let Ok(funcs) = get_functions() {
        unsafe {
            if let Some(cleanup_fn) = funcs.cleanup_agent {
                cleanup_fn();
            }
        }
    }
}
