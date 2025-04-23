#[cfg(feature = "rem_static")]
mod rem_static;

#[cfg(all(
    target_os = "windows",
    feature = "rem_reflection",
    not(feature = "rem_static")
))]
mod rem_reflection;

#[cfg(feature = "rem_static")]
use rem_static::RemStatic as RemImpl;

#[cfg(all(
    target_os = "windows",
    feature = "rem_reflection",
    not(feature = "rem_static")
))]
use rem_reflection::RemReflection as RemImpl;

#[cfg(all(feature = "rem_reflection", not(feature = "rem_static")))]
pub use rem_reflection::RemReflection;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

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
            let error_msg = match err_code {
                1 => "Command line parsing error",
                2 => "Parameter parsing error",
                3 => "Preparation failed",
                4 => "No console URL",
                5 => "Failed to create console",
                6 => "Connection failed",
                _ => "Unknown error",
            };
            Err(error_msg.to_string())
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
            let error_msg = match err_code {
                1 => "Failed to create client",
                2 => "Connection failed",
                _ => "Unknown error",
            };
            Err(error_msg.to_string())
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
            let error_msg = match err_code {
                1 => "Invalid connection handle",
                2 => "Read error",
                _ => "Unknown error",
            };
            Err(error_msg.to_string())
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
            let error_msg = match err_code {
                1 => "Invalid connection handle",
                2 => "Write error",
                _ => "Unknown error",
            };
            Err(error_msg.to_string())
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
            let error_msg = match err_code {
                1 => "Invalid connection handle",
                2 => "Close error",
                _ => "Unknown error",
            };
            Err(error_msg.to_string())
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
