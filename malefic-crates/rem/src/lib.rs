#[cfg(feature = "rem_static")]
mod rem_static;

#[cfg(feature = "rem_dynamic")]
mod rem_dynamic;

#[cfg(feature = "rem_static")]
use rem_static::RemStatic as RemImpl;

#[cfg(feature = "rem_dynamic")]
use rem_dynamic::RemDynamic as RemImpl;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

/// CGo multi-return: (*C.char, C.int)
#[repr(C)]
pub struct RemDialResult {
    pub ptr: *mut c_char,
    pub err: c_int,
}

/// CGo multi-return: (C.int, C.int)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IntPairResult {
    pub val: c_int,
    pub err: c_int,
}

const ERR_CMD_PARSE_FAILED: c_int = 1;
const ERR_ARGS_PARSE_FAILED: c_int = 2;
const ERR_PREPARE_FAILED: c_int = 3;
const ERR_NO_CONSOLE_URL: c_int = 4;
const ERR_CREATE_CONSOLE: c_int = 5;
const ERR_DIAL_FAILED: c_int = 6;
pub const ERR_WOULD_BLOCK: c_int = 7;

fn handle_rem_error(err_code: c_int) -> String {
    match err_code {
        ERR_CMD_PARSE_FAILED => "Command line parsing error".to_string(),
        ERR_ARGS_PARSE_FAILED => "Parameter parsing error".to_string(),
        ERR_PREPARE_FAILED => "Preparation failed".to_string(),
        ERR_NO_CONSOLE_URL => "No console URL".to_string(),
        ERR_CREATE_CONSOLE => "Failed to create console".to_string(),
        ERR_DIAL_FAILED => "Connection failed".to_string(),
        ERR_WOULD_BLOCK => "Would block".to_string(),
        _ => format!("Unknown REM error: {}", err_code),
    }
}

/// Error type that distinguishes "would block" (no data) from real errors.
#[derive(Debug)]
pub enum RemError {
    /// Non-blocking read/write: no data available right now.
    WouldBlock,
    /// A real error (connection lost, invalid handle, etc.).
    Other(String),
}

#[cfg(feature = "rem_static")]
extern "C" {
    fn RemDial(cmdline: *const c_char) -> RemDialResult;
    fn MemoryDial(memhandle: *const c_char, dst: *const c_char) -> IntPairResult;
    fn MemoryRead(handle: c_int, buf: *mut c_void, size: c_int) -> IntPairResult;
    fn MemoryTryRead(handle: c_int, buf: *mut c_void, size: c_int) -> IntPairResult;
    fn MemoryWrite(handle: c_int, buf: *const c_void, size: c_int) -> IntPairResult;
    fn MemoryClose(handle: c_int) -> c_int;
    fn CleanupAgent();
}

pub struct RemFunctions {
    pub rem_dial: Option<unsafe extern "C" fn(*const c_char) -> RemDialResult>,
    pub memory_dial: Option<unsafe extern "C" fn(*const c_char, *const c_char) -> IntPairResult>,
    pub memory_read: Option<unsafe extern "C" fn(c_int, *mut c_void, c_int) -> IntPairResult>,
    pub memory_try_read: Option<unsafe extern "C" fn(c_int, *mut c_void, c_int) -> IntPairResult>,
    pub memory_write: Option<unsafe extern "C" fn(c_int, *const c_void, c_int) -> IntPairResult>,
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
        let result = (funcs.rem_dial.unwrap())(c_cmdline.as_ptr());
        if result.err != 0 {
            Err(handle_rem_error(result.err))
        } else {
            if result.ptr.is_null() {
                return Err("Invalid agent ID".to_string());
            }
            let agent_id = CStr::from_ptr(result.ptr).to_string_lossy().into_owned();
            Ok(agent_id)
        }
    }
}

pub fn memory_dial(memhandle: &str, dst: &str) -> Result<i32, String> {
    let funcs = get_functions()?;
    unsafe {
        let c_memhandle = CString::new(memhandle).map_err(|e| e.to_string())?;
        let c_dst = CString::new(dst).map_err(|e| e.to_string())?;
        let result = (funcs.memory_dial.unwrap())(c_memhandle.as_ptr(), c_dst.as_ptr());
        if result.err != 0 {
            Err(handle_rem_error(result.err))
        } else {
            Ok(result.val)
        }
    }
}

pub fn memory_read(handle: i32, buf: &mut [u8]) -> Result<usize, String> {
    let funcs = get_functions()?;
    unsafe {
        let result = (funcs.memory_read.unwrap())(
            handle,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as c_int,
        );
        if result.err != 0 {
            Err(handle_rem_error(result.err))
        } else {
            Ok(result.val as usize)
        }
    }
}

/// Non-blocking read: returns immediately with data or `WouldBlock`.
///
/// Calls the Go-side `MemoryTryRead` which checks the internal buffer
/// without touching deadlines or blocking.  Pure memory operation.
///
/// Falls back to `WouldBlock` if the linked librem does not export
/// `MemoryTryRead` (old version without BufferedConn).
pub fn memory_try_read(handle: i32, buf: &mut [u8]) -> Result<usize, RemError> {
    let funcs = get_functions().map_err(RemError::Other)?;
    unsafe {
        let result = if let Some(func) = funcs.memory_try_read {
            func(handle, buf.as_mut_ptr() as *mut c_void, buf.len() as c_int)
        } else {
            // Fallback: old librem without MemoryTryRead.
            return Err(RemError::WouldBlock);
        };
        if result.err == ERR_WOULD_BLOCK {
            Err(RemError::WouldBlock)
        } else if result.err != 0 {
            Err(RemError::Other(handle_rem_error(result.err)))
        } else {
            Ok(result.val as usize)
        }
    }
}

pub fn memory_write(handle: i32, buf: &[u8]) -> Result<usize, String> {
    let funcs = get_functions()?;
    unsafe {
        let result = (funcs.memory_write.unwrap())(
            handle,
            buf.as_ptr() as *const c_void,
            buf.len() as c_int,
        );
        if result.err != 0 {
            Err(handle_rem_error(result.err))
        } else {
            Ok(result.val as usize)
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
