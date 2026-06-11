use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{BSTR, HRESULT, PCWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR};

pub fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub fn wide_to_string(ptr: PCWSTR) -> String {
    unsafe {
        let len = (0..).take_while(|&i| *ptr.0.offset(i) != 0).count();
        let slice = std::slice::from_raw_parts(ptr.0, len);
        String::from_utf16_lossy(slice)
    }
}

pub fn bstr_to_string(bstr: &BSTR) -> String {
    if bstr.is_empty() {
        return String::new();
    }
    bstr.to_string()
}

pub fn get_buffer(res: windows::core::Result<()>) -> windows::core::Result<()> {
    if let Err(e) = res {
        if e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) {
            Err(e)
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

/// Build a `windows::core::Error` from the thread-local `GetLastError()`.
pub fn last_win32_error() -> windows::core::Error {
    let err = unsafe { GetLastError() };
    windows::core::Error::from(WIN32_ERROR(err.0))
}

/// Convert a `WIN32_ERROR` status into `Result<()>`.
/// `ERROR_SUCCESS (0)` → `Ok(())`, otherwise → `Err`.
pub fn check_win32(status: WIN32_ERROR) -> windows::core::Result<()> {
    if status.0 == 0 {
        Ok(())
    } else {
        Err(windows::core::Error::from(status))
    }
}

/// Safe reinterpretation of a `&[u16]` slice as `&[u8]`.
pub fn wide_as_bytes(wide: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) }
}
