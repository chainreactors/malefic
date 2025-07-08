use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{BSTR, HRESULT, PCWSTR};

pub fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// 辅助函数：将宽字符指针转换为 String
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
        if e.code() != HRESULT::from_win32(0x7A) {
            Err(e)
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}
