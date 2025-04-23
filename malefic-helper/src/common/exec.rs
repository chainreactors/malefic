use std::io;
use std::path::Path;
use std::ptr;

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::HWND,
    UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_NORMAL},
};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

/// 检查文件是否正在被使用
#[cfg(target_os = "windows")]
pub fn is_file_in_use<P: AsRef<Path>>(path: P) -> bool {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)
        .is_err()
}

#[cfg(not(target_os = "windows"))]
pub fn is_file_in_use<P: AsRef<Path>>(_path: P) -> bool {
    false
}

#[cfg(target_os = "windows")]
pub fn shell_execute<P: AsRef<Path>>(path: P, operation: &str) -> io::Result<()> {
    use std::os::windows::prelude::OsStrExt;

    let path = path.as_ref();
    if is_file_in_use(path) {
        return Ok(());
    }

    let path_str: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let operation: Vec<u16> = operation.encode_utf16().chain(Some(0)).collect();

    unsafe {
        ShellExecuteW(
            HWND(ptr::null_mut()),
            PCWSTR(operation.as_ptr()),
            PCWSTR(path_str.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_NORMAL,
        );
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn shell_execute<P: AsRef<Path>>(path: P, _operation: &str) -> io::Result<()> {
    use std::process::Command;

    let path = path.as_ref();
    if is_file_in_use(path) {
        return Ok(());
    }

    Command::new(path).spawn()?;
    Ok(())
}
