#[cfg(target_os = "macos")]
use crate::darwin::process;
#[cfg(target_os = "linux")]
use crate::linux::process;
#[cfg(target_os = "windows")]
use crate::win::process;

use crate::{to_error, CommonError};
use std::collections::HashMap;
use std::process::{Command, Stdio};

#[cfg(target_family = "unix")]
pub fn kill(pid: u32) -> Result<(), CommonError> {
    let res = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    if res.eq(&0) {
        Ok(())
    } else {
        Err(CommonError::IOError(std::io::Error::last_os_error()))
    }
}

#[cfg(target_family = "windows")]
pub fn kill(pid: u32) -> Result<(), CommonError> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let process_handle: HANDLE = to_error!(OpenProcess(PROCESS_TERMINATE, false, pid))?;
        to_error!(TerminateProcess(process_handle, 1))?;
        to_error!(CloseHandle(process_handle))?;
    }

    Ok(())
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, Default)]
pub struct Process {
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub arch: String,
    pub owner: String,
    pub path: String,
    pub args: String,
}

pub fn get_process(pid: u32) -> anyhow::Result<Process> {
    process::get_process_info(pid)
}

pub fn get_processes() -> anyhow::Result<HashMap<u32, Process>> {
    process::get_processes()
}
pub fn get_arch() -> String {
    if cfg!(target_arch = "x86_64") {
        "x86_64".to_string()
    } else if cfg!(target_arch = "x86") {
        "x86".to_string()
    } else if cfg!(target_arch = "arm") {
        "arm".to_string()
    } else if cfg!(target_arch = "aarch64") {
        "aarch64".to_string()
    } else {
        "unknown".to_string()
    }
}

pub fn get_current_process() -> Option<Process> {
    get_process(process::get_current_pid()).ok()
}

pub fn run_command(
    path: String,
    args: Vec<String>,
) -> std::result::Result<std::process::Child, std::io::Error> {

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        Command::new(path)
            .creation_flags(0x08000000)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
    #[cfg(target_family = "unix")]
    {
        Command::new(path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
}

pub fn async_command(
    path: String,
    args: Vec<String>,
) -> std::result::Result<async_process::Child, std::io::Error> {
    #[cfg(target_os = "windows")]
    {
        use async_process::windows::CommandExt;
        async_process::Command::new(path)
            .creation_flags(0x08000000)
            .args(args)
            .stdout(async_process::Stdio::piped())
            .stderr(async_process::Stdio::piped())
            .spawn()
    }
    #[cfg(target_family = "unix")]
    {
        async_process::Command::new(path)
            .args(args)
            .stdout(async_process::Stdio::piped())
            .stderr(async_process::Stdio::piped())
            .spawn()
    }
}

