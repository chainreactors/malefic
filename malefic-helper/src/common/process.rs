use crate::protobuf::implantpb;
use crate::CommonError;
use std::collections::HashMap;
use std::process;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

#[cfg(target_family = "unix")]
pub fn kill(pid: u32) -> Result<(), CommonError> {
    let res = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    if res.eq(&0) {
        Ok(())
    } else {
        Err(CommonError::UnixError(std::io::Error::last_os_error()))
    }
}

#[cfg(target_family = "windows")]
pub fn kill(pid: u32) -> Result<(), CommonError> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let process_handle: HANDLE = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        TerminateProcess(process_handle, 1)?;
        CloseHandle(process_handle)?;
    }

    Ok(())
}

#[cfg(target_family = "unix")]
pub fn get_current_process_name() -> String {
    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::{self, Read};

        let mut file = match File::open("/proc/self/comm") {
            Ok(file) => file,
            Err(_) => return String::from("Unknown"),
        };

        let mut name = String::new();
        match file.read_to_string(&mut name) {
            Ok(_) => {
                if name.ends_with('\n') {
                    name.pop();
                }
                name
            }
            Err(_) => String::from("Unknown"),
        }
    }

    #[cfg(target_os = "macos")]
    {
        use libc::{getpid, proc_pidpath};
        use std::ffi::CString;
        use std::ptr;

        let pid = unsafe { getpid() };
        let mut pathbuf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let ret = unsafe { proc_pidpath(pid, pathbuf.as_mut_ptr() as _, pathbuf.len() as u32) };

        if ret > 0 {
            let c_str = unsafe { CString::from_vec_unchecked(pathbuf) };
            c_str.to_string_lossy().into_owned()
        } else {
            String::from("Unknown")
        }
    }
}

#[cfg(target_family = "windows")]
pub fn get_current_process_name() -> String {
    use std::path::Path;

    if let Ok(path) = std::env::current_exe() {
        Path::new(&path)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            .to_string()
    } else {
        "".to_string()
    }
}

pub fn get_current_pid() -> u32 {
    process::id()
}

#[cfg(target_family = "unix")]
pub fn get_parent_pid() -> u32 {
    unsafe { libc::getppid() as u32 }
}

#[cfg(target_family = "windows")]
pub fn get_parent_pid() -> Result<u32, CommonError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    let mut process_entry = PROCESSENTRY32::default();
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot, &mut process_entry) }.is_ok() {
        let current_process_id = get_current_pid();

        loop {
            if process_entry.th32ProcessID == current_process_id {
                return Ok(process_entry.th32ParentProcessID);
            }

            if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                break;
            }
        }
    }

    Err(CommonError::WinApiError(windows::core::Error::from_win32()))
}

#[derive(Clone, Debug)]
pub struct Process {
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub arch: String,
    pub owner: String,
    pub path: String,
    pub args: String,
}

pub fn get_process(pid: u32) -> Result<Process, CommonError> {
    let mut processes = get_processes()?;
    Ok(processes.remove(&pid).expect("process not found"))
}

pub fn get_current_process() -> Result<Process, CommonError> {
    get_process(get_current_pid())
}

pub fn get_processes() -> Result<HashMap<u32, Process>, CommonError> {
    let mut processes = HashMap::new();

    for (pid, process) in System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    )
    .processes()
    .into_iter()
    {
        processes.insert(
            pid.as_u32(),
            Process {
                name: process.name().to_string_lossy().to_string(),
                pid: pid.as_u32(),
                ppid: process.parent().map_or_else(|| 0, |p| p.as_u32()),
                arch: "".to_string(),
                owner: "".to_string(),
                path: process
                    .exe()
                    .map_or_else(|| "".to_string(), |p| p.to_string_lossy().into_owned()),
                args: process
                    .cmd()
                    .iter()
                    .map(|os_str| os_str.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
            },
        );
    }
    Ok(processes)
}

pub fn default_arch() -> String {
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

pub fn default_process() -> Option<implantpb::Process> {
    crate::common::process::get_current_process()
        .ok()
        .map(|process| implantpb::Process {
            pid: process.pid,
            ppid: process.ppid,
            name: process.name,
            path: process.path,
            args: process.args,
            owner: process.owner,
            arch: default_arch(),
        })
}