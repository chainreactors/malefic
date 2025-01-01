use crate::{to_error, CommonError};
use std::collections::HashMap;
use std::process;
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

#[cfg(target_family = "unix")]
pub fn get_current_process_name() -> String {
    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::Read;

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

    let snapshot = unsafe { to_error!(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) }?;
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

    Err(CommonError::AnyError(anyhow::anyhow!("Parent process not found")))
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, Default)]
pub struct Process {
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: String,
    pub arch: String,
    pub owner: String,
    pub path: String,
    pub args: String,
}

pub fn get_process(pid: u32) -> Result<Process, CommonError> {
    let mut processes = get_processes()?;
    Ok(processes.remove(&pid).unwrap_or_default())
}

pub fn get_process_owner(pid: u32) -> String {
    #[cfg(target_family = "windows")]
    {
        crate::win::process::get_process_owner(pid).unwrap_or_default()
    }

    #[cfg(not(target_family = "windows"))]
    {
        "".to_string()
    }
}

pub fn get_process_arch(pid: u32) -> String{
    #[cfg(target_family = "windows")]
    {
        crate::win::process::get_process_architecture(pid).unwrap_or_default()
    }

    #[cfg(not(target_family = "windows"))]
    {
        "".to_string()
    }
}

pub fn get_processes() -> Result<HashMap<u32, Process>, CommonError> {
    #[cfg(feature = "sysinfo")]
    {
        let mut processes = HashMap::new();

        for (pid, process) in sysinfo::System::new_with_specifics(
            sysinfo::RefreshKind::new().with_processes(sysinfo::ProcessRefreshKind::everything()),
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
                    arch: get_process_arch(pid.as_u32()),
                    uid: process.user_id().map_or_else(||"".to_string(), |uid| uid.to_string()),
                    owner: get_process_owner(pid.as_u32()),
                    path: process.exe().map_or_else(|| "".to_string(), |p| p.to_string_lossy().into_owned()),
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
    get_process(get_current_pid())
        .ok()
        .map(|process| Process {
            pid: process.pid,
            ppid: process.ppid,
            uid: process.uid,
            name: process.name,
            path: process.path,
            args: process.args,
            owner: process.owner,
            arch: process.arch,
        })
}


pub fn run_command(path: String, args: Vec<String>, _output: bool) -> std::result::Result<std::process::Child, std::io::Error> {
    // let (stdout, stderr) = if output {
    //     (Stdio::piped(), Stdio::piped())
    // } else {
    //     (Stdio::null(), Stdio::null())
    // };

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