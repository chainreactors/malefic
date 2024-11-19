use sysinfo::System;

use crate::common::{filesys, process};

pub fn name() -> String {
    System::name().unwrap_or("".to_string())
}

pub fn release() -> String {
    System::kernel_version().unwrap_or("".to_string())
}

pub fn username() -> String {
    whoami::username()
}

pub fn version() -> String {
    System::os_version().unwrap_or("".to_string())
}

pub fn hostname() -> String {
    System::host_name().unwrap_or("".to_string())
}

pub fn arch() -> String {
    System::cpu_arch().unwrap_or("".to_string())
}

#[allow(deprecated)]
pub fn language() -> String {
    whoami::lang().collect::<Vec<String>>().join(",")
}

pub fn gid() -> String {
    #[cfg(target_family = "unix")]{
       return unsafe { libc::getgid().to_string() };
    }
    "".to_string()
}


pub struct Os {
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub username: String,
    pub hostname: String,
    pub locale: String,
}

pub fn default_os() -> Option<Os> {
    Some(Os {
        name: name(),
        version: version(),
        release: release(),
        arch: arch(),
        username: username(),
        hostname: hostname(),
        locale: language(),
    })
}


pub fn is_privilege() -> bool {
    #[cfg(target_os = "windows")]
    {
        return crate::win::token::is_privilege().unwrap_or(false);
    }
    #[cfg(not(target_os = "windows"))]{
        return unsafe { libc::geteuid() == 0 };
    }
}

pub struct SysInfo {
    pub workdir: String,
    pub filepath: String,
    pub os: Option<Os>,
    pub process: Option<process::Process>,
    pub is_privilege: bool
}

pub fn get_sysinfo() -> SysInfo {
    SysInfo {
        workdir: filesys::get_cwd().unwrap_or_else(|e| e.to_string()),
        filepath: filesys::get_executable_path().unwrap_or_else(|e| e.to_string()),
        os: default_os(),
        process: process::get_current_process(),
        is_privilege: is_privilege()
    }
}
