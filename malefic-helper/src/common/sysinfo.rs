use crate::common::{filesys, process};
#[cfg(target_os = "macos")]
use crate::darwin::whoami;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::linux::whoami;
#[cfg(target_os = "windows")]
use crate::win::whoami;

#[cfg(target_os = "windows")]
use crate::win::domain;
#[cfg(target_os = "windows")]
use crate::win::ipconfig;

#[cfg(target_os = "macos")]
use crate::darwin::domain;
#[cfg(target_os = "macos")]
use crate::darwin::ipconfig;

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::linux::domain;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::linux::ipconfig;

#[cfg(target_os = "windows")]
use crate::win::clr::{clr_version};

pub fn name() -> String {
    whoami::name().unwrap_or_default()
}

pub fn release() -> String {
    whoami::kernel_version().unwrap_or_default()
}

pub fn username() -> String {
    whoami::username()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

pub fn version() -> String {
    whoami::os_version().unwrap_or_default()
}

pub fn hostname() -> String {
    whoami::hostname()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

pub fn arch() -> String {
    whoami::cpu_arch().unwrap_or_default()
}

pub fn language() -> String {
    whoami::lang().unwrap_or_default()
}

pub fn gid() -> String {
    #[cfg(target_family = "unix")]
    {
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
    pub clr_version: Vec<String>
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
        #[cfg(target_os = "windows")]
        clr_version: clr_version(),
        #[cfg(not(target_os = "windows"))]
        clr_version: vec![],
    })
}

pub fn is_privilege() -> bool {
    #[cfg(target_os = "windows")]
    {
        return crate::win::token::is_privilege().unwrap_or(false);
    }
    #[cfg(not(target_os = "windows"))]
    {
        return unsafe { libc::geteuid() == 0 };
    }
}

pub struct SysInfo {
    pub workdir: String,
    pub filepath: String,
    pub os: Option<Os>,
    pub process: Option<process::Process>,
    pub is_privilege: bool,
    // Platform-specific implementation for new fields
    pub ip_addresses: Vec<String>,
    pub domain_name: String,
}

pub fn get_sysinfo() -> SysInfo {
    let ip_addresses = {
        #[cfg(target_os = "windows")]
        {
            ipconfig::get_ipv4_addresses()
        }
        #[cfg(target_os = "macos")]
        {
            ipconfig::get_ipv4_addresses()
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            ipconfig::get_ipv4_addresses()
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux", target_os = "android")))]
        {
            Vec::new() // Return empty vector for unsupported platforms
        }
    };

    SysInfo {
        workdir: filesys::get_cwd().unwrap_or_else(|e| e.to_string()),
        filepath: filesys::get_executable_path().unwrap_or_else(|e| e.to_string()),
        os: default_os(),
        process: process::get_current_process(),
        is_privilege: is_privilege(),
        ip_addresses,
        domain_name: domain::get_domain(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username() {
        let username = username();
        assert!(!username.is_empty(), "Username should not be empty");
    }

    #[test]
    fn test_hostname() {
        let hostname = hostname();
        assert!(!hostname.is_empty(), "Hostname should not be empty");
    }

    #[test]
    fn test_language() {
        let lang = language();
        assert!(!lang.is_empty(), "Language should not be empty");
    }

    #[test]
    fn test_sysinfo() {
        let info = get_sysinfo();
        assert!(
            !info.workdir.is_empty(),
            "Working directory should not be empty"
        );
        assert!(!info.filepath.is_empty(), "File path should not be empty");
        assert!(!info.os.is_none(), "OS info should not be None");
        assert!(!info.process.is_none(), "Process info should not be None");

        if let Some(os) = info.os {
            assert!(!os.username.is_empty(), "OS username should not be empty");
            assert!(!os.hostname.is_empty(), "OS hostname should not be empty");
            assert!(!os.locale.is_empty(), "OS locale should not be empty");
        }

        if let Some(process) = info.process {
            assert!(!process.name.is_empty(), "Process name should not be empty");
            assert!(!process.path.is_empty(), "Process path should not be empty");
            assert!(!process.args.is_empty(), "Process args should not be empty");
            assert!(!process.pid.le(&0), "Process PID should be greater than 0");
            assert!(!process.ppid.le(&0), "Process PPID should be greater than 0");
        }
    }

    #[test]
    fn test_sysinfo_print() {
        let info = get_sysinfo();
        println!("info file path: {}", info.filepath);
        println!("info work dir: {}", info.workdir);
        println!("info os name: {}", info.os.as_ref().unwrap().name);
        println!("info os version: {}", info.os.as_ref().unwrap().version);
        println!("info os release: {}", info.os.as_ref().unwrap().release);
        println!("info os arch: {}", info.os.as_ref().unwrap().arch);
        println!("info os username: {}", info.os.as_ref().unwrap().username);
        println!("info os hostname: {}", info.os.as_ref().unwrap().hostname);
        println!("info os locale: {}", info.os.as_ref().unwrap().locale);
        println!("info process name: {}", info.process.as_ref().unwrap().name);
        println!("info process pid: {}", info.process.as_ref().unwrap().pid);
        println!("info process ppid: {}", info.process.as_ref().unwrap().ppid);
        println!("info process arch: {}", info.process.as_ref().unwrap().arch);
        println!("info process owner: {}", info.process.as_ref().unwrap().owner);
        println!("info process path: {}", info.process.as_ref().unwrap().path);
        println!("info process args: {}", info.process.as_ref().unwrap().args);
        println!("info is privilege: {}", info.is_privilege);
        println!("info domain : {}",info.domain_name)
    }
}
