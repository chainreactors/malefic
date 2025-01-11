use crate::common::{filesys, process};
#[cfg(target_os = "macos")]
use crate::darwin::whoami;
#[cfg(target_os = "linux")]
use crate::linux::whoami;
#[cfg(target_os = "windows")]
use crate::win::whoami;

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
}

pub fn get_sysinfo() -> SysInfo {
    SysInfo {
        workdir: filesys::get_cwd().unwrap_or_else(|e| e.to_string()),
        filepath: filesys::get_executable_path().unwrap_or_else(|e| e.to_string()),
        os: default_os(),
        process: process::get_current_process(),
        is_privilege: is_privilege(),
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

        if let Some(os) = info.os {
            assert!(!os.username.is_empty(), "OS username should not be empty");
            assert!(!os.hostname.is_empty(), "OS hostname should not be empty");
            assert!(!os.locale.is_empty(), "OS locale should not be empty");
        }
    }
}
