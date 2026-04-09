macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!($($arg)*);
    };
}

pub mod filesys;

#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod win;

#[cfg(target_os = "macos")]
use darwin::{domain, ipconfig, whoami};
#[cfg(any(target_os = "linux", target_os = "android"))]
use linux::{domain, ipconfig, whoami};
#[cfg(target_os = "windows")]
use win::{domain, ipconfig, whoami};

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
    #[allow(unreachable_code)]
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
    pub clr_version: Vec<String>,
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
        clr_version: {
            #[cfg(all(target_os = "windows", feature = "clr"))]
            {
                win::clr::clr_version()
            }
            #[cfg(not(all(target_os = "windows", feature = "clr")))]
            {
                vec![]
            }
        },
    })
}

pub fn is_privilege() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Inline privilege check to avoid depending on the full token module
        use std::ffi::c_void;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::GetCurrentProcessId;
        use windows::Win32::System::Threading::OpenProcess;
        use windows::Win32::System::Threading::OpenProcessToken;

        unsafe {
            let pid = GetCurrentProcessId();
            let Ok(h_process) = OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION,
                false,
                pid,
            ) else {
                return false;
            };
            let mut h_token = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(h_process, TOKEN_QUERY, &mut h_token).is_err() {
                let _ = CloseHandle(h_process);
                return false;
            }
            let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
            let mut size: u32 = 0;
            let result = GetTokenInformation(
                h_token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            )
            .is_ok()
                && elevation.TokenIsElevated != 0;
            let _ = CloseHandle(h_token);
            let _ = CloseHandle(h_process);
            return result;
        }
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
    pub process: Option<malefic_process::Process>,
    pub is_privilege: bool,
    pub ip_addresses: Vec<String>,
    pub domain_name: String,
}

pub fn get_sysinfo() -> SysInfo {
    let ip_addresses = ipconfig::get_ipv4_addresses();

    SysInfo {
        workdir: crate::filesys::get_cwd().unwrap_or_else(|e| e.to_string()),
        filepath: crate::filesys::get_executable_path().unwrap_or_else(|e| e.to_string()),
        os: default_os(),
        process: malefic_process::get_current_process(),
        is_privilege: is_privilege(),
        ip_addresses,
        domain_name: domain::get_domain(),
    }
}
