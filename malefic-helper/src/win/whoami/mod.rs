use std::ffi::{OsStr, OsString};
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;
use std::time::SystemTime;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_NONE,
};
use windows::Win32::System::SystemInformation::{
    self, ComputerNamePhysicalDnsHostname, GetComputerNameExW, GetSystemInfo, GetTickCount64,
    SYSTEM_INFO,
};
use windows::Win32::System::WindowsProgramming::GetUserNameW;

#[repr(C)]
#[allow(non_snake_case)]
struct OSVERSIONINFOEXW {
    dwOSVersionInfoSize: u32,
    dwMajorVersion: u32,
    dwMinorVersion: u32,
    dwBuildNumber: u32,
    dwPlatformId: u32,
    szCSDVersion: [u16; 128],
    wServicePackMajor: u16,
    wServicePackMinor: u16,
    wSuiteMask: u16,
    wProductType: u8,
    wReserved: u8,
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(lpVersionInformation: *mut OSVERSIONINFOEXW) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetUserPreferredUILanguages(
        dwFlags: u32,
        pulNumLanguages: *mut u32,
        pwszLanguagesBuffer: *mut u16,
        pcchLanguagesBuffer: *mut u32,
    ) -> i32;
}

const WINDOWS_ELEVEN_BUILD_NUMBER: u32 = 22000;
const MUI_LANGUAGE_NAME: u32 = 0x8;

pub fn username() -> Option<OsString> {
    let mut size = 0u32;
    unsafe {
        // First call gets the size
        let _ = GetUserNameW(PWSTR::null(), &mut size);
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u16; size as usize];
        if GetUserNameW(PWSTR::from_raw(buffer.as_mut_ptr()), &mut size).is_ok() {
            if let Some(pos) = buffer.iter().position(|&c| c == 0) {
                buffer.resize(pos, 0);
            }
            Some(OsString::from_wide(&buffer))
        } else {
            None
        }
    }
}

pub fn hostname() -> Option<OsString> {
    let mut size = 0u32;
    unsafe {
        let _ = GetComputerNameExW(ComputerNamePhysicalDnsHostname, PWSTR::null(), &mut size);
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u16; size as usize];
        if GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            PWSTR::from_raw(buffer.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            if let Some(pos) = buffer.iter().position(|&c| c == 0) {
                buffer.resize(pos, 0);
            }
            Some(OsString::from_wide(&buffer))
        } else {
            None
        }
    }
}

pub fn lang() -> Option<String> {
    unsafe {
        let mut num_languages = 0u32;
        let mut buffer_size = 0u32;

        // First call to get the required buffer size
        if GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut num_languages,
            ptr::null_mut(),
            &mut buffer_size,
        ) != 0
        {
            let mut buffer = vec![0u16; buffer_size as usize];

            // Second call to get the actual language list
            if GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME,
                &mut num_languages,
                buffer.as_mut_ptr(),
                &mut buffer_size,
            ) != 0
            {
                // Remove trailing null characters
                buffer.pop();
                buffer.pop();

                // Combine multiple languages into a single string, separated by semicolons
                return Some(
                    String::from_utf16_lossy(&buffer)
                        .split('\0')
                        .collect::<Vec<&str>>()
                        .join(";"),
                );
            }
        }
    }

    // If Windows API call fails, try to get from environment variables
    std::env::var("LANG")
        .or_else(|_| std::env::var("LANGUAGE"))
        .ok()
}

pub fn name() -> Option<String> {
    Some("Windows".to_owned())
}

pub fn os_version() -> Option<String> {
    unsafe {
        let mut version_info = OSVERSIONINFOEXW {
            dwOSVersionInfoSize: mem::size_of::<OSVERSIONINFOEXW>() as u32,
            dwMajorVersion: 0,
            dwMinorVersion: 0,
            dwBuildNumber: 0,
            dwPlatformId: 0,
            szCSDVersion: [0; 128],
            wServicePackMajor: 0,
            wServicePackMinor: 0,
            wSuiteMask: 0,
            wProductType: 0,
            wReserved: 0,
        };

        if RtlGetVersion(&mut version_info) == 0 {
            let major = if version_info.dwBuildNumber >= WINDOWS_ELEVEN_BUILD_NUMBER {
                11
            } else {
                version_info.dwMajorVersion
            };
            return Some(major.to_string());
        }
    }

    // 如果 API 调用失败，使用注册表作为备选方案
    let major = if is_windows_eleven() {
        11u32
    } else {
        u32::from_le_bytes(
            get_reg_value_u32(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "CurrentMajorVersionNumber",
            )
            .unwrap_or_default(),
        )
    };
    Some(major.to_string())
}

pub fn kernel_version() -> Option<String> {
    get_reg_string_value(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
    )
}

pub fn long_os_version() -> Option<String> {
    if is_windows_eleven() {
        get_reg_string_value(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
        .map(|product_name| product_name.replace("Windows 10 ", "Windows 11 "))
    } else {
        get_reg_string_value(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        )
    }
}

pub fn distribution_id() -> String {
    std::env::consts::OS.to_owned()
}

pub fn cpu_arch() -> Option<String> {
    unsafe {
        let mut info = SYSTEM_INFO::default();
        GetSystemInfo(&mut info);
        match info.Anonymous.Anonymous.wProcessorArchitecture {
            SystemInformation::PROCESSOR_ARCHITECTURE_ALPHA => Some("alpha".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_ALPHA64 => Some("alpha64".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_AMD64 => Some("x86_64".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_ARM => Some("arm".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64 => Some("arm".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_ARM64 => Some("arm64".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_IA32_ON_ARM64
            | SystemInformation::PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 => Some("ia32".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_IA64 => Some("ia64".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_INTEL => Some("x86".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_MIPS => Some("mips".to_string()),
            SystemInformation::PROCESSOR_ARCHITECTURE_PPC => Some("powerpc".to_string()),
            _ => None,
        }
    }
}

pub fn physical_core_count() -> Option<usize> {
    unsafe {
        let mut info = SYSTEM_INFO::default();
        GetSystemInfo(&mut info);
        Some(info.dwNumberOfProcessors as usize)
    }
}

pub fn uptime() -> u64 {
    unsafe { GetTickCount64() / 1_000 }
}

pub fn boot_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => {
            let system_time_ns = n.as_nanos();
            let tick_count_ns = unsafe { GetTickCount64() } as u128 * 1_000_000;
            let boot_time_sec = system_time_ns.saturating_sub(tick_count_ns) / 1_000_000_000;
            boot_time_sec.try_into().unwrap_or(u64::MAX)
        }
        Err(_) => 0,
    }
}

fn is_windows_eleven() -> bool {
    WINDOWS_ELEVEN_BUILD_NUMBER <= kernel_version().unwrap_or_default().parse().unwrap_or(0)
}

fn utf16_str<S: AsRef<OsStr> + ?Sized>(text: &S) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>()
}

struct RegKey(HKEY);

impl RegKey {
    unsafe fn open(hkey: HKEY, path: &[u16]) -> Option<Self> {
        let mut new_hkey = HKEY::default();
        if RegOpenKeyExW(
            hkey,
            PCWSTR::from_raw(path.as_ptr()),
            0,
            KEY_READ,
            &mut new_hkey,
        )
        .is_err()
        {
            return None;
        }
        Some(Self(new_hkey))
    }

    unsafe fn get_value(
        &self,
        field_name: &[u16],
        buf: &mut [u8],
        buf_len: &mut u32,
    ) -> windows::core::Result<()> {
        let mut buf_type = REG_NONE;

        RegQueryValueExW(
            self.0,
            PCWSTR::from_raw(field_name.as_ptr()),
            None,
            Some(&mut buf_type),
            Some(buf.as_mut_ptr()),
            Some(buf_len),
        )
        .ok()
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        let _err = unsafe { RegCloseKey(self.0) };
    }
}

fn get_reg_string_value(hkey: HKEY, path: &str, field_name: &str) -> Option<String> {
    let c_path = utf16_str(path);
    let c_field_name = utf16_str(field_name);

    unsafe {
        let new_key = RegKey::open(hkey, &c_path)?;
        let mut buf_len: u32 = 2048;
        let mut buf: Vec<u8> = Vec::with_capacity(buf_len as usize);

        loop {
            match new_key.get_value(&c_field_name, &mut buf, &mut buf_len) {
                Ok(()) => break,
                Err(err) if err.code() == Foundation::ERROR_MORE_DATA.to_hresult() => {
                    buf.set_len(buf.capacity());
                    buf.reserve(buf_len as _);
                }
                _ => return None,
            }
        }

        buf.set_len(buf_len as _);

        let words = std::slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len() / 2);
        let mut s = String::from_utf16_lossy(words);
        while s.ends_with('\u{0}') {
            s.pop();
        }
        Some(s)
    }
}

fn get_reg_value_u32(hkey: HKEY, path: &str, field_name: &str) -> Option<[u8; 4]> {
    let c_path = utf16_str(path);
    let c_field_name = utf16_str(field_name);

    unsafe {
        let new_key = RegKey::open(hkey, &c_path)?;
        let mut buf_len: u32 = 4;
        let mut buf = [0u8; 4];

        new_key
            .get_value(&c_field_name, &mut buf, &mut buf_len)
            .map(|_| buf)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username() {
        let result = username();
        assert!(result.is_some(), "Username should be retrievable");
        assert!(!result.unwrap().is_empty(), "Username should not be empty");
    }

    #[test]
    fn test_hostname() {
        let result = hostname();
        assert!(result.is_some(), "Hostname should be retrievable");
        assert!(!result.unwrap().is_empty(), "Hostname should not be empty");
    }

    #[test]
    fn test_lang() {
        println!("Current language: {:?}", lang());
    }

    #[test]
    fn test_os_info() {
        println!("OS Name: {:?}", name());
        println!("OS Version: {:?}", os_version());
        println!("Kernel Version: {:?}", kernel_version());
        println!("Long OS Version: {:?}", long_os_version());
        println!("Distribution ID: {}", distribution_id());
        println!("CPU Architecture: {:?}", cpu_arch());
    }

    #[test]
    fn test_physical_core_count() {
        println!("Physical Core Count: {:?}", physical_core_count());
    }

    #[test]
    fn test_time_info() {
        println!("Uptime: {}", uptime());
        println!("Boot Time: {}", boot_time());
    }
}
