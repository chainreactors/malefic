use std::ffi::{CStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStringExt;

pub fn username() -> Option<OsString> {
    std::env::var_os("USER").or_else(|| unsafe {
        let uid = libc::geteuid();
        let mut result = std::ptr::null_mut();
        let mut passwd = std::mem::MaybeUninit::uninit();
        let mut buf = vec![0u8; 2048];

        let ret = libc::getpwuid_r(
            uid,
            passwd.as_mut_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        );

        if ret == 0 && !result.is_null() {
            let passwd = passwd.assume_init();
            if !passwd.pw_name.is_null() {
                return Some(OsString::from_vec(
                    CStr::from_ptr(passwd.pw_name).to_bytes().to_vec(),
                ));
            }
        }
        None
    })
}

pub fn hostname() -> Option<OsString> {
    let mut buffer = vec![0u8; 256];
    unsafe {
        if libc::gethostname(buffer.as_mut_ptr() as *mut libc::c_char, buffer.len()) == 0 {
            let hostname = CStr::from_ptr(buffer.as_ptr() as *const libc::c_char);
            Some(OsString::from_vec(hostname.to_bytes().to_vec()))
        } else {
            None
        }
    }
}

pub fn lang() -> Option<String> {
    std::env::var("LANG")
        .or_else(|_| std::env::var("LANGUAGE"))
        .ok()
}

pub fn name() -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.starts_with("NAME="))
                .map(|line| {
                    line.trim_start_matches("NAME=")
                        .trim_matches('"')
                        .to_string()
                })
        })
        .or_else(|| Some("Linux".to_string()))
}

pub fn os_version() -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.starts_with("VERSION_ID="))
                .map(|line| {
                    line.trim_start_matches("VERSION_ID=")
                        .trim_matches('"')
                        .to_string()
                })
        })
}

pub fn kernel_version() -> Option<String> {
    let mut uts = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } == 0 {
        let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) };
        release.to_str().ok().map(String::from)
    } else {
        None
    }
}

pub fn long_os_version() -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            let name = content
                .lines()
                .find(|line| line.starts_with("NAME="))
                .map(|line| {
                    line.trim_start_matches("NAME=")
                        .trim_matches('"')
                        .to_string()
                });
            let version = content
                .lines()
                .find(|line| line.starts_with("VERSION="))
                .map(|line| {
                    line.trim_start_matches("VERSION=")
                        .trim_matches('"')
                        .to_string()
                });
            match (name, version) {
                (Some(name), Some(version)) => Some(format!("{} {}", name, version)),
                (Some(name), None) => Some(name),
                _ => None,
            }
        })
}

pub fn distribution_id() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.starts_with("ID="))
                .map(|line| line.trim_start_matches("ID=").trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "linux".to_string())
}

pub fn cpu_arch() -> Option<String> {
    let mut uts = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } == 0 {
        let machine = unsafe { CStr::from_ptr(uts.machine.as_ptr()) };
        machine.to_str().ok().map(String::from)
    } else {
        None
    }
}

pub fn physical_core_count() -> Option<usize> {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|content| {
            let count = content
                .lines()
                .filter(|line| line.starts_with("processor"))
                .count();
            if count > 0 {
                Some(count)
            } else {
                None
            }
        })
}

pub fn uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|content| {
            content
                .split_whitespace()
                .next()
                .and_then(|secs| secs.parse::<f64>().ok())
                .map(|secs| secs as u64)
        })
        .unwrap_or(0)
}

pub fn boot_time() -> u64 {
    fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.starts_with("btime"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|val| val.parse().ok())
                })
        })
        .unwrap_or(0)
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
