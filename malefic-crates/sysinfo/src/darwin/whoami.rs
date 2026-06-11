use libc::{c_int, c_void, sysctl, timeval};
use std::ffi::{CStr, OsString};
use std::mem;
use std::ptr;

pub fn username() -> Option<OsString> {
    std::env::var_os("USER")
}

pub fn hostname() -> Option<OsString> {
    get_system_info(libc::KERN_HOSTNAME, None).map(OsString::from)
}

pub fn lang() -> Option<String> {
    std::env::var("LANG")
        .or_else(|_| std::env::var("LANGUAGE"))
        .ok()
}

pub fn name() -> Option<String> {
    get_system_info(libc::KERN_OSTYPE, Some("Darwin"))
}

pub fn os_version() -> Option<String> {
    unsafe {
        let mut size = 0;
        if get_sys_value_by_name(b"kern.osproductversion\0", &mut size, ptr::null_mut()) && size > 0
        {
            let mut buf = vec![0_u8; size as _];
            if get_sys_value_by_name(
                b"kern.osproductversion\0",
                &mut size,
                buf.as_mut_ptr() as *mut c_void,
            ) {
                if let Some(pos) = buf.iter().position(|x| *x == 0) {
                    buf.resize(pos, 0);
                }
                String::from_utf8(buf).ok()
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub fn kernel_version() -> Option<String> {
    get_system_info(libc::KERN_OSRELEASE, None)
}

pub fn long_os_version() -> Option<String> {
    let os_version = os_version()?;
    // https://en.wikipedia.org/wiki/MacOS_version_history
    for (version_prefix, macos_spelling, friendly_name) in [
        ("15", "macOS", "Sequoia"),
        ("14", "macOS", "Sonoma"),
        ("13", "macOS", "Ventura"),
        ("12", "macOS", "Monterey"),
        ("11", "macOS", "Big Sur"),
        ("10.16", "macOS", "Big Sur"),
        ("10.15", "macOS", "Catalina"),
        ("10.14", "macOS", "Mojave"),
        ("10.13", "macOS", "High Sierra"),
        ("10.12", "macOS", "Sierra"),
        ("10.11", "OS X", "El Capitan"),
        ("10.10", "OS X", "Yosemite"),
        ("10.9", "OS X", "Mavericks"),
        ("10.8", "OS X", "Mountain Lion"),
        ("10.7", "Mac OS X", "Lion"),
        ("10.6", "Mac OS X", "Snow Leopard"),
        ("10.5", "Mac OS X", "Leopard"),
        ("10.4", "Mac OS X", "Tiger"),
        ("10.3", "Mac OS X", "Panther"),
        ("10.2", "Mac OS X", "Jaguar"),
        ("10.1", "Mac OS X", "Puma"),
        ("10.0", "Mac OS X", "Cheetah"),
    ] {
        if os_version.starts_with(version_prefix) {
            return Some(format!("{macos_spelling} {os_version} {friendly_name}"));
        }
    }
    Some(format!("macOS {os_version}"))
}

pub fn distribution_id() -> String {
    std::env::consts::OS.to_owned()
}

pub fn cpu_arch() -> Option<String> {
    let mut arch_str: [u8; 32] = [0; 32];
    let mut mib = [libc::CTL_HW as _, libc::HW_MACHINE as _];

    unsafe {
        if get_sys_value(
            mem::size_of::<[u8; 32]>(),
            arch_str.as_mut_ptr() as *mut _,
            &mut mib,
        ) {
            CStr::from_bytes_until_nul(&arch_str)
                .ok()
                .and_then(|res| res.to_str().ok())
                .map(String::from)
        } else {
            None
        }
    }
}

pub fn physical_core_count() -> Option<usize> {
    let mut mib = [libc::CTL_HW as _, libc::HW_NCPU as _];
    let mut size = mem::size_of::<u32>();
    let mut count: u32 = 0;

    unsafe {
        if get_sys_value(size, &mut count as *mut _ as *mut _, &mut mib) {
            Some(count as usize)
        } else {
            None
        }
    }
}

pub fn uptime() -> u64 {
    unsafe {
        let csec = libc::time(ptr::null_mut());
        libc::difftime(csec, boot_time() as _) as u64
    }
}

pub fn boot_time() -> u64 {
    let mut boot_time = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = mem::size_of::<timeval>();
    let mut mib: [c_int; 2] = [libc::CTL_KERN, libc::KERN_BOOTTIME];

    unsafe {
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            &mut boot_time as *mut timeval as *mut _,
            &mut len,
            ptr::null_mut(),
            0,
        ) < 0
        {
            0
        } else {
            boot_time.tv_sec as _
        }
    }
}

fn get_system_info(value: c_int, default: Option<&str>) -> Option<String> {
    let mut mib: [c_int; 2] = [libc::CTL_KERN, value];
    let mut size = 0;

    unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        );

        if size == 0 {
            return default.map(String::from);
        }

        let mut buf = vec![0_u8; size as _];
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            buf.as_mut_ptr() as _,
            &mut size,
            ptr::null_mut(),
            0,
        ) == -1
        {
            default.map(String::from)
        } else {
            if let Some(pos) = buf.iter().position(|x| *x == 0) {
                buf.resize(pos, 0);
            }
            String::from_utf8(buf).ok()
        }
    }
}

unsafe fn get_sys_value(length: usize, value: *mut c_void, mib: &mut [c_int]) -> bool {
    let mut len = length;
    sysctl(
        mib.as_mut_ptr(),
        mib.len() as _,
        value,
        &mut len,
        ptr::null_mut(),
        0,
    ) == 0
}

unsafe fn get_sys_value_by_name(name: &[u8], length: &mut usize, value: *mut c_void) -> bool {
    libc::sysctlbyname(name.as_ptr() as *const _, value, length, ptr::null_mut(), 0) == 0
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
